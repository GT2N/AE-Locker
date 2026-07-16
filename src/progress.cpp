// progress.cpp — self-contained multi-file progress bars (renderer rewrite, no indicators).
//
// Layout (N input files):
//   <file 0 prefix padded to kLabelWidth> <bar-file-0> <suffix-0>
//   <file 1 prefix padded to kLabelWidth> <bar-file-1> <suffix-1>
//   ...
//   <file N-1 prefix padded to kLabelWidth> <bar-file-N-1> <suffix-N-1>
//   <overall label padded to kLabelWidth> <bar-overall> <suffix-overall>
//
// Each bar uses ASCII `[=====>     ]` style (no color, no Unicode).
// The overall bar sits at the BOTTOM (per user request — original code had it
// at the top, which felt counter-intuitive).
//
// In-place refresh is done by hand with `\x1b[<N>A` cursor-up escape codes:
//   - At start(): emit `N+1` newlines to reserve the bars block, then cursor
//     back up `N+1` rows. Cursor lands at row 0 col 0.
//   - Each render writes every bar line via one big std::string appended to
//     stderr, ending with cursor-up `N` rows + `\r` so the next render's
//     first bar lands on row 0 col 0 again.
//   - finish() renders once more and then moves cursor DOWN `N+1` rows + one
//     `\n` so subsequent CLI output starts on a fresh line below the block.
//
// Why replace indicators (v2.3):
//   * DynamicProgress::operator[] never took a lock, so concurrent
//     set_progress calls from multiple worker threads tore cursor state
//     (indicators Issue #132, PR #133 unmerged).
//   * The `==>` / Unicode block glyphs and forced bright colors leaked
//     outside narrow terminals, but terminals narrower than the rendered row
//     would re-wrap each bar down multiple rows, then `move_up(N)` couldn't
//     backtrack to the right row and the screen kept scrolling — exactly the
//     pattern the user observed.
//   * Hand-rolling takes ~250 LOC, gives us a unified render pass (any
//     per-slot state update repaints the whole block atomically), and lets
//     us color-grade the layout to fit on an 80-column terminal.

#include <lock/progress.hpp>
#include <lock/i18n.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

namespace lock {

namespace {

// Fixed layout constants — chosen so a 4-file tracker fits comfortably in
// an 80-column TTY: 24 (label) + 1 (sep) + 30 (bar) + 1 (sep) + ~16 (suffix)
// = ~72 columns total. The label is right-padded with spaces; long filenames
// get an ellipsis prefix.
constexpr size_t kLabelWidth   = 24;
constexpr size_t kBarWidth     = 30;
constexpr auto kRenderInterval = std::chrono::milliseconds(33);  // ~30 fps

// Truncate `name` to `limit` chars. If too long, render as
// "..." + last (limit-3) chars so users still see the file extension.
std::string truncate_filename(std::string_view name, size_t limit) {
    std::string s(name);
    if (limit > 3 && s.size() > limit) {
        s = "..." + s.substr(s.size() - (limit - 3));
    } else if (s.size() > limit) {
        s.resize(limit);
    }
    return s;
}

// Build a bar string. Style: `[` + (fill-1)*'=' + '>' + (width-fill)*' ' + `]`.
// Special cases:
//   * pct == 0   -> `[                              ]`
//   * pct == 100 -> `[==============================]`
//   * otherwise  -> `[=========>                     ]` (lead char `>` on last fill)
std::string make_bar(size_t pct_clamped) {
    std::string s;
    s.reserve(kBarWidth + 2);
    s.push_back('[');
    size_t fill = (pct_clamped * kBarWidth) / 100;
    if (fill > kBarWidth) fill = kBarWidth;
    if (fill > 0 && fill < kBarWidth) {
        s.append(fill - 1, '=');
        s.push_back('>');
    } else if (fill == kBarWidth) {
        s.append(fill, '=');
    }
    s.append(kBarWidth - fill, ' ');
    s.push_back(']');
    return s;
}

std::string pad_label(std::string s) {
    if (s.size() > kLabelWidth) {
        s.resize(kLabelWidth);
    } else if (s.size() < kLabelWidth) {
        s.append(kLabelWidth - s.size(), ' ');
    }
    return s;
}

}  // namespace

struct ProgressTracker::Impl {
    size_t total_files = 0;
    std::atomic<size_t> files_done{0};

    std::atomic<size_t> total_chunks_done{0};
    std::atomic<size_t> total_chunks_all{0};

    // slot 0 = overall, slot 1..N = per-file. Sized total_files + 1 with
    // unique_ptr because std::vector<atomic> is not movable-assign-able.
    std::unique_ptr<std::atomic<size_t>[]> chunks_done_per_file;

    // Non-atomic state — guarded by `mutex_`. Set once at start_file, read on
    // every render_all. Holding the mutex guarantees consistent snapshots
    // across all slots' non-atomic fields + serializes the screen flush so
    // two worker threads never interleave their ANSI cursor writes.
    std::vector<size_t> total_chunks_per_file;
    std::vector<std::string> file_names;
    std::vector<bool>        file_finished;
    std::vector<std::chrono::steady_clock::time_point> last_render;  // per-slot throttle

    std::mutex mutex_;          // guards the four containers above + stderr writes
    bool started = false;
    bool finished = false;
};

ProgressTracker::ProgressTracker() : pimpl_(std::make_unique<Impl>()) {}

ProgressTracker::~ProgressTracker() {
    if (pimpl_ && pimpl_->started && !pimpl_->finished) {
        try {
            finish();
        } catch (...) {
            // Destructor must not throw — best-effort cleanup only.
        }
    }
}

ProgressTracker::ProgressTracker(ProgressTracker&&) noexcept = default;
ProgressTracker& ProgressTracker::operator=(ProgressTracker&&) noexcept = default;

void ProgressTracker::start(size_t total_files) {
    std::lock_guard<std::mutex> lock(pimpl_->mutex_);
    pimpl_->total_files = total_files;
    pimpl_->files_done.store(0, std::memory_order_relaxed);
    pimpl_->total_chunks_done.store(0, std::memory_order_relaxed);
    pimpl_->total_chunks_all.store(0, std::memory_order_relaxed);
    pimpl_->chunks_done_per_file =
        std::make_unique<std::atomic<size_t>[]>(total_files + 1);
    for (size_t i = 0; i <= total_files; ++i) {
        pimpl_->chunks_done_per_file[i].store(0, std::memory_order_relaxed);
    }
    pimpl_->total_chunks_per_file.assign(total_files + 1, 0);
    pimpl_->file_names.assign(total_files, {});
    pimpl_->file_finished.assign(total_files, false);
    pimpl_->last_render.assign(total_files + 1,
                                std::chrono::steady_clock::time_point{});
    // Reserve the screen real estate: print N+1 newlines so the terminal
    // scrolls and there's blank space below the cursor for the bars to occupy,
    // then move cursor back UP N+1 lines so it sits at the topmost bar row.
    // We emit a single string with one fwrite to keep the syscall atomic —
    // partial writes here would leave a half-reserved block.
    const size_t lines = total_files + 1;
    std::string out;
    out.reserve(lines + 16);
    for (size_t i = 0; i < lines; ++i) out.push_back('\n');
    out.append("\x1b[");
    out.append(std::to_string(lines));
    out.append("A\r");
    std::fwrite(out.data(), 1, out.size(), stderr);
    std::fflush(stderr);

    pimpl_->started = true;
    render_all_locked();
}

void ProgressTracker::start_file(size_t file_idx,
                                  std::string_view filename,
                                  size_t total_chunks) {
    std::lock_guard<std::mutex> lock(pimpl_->mutex_);
    const size_t slot = file_idx + 1;
    if (slot < pimpl_->total_chunks_per_file.size()) {
        pimpl_->total_chunks_per_file[slot] = total_chunks;
    }
    if (file_idx < pimpl_->file_names.size()) {
        pimpl_->file_names[file_idx] = std::string(filename);
    }
    pimpl_->total_chunks_all.fetch_add(total_chunks,
                                       std::memory_order_relaxed);
    if (slot <= pimpl_->total_files) {
        pimpl_->chunks_done_per_file[slot].store(0,
                                                  std::memory_order_relaxed);
    }
    render_all_locked();
}

void ProgressTracker::update_file(size_t file_idx, size_t chunk_done) {
    const size_t slot = file_idx + 1;
    if (slot >= pimpl_->total_chunks_per_file.size()) return;
    // total is set by start_file under mutex_ and never mutated again for this
    // slot — safe to read without the lock. (Happens-before comes from the
    // thread that calls update_file having been spawned *after* start_file
    // returned, which the cli.cpp launcher establishes.)
    const size_t total = pimpl_->total_chunks_per_file[slot];
    if (total == 0) {
        return;
    }
    size_t clamped = std::min(chunk_done, total);

    size_t old = pimpl_->chunks_done_per_file[slot].exchange(
        clamped, std::memory_order_relaxed);
    if (clamped == old) {
        return;
    }
    if (clamped > old) {
        pimpl_->total_chunks_done.fetch_add(clamped - old,
                                            std::memory_order_relaxed);
    }

    // Per-slot throttle: don't repaint the screen more than ~30 fps even if
    // the cipher worker calls us back faster. The "global" rate of repaints
    // is naturally bounded by the worker with the most progress to report.
    auto now = std::chrono::steady_clock::now();
    if (now - pimpl_->last_render[slot] < kRenderInterval) {
        return;
    }
    pimpl_->last_render[slot] = now;

    render_all();
}

void ProgressTracker::finish_file(size_t file_idx) {
    if (file_idx >= pimpl_->total_files) return;
    const size_t slot = file_idx + 1;
    if (slot >= pimpl_->total_chunks_per_file.size()) return;
    const size_t total = pimpl_->total_chunks_per_file[slot];

    // Top up the slot's chunk counter to its declared total so the overall
    // bar reaches 100% even when the last chunk's update_file() was throttled
    // away below the 33 ms render window.
    size_t old = pimpl_->chunks_done_per_file[slot].exchange(
        total, std::memory_order_relaxed);
    if (total > old) {
        pimpl_->total_chunks_done.fetch_add(total - old,
                                            std::memory_order_relaxed);
    }
    pimpl_->files_done.fetch_add(1, std::memory_order_relaxed);

    {
        std::lock_guard<std::mutex> lock(pimpl_->mutex_);
        pimpl_->file_finished[file_idx] = true;
    }
    render_all();
}

void ProgressTracker::set_overall(size_t /*files_done*/) {
    // Legacy entry point. The chunk-level accumulators drive the overall bar
    // now — the reported `files_done` count is ignored. We still tick a
    // repaint so any caller who touches the overall bar via this method sees
    // their progress land on-screen.
    render_all();
}

void ProgressTracker::finish() {
    if (!pimpl_->started || pimpl_->finished) {
        return;
    }
    // Force overall bar to 100% explicitly so the final frame looks complete
    // even if the very last update was throttled away.
    pimpl_->total_chunks_done.store(
        pimpl_->total_chunks_all.load(std::memory_order_relaxed),
        std::memory_order_relaxed);

    {
        std::lock_guard<std::mutex> lock(pimpl_->mutex_);
        for (size_t i = 0; i < pimpl_->total_files; ++i) {
            pimpl_->file_finished[i] = true;
        }
        render_all_locked();
    }

    // Cursor is now at row 0 col 0. Move DOWN past the bars block (N+1 rows)
    // plus one extra `\n` so any subsequent CLI output starts on a clean line
    // below the tracker instead of overwriting the overall bar.
    const size_t lines = pimpl_->total_files + 1;
    std::string out;
    out.reserve(16);
    out.append("\x1b[");
    out.append(std::to_string(lines));
    out.append("B\n");
    std::fwrite(out.data(), 1, out.size(), stderr);
    std::fflush(stderr);

    pimpl_->finished = true;
}

std::function<void(size_t, size_t)>
ProgressTracker::make_callback(size_t file_idx, size_t chunk_size) {
    const size_t slot = file_idx + 1;
    const size_t total = (slot < pimpl_->total_chunks_per_file.size())
                          ? pimpl_->total_chunks_per_file[slot]
                          : 0;
    ProgressTracker* self = this;
    return [self, slot, total, chunk_size](size_t bytes_done, size_t /*bytes_total*/) {
        if (total == 0) {
            return;
        }
        size_t chunks_done = (chunk_size == 0) ? 0 : (bytes_done / chunk_size);
        if (chunks_done > total) {
            chunks_done = total;
        }
        self->update_file(slot - 1, chunks_done);
    };
}

// Public wrapper used by callers that already hold the mutex_ (start(),
// start_file()). External callers go through render_all().
void ProgressTracker::render_all() {
    if (!pimpl_->started || pimpl_->finished) return;
    std::lock_guard<std::mutex> lock(pimpl_->mutex_);
    render_all_locked();
}

// Render the whole bars block to stderr in one fwrite. Pre-condition: caller
// holds mutex_ AND cursor is at row 0 col 0 of the bars block (the invariant
// established by start() and re-established at the bottom of every render).
void ProgressTracker::render_all_locked() {
    if (!pimpl_->started || pimpl_->finished) return;

    const size_t total_files = pimpl_->total_files;

    std::string out;
    out.reserve(4096);

    for (size_t i = 0; i < total_files; ++i) {
        const size_t slot = i + 1;
        const size_t total = pimpl_->total_chunks_per_file[slot];
        const bool   done  = pimpl_->file_finished[i];
        size_t chunks_done = pimpl_->chunks_done_per_file[slot].load(
            std::memory_order_relaxed);
        const std::string& raw_label = pimpl_->file_names[i];

        std::string label = pad_label(truncate_filename(raw_label, kLabelWidth));

        std::string bar;
        std::string suffix;
        if (total == 0) {
            bar = make_bar(0);
            suffix = tr(Str::Progress_pending);
        } else if (done) {
            bar = make_bar(100);
            suffix = std::string("100% ") + tr(Str::Progress_done);
        } else {
            size_t clamped = std::min(chunks_done, total);
            size_t pct = (clamped * 100) / total;
            bar = make_bar(pct);
            suffix = std::to_string(pct) + "% " +
                     std::to_string(clamped) + "/" + std::to_string(total);
        }

        out.push_back('\r');
        out.append("\x1b[K");   // erase-to-end-of-line — clears any prior content
        out.append(label);
        out.push_back(' ');
        out.append(bar);
        out.push_back(' ');
        out.append(suffix);
        out.push_back('\n');
    }

    {
        size_t total = pimpl_->total_chunks_all.load(std::memory_order_relaxed);
        size_t done  = pimpl_->total_chunks_done.load(std::memory_order_relaxed);
        std::string label = pad_label(tr(Str::Progress_overall_prefix));

        std::string bar;
        std::string suffix;
        if (total == 0) {
            bar = make_bar(0);
            suffix = "0/" + std::to_string(pimpl_->total_files);
        } else {
            size_t clamped = std::min(done, total);
            size_t pct = (clamped * 100) / total;
            bar = make_bar(pct);
            suffix = std::to_string(pct) + "% " +
                     std::to_string(clamped) + "/" + std::to_string(total);
        }

        out.push_back('\r');
        out.append("\x1b[K");
        out.append(label);
        out.push_back(' ');
        out.append(bar);
        out.push_back(' ');
        out.append(suffix);
        // No trailing `\n` — cursor sits on the overall row after writing.
    }

    // Restore cursor to row 0 col 0 so the next render can replay from the
    // top. We need to move UP `total_files` rows (one less than the block
    // height, because we left cursor on the bottom row without advancing).
    if (total_files > 0) {
        out.append("\x1b[");
        out.append(std::to_string(total_files));
        out.append("A\r");
    }

    std::fwrite(out.data(), 1, out.size(), stderr);
    std::fflush(stderr);
}

}  // namespace lock
