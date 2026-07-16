#include <lock/progress.hpp>
#include <lock/i18n.hpp>

#include <indicators/cursor_control.hpp>
#include <indicators/dynamic_progress.hpp>
#include <indicators/progress_bar.hpp>
#include <indicators/termcolor.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace lock {

namespace {

std::string truncate_filename(std::string_view name) {
    std::string s(name);
    if (s.size() > 40) {
        s = "..." + s.substr(s.size() - 37);
    }
    return s;
}

constexpr size_t kOverallBarWidth = 40;
constexpr size_t kFileBarWidth    = 30;
constexpr auto kRenderInterval = std::chrono::milliseconds(33);

indicators::Color overall_color() {
    return color_enabled() ? indicators::Color::green
                           : indicators::Color::unspecified;
}

indicators::Color file_color() {
    return color_enabled() ? indicators::Color::cyan
                           : indicators::Color::unspecified;
}

std::vector<indicators::FontStyle> bold_style() {
    if (color_enabled()) {
        return {indicators::FontStyle::bold};
    }
    return {};
}

}  // namespace

struct ProgressTracker::Impl {
    std::deque<indicators::ProgressBar> bar_storage;
    indicators::DynamicProgress<indicators::ProgressBar> bars;

    size_t total_files = 0;
    std::atomic<size_t> files_done{0};

    std::atomic<size_t> total_chunks_done{0};
    std::atomic<size_t> total_chunks_all{0};

    std::unique_ptr<std::atomic<size_t>[]> chunks_done_per_file;
    std::vector<size_t> total_chunks_per_file;
    std::vector<std::string> file_names;
    std::vector<std::chrono::steady_clock::time_point> last_render;

    bool started = false;
    bool finished = false;
    bool plain = false;
    std::mutex start_mutex;
    std::mutex plain_mutex;
};

ProgressTracker::ProgressTracker() : pimpl_(std::make_unique<Impl>()) {}

ProgressTracker::~ProgressTracker() {
    if (pimpl_ && pimpl_->started && !pimpl_->finished) {
        try {
            finish();
        } catch (...) {
        }
    }
}

ProgressTracker::ProgressTracker(ProgressTracker&&) noexcept = default;
ProgressTracker& ProgressTracker::operator=(ProgressTracker&&) noexcept = default;

void ProgressTracker::start(size_t total_files) {
    std::lock_guard<std::mutex> lock(pimpl_->start_mutex);
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
    pimpl_->last_render.assign(total_files + 1,
                               std::chrono::steady_clock::time_point{});
    pimpl_->plain = !color_enabled();

    if (pimpl_->plain) {
        pimpl_->started = true;
        std::cerr << tr(Str::Progress_overall_prefix) << " 0/"
                  << total_files << "\n";
        return;
    }

    indicators::show_console_cursor(false);

    pimpl_->bar_storage.emplace_back(
        indicators::option::BarWidth{kOverallBarWidth},
        indicators::option::Start{"Progress "},
        indicators::option::End{""},
        indicators::option::PrefixText{tr(Str::Progress_overall_prefix)},
        indicators::option::PostfixText{"0/0"},
        indicators::option::ForegroundColor{overall_color()},
        indicators::option::FontStyles{bold_style()},
        indicators::option::ShowPercentage{true},
        indicators::option::MaxPostfixTextLen{16}
    );
    pimpl_->bars.push_back(pimpl_->bar_storage.back());
    pimpl_->bar_storage.back().set_progress(0);

    for (size_t i = 0; i < total_files; ++i) {
        pimpl_->bar_storage.emplace_back(
            indicators::option::BarWidth{kFileBarWidth},
            indicators::option::Start{"  "},
            indicators::option::End{""},
            indicators::option::PrefixText{tr(Str::Progress_pending)},
            indicators::option::PostfixText{""},
            indicators::option::ForegroundColor{file_color()},
            indicators::option::ShowPercentage{true},
            indicators::option::MaxPostfixTextLen{16}
        );
        pimpl_->bars.push_back(pimpl_->bar_storage.back());
        pimpl_->bar_storage.back().set_progress(0);
    }

    pimpl_->started = true;
}

void ProgressTracker::start_file(size_t file_idx,
                                  std::string_view filename,
                                  size_t total_chunks) {
    std::lock_guard<std::mutex> lock(pimpl_->start_mutex);
    const size_t slot = file_idx + 1;
    pimpl_->total_chunks_per_file[slot] = total_chunks;
    if (file_idx < pimpl_->file_names.size()) {
        pimpl_->file_names[file_idx] = std::string(filename);
    }
    pimpl_->total_chunks_all.fetch_add(total_chunks,
                                       std::memory_order_relaxed);
    pimpl_->chunks_done_per_file[slot].store(0,
                                             std::memory_order_relaxed);

    if (pimpl_->plain) {
        std::lock_guard<std::mutex> pl(pimpl_->plain_mutex);
        std::cerr << truncate_filename(filename) << ": 0/"
                  << total_chunks << " " << tr(Str::Progress_pending) << "\n";
        return;
    }

    auto& bar = pimpl_->bars[slot];
    bar.set_option(indicators::option::PrefixText{truncate_filename(filename) + ": "});
    bar.set_option(indicators::option::PostfixText{
        "0/" + std::to_string(total_chunks)});
    bar.set_progress(0);
    pimpl_->last_render[slot] = std::chrono::steady_clock::now();
}

void ProgressTracker::update_file(size_t file_idx, size_t chunk_done) {
    if (pimpl_->plain) return;
    const size_t slot = file_idx + 1;
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

    auto now = std::chrono::steady_clock::now();
    if (now - pimpl_->last_render[slot] < kRenderInterval) {
        return;
    }
    pimpl_->last_render[slot] = now;

    size_t pct = (clamped * 100) / total;
    auto& bar = pimpl_->bars[slot];
    bar.set_option(indicators::option::PostfixText{
        std::to_string(clamped) + "/" + std::to_string(total)});
    bar.set_progress(std::min<size_t>(pct, 100));

    advance_overall();
}

void ProgressTracker::finish_file(size_t file_idx) {
    if (pimpl_->plain) {
        std::lock_guard<std::mutex> pl(pimpl_->plain_mutex);
        std::string nm = (file_idx < pimpl_->file_names.size())
                              ? pimpl_->file_names[file_idx]
                              : "";
        std::cerr << truncate_filename(nm) << " " << tr(Str::Progress_done)
                  << "\n";
        size_t done =
            pimpl_->files_done.fetch_add(1, std::memory_order_relaxed) + 1;
        std::cerr << tr(Str::Progress_overall_prefix) << " " << done << "/"
                  << pimpl_->total_files << "\n";
        return;
    }
    const size_t slot = file_idx + 1;
    const size_t total = pimpl_->total_chunks_per_file[slot];

    size_t old = pimpl_->chunks_done_per_file[slot].exchange(
        total, std::memory_order_relaxed);
    if (total > old) {
        pimpl_->total_chunks_done.fetch_add(total - old,
                                            std::memory_order_relaxed);
    }

    auto& bar = pimpl_->bars[slot];
    bar.set_option(indicators::option::PostfixText{tr(Str::Progress_done)});
    bar.set_progress(100);
    bar.mark_as_completed();

    pimpl_->files_done.fetch_add(1, std::memory_order_relaxed);
    advance_overall();
}

void ProgressTracker::advance_overall() {
    if (pimpl_->plain) return;
    const size_t total = pimpl_->total_chunks_all.load(std::memory_order_relaxed);
    if (total == 0) {
        return;
    }
    size_t done = pimpl_->total_chunks_done.load(std::memory_order_relaxed);
    size_t clamped = std::min(done, total);
    size_t pct = (clamped * 100) / total;
    pimpl_->bars[0].set_option(indicators::option::PostfixText{
        std::to_string(clamped) + "/" + std::to_string(total)});
    pimpl_->bars[0].set_progress(std::min<size_t>(pct, 100));
}

void ProgressTracker::set_overall(size_t files_done) {
    if (pimpl_->plain) return;
    const size_t total = pimpl_->total_files;
    if (total == 0) {
        return;
    }
    const size_t clamped = std::min(files_done, total);
    const size_t pct = (clamped * 100) / total;
    pimpl_->bars[0].set_option(indicators::option::PostfixText{
        std::to_string(clamped) + "/" + std::to_string(total)});
    pimpl_->bars[0].set_progress(std::min<size_t>(pct, 100));
}

void ProgressTracker::finish() {
    if (!pimpl_->started || pimpl_->finished) {
        return;
    }
    if (pimpl_->plain) {
        pimpl_->finished = true;
        return;
    }
    pimpl_->bars[0].set_option(indicators::option::PostfixText{
        std::to_string(pimpl_->total_files) + "/" +
        std::to_string(pimpl_->total_files)});
    pimpl_->bars[0].set_progress(100);
    pimpl_->bars[0].mark_as_completed();

    std::cout << "\n";
    if (color_enabled()) {
        indicators::show_console_cursor(true);
    }
    pimpl_->finished = true;
}

std::function<void(size_t, size_t)>
ProgressTracker::make_callback(size_t file_idx, size_t chunk_size) {
    if (pimpl_->plain) {
        return [](size_t, size_t) {};
    }
    const size_t slot = file_idx + 1;
    const size_t total = pimpl_->total_chunks_per_file[slot];
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

}  // namespace lock
