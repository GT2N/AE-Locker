#pragma once
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <functional>

namespace lock {

// RAII multi-file progress tracker.
// Shows one overall bar + N per-file bars (where N = file count).
// Each per-file bar's prefix shows the filename (truncated); its postfix shows "chunk i / total".
// All methods except `start` and `finish` are designed to be callable from any thread.
class ProgressTracker {
public:
    ProgressTracker();
    ~ProgressTracker();
    ProgressTracker(const ProgressTracker&) = delete;
    ProgressTracker& operator=(const ProgressTracker&) = delete;
    ProgressTracker(ProgressTracker&&) noexcept;
    ProgressTracker& operator=(ProgressTracker&&) noexcept;

    // Begin tracking. Hides the cursor. Allocates the overall bar.
    // After this, callers should use start_file to add per-file bars (one per file).
    void start(size_t total_files);

    // Add a new per-file bar at slot `file_idx` (0-based). The filename is truncated
    // for display if longer than ~40 chars. `total_chunks` is the per-file chunk count
    // used to compute percentage.
    void start_file(size_t file_idx, std::string_view filename, size_t total_chunks);

    // Update a per-file bar's progress. `chunk_done` is the number of chunks completed
    // for this file so far (out of total_chunks). Thread-safe: any worker thread can
    // call this for its own file_idx.
    void update_file(size_t file_idx, size_t chunk_done);

    // Mark a per-file bar as completed (100%). Thread-safe.
    void finish_file(size_t file_idx);

    // Tick the overall progress (advance by `files_done` files out of `total_files`).
    void set_overall(size_t files_done);

    // Final cleanup: prints newline, restores cursor. Must be called from the main
    // thread after all files have been processed (i.e., all threads joined).
    void finish();

    // Returns a per-file progress callback suitable for passing to `lock::encrypt_file` / `decrypt_file`.
    // The returned callback updates bar[file_idx]'s postfix and progress.
    // Signature of callback: (size_t bytes_done, size_t bytes_total).
    // The callback uses an internal chunk counter that increments per file's bytes-processed
    // relative to the chunk_size — OR simplest: directly map bytes_done/bytes_total to the bar %.
    //
    // IMPORTANT: the ProgressTracker must outlive all worker threads that hold copies of
    // the returned callback (the callback captures `this` by pointer).
    [[nodiscard]] std::function<void(size_t, size_t)> make_callback(size_t file_idx, size_t chunk_size);

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

}  // namespace lock
