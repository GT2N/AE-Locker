#pragma once

#include <cstddef>
#include <cstdint>

namespace lock {

// Snapshot of the system memory available to the process.
struct memory_status {
    size_t available_bytes;  // memory currently free / reclaimable
    size_t total_bytes;      // physical RAM installed
};

// Detect available and total physical memory.  Never throws; on any failure
// returns conservative fallback values (available = 512 MiB, total = 1 GiB).
[[nodiscard]] memory_status detect_memory() noexcept;

// Pick a chunk size for multi-threaded encryption.
//   user_chunk_size != 0  -> returned as-is (caller specified explicitly)
//   otherwise a size is chosen based on file_size, clamped to [256 KiB, 4 MiB]
//   and rounded up to a multiple of 16 (AES block size).
[[nodiscard]] size_t recommend_chunk_size(
    size_t available_bytes,
    size_t user_chunk_size,
    size_t file_size) noexcept;

// Pick a worker-thread count for processing `chunk_size` buffers.
//   user_jobs != 0  -> returned as-is (caller specified explicitly)
//   otherwise clamp(1, hw_concurrency, available_bytes / (chunk_size * 4))
//   The factor 4 budgets 4 chunk buffers per worker (compression + encryption
//   double-buffering).  Always returns at least 1 and never exceeds
//   hw_concurrency.
[[nodiscard]] unsigned recommend_jobs(
    unsigned user_jobs,
    size_t   available_bytes,
    size_t   chunk_size,
    unsigned hw_concurrency) noexcept;

}  // namespace lock
