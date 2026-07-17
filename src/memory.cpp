#include <ae-locker/memory.hpp>

#include <algorithm>
#include <cstddef>

#if defined(__linux__)
#include <unistd.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#include <unistd.h>
#endif

namespace ae_locker {

namespace {

constexpr size_t KIB = 1024ULL;
constexpr size_t MIB = 1024ULL * KIB;
constexpr size_t GIB = 1024ULL * MIB;

constexpr size_t FALLBACK_AVAILABLE = 512 * MIB;
constexpr size_t FALLBACK_TOTAL     = 1 * GIB;

constexpr size_t AES_BLOCK       = 16;
constexpr size_t SMALL_FILE_MAX  = 100 * MIB;
constexpr size_t MEDIUM_FILE_MAX = 1 * GIB;
constexpr size_t CHUNK_MIN       = 256 * KIB;
constexpr size_t CHUNK_MAX       = 4 * MIB;
constexpr size_t CHUNK_SMALL     = 256 * KIB;
constexpr size_t CHUNK_MEDIUM    = 1 * MIB;

size_t round_up_to_block(size_t v) noexcept {
    if (v == 0) {
        return AES_BLOCK;
    }
    size_t r = v % AES_BLOCK;
    if (r == 0) {
        return v;
    }
    return v + (AES_BLOCK - r);
}

}  // namespace

memory_status detect_memory() noexcept {
#if defined(__linux__)
    long pages = sysconf(_SC_AVPHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    long total_pages = sysconf(_SC_PHYS_PAGES);
    if (pages <= 0 || page_size <= 0 || total_pages <= 0) {
        return {FALLBACK_AVAILABLE, FALLBACK_TOTAL};
    }
    return {
        static_cast<size_t>(pages) * static_cast<size_t>(page_size),
        static_cast<size_t>(total_pages) * static_cast<size_t>(page_size),
    };
#elif defined(__APPLE__)
    uint64_t total = 0;
    size_t len = sizeof(total);
    if (sysctlbyname("hw.memsize", &total, &len, nullptr, 0) != 0 || total == 0) {
        return {FALLBACK_AVAILABLE, FALLBACK_TOTAL};
    }
    // macOS lacks a portable free-RAM syscall; fall back to 50% of total as a
    // conservative estimate of what is safe to budget for chunk buffers.
    return {total / 2, static_cast<size_t>(total)};
#else
    return {FALLBACK_AVAILABLE, FALLBACK_TOTAL};
#endif
}

size_t recommend_chunk_size(size_t available_bytes,
                            size_t user_chunk_size,
                            size_t file_size) noexcept {
    (void)available_bytes;
    if (user_chunk_size != 0) {
        return user_chunk_size;
    }
    size_t chosen;
    if (file_size < SMALL_FILE_MAX) {
        chosen = CHUNK_SMALL;
    } else if (file_size < MEDIUM_FILE_MAX) {
        chosen = CHUNK_MEDIUM;
    } else {
        chosen = file_size / 100;
        if (chosen < CHUNK_MIN) {
            chosen = CHUNK_MIN;
        } else if (chosen > CHUNK_MAX) {
            chosen = CHUNK_MAX;
        }
    }
    return round_up_to_block(chosen);
}

unsigned recommend_jobs(unsigned user_jobs,
                        size_t   available_bytes,
                        size_t   chunk_size,
                        unsigned hw_concurrency) noexcept {
    if (user_jobs != 0) {
        return user_jobs;
    }
    if (hw_concurrency == 0) {
        return 1;
    }
    if (chunk_size == 0) {
        return 1;
    }
    constexpr size_t buffers_per_worker = 4;
    size_t budget = chunk_size * buffers_per_worker;
    if (budget > available_bytes) {
        return 1;
    }
    size_t max_workers = available_bytes / budget;
    if (max_workers == 0) {
        return 1;
    }
    if (max_workers > static_cast<size_t>(hw_concurrency)) {
        return hw_concurrency;
    }
    return static_cast<unsigned>(max_workers);
}

}  // namespace ae_locker
