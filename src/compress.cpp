#include <ae-locker/compress.hpp>

#include <memory>
#include <stdexcept>
#include <string>

#include <lz4.h>
#include <zstd.h>

namespace ae_locker {

namespace {

struct ZstdCCtxDeleter {
    void operator()(ZSTD_CCtx* p) const noexcept {
        if (p) {
            ZSTD_freeCCtx(p);
        }
    }
};

struct ZstdCCtxHolder {
    std::unique_ptr<ZSTD_CCtx, ZstdCCtxDeleter> ctx;
    explicit ZstdCCtxHolder() : ctx(ZSTD_createCCtx()) {
        if (!ctx) {
            throw std::runtime_error("ZSTD_createCCtx() failed");
        }
    }
};

ZstdCCtxHolder& thread_local_zstd_cctx() {
    thread_local ZstdCCtxHolder holder;
    return holder;
}

}  // namespace

const char* compression_id_name(CompressionId id) noexcept {
    switch (id) {
        case CompressionId::NONE:  return "none";
        case CompressionId::LZ4:   return "lz4";
        case CompressionId::ZSTD:  return "zstd";
    }
    return "?";
}

size_t compress_bound(CompressionId algo, size_t src_size) {
    switch (algo) {
        case CompressionId::NONE:
            return src_size;
        case CompressionId::LZ4:
            return static_cast<size_t>(LZ4_compressBound(static_cast<int>(src_size)));
        case CompressionId::ZSTD:
            return ZSTD_compressBound(src_size);
    }
    throw std::runtime_error("compress_bound: unknown CompressionId");
}

std::vector<unsigned char> compress_chunk(
    CompressionId                  algo,
    std::span<const unsigned char> src,
    int                            level) {

    const size_t n = src.size();

    // Zero-input must produce zero-output across all algorithms. Avoids the
    // overhead (and any boundary edge cases) of calling the block APIs with 0.
    if (n == 0) {
        return {};
    }

    switch (algo) {
        case CompressionId::NONE: {
            return std::vector<unsigned char>(src.begin(), src.end());
        }
        case CompressionId::LZ4: {
            const auto src_size_int = static_cast<int>(n);
            const int  dst_cap      = LZ4_compressBound(src_size_int);
            if (dst_cap <= 0) {
                throw std::runtime_error(
                    "LZ4_compressBound failed for src_size=" + std::to_string(n) +
                    " (code=" + std::to_string(dst_cap) + ")");
            }
            std::vector<unsigned char> dst(static_cast<size_t>(dst_cap));
            const int written = LZ4_compress_default(
                reinterpret_cast<const char*>(src.data()),
                reinterpret_cast<char*>(dst.data()),
                src_size_int,
                dst_cap);
            // LZ4_compress_default returns 0 on error (never negative).
            if (written == 0) {
                throw std::runtime_error(
                    "LZ4_compress_default failed (returned 0) for src_size=" +
                    std::to_string(n));
            }
            dst.resize(static_cast<size_t>(written));
            return dst;
        }
        case CompressionId::ZSTD: {
            if (level == 0) {
                level = 3;
            }
            if (level < 1 || level > 22) {
                throw std::runtime_error(
                    "ZSTD compress_chunk: level " + std::to_string(level) +
                    " out of range [1, 22]");
            }
            const size_t dst_cap = ZSTD_compressBound(n);
            if (ZSTD_isError(dst_cap)) {
                throw std::runtime_error(
                    "ZSTD_compressBound failed: " +
                    std::string(ZSTD_getErrorName(dst_cap)));
            }
            ZSTD_CCtx* ctx = thread_local_zstd_cctx().ctx.get();
            std::vector<unsigned char> dst(dst_cap);
            const size_t written = ZSTD_compressCCtx(
                ctx,
                dst.data(), dst_cap,
                src.data(), n,
                level);
            if (ZSTD_isError(written)) {
                throw std::runtime_error(
                    "ZSTD_compressCCtx failed: " +
                    std::string(ZSTD_getErrorName(written)));
            }
            dst.resize(written);
            return dst;
        }
    }
    throw std::runtime_error("compress_chunk: unknown CompressionId");
}

std::vector<unsigned char> decompress_chunk(
    CompressionId                  algo,
    std::span<const unsigned char> src,
    size_t                         expected_size) {

    switch (algo) {
        case CompressionId::NONE: {
            if (src.size() != expected_size) {
                throw std::runtime_error("size mismatch on decompress NONE");
            }
            return std::vector<unsigned char>(src.begin(), src.end());
        }
        case CompressionId::LZ4: {
            if (expected_size == 0) {
                return {};
            }
            std::vector<unsigned char> dst(expected_size);
            const int written = LZ4_decompress_safe(
                reinterpret_cast<const char*>(src.data()),
                reinterpret_cast<char*>(dst.data()),
                static_cast<int>(src.size()),
                static_cast<int>(expected_size));
            // Negative return = error code.
            if (written < 0) {
                throw std::runtime_error(
                    "LZ4_decompress_safe failed (code=" +
                    std::to_string(written) +
                    ") expected_size=" + std::to_string(expected_size) +
                    " compressed=" + std::to_string(src.size()));
            }
            return dst;
        }
        case CompressionId::ZSTD: {
            if (expected_size == 0) {
                return {};
            }
            std::vector<unsigned char> dst(expected_size);
            const size_t written = ZSTD_decompress(
                dst.data(), expected_size,
                src.data(), src.size());
            if (ZSTD_isError(written)) {
                throw std::runtime_error(
                    "ZSTD_decompress failed: " +
                    std::string(ZSTD_getErrorName(written)));
            }
            if (written != expected_size) {
                throw std::runtime_error(
                    "ZSTD_decompress size mismatch: got " +
                    std::to_string(written) +
                    " expected " + std::to_string(expected_size));
            }
            return dst;
        }
    }
    throw std::runtime_error("decompress_chunk: unknown CompressionId");
}

}  // namespace ae_locker
