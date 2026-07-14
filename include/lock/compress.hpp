#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <lock/constants.hpp>

namespace lock {

[[nodiscard]] const char* compression_id_name(CompressionId id) noexcept;

[[nodiscard]] size_t compress_bound(CompressionId algo, size_t src_size);

// `level` is ignored for LZ4. For ZSTD, 0 means default (3); valid range is [1, 22].
[[nodiscard]] std::vector<unsigned char> compress_chunk(
    CompressionId                  algo,
    std::span<const unsigned char> src,
    int                            level);

// Returns a vector of size == expected_size. For NONE, src.size() must equal expected_size.
[[nodiscard]] std::vector<unsigned char> decompress_chunk(
    CompressionId                  algo,
    std::span<const unsigned char> src,
    size_t                         expected_size);

}  // namespace lock
