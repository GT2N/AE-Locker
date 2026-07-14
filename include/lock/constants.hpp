#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

namespace lock {

// File format magic: "ENCF0001v1\0\0\0\0\0\0" (16 bytes, AES-block-aligned)
inline constexpr std::array<unsigned char, 16> MAGIC = {
    0x45, 0x4e, 0x43, 0x46, 0x30, 0x30, 0x30, 0x31,
    0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

inline constexpr uint32_t FORMAT_VERSION = 2;

// Algorithm identifiers (stored as big-endian uint32 in the file header)
enum class AlgorithmId : uint32_t {
    AES_256_GCM             = 0x01,
    AES_256_CTR_HMAC_SHA256 = 0x02,  // ← we use this
    XCHACHA20_POLY1305      = 0x03,
};

enum class KdfId : uint32_t {
    ARGON2ID  = 0x01,
    SCRYPT    = 0x02,  // ← we use this
    HKDF_SHA256 = 0x03,
};

// Compression identifiers for the v2 .locked file format (stored as
// big-endian uint32 at header offset 112). v1 files have no such field and
// are normalised to NONE on read; stored_size is then set to original_size.
enum class CompressionId : uint32_t {
    NONE  = 0,
    LZ4   = 1,
    ZSTD  = 2,
};

inline constexpr size_t AES_BLOCK_SIZE      = 16;
inline constexpr size_t AES_256_KEY_SIZE    = 32;   // 256 bits
inline constexpr size_t HMAC_SHA256_SIZE    = 32;   // 256 bits
inline constexpr size_t KEY_MATERIAL_SIZE   = 64;   // file_key(32) + hmac_key(32)
inline constexpr size_t SALT_SIZE           = 32;
inline constexpr size_t IV_SIZE             = 16;   // AES-CTR uses 16-byte IV
inline constexpr size_t NONCE_HIGH_BYTES    = 8;    // upper 64 bits of IV = nonce
inline constexpr size_t COUNTER_LOW_BYTES   = 8;   // lower 64 bits of IV = big-endian counter

inline constexpr size_t FILENAME_TAG_SIZE   = 16;   // GCM tag for filename encryption

// Default scrypt parameters (N=2^14 interactive)
inline constexpr uint64_t SCRYPT_DEFAULT_N = 16384;
inline constexpr uint32_t SCRYPT_DEFAULT_R = 8;
inline constexpr uint32_t SCRYPT_DEFAULT_P = 1;
inline constexpr uint64_t SCRYPT_DEFAULT_MAXMEM = 64 * 1024 * 1024;  // 64 MiB

// Default chunk size for multi-threaded encryption (1 MiB, multiple of AES_BLOCK_SIZE)
inline constexpr uint64_t DEFAULT_CHUNK_SIZE = 1 * 1024 * 1024;

// Default file extension for encrypted output
inline constexpr const char* LOCKED_EXTENSION = ".locked";

// Output buffer sizes
inline constexpr size_t HEADER_FIXED_SIZE = 124;   // see container format spec (v2: added compression_id@112 + stored_size@116;8-byte stored_size runs 116..123, filename starts at 124)
inline constexpr size_t FOOTER_SIZE      = HMAC_SHA256_SIZE;  // 32 bytes

}  // namespace lock
