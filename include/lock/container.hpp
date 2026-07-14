#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <fstream>
#include <lock/constants.hpp>

namespace lock {

// In-memory representation of the .locked file header.
// Serialize with HeaderWriter; deserialize with HeaderReader.
//
// On-disk serialised layout (big-endian), offsets in bytes:
//   offset 0   : magic (16 bytes)
//   offset 16  : version (4)
//   offset 20  : algorithm_id (4)
//   offset 24  : kdf_id (4)
//   offset 28  : kdf_N (4)
//   offset 32  : kdf_r (4)
//   offset 36  : kdf_p (4)
//   offset 40  : salt (32)
//   offset 72  : base_iv (16)
//   offset 88  : flags (4)
//   offset 92  : filename_len (4)
//   offset 96  : original_size (8)
//   offset 104 : chunk_size (4)
//   offset 108 : chunk_count (4)
//   offset 112 : compression_id (4)        -- new v2 field
//   offset 116 : stored_size (8)           -- new v2 field (size of ciphertext region
//                                            incl offset table, i.e. the bytes from
//                                            data_offset() up to the start of the
//                                            32-byte HMAC footer)
//   total fixed: 124 bytes
//
// Note: the in-memory struct layout is separate from the on-disk serialised
// form — the per-field offset comments above describe the on-disk bytes,
// not the C++ member order/offset.
struct FileHeader {
    // --- Fixed portion (124 bytes on disk) ---
    std::array<unsigned char, 16> magic;             // offset 0
    uint32_t version              = FORMAT_VERSION;  // offset 16
    uint32_t algorithm_id         = (uint32_t)AlgorithmId::AES_256_CTR_HMAC_SHA256;  // offset 20
    uint32_t kdf_id               = (uint32_t)KdfId::SCRYPT;  // offset 24
    uint32_t kdf_N                = (uint32_t)SCRYPT_DEFAULT_N;  // offset 28 (smaller type-safe field)
    uint32_t kdf_r                = SCRYPT_DEFAULT_R;  // offset 32
    uint32_t kdf_p                = SCRYPT_DEFAULT_P;  // offset 36
    std::array<unsigned char, SALT_SIZE> salt;        // offset 40 (32 bytes)
    std::array<unsigned char, IV_SIZE> base_iv;       // offset 72 (16 bytes)
    uint32_t flags                = 0x01;             // offset 88: bit 0 = filename present
    uint32_t filename_len         = 0;                // offset 92
    uint64_t original_size        = 0;                // offset 96
    uint32_t chunk_size           = (uint32_t)DEFAULT_CHUNK_SIZE;  // offset 104
    uint32_t chunk_count          = 0;                // offset 108
    uint32_t compression_id       = (uint32_t)CompressionId::NONE;  // offset 112 -- new v2 field
    uint64_t stored_size          = 0;                // offset 116 -- new v2 field

    // --- Variable portion ---
    // Encrypted filename (ciphertext bytes, length = filename_len)
    std::vector<unsigned char> encrypted_filename;
    // GCM tag for filename authentication (16 bytes)
    std::array<unsigned char, FILENAME_TAG_SIZE> filename_tag{};

    // Total header size (serialised) on disk.
    // 124 (HEADER_FIXED_SIZE) + filename_len + 4 (FILENAME_TAG_LEN be32) + 16 (tag).
    [[nodiscard]] size_t serialised_size() const noexcept {
        return HEADER_FIXED_SIZE     // 124 (v2: 112 fixed through v1 + 4 compression_id + 8 stored_size)
             + filename_len          // encrypted_filename.size()
             + 4                     // FILENAME_TAG_LEN (always 16, but still stored as be32)
             + FILENAME_TAG_SIZE;    // tag = 16
    }

    // Starting byte offset of the encrypted data chunks within the file
    // (byte position of chunk 0's ciphertext). v1 files are 12 bytes smaller
    // in the fixed portion than v2 (no compression_id @112 + stored_size
    // @116..123); we subtract 12 so data_offset matches the on-disk byte.
    [[nodiscard]] size_t data_offset() const noexcept {
        size_t v2 = serialised_size();
        return (version == 1) ? v2 - 12 : v2;
    }
};

class HeaderWriter {
public:
    // Serialise `header` to `path`, leaving the file open at the position
    // just after the header (i.e. ready to write chunks).
    // Creates or truncates the file. Throws std::runtime_error on I/O failure.
    static void write(std::ofstream& out, const FileHeader& header);
    // Convenience: serialise to a fresh std::vector<unsigned char> for inspection
    [[nodiscard]] static std::vector<unsigned char> serialise(const FileHeader& header);
};

class HeaderReader {
public:
    // Attempt to read and parse the header from `path`. Opens file for binary
    // read and leaves it positioned at the start of the data chunks.
    //
    // Reads v1 and v2 files. v1 (which predates compression_id / stored_size)
    // is silently normalised to the v2 in-memory shape: compression_id is set
    // to NONE (0) and stored_size is set to original_size, so downstream
    // decryption code has exactly one code path that consults compression_id
    // and stored_size. v2 files keep their on-disk compression_id / stored_size.
    //
    // Throws std::runtime_error with a descriptive message if:
    //   - the file cannot be opened
    //   - the magic does not match
    //   - the version is not supported (v1 or v2 only)
    //   - the algorithm_id is not AES_256_CTR_HMAC_SHA256
    //   - the kdf_id is not SCRYPT
    //   - the compression_id is not NONE / LZ4 / ZSTD (v2 only)
    //   - any field is malformed
    static FileHeader read(std::ifstream& in);

    // Quick magic-check without parsing the rest. Used for `lock decrypt`
    // pre-validation. Does not throw on version mismatch.
    [[nodiscard]] static bool is_locked_file(const std::string& path);
};

}  // namespace lock
