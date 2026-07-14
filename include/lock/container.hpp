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
struct FileHeader {
    // --- Fixed portion (112 bytes) ---
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
    uint32_t reserved             = 0;                // NOT serialised — struct placeholder only

    // --- Variable portion ---
    // Encrypted filename (ciphertext bytes, length = filename_len)
    std::vector<unsigned char> encrypted_filename;
    // GCM tag for filename authentication (16 bytes)
    std::array<unsigned char, FILENAME_TAG_SIZE> filename_tag{};

    // Total header size (serialised) on disk
    [[nodiscard]] size_t serialised_size() const noexcept {
        return HEADER_FIXED_SIZE     // 112
             + filename_len          // encrypted_filename.size()
             + 4                     // FILENAME_TAG_LEN (always 16, but still stored as be32)
             + FILENAME_TAG_SIZE;    // tag = 16
    }

    // Starting byte offset of the encrypted data chunks within the file
    [[nodiscard]] size_t data_offset() const noexcept { return serialised_size(); }
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
    // Throws std::runtime_error with a descriptive message if:
    //   - the file cannot be opened
    //   - the magic does not match
    //   - the version is not supported
    //   - the algorithm_id is not AES_256_CTR_HMAC_SHA256
    //   - the kdf_id is not SCRYPT
    //   - any field is malformed
    static FileHeader read(std::ifstream& in);

    // Quick magic-check without parsing the rest. Used for `lock decrypt`
    // pre-validation. Does not throw on version mismatch.
    [[nodiscard]] static bool is_locked_file(const std::string& path);
};

}  // namespace lock
