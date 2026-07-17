#pragma once
#include <string>
#include <string_view>
#include <array>
#include <cstdint>
#include <vector>
#include <ae-locker/constants.hpp>

namespace ae_locker {

struct ScryptParams {
    uint64_t N       = SCRYPT_DEFAULT_N;
    uint32_t r       = SCRYPT_DEFAULT_R;
    uint32_t p       = SCRYPT_DEFAULT_P;
    uint64_t maxmem  = SCRYPT_DEFAULT_MAXMEM;
};

// Returned key material (64 bytes total: 32 file key + 32 HMAC key)
struct KeyMaterial {
    std::array<unsigned char, AES_256_KEY_SIZE> file_key;
    std::array<unsigned char, HMAC_SHA256_SIZE> hmac_key;
};

[[nodiscard]] KeyMaterial derive_key_scrypt(std::string_view password,
                                             const std::array<unsigned char, SALT_SIZE>& salt,
                                             const ScryptParams& params = {});

// Generate a cryptographically random salt using OpenSSL RAND_bytes
[[nodiscard]] std::array<unsigned char, SALT_SIZE> generate_salt();

// Generate a cryptographically random n bytes using OpenSSL RAND_bytes
[[nodiscard]] std::vector<unsigned char> random_bytes(size_t n);

}  // namespace ae_locker
