#include <ae-locker/kdf.hpp>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#include <stdexcept>
#include <vector>
#include <memory>
#include <string>

namespace ae_locker {

namespace {

std::string openssl_last_error() {
    unsigned long e = ERR_get_error();
    char buf[256] = {};
    ERR_error_string_n(e, buf, sizeof(buf));
    return std::string(buf);
}

std::string password_to_string(std::string_view sv) {
    // scrypt historically hashes the password bytes including no NUL terminator;
    // OpenSSL's EVP_KDF-SCRYPT takes "pass" as an octet string of the literal
    // bytes (length checked). We deliberately copy so we own the storage and
    // can pass a stable pointer to OSSL_PARAM_construct_octet_string.
    return std::string(sv);
}

}  // namespace

KeyMaterial derive_key_scrypt(std::string_view password,
                               const std::array<unsigned char, SALT_SIZE>& salt,
                               const ScryptParams& params) {
    auto kdf_deleter = [](EVP_KDF* k){ if (k) EVP_KDF_free(k); };
    std::unique_ptr<EVP_KDF, decltype(kdf_deleter)> kdf(
        EVP_KDF_fetch(nullptr, "SCRYPT", nullptr), kdf_deleter);
    if (!kdf) {
        throw std::runtime_error("EVP_KDF_fetch(\"SCRYPT\") failed: " + openssl_last_error());
    }

    auto ctx_deleter = [](EVP_KDF_CTX* c){ if (c) EVP_KDF_CTX_free(c); };
    std::unique_ptr<EVP_KDF_CTX, decltype(ctx_deleter)> kctx(
        EVP_KDF_CTX_new(kdf.get()), ctx_deleter);
    if (!kctx) {
        throw std::runtime_error("EVP_KDF_CTX_new failed: " + openssl_last_error());
    }

    // EVP_KDF-SCRYPT reads all inputs (password, salt, N/r/p/maxmem) from the
    // OSSL_PARAM array. The parameter names are lowercase ("n","r","p",
    // "pass","salt","maxmem_bytes"). Sizes are: N=uint64, r=uint32, p=uint32,
    // maxmem=uint64, pass/octet-string, salt/octet-string.
    std::string pass = password_to_string(password);

    uint64_t N_val       = params.N;
    unsigned int r_val   = params.r;
    unsigned int p_val   = params.p;
    uint64_t maxmem_val  = params.maxmem;

    OSSL_PARAM ossl_params[7];
    ossl_params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_PASSWORD,
        reinterpret_cast<void*>(pass.data()),
        pass.size());
    ossl_params[1] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT,
        const_cast<void*>(reinterpret_cast<const void*>(salt.data())),
        salt.size());
    ossl_params[2] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &N_val);
    ossl_params[3] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_SCRYPT_R, &r_val);
    ossl_params[4] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_SCRYPT_P, &p_val);
    ossl_params[5] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM, &maxmem_val);
    ossl_params[6] = OSSL_PARAM_construct_end();

    std::array<unsigned char, KEY_MATERIAL_SIZE> out_buf{};

    int rc = EVP_KDF_derive(kctx.get(),
                            out_buf.data(),
                            KEY_MATERIAL_SIZE,
                            ossl_params);
    if (rc <= 0) {
        throw std::runtime_error("EVP_KDF_derive failed: " + openssl_last_error());
    }

    KeyMaterial result;
    std::copy(out_buf.data(),
              out_buf.data() + AES_256_KEY_SIZE,
              result.file_key.begin());
    std::copy(out_buf.data() + AES_256_KEY_SIZE,
              out_buf.data() + KEY_MATERIAL_SIZE,
              result.hmac_key.begin());

    return result;
}

std::array<unsigned char, SALT_SIZE> generate_salt() {
    std::array<unsigned char, SALT_SIZE> salt{};
    if (RAND_bytes(salt.data(), static_cast<int>(SALT_SIZE)) != 1) {
        throw std::runtime_error("RAND_bytes (salt) failed: " + openssl_last_error());
    }
    return salt;
}

std::vector<unsigned char> random_bytes(size_t n) {
    std::vector<unsigned char> out(n);
    if (n == 0) {
        return out;
    }
    if (RAND_bytes(out.data(), static_cast<int>(n)) != 1) {
        throw std::runtime_error("RAND_bytes failed: " + openssl_last_error());
    }
    return out;
}

}  // namespace ae_locker
