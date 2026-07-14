#include <lock/crypto.hpp>
#include <lock/endian.hpp>
#include <lock/compress.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <fstream>
#include <cstring>
#include <stdexcept>
#include <memory>
#include <algorithm>
#include <span>
#include <string>
#include <limits>

namespace lock {

namespace {

// ---- Error helpers (defined early so file-local classes can use them) -----

std::string openssl_last_error() {
    unsigned long e = ERR_get_error();
    char buf[256] = {};
    ERR_error_string_n(e, buf, sizeof(buf));
    return std::string(buf);
}

[[noreturn]] void throw_openssl(const std::string& what) {
    throw std::runtime_error(what + ": " + openssl_last_error());
}

// ---- RAII helpers --------------------------------------------------------

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* c) const noexcept {
        if (c) EVP_CIPHER_CTX_free(c);
    }
};
struct EvpMacDeleter {
    void operator()(EVP_MAC* m) const noexcept { if (m) EVP_MAC_free(m); }
};
struct EvpMacCtxDeleter {
    void operator()(EVP_MAC_CTX* c) const noexcept {
        if (c) EVP_MAC_CTX_free(c);
    }
};

using CtxPtr    = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;
using MacPtr    = std::unique_ptr<EVP_MAC,        EvpMacDeleter>;
using MacCtxPtr = std::unique_ptr<EVP_MAC_CTX,   EvpMacCtxDeleter>;

// Streaming HMAC-SHA256 over an arbitrary byte stream using the OpenSSL 3.x
// EVP_MAC API (the HMAC_*() family is OSSL_DEPRECATEDIN_3_0). The key is set
// once at construction; chunks are appended via update() and the 32-byte
// tag extracted via final_bytes(). Throws std::runtime_error on any
// OpenSSL failure so callers can stop early.
class StreamingHmac {
public:
    explicit StreamingHmac(std::span<const unsigned char> key) {
        mac_.reset(EVP_MAC_fetch(nullptr, "HMAC", nullptr));
        if (!mac_) {
            throw std::runtime_error("EVP_MAC_fetch(\"HMAC\") failed: "
                                     + openssl_last_error());
        }
        ctx_.reset(EVP_MAC_CTX_new(mac_.get()));
        if (!ctx_) {
            throw std::runtime_error("EVP_MAC_CTX_new failed: "
                                     + openssl_last_error());
        }

        OSSL_PARAM params[2];
        char digest_name[] = "SHA256";
        params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_DIGEST, digest_name, 0);
        params[1] = OSSL_PARAM_construct_end();

        if (EVP_MAC_init(ctx_.get(),
                        key.data(), static_cast<size_t>(key.size()),
                        params) != 1) {
            throw std::runtime_error("EVP_MAC_init failed: "
                                     + openssl_last_error());
        }
    }

    void update(const unsigned char* data, size_t len) {
        if (len == 0) return;
        if (EVP_MAC_update(ctx_.get(), data, len) != 1) {
            throw std::runtime_error("EVP_MAC_update failed: "
                                     + openssl_last_error());
        }
    }

    std::array<unsigned char, HMAC_SHA256_SIZE> final_bytes() {
        std::array<unsigned char, HMAC_SHA256_SIZE> out{};
        size_t written = 0;
        if (EVP_MAC_final(ctx_.get(), out.data(), &written, out.size()) != 1) {
            throw std::runtime_error("EVP_MAC_final failed: "
                                     + openssl_last_error());
        }
        if (written != HMAC_SHA256_SIZE) {
            throw std::runtime_error("EVP_MAC_final produced incorrect length");
        }
        return out;
    }

private:
    MacPtr     mac_;
    MacCtxPtr  ctx_;
};

// ---- AAD digest for filename GCM -----------------------------------------
//
// AAD = SHA-256( magic || version_be32 || algorithm_id_be32 || salt ||
//                base_iv || original_size_be64 )
// The exact byte stream must match between encrypt_filename and
// decrypt_filename; that contract is enforced by centralising the
// construction here.
//
// Why compression_id and stored_size are NOT part of the AAD (v1 ↔ v2
// wire-format stability of the filename GCM tag):
//   * stored_size is only known AFTER every chunk has been compressed and
//     the per-chunk CT sizes have been summed. encrypt_filename must run
//     BEFORE chunk encryption (its output populates header.encrypted_filename
//     which is then serialised into header_bytes that the workers read for
//     HMAC), so binding the GCM tag to stored_size would create a chicken-
//     and-egg deadlock.
//   * Including compression_id could be done up-front, but it would create
//     a hidden dependency: a v1 file normalised to compression_id=NONE on
//     read would produce a DIFFERENT AAD than the original v1 encrypt wrote
//     (v1 has no compression_id field at all). That would silently break
//     GCM authentication on every legacy file. Keeping the AAD locked to
//     the v1 field set preserves both v1 read-back and a clean v2 write
//     path.
//   * stored_size and compression_id are instead covered by the trailing
//     HMAC-SHA256 footer, which can be computed AFTER the chunks are all
//     done. Tampering with either field still fails verification on decrypt.
// Wave 3B will document this in the README. Stronger header binding (e.g.
// including all v2 fields) is a future v3 problem.
std::array<unsigned char, SHA256_DIGEST_LENGTH>
filename_aad_digest(const FileHeader& h) {
    std::vector<unsigned char> buf;
    buf.reserve(16 + 4 + 4 + SALT_SIZE + IV_SIZE + 8);

    buf.insert(buf.end(), h.magic.begin(), h.magic.end());

    unsigned char b4[4];
    endian::store_be32(b4, h.version);
    buf.insert(buf.end(), b4, b4 + 4);

    endian::store_be32(b4, h.algorithm_id);
    buf.insert(buf.end(), b4, b4 + 4);

    buf.insert(buf.end(), h.salt.begin(), h.salt.end());
    buf.insert(buf.end(), h.base_iv.begin(), h.base_iv.end());

    unsigned char b8[8];
    endian::store_be64(b8, h.original_size);
    buf.insert(buf.end(), b8, b8 + 8);

    std::array<unsigned char, SHA256_DIGEST_LENGTH> out{};
    SHA256(buf.data(), buf.size(), out.data());

    return out;
}

// Deterministic per-file GCM nonce for filename encryption:
//   nonce12 = SHA-256(file_key)[0..11]
// Safe because every file gets a freshly generated file_key.
std::array<unsigned char, 12> filename_gcm_nonce(
    const std::array<unsigned char, AES_256_KEY_SIZE>& file_key) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> h{};
    SHA256(file_key.data(), file_key.size(), h.data());
    std::array<unsigned char, 12> nonce{};
    std::copy(h.begin(), h.begin() + 12, nonce.begin());
    return nonce;
}

// CTR is symmetric, so the single chunk routine serves both directions. The
// caller guarantees `out` has room for `in.size()` bytes.
bool ctr_crypt_chunk(std::span<const unsigned char> key,
                     std::span<const unsigned char, IV_SIZE> iv,
                     std::span<const unsigned char> in,
                     std::span<unsigned char> out) noexcept {
    if (key.size() != AES_256_KEY_SIZE)            return false;
    if (iv.size()  != IV_SIZE)                     return false;
    if (in.size()  != out.size())                  return false;
    if (!in.empty() && (in.data() == out.data()))
                                                  return false;  // no in-place

    CtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return false;

    // CTR is a stream cipher: no padding, output length == input length.
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_ctr(), nullptr,
                           key.data(), iv.data()) != 1) {
        return false;
    }
    if (EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1) {
        return false;
    }

    // The EVP API takes int lengths; chunk_size is at most ~4 GiB but the
    // high-level callers always pass <= DEFAULT_CHUNK_SIZE (1 MiB). Cap
    // defensively anyway in case someone calls the chunk routine directly
    // with a giant span.
    if (in.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return false;
    }

    int outl = 0;
    if (EVP_EncryptUpdate(ctx.get(),
                          out.data(), &outl,
                          in.data(),
                          static_cast<int>(in.size())) != 1) {
        return false;
    }
    int finall = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + outl, &finall) != 1) {
        return false;
    }
    return (static_cast<size_t>(outl + finall) == in.size());
}

// ---- Shared parallel runner (legacy; retained for reference) --------------
//
// This uniform-chunk-size worker pool is no longer used by encrypt_file or
// decrypt_file after the v2 rewrite: the v2 codecs need per-chunk variable
// output sizes (compression) and a two-phase compress-then-encrypt pipeline,
// which the in-place `out_buf + off` model here can't express. Both v1 and
// v2 read/write paths now inline their own atomic-dispatch worker pools
// that collect per-chunk results into `std::vector<std::vector<unsigned
// char>>` indexed by chunk_index. Kept here (a) for ABI/source stability for
// any external consumers and (b) as a reference implementation of the
// threading model the v2 paths follow (per-thread EVP_CIPHER_CTX via
// ctr_crypt_chunk; atomic<size_t> chunk dispatch; mutex-guarded error
// channel; never throw across a thread boundary).
template <class ChunkFn>
void run_parallel(size_t total_bytes,
                  size_t chunk_size,
                  uint32_t num_threads,
                  unsigned char* in_buf,
                  unsigned char* out_buf,
                  ChunkFn chunk_fn,
                  const ProgressCallback& progress) {
    if (total_bytes == 0) {
        if (progress) progress(0, 0);
        return;
    }

    const size_t chunk_count =
        (total_bytes + chunk_size - 1) / chunk_size;
    const size_t hw = std::thread::hardware_concurrency();
    size_t nthreads = (num_threads == 0) ? hw : num_threads;
    if (nthreads == 0) nthreads = 1;
    if (nthreads > chunk_count) nthreads = chunk_count;
    if (nthreads == 0) nthreads = 1;

    std::atomic<size_t> next_chunk{0};
    std::atomic<bool>   failed{false};
    std::mutex          err_mutex;
    std::string         err_msg;
    std::atomic<size_t> bytes_done{0};

    auto worker = [&]() {
        for (;;) {
            if (failed.load(std::memory_order_relaxed)) return;
            size_t i = next_chunk.fetch_add(1, std::memory_order_relaxed);
            if (i >= chunk_count) return;

            size_t off      = i * chunk_size;
            size_t this_len = std::min(chunk_size, total_bytes - off);
            unsigned char* in_p  = in_buf  + off;
            unsigned char* out_p = out_buf + off;

            bool ok = chunk_fn(i, in_p, out_p, this_len);
            if (!ok) {
                // Capture only the FIRST failure; later failures are cascades.
                bool expected = false;
                if (failed.compare_exchange_strong(expected, true,
                                                    std::memory_order_acq_rel)) {
                    std::lock_guard<std::mutex> lk(err_mutex);
                    err_msg = "OpenSSL chunk " + std::to_string(i) +
                             " failed: " + openssl_last_error();
                }
                return;
            }

            size_t done = bytes_done.fetch_add(this_len,
                                               std::memory_order_relaxed)
                          + this_len;
            if (progress) {
                progress(done, total_bytes);
            }
        }
    };

    std::vector<std::thread> pool;
    pool.reserve(nthreads);
    for (size_t t = 0; t < nthreads; ++t) pool.emplace_back(worker);
    for (auto& th : pool) th.join();

    if (failed.load(std::memory_order_acquire)) {
        std::lock_guard<std::mutex> lk(err_mutex);
        throw std::runtime_error(err_msg);
    }
}

}  // namespace

// ---- Filename encrypt / decrypt ------------------------------------------

EncryptedFilename encrypt_filename(
    const std::array<unsigned char, AES_256_KEY_SIZE>& file_key,
    const FileHeader& header_for_aad,
    std::string_view original_filename) {

    EncryptedFilename result;
    result.ciphertext.assign(
        reinterpret_cast<const unsigned char*>(original_filename.data()),
        reinterpret_cast<const unsigned char*>(original_filename.data())
            + original_filename.size());

    if (result.ciphertext.empty()) {
        // GCM with zero-length plaintext still yields a valid 16-byte tag.
    }

    auto nonce = filename_gcm_nonce(file_key);
    auto aad32 = filename_aad_digest(header_for_aad);

    CtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw_openssl("EVP_CIPHER_CTX_new (filename)");

    // AES-256-GCM, 12-byte nonce.
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr,
                           nullptr, nullptr) != 1) {
        throw_openssl("EVP_EncryptInit_ex (gcm set cipher)");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1) {
        throw_openssl("EVP_CTRL_GCM_SET_IVLEN");
    }
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                           file_key.data(), nonce.data()) != 1) {
        throw_openssl("EVP_EncryptInit_ex (gcm set key+nonce)");
    }

    // Provide AAD as a 32-byte digest.
    int aad_outl = 0;
    if (EVP_EncryptUpdate(ctx.get(), nullptr, &aad_outl,
                          aad32.data(),
                          static_cast<int>(aad32.size())) != 1) {
        throw_openssl("EVP_EncryptUpdate (AAD)");
    }

    // Encrypt the filename bytes.
    int outl = 0;
    if (!result.ciphertext.empty()) {
        // In-place encrypt: write CT over the PT.
        if (EVP_EncryptUpdate(ctx.get(),
                              result.ciphertext.data(), &outl,
                              result.ciphertext.data(),
                              static_cast<int>(result.ciphertext.size())) != 1) {
            throw_openssl("EVP_EncryptUpdate (filename)");
        }
    } else {
        outl = 0;
    }
    int finall = 0;
    if (EVP_EncryptFinal_ex(ctx.get(),
                            result.ciphertext.data() + outl, &finall) != 1) {
        throw_openssl("EVP_EncryptFinal_ex (filename)");
    }
    if (static_cast<size_t>(outl + finall) != result.ciphertext.size()) {
        throw std::runtime_error("filename GCM: length mismatch");
    }

    // Pull the 16-byte tag.
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(FILENAME_TAG_SIZE),
                            result.tag.data()) != 1) {
        throw_openssl("EVP_CTRL_GCM_GET_TAG");
    }

    return result;
}

std::string decrypt_filename(
    const std::array<unsigned char, AES_256_KEY_SIZE>& file_key,
    const FileHeader& header,
    std::string_view encrypted_filename_bytes,
    std::span<const unsigned char, FILENAME_TAG_SIZE> tag) {

    auto nonce = filename_gcm_nonce(file_key);
    auto aad32  = filename_aad_digest(header);

    std::vector<unsigned char> ct(
        reinterpret_cast<const unsigned char*>(encrypted_filename_bytes.data()),
        reinterpret_cast<const unsigned char*>(encrypted_filename_bytes.data())
            + encrypted_filename_bytes.size());

    CtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw_openssl("EVP_CIPHER_CTX_new (filename)");

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr,
                           nullptr, nullptr) != 1) {
        throw_openssl("EVP_DecryptInit_ex (gcm set cipher)");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1) {
        throw_openssl("EVP_CTRL_GCM_SET_IVLEN");
    }
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
                           file_key.data(), nonce.data()) != 1) {
        throw_openssl("EVP_DecryptInit_ex (gcm set key+nonce)");
    }

    int aad_outl = 0;
    if (EVP_DecryptUpdate(ctx.get(), nullptr, &aad_outl,
                          aad32.data(),
                          static_cast<int>(aad32.size())) != 1) {
        throw_openssl("EVP_DecryptUpdate (AAD)");
    }

    int outl = 0;
    if (!ct.empty()) {
        if (EVP_DecryptUpdate(ctx.get(),
                              ct.data(), &outl,
                              ct.data(),
                              static_cast<int>(ct.size())) != 1) {
            throw_openssl("EVP_DecryptUpdate (filename)");
        }
    } else {
        outl = 0;
    }

    // Set expected tag BEFORE finalising — GCM verifies here.
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(FILENAME_TAG_SIZE),
                            const_cast<unsigned char*>(tag.data())) != 1) {
        throw_openssl("EVP_CTRL_GCM_SET_TAG");
    }

    int finall = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), ct.data() + outl, &finall) != 1) {
        // Tag mismatch — either wrong key, or a bound header field was modified.
        throw std::runtime_error("decrypt_filename: GCM authentication failed");
    }

    return std::string(reinterpret_cast<const char*>(ct.data()),
                       reinterpret_cast<const char*>(ct.data())
                           + static_cast<size_t>(outl + finall));
}

// ---- Per-chunk IV --------------------------------------------------------

std::array<unsigned char, IV_SIZE> derive_chunk_iv(
    const std::array<unsigned char, IV_SIZE>& base_iv,
    uint64_t block_offset) noexcept {
    std::array<unsigned char, IV_SIZE> iv{};

    // High 64 bits (bytes 0..7): per-file nonce, copied verbatim.
    std::copy(base_iv.begin(), base_iv.begin() + NONCE_HIGH_BYTES, iv.begin());

    // Low 64 bits (bytes 8..15): big-endian counter += block_offset.
    uint64_t base_counter = endian::load_be64(base_iv.data() + NONCE_HIGH_BYTES);
    uint64_t ctr = base_counter + block_offset;
    endian::store_be64(iv.data() + NONCE_HIGH_BYTES, ctr);
    return iv;
}

std::array<unsigned char, IV_SIZE> derive_chunk_iv_v2(
    const std::array<unsigned char, IV_SIZE>& base_iv,
    uint64_t chunk_index,
    uint64_t total_ciphertext_bytes) noexcept {
    std::array<unsigned char, IV_SIZE> iv{};

    // High 64 bits: base_iv[0..7] XOR be64(chunk_index). XOR'ing the index
    // into the per-file nonce guarantees each chunk gets a DIFFERENT high
    // nonce (and hence a different IV) even before the low counter is
    // factored in. base_iv high-nonce is random per file, so this stays
    // unique across files too.
    uint64_t high = endian::load_be64(base_iv.data()) ^ chunk_index;
    endian::store_be64(iv.data(), high);

    // Low 64 bits: base_counter + (total_ciphertext_bytes / AES_BLOCK_SIZE).
    // Using the prefix CT size (in AES blocks) as the counter increment
    // guarantees no keystream block is reused across chunks even if the
    // high-nonce XOR happened to collide (which it can't for distinct
    // indices within the same file). See crypto.hpp for the full property
    // argument.
    uint64_t base_counter =
        endian::load_be64(base_iv.data() + NONCE_HIGH_BYTES);
    uint64_t block_offset = total_ciphertext_bytes / AES_BLOCK_SIZE;
    endian::store_be64(iv.data() + NONCE_HIGH_BYTES,
                       base_counter + block_offset);
    return iv;
}

// ---- Single-chunk CTR ----------------------------------------------------

bool encrypt_chunk_ctr(std::span<const unsigned char> key,
                        std::span<const unsigned char, IV_SIZE> iv,
                        std::span<const unsigned char> in,
                        std::span<unsigned char> out) noexcept {
    return ctr_crypt_chunk(key, iv, in, out);
}

bool decrypt_chunk_ctr(std::span<const unsigned char> key,
                        std::span<const unsigned char, IV_SIZE> iv,
                        std::span<const unsigned char> in,
                        std::span<unsigned char> out) noexcept {
    return ctr_crypt_chunk(key, iv, in, out);
}

// ---- HMAC-SHA256 ----------------------------------------------------------

std::array<unsigned char, HMAC_SHA256_SIZE>
hmac_sha256(std::span<const unsigned char> key,
            std::span<const unsigned char> msg) noexcept {
    std::array<unsigned char, HMAC_SHA256_SIZE> out{};
    unsigned int mdlen = 0;
    unsigned char* p = ::HMAC(EVP_sha256(),
                              key.data(),  static_cast<int>(key.size()),
                              msg.data(),  msg.size(),
                              out.data(),  &mdlen);
    if (p == nullptr || mdlen != HMAC_SHA256_SIZE) {
        out.fill(0);
    }
    return out;
}

// ---- File encrypt ---------------------------------------------------------

namespace {

// Hard cap: 64 GiB plaintext in memory. CTR's 64-bit counter would not
// overflow for far larger files, but loading tens of GiB into RAM is not
// what this module is for.
constexpr size_t MAX_PLAINTEXT_BYTES = size_t(64) * 1024 * 1024 * 1024;

std::vector<unsigned char> read_whole_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) {
        throw std::runtime_error("cannot open input file: " + path);
    }
    std::streamoff size = in.tellg();
    if (size < 0) {
        throw std::runtime_error("cannot determine size of: " + path);
    }
    if (static_cast<size_t>(size) > MAX_PLAINTEXT_BYTES) {
        throw std::runtime_error("input file too large (>64 GiB): " + path);
    }
    in.seekg(0, std::ios::beg);

    std::vector<unsigned char> buf(static_cast<size_t>(size));
    if (!buf.empty()) {
        in.read(reinterpret_cast<char*>(buf.data()),
                static_cast<std::streamsize>(buf.size()));
        if (static_cast<std::streamsize>(in.gcount())
              != static_cast<std::streamsize>(buf.size())) {
            throw std::runtime_error("short read on input: " + path);
        }
    }
    return buf;
}

}  // namespace

void encrypt_file(const std::string& input_path,
                  const std::string& output_path,
                  std::string_view original_filename_for_header,
                  const EncryptOptions& opts) {

    if (opts.chunk_size == 0 || (opts.chunk_size % AES_BLOCK_SIZE) != 0) {
        throw std::runtime_error("chunk_size must be a positive multiple of "
                                 "AES_BLOCK_SIZE");
    }
    if (opts.chunk_size > static_cast<uint32_t>(
            std::numeric_limits<int>::max())) {
        throw std::runtime_error("chunk_size too large for EVP int length");
    }

    // 1. Read the entire plaintext into RAM.
    std::vector<unsigned char> pt = read_whole_file(input_path);

    const size_t cs = opts.chunk_size;
    const size_t total_pt = pt.size();

    // 2. Build the FileHeader. version = 2 (v2 format with offset table +
    //    compression_id / stored_size). stored_size is filled in after step
    //    5 once the per-chunk CT sizes are known.
    FileHeader header;
    header.magic        = MAGIC;
    header.version      = 2;  // explicit v2; FORMAT_VERSION (=2) documents intent
    header.algorithm_id = (uint32_t)AlgorithmId::AES_256_CTR_HMAC_SHA256;
    header.kdf_id       = (uint32_t)KdfId::SCRYPT;
    header.kdf_N        = opts.kdf_N;
    header.kdf_r        = opts.kdf_r;
    header.kdf_p        = opts.kdf_p;
    header.salt         = opts.salt;
    header.base_iv      = opts.base_iv;
    header.flags        = 0x01;  // filename present
    header.original_size = pt.size();
    header.chunk_size   = opts.chunk_size;
    const size_t chunk_count =
        (pt.size() + cs - 1) / cs;
    header.chunk_count    = static_cast<uint32_t>(chunk_count);
    header.compression_id = static_cast<uint32_t>(opts.compression);
    header.stored_size    = 0;  // placeholder — filled after chunk encryption

    // 3. Encrypt the filename; bind it to the (still-being-built) header.
    //    The AAD is computed from the v1-compatible header field set — see
    //    the comment above filename_aad_digest for the rationale (it must
    //    NOT include compression_id or stored_size so v1 files keep verifying).
    EncryptedFilename enc_name = encrypt_filename(
        opts.file_key, header, original_filename_for_header);
    header.encrypted_filename = std::move(enc_name.ciphertext);
    header.filename_len      = static_cast<uint32_t>(
        header.encrypted_filename.size());
    header.filename_tag       = enc_name.tag;

    // Header bytes are serialised now for filename-AAD use; we OVERWRITE
    // header_bytes at the end of step 5 once stored_size is known.
    std::vector<unsigned char> header_bytes = HeaderWriter::serialise(header);

    // ---------- Phase A: parallel compress (or passthrough) all chunks ------
    //
    // The v2 per-chunk IV (derive_chunk_iv_v2) takes `total_ciphertext_bytes`
    // = sum of compressed sizes [0..i-1] as a counter input. That makes the
    // IV depend on the COMPRESSED sizes of earlier chunks; to know those
    // before encrypting chunk i, we must run compression to completion
    // first. So encrypt is two phases:
    //   A. Parallel-compress each chunk into `compressed_per_chunk[i]`
    //      (thread-safe: compress_chunk uses a thread-local ZSTD_CCtx).
    //   B. Compute prefix sums of compressed sizes.
    //   C. Parallel-CTR-encrypt each chunk with its known prefix sum.
    // Memory cost: ~2x original_size for compression intermediates (kept
    // in RAM) — tolerable per the spec.
    std::vector<std::vector<unsigned char>> compressed_per_chunk(chunk_count);
    if (chunk_count > 0) {
        const size_t hw_a = std::thread::hardware_concurrency();
        size_t nthreads_a = (opts.num_threads == 0) ? hw_a : opts.num_threads;
        if (nthreads_a == 0) nthreads_a = 1;
        if (nthreads_a > chunk_count) nthreads_a = chunk_count;

        std::atomic<size_t> next_a{0};
        std::atomic<bool>   failed_a{false};
        std::mutex          err_mutex_a;
        std::string         err_msg_a;

        auto compressor = [&]() {
            for (;;) {
                if (failed_a.load(std::memory_order_relaxed)) return;
                size_t i = next_a.fetch_add(1, std::memory_order_relaxed);
                if (i >= chunk_count) return;

                size_t off      = i * cs;
                size_t this_len = std::min(cs, total_pt - off);
                std::span<const unsigned char> pt_span(pt.data() + off, this_len);
                try {
                    if (opts.compression != CompressionId::NONE) {
                        compressed_per_chunk[i] =
                            compress_chunk(opts.compression, pt_span,
                                            opts.compression_level);
                    } else {
                        compressed_per_chunk[i].assign(pt_span.begin(),
                                                       pt_span.end());
                    }
                } catch (const std::exception& e) {
                    bool expected = false;
                    if (failed_a.compare_exchange_strong(
                            expected, true, std::memory_order_acq_rel)) {
                        std::lock_guard<std::mutex> lk(err_mutex_a);
                        err_msg_a = std::string("compress chunk ")
                                    + std::to_string(i) + " failed: " + e.what();
                    }
                    return;
                }
            }
        };

        std::vector<std::thread> pool_a;
        pool_a.reserve(nthreads_a);
        for (size_t t = 0; t < nthreads_a; ++t) pool_a.emplace_back(compressor);
        for (auto& th : pool_a) th.join();

        if (failed_a.load(std::memory_order_acquire)) {
            std::lock_guard<std::mutex> lk(err_mutex_a);
            throw std::runtime_error(err_msg_a);
        }
    }

    // ---------- Phase B: compute per-chunk sizes and prefix sums ------------
    // prefix_ct[i] = sum of compressed_per_chunk[0..i-1].size(); prefix_ct[0]=0.
    // This is EXACTLY the same value the decrypt loop computes from the
    // on-disk offset table, so iv stability across encrypt/decrypt holds.
    std::vector<uint64_t> prefix_ct(chunk_count == 0 ? 0 : chunk_count, 0ULL);
    uint64_t running = 0;
    for (size_t i = 0; i < chunk_count; ++i) {
        prefix_ct[i] = running;
        const size_t sz = compressed_per_chunk[i].size();
        running += sz;
        if (running > static_cast<uint64_t>(std::numeric_limits<uint64_t>::max())) {
            throw std::runtime_error("compressed size overflow prefix sum");
        }
        // Sanity: ct sizes written to the offset table must fit in uint32.
        if (static_cast<uint64_t>(static_cast<uint32_t>(sz)) != sz) {
            throw std::runtime_error("chunk CT size overflow uint32");
        }
    }

    // ---------- Phase C: parallel CTR-encrypt all (now-fixed-size) chunks ---
    std::vector<std::vector<unsigned char>> ct_per_chunk(chunk_count);
    if (chunk_count > 0) {
        const size_t hw_c = std::thread::hardware_concurrency();
        size_t nthreads_c = (opts.num_threads == 0) ? hw_c : opts.num_threads;
        if (nthreads_c == 0) nthreads_c = 1;
        if (nthreads_c > chunk_count) nthreads_c = chunk_count;

        std::atomic<size_t> next_c{0};
        std::atomic<bool>   failed_c{false};
        std::mutex          err_mutex_c;
        std::string         err_msg_c;
        std::atomic<size_t> bytes_done{0};

        auto encryptor = [&]() {
            for (;;) {
                if (failed_c.load(std::memory_order_relaxed)) return;
                size_t i = next_c.fetch_add(1, std::memory_order_relaxed);
                if (i >= chunk_count) return;

                auto& compressed = compressed_per_chunk[i];
                std::vector<unsigned char> ct(compressed.size());
                auto chunk_iv = derive_chunk_iv_v2(
                    opts.base_iv,
                    static_cast<uint64_t>(i),
                    prefix_ct[i]);

                bool ok = encrypt_chunk_ctr(
                    std::span<const unsigned char>(opts.file_key.data(),
                                                    opts.file_key.size()),
                    std::span<const unsigned char, IV_SIZE>(chunk_iv),
                    std::span<const unsigned char>(compressed.data(),
                                                    compressed.size()),
                    std::span<unsigned char>(ct.data(), ct.size()));
                if (!ok) {
                    bool expected = false;
                    if (failed_c.compare_exchange_strong(
                            expected, true, std::memory_order_acq_rel)) {
                        std::lock_guard<std::mutex> lk(err_mutex_c);
                        err_msg_c = "OpenSSL chunk " + std::to_string(i) +
                                    " failed: " + openssl_last_error();
                    }
                    return;
                }

                // Each chunk_index is uniquely dispatched to exactly one worker,
                // so ct_per_chunk[i] is written exactly once — no mutex needed.
                ct_per_chunk[i] = std::move(ct);

                // Progress is reported in PLAINTEXT bytes per chunk (not
                // compressed bytes) so the user-visible rate matches the
                // file they handed us.
                const size_t this_pt_len = std::min(
                    cs, total_pt - i * cs);
                size_t done = bytes_done.fetch_add(this_pt_len,
                                                   std::memory_order_relaxed)
                              + this_pt_len;
                if (opts.progress) opts.progress(done, total_pt);
            }
        };

        std::vector<std::thread> pool_c;
        pool_c.reserve(nthreads_c);
        for (size_t t = 0; t < nthreads_c; ++t) pool_c.emplace_back(encryptor);
        for (auto& th : pool_c) th.join();

        if (failed_c.load(std::memory_order_acquire)) {
            std::lock_guard<std::mutex> lk(err_mutex_c);
            throw std::runtime_error(err_msg_c);
        }
    } else if (opts.progress) {
        opts.progress(0, 0);
    }

    // 6. Geometry: per-chunk CT sizes, offset table, stored_size, final header.
    uint64_t total_ct_bytes = 0;
    std::vector<uint32_t> compressed_sizes(chunk_count);
    for (size_t i = 0; i < chunk_count; ++i) {
        const auto& cti = ct_per_chunk[i];
        const uint32_t sz = static_cast<uint32_t>(cti.size());
        compressed_sizes[i] = sz;
        total_ct_bytes += sz;
    }
    const uint64_t offset_table_bytes =
        static_cast<uint64_t>(chunk_count) * 4ULL;
    header.stored_size = total_ct_bytes + offset_table_bytes;

    // Re-serialise the header with stored_size & compression_id now final.
    header_bytes = HeaderWriter::serialise(header);

    // Build the offset table on disk (be32 per chunk).
    std::vector<unsigned char> offset_table(static_cast<size_t>(offset_table_bytes));
    for (size_t i = 0; i < chunk_count; ++i) {
        endian::store_be32(offset_table.data() + i * 4,
                            compressed_sizes[i]);
    }

    // 7. Compute HMAC over (header_serialised || concatenated_chunk_ciphertext
    //    || offset_table_bytes). Single-threaded pass after every worker has
    //    joined — the covered bytes are immutable by the time we get here.
    //    HMAC coverage: header || chunk_cts || offset_table.
    StreamingHmac hmac(std::span<const unsigned char>(opts.hmac_key.data(),
                                                     opts.hmac_key.size()));
    if (!header_bytes.empty()) hmac.update(header_bytes.data(),
                                            header_bytes.size());
    for (size_t i = 0; i < chunk_count; ++i) {
        const auto& cti = ct_per_chunk[i];
        if (!cti.empty()) hmac.update(cti.data(), cti.size());
    }
    if (!offset_table.empty()) hmac.update(offset_table.data(),
                                            offset_table.size());
    std::array<unsigned char, HMAC_SHA256_SIZE> mac = hmac.final_bytes();

    // 8. Write the output file: header || chunk_cts || offset_table || mac.
    std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("cannot open output file: " + output_path);
    }
    if (!header_bytes.empty()) {
        out.write(reinterpret_cast<const char*>(header_bytes.data()),
                  static_cast<std::streamsize>(header_bytes.size()));
        if (!out) throw std::runtime_error("write header failed");
    }
    for (size_t i = 0; i < chunk_count; ++i) {
        const auto& cti = ct_per_chunk[i];
        if (!cti.empty()) {
            out.write(reinterpret_cast<const char*>(cti.data()),
                      static_cast<std::streamsize>(cti.size()));
            if (!out) throw std::runtime_error("write ciphertext failed");
        }
    }
    if (!offset_table.empty()) {
        out.write(reinterpret_cast<const char*>(offset_table.data()),
                  static_cast<std::streamsize>(offset_table.size()));
        if (!out) throw std::runtime_error("write offset table failed");
    }
    out.write(reinterpret_cast<const char*>(mac.data()),
              static_cast<std::streamsize>(mac.size()));
    if (!out) throw std::runtime_error("write HMAC footer failed");
    out.flush();
    if (!out) throw std::runtime_error("flush output failed");
}

// ---- File decrypt --------------------------------------------------------

void decrypt_file(const std::string& input_path,
                  const std::string& output_path,
                  const DecryptOptions& opts) {

    std::ifstream in(input_path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot open input file: " + input_path);
    }
    FileHeader header = HeaderReader::read(in);

    // Validate the chunk geometry before allocating buffers; otherwise a
    // malicious header could force us to allocate gigabytes.
    if (header.chunk_size == 0 ||
        (header.chunk_size % AES_BLOCK_SIZE) != 0) {
        throw std::runtime_error("header has invalid chunk_size");
    }
    if (header.chunk_size > static_cast<uint32_t>(
            std::numeric_limits<int>::max())) {
        throw std::runtime_error("header chunk_size too large for EVP");
    }
    if (header.original_size > MAX_PLAINTEXT_BYTES) {
        throw std::runtime_error("declared original_size > 64 GiB");
    }
    const size_t expected_chunks = (header.original_size == 0)
        ? 0
        : (header.original_size + header.chunk_size - 1) / header.chunk_size;
    if (expected_chunks != header.chunk_count) {
        throw std::runtime_error("header chunk_count mismatch");
    }

    // 3. Geometry validation. Two paths:
    //    v1: offset_table_size = 0, ct_total_size = original_size,
    //        offsets are SYNTHESISED as min(chunk_size, original_size - i*chunk_size)
    //        so v1 and v2 share the same parallel decrypt loop body.
    //        (HeaderReader has already normalised stored_size=original_size,
    //        compression_id=NONE for v1.)
    //    v2: offset_table_size = chunk_count * 4, ct_total_size =
    //        stored_size - offset_table_size (validated to be >= 0);
    //        offsets come straight off disk; their sum is checked against
    //        ct_total_size.
    const bool is_v1 = (header.version == 1);
    const size_t cs = header.chunk_size;
    const size_t chunk_count = header.chunk_count;
    const uint64_t offset_table_size =
        is_v1 ? 0ULL : (static_cast<uint64_t>(chunk_count) * 4ULL);
    uint64_t ct_total_size;
    if (is_v1) {
        ct_total_size = header.original_size;  // == header.stored_size post-norm
    } else {
        if (header.stored_size < offset_table_size) {
            throw std::runtime_error("stored_size too small for offset table");
        }
        ct_total_size = header.stored_size - offset_table_size;
    }

    if (ct_total_size > MAX_PLAINTEXT_BYTES) {
        throw std::runtime_error("declared ciphertext region > 64 GiB");
    }

    // Read ct_region.
    std::vector<unsigned char> ct_region(static_cast<size_t>(ct_total_size));
    if (!ct_region.empty()) {
        in.read(reinterpret_cast<char*>(ct_region.data()),
                static_cast<std::streamsize>(ct_region.size()));
        if (static_cast<std::streamsize>(in.gcount())
              != static_cast<std::streamsize>(ct_region.size())) {
            throw std::runtime_error("short read on ciphertext region");
        }
    }

    // Read & parse the offset table (v2 only). For v1 there is no table —
    // synthesised offsets are computed below.
    std::vector<unsigned char> offset_table_bytes(
        static_cast<size_t>(offset_table_size));
    std::vector<uint32_t> offsets(chunk_count);
    if (!is_v1) {
        if (!offset_table_bytes.empty()) {
            in.read(reinterpret_cast<char*>(offset_table_bytes.data()),
                    static_cast<std::streamsize>(offset_table_bytes.size()));
            if (static_cast<std::streamsize>(in.gcount())
                  != static_cast<std::streamsize>(offset_table_bytes.size())) {
                throw std::runtime_error("short read on offset table");
            }
        }
        uint64_t sum = 0;
        for (size_t i = 0; i < chunk_count; ++i) {
            offsets[i] = endian::load_be32(
                offset_table_bytes.data() + i * 4);
            sum += offsets[i];
        }
        if (sum != ct_total_size) {
            throw std::runtime_error("offset table sum != ciphertext region size");
        }
    } else {
        // Synthesise the v1 chunk geometry: each chunk has size
        // min(chunk_size, original_size - i*chunk_size), so the layout
        // matches the legacy fixed-chunk layout. Sum-check vs original_size.
        uint64_t sum = 0;
        for (size_t i = 0; i < chunk_count; ++i) {
            const uint64_t remaining =
                header.original_size - static_cast<uint64_t>(i) * cs;
            const uint32_t this_sz = static_cast<uint32_t>(
                std::min<uint64_t>(cs, remaining));
            offsets[i] = this_sz;
            sum += this_sz;
        }
        if (sum != header.original_size) {
            throw std::runtime_error("synthesised v1 offsets sum mismatch");
        }
    }

    // 4. Read the trailing 32-byte HMAC footer.
    std::array<unsigned char, HMAC_SHA256_SIZE> stored_mac{};
    in.read(reinterpret_cast<char*>(stored_mac.data()),
            static_cast<std::streamsize>(HMAC_SHA256_SIZE));
    if (static_cast<std::streamsize>(in.gcount())
          != static_cast<std::streamsize>(HMAC_SHA256_SIZE)) {
        throw std::runtime_error("input file missing HMAC footer");
    }

    // 5. Reconstruct the header bytes that were HMACed on encrypt and compute
    //    HMAC(hmac_key, header_serialised || ct_region || offset_table_bytes).
    //    HMAC coverage: header_serialised || chunk_cts || offset_table.
    //    v1's writer emitted a 112-byte fixed header (no compression_id nor
    //    stored_size); v2's HeaderWriter always emits 124. For v1 files we
    //    shift the variable part (filename+tag+taglen) back 12 bytes to where
    //    v1 placed it, then truncate to 112+variable so the HMAC input matches
    //    what v1 encrypt produced.
    std::vector<unsigned char> header_bytes = HeaderWriter::serialise(header);
    if (is_v1) {
        const size_t var_size = header.filename_len + 4 + FILENAME_TAG_SIZE;
        if (header_bytes.size() < 12 + var_size) {
            throw std::runtime_error("internal: v1 header too short");
        }
        const size_t var_off_v2 = header_bytes.size() - var_size;
        std::memmove(header_bytes.data() + 112,
                     header_bytes.data() + var_off_v2,
                     var_size);
        header_bytes.resize(112 + var_size);
    }

    std::array<unsigned char, HMAC_SHA256_SIZE> computed_mac{};
    {
        StreamingHmac hmac(std::span<const unsigned char>(
            opts.hmac_key.data(), opts.hmac_key.size()));
        if (!header_bytes.empty()) hmac.update(header_bytes.data(),
                                                header_bytes.size());
        if (!ct_region.empty())   hmac.update(ct_region.data(),
                                                ct_region.size());
        if (!offset_table_bytes.empty())
            hmac.update(offset_table_bytes.data(),
                        offset_table_bytes.size());
        computed_mac = hmac.final_bytes();
    }
    // 6. Constant-time compare to defeat timing oracles on tamper detection.
    if (CRYPTO_memcmp(computed_mac.data(), stored_mac.data(),
                      HMAC_SHA256_SIZE) != 0) {
        throw std::runtime_error(
            "HMAC verification failed — file is truncated or tampered");
    }

    // Compute chunk start offsets (prefix sums of `offsets`).
    std::vector<uint64_t> chunk_start(chunk_count == 0 ? 0 : chunk_count, 0ULL);
    uint64_t running = 0;
    for (size_t i = 0; i < chunk_count; ++i) {
        chunk_start[i] = running;
        running += offsets[i];
    }

    // 7. Parallel-decrypt. Per-thread EVP_CIPHER_CTX via ctr_crypt_chunk,
    //    chunks dispatched off an atomic counter. Each chunk is CTR-decrypted
    //    to its "compressed plaintext" then (if compression_id != NONE) passed
    //    through decompress_chunk before being written to its slot in pt_buffer
    //    at offset i * chunk_size. Progress is reported in PLAINTEXT bytes
    //    per chunk (same as encrypt).
    std::vector<unsigned char> pt(static_cast<size_t>(header.original_size));
    const CompressionId cid = static_cast<CompressionId>(header.compression_id);

    if (chunk_count > 0) {
        const size_t hw = std::thread::hardware_concurrency();
        size_t nthreads = (opts.num_threads == 0) ? hw : opts.num_threads;
        if (nthreads == 0) nthreads = 1;
        if (nthreads > chunk_count) nthreads = chunk_count;

        std::atomic<size_t> next_chunk{0};
        std::atomic<bool>   failed{false};
        std::mutex          err_mutex;
        std::string         err_msg;
        std::atomic<size_t> bytes_done{0};

        auto worker = [&]() {
            for (;;) {
                if (failed.load(std::memory_order_relaxed)) return;
                size_t i = next_chunk.fetch_add(1, std::memory_order_relaxed);
                if (i >= chunk_count) return;

                const uint64_t start_i = chunk_start[i];
                const uint32_t this_ct = offsets[i];
                // Expected PLAINTEXT (post-decompress) size of this chunk.
                const size_t expected_pt =
                    (i + 1 == chunk_count)
                        ? static_cast<size_t>(
                              header.original_size - (uint64_t)i * cs)
                        : cs;

                std::span<const unsigned char> ct_span(
                    ct_region.data() + static_cast<size_t>(start_i),
                    static_cast<size_t>(this_ct));

                // CTR-decrypt to "compressed plaintext".
                std::vector<unsigned char> compressed_pt(this_ct);
                // IV: v1 uses the legacy derive_chunk_iv with
                //     block_offset = i*chunk_size / AES_BLOCK_SIZE;
                //     v2 uses derive_chunk_iv_v2 with the prefix-CT sum,
                //     which equals chunk_start[i] from the offset table.
                std::array<unsigned char, IV_SIZE> chunk_iv;
                if (is_v1) {
                    const uint64_t block_offset =
                        (static_cast<uint64_t>(i) * cs) / AES_BLOCK_SIZE;
                    chunk_iv = derive_chunk_iv(header.base_iv, block_offset);
                } else {
                    chunk_iv = derive_chunk_iv_v2(header.base_iv,
                                                   static_cast<uint64_t>(i),
                                                   start_i);
                }

                bool ok = decrypt_chunk_ctr(
                    std::span<const unsigned char>(opts.file_key.data(),
                                                    opts.file_key.size()),
                    std::span<const unsigned char, IV_SIZE>(chunk_iv),
                    ct_span,
                    std::span<unsigned char>(compressed_pt.data(),
                                              compressed_pt.size()));
                if (!ok) {
                    bool expected = false;
                    if (failed.compare_exchange_strong(
                            expected, true, std::memory_order_acq_rel)) {
                        std::lock_guard<std::mutex> lk(err_mutex);
                        err_msg = "OpenSSL decrypt chunk " + std::to_string(i) +
                                  " failed: " + openssl_last_error();
                    }
                    return;
                }

                // Decompress (or pass through with size-check for NONE).
                std::vector<unsigned char> pt_chunk;
                try {
                    pt_chunk = decompress_chunk(
                        cid,
                        std::span<const unsigned char>(compressed_pt.data(),
                                                         compressed_pt.size()),
                        expected_pt);
                } catch (const std::exception& e) {
                    bool expected = false;
                    if (failed.compare_exchange_strong(
                            expected, true, std::memory_order_acq_rel)) {
                        std::lock_guard<std::mutex> lk(err_mutex);
                        err_msg = std::string("decompress chunk ")
                                  + std::to_string(i) + " failed: " + e.what();
                    }
                    return;
                }
                if (pt_chunk.size() != expected_pt) {
                    bool expected = false;
                    if (failed.compare_exchange_strong(
                            expected, true, std::memory_order_acq_rel)) {
                        std::lock_guard<std::mutex> lk(err_mutex);
                        err_msg = "decompressed chunk " + std::to_string(i) +
                                  " size mismatch (got " +
                                  std::to_string(pt_chunk.size()) + ", expected " +
                                  std::to_string(expected_pt) + ")";
                    }
                    return;
                }

                // Write pt_chunk into pt at offset i * chunk_size.
                // Each chunk_index is uniquely dispatched to exactly one worker,
                // so pt[i*cs .. i*cs + expected_pt) is written once — no mutex.
                std::memcpy(pt.data() + static_cast<size_t>(i) * cs,
                            pt_chunk.data(), expected_pt);

                size_t done = bytes_done.fetch_add(expected_pt,
                                                    std::memory_order_relaxed)
                              + expected_pt;
                if (opts.progress) {
                    opts.progress(done, static_cast<size_t>(header.original_size));
                }
            }
        };

        std::vector<std::thread> pool;
        pool.reserve(nthreads);
        for (size_t t = 0; t < nthreads; ++t) pool.emplace_back(worker);
        for (auto& th : pool) th.join();

        if (failed.load(std::memory_order_acquire)) {
            std::lock_guard<std::mutex> lk(err_mutex);
            throw std::runtime_error(err_msg);
        }
    } else if (opts.progress) {
        opts.progress(0, 0);
    }

    // 8. Write the plaintext. Any HMAC/tamper check has already passed, so
    //    writing the plaintext here is safe.
    std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("cannot open output file: " + output_path);
    }
    if (!pt.empty()) {
        out.write(reinterpret_cast<const char*>(pt.data()),
                  static_cast<std::streamsize>(pt.size()));
        if (!out) throw std::runtime_error("write plaintext failed");
    }
    out.flush();
    if (!out) throw std::runtime_error("flush output failed");
}

}  // namespace lock
