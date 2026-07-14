#include <lock/crypto.hpp>
#include <lock/endian.hpp>

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

// ---- Shared parallel runner ---------------------------------------------
//
// Both encrypt_file and decrypt_file split the buffer into chunk_size chunks,
// hand each chunk to a worker pulled from a fixed-size thread pool, and have
// each worker carve chunks off a std::atomic<size_t> counter. This is the
// simplest correct structure: per-thread EVP_CIPHER_CTX (OpenSSL contexts are
// NOT thread-safe), no shared mutable state except the atomic counter, the
// error flag, the error message, and the per-chunk output regions (which are
// disjoint by construction).
//
// `chunk_fn(i, plaintext_start, ciphertext_start, chunk_bytes)` does the
// actual cryptographic work for chunk i. Throws are forbidden inside it —
// the wrapper translates failures into the atomic error channel.
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

    // 2. Build the FileHeader (we need it fully populated BEFORE
    //    encrypt_filename, because the header feeds the AAD digest).
    FileHeader header;
    header.magic        = MAGIC;
    header.version      = FORMAT_VERSION;
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
    header.chunk_count  = static_cast<uint32_t>(
        (pt.size() + opts.chunk_size - 1) / opts.chunk_size);
    header.reserved     = 0;

    // 3. Encrypt the filename; bind it to the (still-being-built) header.
    EncryptedFilename enc_name = encrypt_filename(
        opts.file_key, header, original_filename_for_header);
    header.encrypted_filename = std::move(enc_name.ciphertext);
    header.filename_len      = static_cast<uint32_t>(
        header.encrypted_filename.size());
    header.filename_tag       = enc_name.tag;

    // Serialise once — these bytes are written to disk AND feed the HMAC.
    std::vector<unsigned char> header_bytes = HeaderWriter::serialise(header);

    // 4. Allocate the ciphertext buffer (same length as plaintext for CTR).
    std::vector<unsigned char> ct(pt.size());

    // 5. Parallel-encrypt every chunk.
    //    Each worker builds its own per-call EVP_CIPHER_CTX via
    //    ctr_crypt_chunk (which constructs a fresh ctx and tears it down
    //    before returning) — so no context ever crosses a thread boundary.
    const size_t cs = opts.chunk_size;
    auto do_chunk = [&](size_t i, unsigned char* in_p, unsigned char* out_p,
                        size_t len) -> bool {
        uint64_t block_offset =
            (static_cast<uint64_t>(i) * cs) / AES_BLOCK_SIZE;
        auto chunk_iv = derive_chunk_iv(opts.base_iv, block_offset);
        return encrypt_chunk_ctr(
            std::span<const unsigned char>(opts.file_key.data(),
                                            opts.file_key.size()),
            std::span<const unsigned char, IV_SIZE>(chunk_iv),
            std::span<const unsigned char>(in_p,  len),
            std::span<unsigned char>(out_p, len));
    };

    run_parallel(pt.size(), cs, opts.num_threads,
                 pt.data(), ct.data(),
                 do_chunk, opts.progress);

    // 6. Compute HMAC over (header_serialised || ciphertext). Single-threaded
    //    pass after every worker joined — the covered bytes are immutable by
    //    the time we get here.
    StreamingHmac hmac(std::span<const unsigned char>(opts.hmac_key.data(),
                                                     opts.hmac_key.size()));
    if (!header_bytes.empty()) hmac.update(header_bytes.data(),
                                            header_bytes.size());
    if (!ct.empty())           hmac.update(ct.data(), ct.size());
    std::array<unsigned char, HMAC_SHA256_SIZE> mac = hmac.final_bytes();

    // 7. Write the output file: header || ct || mac.
    std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("cannot open output file: " + output_path);
    }
    if (!header_bytes.empty()) {
        out.write(reinterpret_cast<const char*>(header_bytes.data()),
                  static_cast<std::streamsize>(header_bytes.size()));
        if (!out) throw std::runtime_error("write header failed");
    }
    if (!ct.empty()) {
        out.write(reinterpret_cast<const char*>(ct.data()),
                  static_cast<std::streamsize>(ct.size()));
        if (!out) throw std::runtime_error("write ciphertext failed");
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

    // Read ciphertext region.
    std::vector<unsigned char> ct(header.original_size);
    if (!ct.empty()) {
        in.read(reinterpret_cast<char*>(ct.data()),
                static_cast<std::streamsize>(ct.size()));
        if (static_cast<std::streamsize>(in.gcount())
              != static_cast<std::streamsize>(ct.size())) {
            throw std::runtime_error("short read on ciphertext region");
        }
    }

    // Read + verify the trailing 32-byte HMAC footer.
    std::array<unsigned char, HMAC_SHA256_SIZE> stored_mac{};
    in.read(reinterpret_cast<char*>(stored_mac.data()),
            static_cast<std::streamsize>(HMAC_SHA256_SIZE));
    if (static_cast<std::streamsize>(in.gcount())
          != static_cast<std::streamsize>(HMAC_SHA256_SIZE)) {
        throw std::runtime_error("input file missing HMAC footer");
    }

    // Reconstruct the header bytes that were HMACed on encrypt. We use the
    // *parsed* header, re-serialised — HeaderWriter::serialise is
    // round-trippable for the fields it round-trips (which is all the
    // fields HMAC covers). If the on-disk header bytes had been tampered
    // with but still parsed, the AAD/round-trip mismatch would also break
    // filename GCM authentication if the user attempted it.
    std::vector<unsigned char> header_bytes = HeaderWriter::serialise(header);

    std::array<unsigned char, HMAC_SHA256_SIZE> computed_mac{};
    {
        StreamingHmac hmac(std::span<const unsigned char>(opts.hmac_key.data(),
                                                         opts.hmac_key.size()));
        if (!header_bytes.empty()) hmac.update(header_bytes.data(),
                                                header_bytes.size());
        if (!ct.empty())           hmac.update(ct.data(), ct.size());
        computed_mac = hmac.final_bytes();
    }
    // Constant-time compare to defeat timing oracles on tamper detection.
    if (CRYPTO_memcmp(computed_mac.data(), stored_mac.data(),
                      HMAC_SHA256_SIZE) != 0) {
        throw std::runtime_error(
            "HMAC verification failed — file is truncated or tampered");
    }

    // Parallel-decrypt. Same shape as encrypt: per-thread EVP_CIPHER_CTX
    // via ctr_crypt_chunk, chunks dispatched off an atomic counter.
    std::vector<unsigned char> pt(header.original_size);
    const size_t cs = header.chunk_size;
    auto do_chunk = [&](size_t i, unsigned char* in_p, unsigned char* out_p,
                        size_t len) -> bool {
        uint64_t block_offset =
            (static_cast<uint64_t>(i) * cs) / AES_BLOCK_SIZE;
        auto chunk_iv = derive_chunk_iv(header.base_iv, block_offset);
        return decrypt_chunk_ctr(
            std::span<const unsigned char>(opts.file_key.data(),
                                            opts.file_key.size()),
            std::span<const unsigned char, IV_SIZE>(chunk_iv),
            std::span<const unsigned char>(in_p,  len),
            std::span<unsigned char>(out_p, len));
    };

    run_parallel(ct.size(), cs, opts.num_threads,
                 ct.data(), pt.data(),
                 do_chunk, opts.progress);

    // Write the plaintext. Any HMAC/tamper check has already passed, so
    // writing the plaintext here is safe.
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
