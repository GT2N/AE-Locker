#include <ae-locker/crypto.hpp>
#include <ae-locker/endian.hpp>
#include <ae-locker/compress.hpp>

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
#include <condition_variable>
#include <vector>
#include <fstream>
#include <cstring>
#include <stdexcept>
#include <memory>
#include <algorithm>
#include <span>
#include <string>
#include <limits>
#include <queue>
#include <filesystem>
#include <optional>
#include <unordered_map>
#include <utility>
#include <unistd.h>

namespace ae_locker {

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

// ============================================================================
// Streaming file encrypt / decrypt
//
// Both encrypt_file and decrypt_file used to read the entire plaintext (or
// ciphertext region) into RAM and run a flat parallel worker pool on the
// in-memory slab. The streaming rewrite replaces that with a bounded-queue
// chunk pipeline so peak memory is O(N * chunk_size) — independent of the
// file size — and removes the legacy 64 GiB RAM ceiling. The on-disk v2 wire
// format (header || chunk_ciphertext || offset_table || HMAC_footer) is bit
// for bit compatible with what the old writer produced, so the v1 ↔ v2 read
// contract and existing tests are preserved.
//
// Pipelines are deliberately coarse-grained: a single producer thread (read +
// compress on encrypt; read on decrypt), an atomic-dispatch pool of worker
// threads (decrypt-then-decompress on decrypt), and a single writer thread
// that owns the ofstream and the single StreamingHmac. The writer is serial
// by construction, so the per-chunk CT is fed into the HMAC in on-disk order
// — exactly matching what decrypt recomputes.
//
// Memory: bounded blocking queues (capacity N + 1) keep at most a small
// number of chunk-sized buffers in flight at any moment, so peak RAM equals
// roughly (queue_capacity + worker_count) * chunk_size, never file_size.
// ============================================================================

namespace {

// -------- Sanity ceilings (anti-malicious-header OOM defense) --------
//
// The streaming codec no longer has a hard 64 GiB input cap because peak RAM
// is independent of file size, but we still have to refuse a header that
// claims an absurd chunk_count / original_size: a header that lies about
// chunk_count would let an attacker force us to allocate a 4-byte-per-chunk
// offset table that is itself gigabytes, and a header that lies about
// original_size would let an attacker claim a file is 2^64 bytes (breaking
// downstream code that multiplies original_size by chunk_size). These
// ceilings are deliberately far above any real-world file but small enough
// to keep a malicious file from forcing a 4 GiB offset table allocation:
//
//   MAX_CHUNK_COUNT     = 1 billion      -> offset table <= 4 GiB worst case
//                                          (and typical real chunk_count is
//                                           orders of magnitude smaller)
//   MAX_ORIGINAL_SIZE  = 64 PiB          -> far beyond any filesystem limit
//                                          on Linux/macOS today, while small
//                                          enough to keep any reasonable
//                                          size_t arithmetic from wrapping
//                                          on 64-bit hosts.
//   MAX_STORED_SIZE    = 64 PiB          -> same reasoning, applied to the
//                                          on-disk ciphertext + offset-table
//                                          region for v2 files.
constexpr uint64_t MAX_CHUNK_COUNT    = uint64_t(1) * 1000ULL * 1000ULL * 1000ULL;
constexpr uint64_t MAX_ORIGINAL_SIZE  = uint64_t(64) * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr uint64_t MAX_STORED_SIZE    = uint64_t(64) * 1024ULL * 1024ULL * 1024ULL * 1024ULL;

// Per-thread EVP_CIPHER_CTX cache. ctr_crypt_chunk builds a fresh context on
// every call which is fine but slightly wasteful inside a tight worker loop;
// we hand-roll a per-thread long-lived context here so each decrypt worker
// reuses its own EVP_CIPHER_CTX across all the chunks it pulls off the queue.
// OpenSSL contexts are NOT thread-safe, but they ARE safe to reuse from the
// SAME thread, so one thread_local cache per worker thread is correct.
CtxPtr& thread_local_ctr_ctx() {
    thread_local CtxPtr ctx;
    return ctx;
}

// Reuse a per-thread EVP_CIPHER_CTX for CTR. Returns true on success.
// Re-initialising an existing CTR context with a fresh key+IV via
// EVP_EncryptInit_ex is cheaper than EVP_CIPHER_CTX_new + free per chunk;
// the semantics are identical because CTR has no running state other than
// the keystream counter (which set_key+set_iv resets wholesale).
bool ctr_crypt_with_ctx(EVP_CIPHER_CTX* raw,
                        std::span<const unsigned char> key,
                        std::span<const unsigned char, IV_SIZE> iv,
                        std::span<const unsigned char> in,
                        std::span<unsigned char> out) noexcept {
    if (raw == nullptr)                                return false;
    if (key.size() != AES_256_KEY_SIZE)                return false;
    if (iv.size()  != IV_SIZE)                         return false;
    if (in.size()  != out.size())                       return false;
    if (!in.empty() && (in.data() == out.data()))      return false;
    if (in.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return false;
    }

    if (EVP_EncryptInit_ex(raw, EVP_aes_256_ctr(), nullptr,
                           key.data(), iv.data()) != 1) {
        return false;
    }
    if (EVP_CIPHER_CTX_set_padding(raw, 0) != 1) {
        return false;
    }
    int outl = 0;
    if (EVP_EncryptUpdate(raw, out.data(), &outl,
                          in.data(), static_cast<int>(in.size())) != 1) {
        return false;
    }
    int finall = 0;
    if (EVP_EncryptFinal_ex(raw, out.data() + outl, &finall) != 1) {
        return false;
    }
    return (static_cast<size_t>(outl + finall) == in.size());
}

// Ensure the calling thread's thread_local CTR context is allocated and reuse
// it for one CTR pass. Allocates lazily on first use per thread.
bool ctr_crypt_thread_local(std::span<const unsigned char> key,
                            std::span<const unsigned char, IV_SIZE> iv,
                            std::span<const unsigned char> in,
                            std::span<unsigned char> out) noexcept {
    CtxPtr& ctx = thread_local_ctr_ctx();
    if (!ctx) {
        ctx.reset(EVP_CIPHER_CTX_new());
        if (!ctx) return false;
    }
    return ctr_crypt_with_ctx(ctx.get(), key, iv, in, out);
}

// -------- Bounded blocking queue with stop flag --------
//
// A single-producer / single-consumer queue would suffice for the encrypt
// pipeline; the decrypt pipeline has a many-producer (workers push pt
// results) + single-consumer (writer) write queue and a single-producer
// (reader) + many-consumer (workers) read queue, so the queue is written to
// be N-producer / N-consumer safe by guarding std::queue with a mutex +
// condition_variable. Capacity is bounded so producers block when the queue
// is full (this is what bounds peak RAM — at most `capacity` chunk-sized
// buffers can be in flight).
//
// The queue supports a stop() call that releases any blocked producer or
// consumer; subsequent pushes are dropped and pops return nullopt. This is
// how the main thread cancels workers when an exception (read failure,
// OpenSSL error, decompress failure) is reported via the atomic error flag.
template <typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t capacity) : capacity_(capacity) {}

    // Push returns false if the queue has been stopped (caller should bail).
    bool push(T v) {
        std::unique_lock<std::mutex> lk(m_);
        cv_not_full_.wait(lk, [&] {
            return stopped_ || q_.size() < capacity_;
        });
        if (stopped_) return false;
        q_.push(std::move(v));
        cv_not_empty_.notify_one();
        return true;
    }

    // Pop returns nullopt if the queue is stopped AND drained.
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lk(m_);
        cv_not_empty_.wait(lk, [&] {
            return stopped_ || !q_.empty();
        });
        if (q_.empty()) {
            // Either stopped with nothing left, or spurious wake — in either
            // case there is nothing for the caller to do.
            return std::nullopt;
        }
        T v = std::move(q_.front());
        q_.pop();
        cv_not_full_.notify_one();
        return v;
    }

    void stop() {
        std::lock_guard<std::mutex> lk(m_);
        stopped_ = true;
        cv_not_empty_.notify_all();
        cv_not_full_.notify_all();
    }

    // For writer threads that must drain strictly in order: try_pop returns
    // nullopt without blocking if the queue is empty (caller decides whether
    // to keep waiting). Not used currently; kept here for completeness.
    std::optional<T> try_pop() {
        std::lock_guard<std::mutex> lk(m_);
        if (q_.empty()) return std::nullopt;
        T v = std::move(q_.front());
        q_.pop();
        cv_not_full_.notify_one();
        return v;
    }

private:
    std::mutex              m_;
    std::condition_variable cv_not_empty_;
    std::condition_variable cv_not_full_;
    std::queue<T>           q_;
    size_t                  capacity_;
    bool                    stopped_ = false;
};

// Shared error channel: workers report a single failure via CAS on `failed`;
// the captured message is held under a mutex. The main thread inspects it
// after every worker has joined and rethrows. Exception THROWING across a
// thread boundary would terminate the process, so we never do it; instead
// workers write into err_msg and signal stop() on the queues.
struct ErrorChannel {
    std::atomic<bool> failed{false};
    std::mutex        err_mutex;
    std::string       err_msg;

    // Record `msg` only if this is the FIRST failure. Returns true when the
    // caller is the winner of the CAS and so its message is the one that
    // will be rethrown.
    bool report_first(std::string_view msg) {
        bool expected = false;
        if (failed.compare_exchange_strong(expected, true,
                                            std::memory_order_acq_rel)) {
            std::lock_guard<std::mutex> lk(err_mutex);
            err_msg.assign(msg);
            return true;
        }
        return false;
    }
};

}  // namespace

// ---------------------------------------------------------------------------
// encrypt_file — streaming compress-then-encrypt pipeline.
//
//   main:        stat() -> chunk_count -> header (stored_size = 0 placeholder)
//                -> encrypt_filename -> serialise header -> open fstream(trunc)
//                -> seekp to data_offset -> start pipeline -> join
//                -> rewrite header (final stored_size) at offset 0
//                -> streaming HMAC.update(final header_bytes)
//                -> write offset_table (chunk_count * be32) -> HMAC.update
//                -> write HMAC footer
//
//   Thread A:    for i in 0..chunk_count:
//                  read pt chunk from ifstream
//                  compress_chunk (thread_local ZSTD_CCtx inside compress_chunk)
//                  BoundedQueue<CompressedChunk>.push({i, compressed})
//                then queue.stop()
//
//   Thread B:    while pop {i, compressed}:
//                  iv = derive_chunk_iv_v2(base_iv, i, prefix_ct_so_far)
//                  ctr_crypt_thread_local(file_key, iv, compressed, ct_buf)
//                  out.write(ct_buf)            // sequential, single writer
//                  streaming_hmac.update(ct)    // in on-disk order
//                  prefix_ct_so_far += ct.size()
//                  ct_per_chunk_size[i] = ct.size()
//                  progress(pt_offset, total_pt)
//                (queue drained -> exit)
//
// Memory peak: ~ (queue_capacity + 1 + thread_local_compress_buffer) * chunk_size,
//              ~ O(N * chunk_size), independent of input file size.
// ---------------------------------------------------------------------------
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

    // 1. stat() for the input size — we never read the whole file into RAM.
    std::error_code st_ec;
    const auto entry = std::filesystem::directory_entry(input_path, st_ec);
    if (st_ec || !entry.is_regular_file(st_ec)) {
        // directory_entry falls back to status() — covers symlinks etc.
        const auto st = std::filesystem::status(input_path, st_ec);
        if (st_ec || !std::filesystem::is_regular_file(st)) {
            throw std::runtime_error("cannot stat input file: " + input_path);
        }
    }
    std::error_code sz_ec;
    const uint64_t file_size_u64 =
        static_cast<uint64_t>(std::filesystem::file_size(input_path, sz_ec));
    if (sz_ec) {
        throw std::runtime_error("cannot determine size of: " + input_path);
    }
    if (file_size_u64 > MAX_ORIGINAL_SIZE) {
        throw std::runtime_error("input file too large (>64 PiB sanity cap): "
                                 + input_path);
    }
    const size_t total_pt = static_cast<size_t>(file_size_u64);
    const size_t cs       = opts.chunk_size;
    const size_t chunk_count = (total_pt + cs - 1) / cs;
    if (static_cast<uint64_t>(chunk_count) > MAX_CHUNK_COUNT) {
        throw std::runtime_error("chunk_count exceeds sanity cap");
    }

    // 2. Build the FileHeader. stored_size stays a placeholder (0) until
    //    every chunk has been compressed and we know the per-chunk CT sizes.
    FileHeader header;
    header.magic          = MAGIC;
    header.version       = 2;  // v2 wire format (offset table + compression_id)
    header.algorithm_id  = static_cast<uint32_t>(AlgorithmId::AES_256_CTR_HMAC_SHA256);
    header.kdf_id        = static_cast<uint32_t>(KdfId::SCRYPT);
    header.kdf_N         = opts.kdf_N;
    header.kdf_r         = opts.kdf_r;
    header.kdf_p         = opts.kdf_p;
    header.salt          = opts.salt;
    header.base_iv       = opts.base_iv;
    header.flags         = 0x01;  // filename present
    header.original_size = file_size_u64;
    header.chunk_size    = opts.chunk_size;
    header.chunk_count   = static_cast<uint32_t>(chunk_count);
    header.compression_id = static_cast<uint32_t>(opts.compression);
    header.stored_size   = 0;  // overwritten once the pipeline emits every chunk

    // 3. Encrypt the filename; this MUST run before the chunks write any
    //    bytes (encrypted_filename populates header fields that serialise
    //    into the header bytes the writer will HMAC later). The AAD is
    //    computed over the v1-stable header field set — see the long comment
    //    above filename_aad_digest for the rationale.
    EncryptedFilename enc_name = encrypt_filename(
        opts.file_key, header, original_filename_for_header);
    header.encrypted_filename = std::move(enc_name.ciphertext);
    header.filename_len       = static_cast<uint32_t>(
        header.encrypted_filename.size());
    header.filename_tag        = enc_name.tag;

    // 4. Serialise the placeholder header (stored_size is still 0). The
    //    header bytes are written ONCE with the final stored_size after the
    //    pipeline finishes; we never emit a placeholder to disk. We keep a
    //    placeholder `header_bytes` here only to know its LENGTH, which
    //    tells us where the ciphertext region starts.
    std::vector<unsigned char> header_bytes = HeaderWriter::serialise(header);
    const std::streamoff data_off =
        static_cast<std::streamoff>(header_bytes.size());

    // 5. Open the output file. We use std::fstream (in | out | trunc) so we
    //    can seek back to offset 0 and rewrite the header once stored_size
    //    is known, while the writer thread keeps appending chunk CTs at
    //    data_off onwards.
    std::fstream out(output_path,
                     std::ios::in | std::ios::out | std::ios::binary
                     | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("cannot open output file: " + output_path);
    }
    // Position the put pointer at the start of the ciphertext region. The
    // header bytes are filled in later (single re-serialise + seekp(0)).
    out.seekp(data_off, std::ios::beg);
    if (!out) {
        throw std::runtime_error("seek failed on output: " + output_path);
    }

    // 6. Per-chunk CT sizes collected by the writer thread. uint32 per the
    //    v2 offset-table wire format; capped to chunk_count entries.
    std::vector<uint32_t> ct_per_chunk_size(chunk_count, 0);
    const CompressionId cid = opts.compression;

    // 7. Streaming HMAC. Only the MAIN thread touches it, updated post-join
    //    over (header || ct || offset_table) in the on-disk wire-format
    //    order — see step 13. The writer thread emits ct to disk without
    //    touching the HMAC; main reads the persisted ct back with a tiny
    //    buffer (peak RAM stays O(chunk_size), not O(file_size)).
    StreamingHmac hmac(std::span<const unsigned char>(
        opts.hmac_key.data(), opts.hmac_key.size()));

    // 8. Bounded queue carrying compressed (or passthrough) PT chunks from
    //    the reader+compressor to the encryptor+writer. Capacity N+1 (where
    //    N = opts.num_threads or hw_concurrency) keeps at most N+1 chunk
    //    buffers in flight, so peak RAM is ~ (N+1) * chunk_size.
    const size_t hw   = std::thread::hardware_concurrency();
    size_t nthreads  = (opts.num_threads == 0) ? hw : static_cast<size_t>(opts.num_threads);
    if (nthreads == 0) nthreads = 1;

    struct CompressedChunk {
        size_t                    i;
        std::vector<unsigned char> data;
    };
    BoundedQueue<CompressedChunk> cq(nthreads + 1);

    // Shared error state between threads (CAS-first semantics, see
    // ErrorChannel::report_first).
    ErrorChannel err;

    // 9. Open the input stream sequentially. We never seek on it.
    std::ifstream in(input_path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot open input file: " + input_path);
    }

    // -------- Thread A: reader + compressor --------
    auto reader = [&]() {
        std::vector<unsigned char> pt_buf(cs);
        for (size_t i = 0; i < chunk_count; ++i) {
            if (err.failed.load(std::memory_order_relaxed)) break;
            const size_t off = i * cs;
            const size_t this_len = std::min(cs, total_pt - off);
            if (this_len > 0) {
                pt_buf.resize(this_len);
                in.read(reinterpret_cast<char*>(pt_buf.data()),
                        static_cast<std::streamsize>(this_len));
                if (static_cast<size_t>(in.gcount()) != this_len) {
                    err.report_first("short read on input chunk "
                                     + std::to_string(i)
                                     + ": " + input_path);
                    break;
                }
            } else {
                pt_buf.clear();
            }
            std::vector<unsigned char> compressed;
            try {
                if (cid != CompressionId::NONE) {
                    compressed = compress_chunk(
                        cid,
                        std::span<const unsigned char>(pt_buf.data(),
                                                        pt_buf.size()),
                        opts.compression_level);
                } else {
                    compressed.assign(pt_buf.begin(), pt_buf.end());
                }
            } catch (const std::exception& e) {
                err.report_first(std::string("compress chunk ")
                                + std::to_string(i) + " failed: " + e.what());
                break;
            }
            if (!cq.push(CompressedChunk{ i, std::move(compressed) })) {
                // Queue was stopped (worker failed); abort.
                break;
            }
        }
        cq.stop();
    };

    // -------- Thread B: encryptor + writer + HMAC --------
    auto writer = [&]() {
        std::vector<unsigned char> ct_buf;
        uint64_t prefix_ct = 0;  // sum of bytes written to disk before chunk i

        for (;;) {
            auto item = cq.pop();
            if (!item.has_value()) break;  // queue stopped and drained
            CompressedChunk& cc = *item;
            if (err.failed.load(std::memory_order_relaxed)) {
                // Drain the rest without doing work; main loop will stop soon.
                continue;
            }
            ct_buf.assign(cc.data.begin(), cc.data.end());
            const size_t this_ct = ct_buf.size();

            // v2 per-chunk IV: derive_chunk_iv_v2(base_iv, i, prefix_ct_so_far)
            // — exactly what decrypt will recompute from the offset table, so
            // the same IV / keystream is used in both directions.
            auto chunk_iv = derive_chunk_iv_v2(
                opts.base_iv,
                static_cast<uint64_t>(cc.i),
                prefix_ct);

            std::span<const unsigned char> key_span(opts.file_key.data(),
                                                      opts.file_key.size());
            std::span<unsigned char> ct_span(ct_buf.data(), ct_buf.size());
            std::span<const unsigned char, IV_SIZE> iv_span(chunk_iv);

            if (!ctr_crypt_thread_local(key_span, iv_span,
                                         std::span<const unsigned char>(cc.data.data(),
                                                                          cc.data.size()),
                                         ct_span)) {
                err.report_first("OpenSSL encrypt chunk "
                                 + std::to_string(cc.i)
                                 + " failed: " + openssl_last_error());
                continue;
            }

            // Sanity: CTR is length-preserving.
            if (ct_buf.size() != this_ct) {
                err.report_first("CTR length mismatch on chunk "
                                 + std::to_string(cc.i));
                continue;
            }

            // The on-disk CT order is the order this thread writes them; we
            // pop in queue order, which is the order the reader pushed them,
            // which is chunk_index order (reader pushes i=0,1,2,...). So the
            // ct written here is in chunk_index order — the same order
            // decrypt will read + HMAC-feed.
            //
            // The HMAC update is intentionally NOT done in this thread: per
            // the wire-format spec the HMAC order is header || ct || offset
            // table, but here the final header (with definitive stored_size)
            // is unknown until every chunk has been emitted. The main thread
            // therefore re-streams header + ct + offset_table through HMAC
            // AFTER the pipeline joins (see step 13 below), reading the
            // already-persisted ct bytes back from disk with a tiny read
            // buffer — peak RAM stays O(chunk_size), not O(file_size).
            out.write(reinterpret_cast<const char*>(ct_buf.data()),
                      static_cast<std::streamsize>(ct_buf.size()));
            if (!out) {
                err.report_first("write failed on ciphertext chunk "
                                 + std::to_string(cc.i));
                continue;
            }
            prefix_ct += static_cast<uint64_t>(ct_buf.size());

            // Each chunk_index is dispatched to the queue exactly once by
            // the reader, so ct_per_chunk_size[i] is written exactly once —
            // no mutex needed.
            if (cc.i < ct_per_chunk_size.size()) {
                ct_per_chunk_size[cc.i] = static_cast<uint32_t>(ct_buf.size());
            }

            // Progress in PLAINTEXT bytes — matches the file the user gave us.
            if (opts.progress) {
                const size_t pt_off = cc.i * cs;
                const size_t this_pt = std::min(cs, total_pt - pt_off);
                opts.progress(pt_off + this_pt, total_pt);
            }
        }
    };

    // 10. Run the pipeline: spawn both threads, wait for join, throw if any
    //     side reported a failure.
    std::thread reader_th(reader);
    std::thread writer_th(writer);
    reader_th.join();
    writer_th.join();

    if (err.failed.load(std::memory_order_acquire)) {
        out.close();
        // Best effort cleanup of the partial output file.
        std::error_code unlink_ec;
        std::filesystem::remove(output_path, unlink_ec);
        std::lock_guard<std::mutex> lk(err.err_mutex);
        throw std::runtime_error(err.err_msg);
    }

    // 11. All chunks emitted. Compute the final geometry:
    //     total_ct     = sum(ct_per_chunk_size)
    //     stored_size  = total_ct + chunk_count * 4   (offset table is 4 bytes
    //                                                   per chunk, be32)
    uint64_t total_ct = 0;
    for (size_t i = 0; i < chunk_count; ++i) {
        total_ct += static_cast<uint64_t>(ct_per_chunk_size[i]);
        // Sanity: each per-chunk CT size must fit in uint32 (already enforced
        // by the type but document it in case someone widens it later).
        const uint64_t v = ct_per_chunk_size[i];
        if (static_cast<uint64_t>(static_cast<uint32_t>(v)) != v) {
            out.close();
            throw std::runtime_error("chunk CT size overflow uint32");
        }
    }
    const uint64_t offset_table_bytes = static_cast<uint64_t>(chunk_count) * 4ULL;
    header.stored_size = total_ct + offset_table_bytes;
    if (header.stored_size > MAX_STORED_SIZE) {
        out.close();
        throw std::runtime_error("stored_size exceeds sanity cap");
    }

    // 12. Re-serialise the FINAL header (stored_size now set) and rewrite
    //     it at offset 0. The HMAC will run over these final bytes, exactly
    //     matching what decrypt recomputes after re-serialising from disk
    //     (HeaderReader returns identical bytes for identical headers).
    header_bytes = HeaderWriter::serialise(header);
    out.seekp(0, std::ios::beg);
    if (!out) {
        out.close();
        throw std::runtime_error("seekp to header failed");
    }
    out.write(reinterpret_cast<const char*>(header_bytes.data()),
              static_cast<std::streamsize>(header_bytes.size()));
    if (!out) {
        out.close();
        throw std::runtime_error("write final header failed");
    }

    // 13. HMAC over the FINAL header bytes (now persisted at offset 0).
    //     Then read the just-written ct region back from disk — keeping peak
    //     RAM at O(read_buffer) ≤ O(chunk_size) — and update HMAC over it in
    //     the on-disk byte order. This deliberately mirrors the wire-format
    //     order (header || ct || offset_table) so that decrypt, which streams
    //     HMAC in exactly the same order during its own pipeline, arrives at
    //     an identical MAC.
    hmac.update(header_bytes.data(), header_bytes.size());

    if (total_ct > 0) {
        // Open a SEPARATE read handle on the file being written: the
        // ofstream `out` is in write-only mode and cannot be seekg'd.
        std::ifstream hmac_in(output_path, std::ios::binary);
        if (!hmac_in) {
            out.close();
            throw std::runtime_error("cannot reopen output for HMAC read-back: "
                                     + output_path);
        }
        const std::streamoff ct_start =
            static_cast<std::streamoff>(header_bytes.size());
        hmac_in.seekg(ct_start, std::ios::beg);
        if (!hmac_in) {
            out.close();
            throw std::runtime_error("seek to ct region for HMAC failed");
        }
        // Reuse a single 1 MiB buffer across all reads (sized to match the
        // default chunk_size; anything ≥16 bytes works for HMAC since CTR
        // ct is length-preserving and HMAC accepts any byte granularity).
        constexpr size_t HMAC_BUF = 1ULL << 20;  // 1 MiB
        std::vector<unsigned char> buf(HMAC_BUF);
        uint64_t remaining = total_ct;
        while (remaining > 0) {
            const size_t want = std::min(static_cast<uint64_t>(HMAC_BUF),
                                          remaining);
            hmac_in.read(reinterpret_cast<char*>(buf.data()),
                         static_cast<std::streamsize>(want));
            const auto got = static_cast<uint64_t>(hmac_in.gcount());
            if (got != want) {
                out.close();
                throw std::runtime_error("short read during HMAC read-back");
            }
            hmac.update(buf.data(), got);
            remaining -= got;
        }
        hmac_in.close();
    }

    // 14. Seek back to the end of the ciphertext region (offset 0 + header
    //     + total_ct) and append the offset table, then HMAC over it.
    out.seekp(0, std::ios::end);
    if (!out) {
        out.close();
        throw std::runtime_error("seekp to end failed");
    }

    std::vector<unsigned char> offset_table(
        static_cast<size_t>(offset_table_bytes));
    for (size_t i = 0; i < chunk_count; ++i) {
        endian::store_be32(offset_table.data() + i * 4,
                           ct_per_chunk_size[i]);
    }
    if (!offset_table.empty()) {
        out.write(reinterpret_cast<const char*>(offset_table.data()),
                  static_cast<std::streamsize>(offset_table.size()));
        if (!out) {
            out.close();
            throw std::runtime_error("write offset table failed");
        }
        hmac.update(offset_table.data(), offset_table.size());
    }

    // 15. Append the final HMAC and close.
    std::array<unsigned char, HMAC_SHA256_SIZE> mac = hmac.final_bytes();
    out.write(reinterpret_cast<const char*>(mac.data()),
              static_cast<std::streamsize>(mac.size()));
    if (!out) {
        out.close();
        throw std::runtime_error("write HMAC footer failed");
    }
    out.flush();
    if (!out) {
        out.close();
        throw std::runtime_error("flush output failed");
    }
    out.close();

    // chunk_count == 0 path: header is the only thing written (stored_size = 0
    // + size 0 offset table), HMAC covers header_bytes (and the empty offset
    // table). The pipeline was run with zero iterations so queues saw no
    // push and writer exited immediately; everything above still works and
    // produces a perfectly-formed empty container. No special-case branch
    // needed — but schedule the progress callback for the empty case so
    // callers see 0/0 (matches the legacy behaviour).
    if (chunk_count == 0 && opts.progress) {
        opts.progress(0, 0);
    }
}

// ---------------------------------------------------------------------------
// decrypt_file — streaming decrypt-then-decompress pipeline with .tmp +
// atomic rename. The plaintext is never written to its final path until the
// trailing HMAC verifies; a tampered-or-truncated file results in unlink(tmp)
// + throw, leaving the final destination untouched.
//
//   main:        open ifstream -> HeaderReader::read -> geometry validation
//                -> compute offsets[] (v2: from disk table; v1: synthesised)
//                -> tmp_path = output_path + ".lockdec.tmp"
//                -> open ofstream tmp (trunc)
//                -> start streaming HMAC over re-serialised header_bytes
//                -> start pipeline -> join
//                -> read 32-byte footer; HMAC.final() == footer?
//                   yes -> close tmp; rename(tmp -> output_path)
//                   no  -> close tmp; ::unlink(tmp); throw
//
//   Thread A (reader):
//                for i in 0..chunk_count:
//                  read offsets[i] raw ct bytes from ifstream (sequential)
//                  push { i, ct_buf } into read_queue (bounded -> backpressure)
//                then read_queue.stop()
//
//   N worker threads (decrypt + decompress):
//                pop { i, ct_buf }:
//                  iv = (v1) derive_chunk_iv(base_iv, i*cs/16)
//                       (v2) derive_chunk_iv_v2(base_iv, i, prefix_ct_so_far)
//                       -- prefix_ct_so_far needs to match the encrypt-side
//                          order; pass offsets_sum[i] = sum(offsets[0..i-1])
//                  ctr_crypt_thread_local(file_key, iv, ct_buf, pt_compressed)
//                  decompress_chunk(cid, pt_compressed, expected_pt)
//                  push { i, pt_buf } into write_queue
//
//   Thread B (writer):
//                pop { i, pt_buf } strictly in i order (uses an in-order
//                  reorder buffer keyed on i so worker completion order is
//                  decoupled from disk write order):
//                  tmp.write(pt_buf)             -- sequential writes
//                  streaming_hmac.update(ct[i])  -- ct order == on-disk order
//                  prefix_ct_so_far += ct[i].size()
//                  progress(pt_done, original_size)
//
// HMAC order correctness: ct is read sequentially by the reader and re-fed
// to the HMAC in the writer's strict-i order, so the update sequence is the
// same on-disk order encrypt produced. v1 has no offset table; v2 includes
// it in the HMAC (handled by the main thread after the writer joins, same as
// encrypt).
// ---------------------------------------------------------------------------
void decrypt_file(const std::string& input_path,
                  const std::string& output_path,
                  const DecryptOptions& opts) {

    // 1. Open the input + parse the header.
    std::ifstream in(input_path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot open input file: " + input_path);
    }
    FileHeader header = HeaderReader::read(in);

    // 2. Geometry validation: chunk_size, chunk_count, original_size must
    //    be sane. The old hard 64 GiB ceiling is gone (peak RAM is now
    //    O(N * chunk_size)); replaced with anti-OOM sanity ceilings on
    //    chunk_count, original_size, and stored_size.
    if (header.chunk_size == 0 ||
        (header.chunk_size % AES_BLOCK_SIZE) != 0) {
        throw std::runtime_error("header has invalid chunk_size");
    }
    if (header.chunk_size > static_cast<uint32_t>(
            std::numeric_limits<int>::max())) {
        throw std::runtime_error("header chunk_size too large for EVP");
    }
    if (static_cast<uint64_t>(header.original_size) > MAX_ORIGINAL_SIZE) {
        throw std::runtime_error("declared original_size exceeds sanity cap");
    }
    if (static_cast<uint64_t>(header.chunk_count) > MAX_CHUNK_COUNT) {
        throw std::runtime_error("declared chunk_count exceeds sanity cap");
    }
    if (static_cast<uint64_t>(header.stored_size) > MAX_STORED_SIZE) {
        throw std::runtime_error("declared stored_size exceeds sanity cap");
    }

    const size_t cs = header.chunk_size;
    const size_t chunk_count = header.chunk_count;
    const size_t expected_chunks = (header.original_size == 0)
        ? 0
        : (static_cast<size_t>(header.original_size) + cs - 1) / cs;
    if (expected_chunks != chunk_count) {
        throw std::runtime_error("header chunk_count mismatch");
    }

    // 3. Determine v1 vs v2 layout.
    //    v1: offset_table_size = 0, ct_total_size = original_size,
    //        offset[i] = min(chunk_size, original_size - i*chunk_size).
    //        (HeaderReader has already normalised stored_size=original_size,
    //        compression_id=NONE for v1.)
    //    v2: offset_table_size = chunk_count * 4, ct_total_size =
    //        stored_size - offset_table_size (validated >= 0); offset[i]
    //        read straight off disk; sum-checked against ct_total_size.
    const bool is_v1 = (header.version == 1);
    const uint64_t offset_table_size =
        is_v1 ? 0ULL : (static_cast<uint64_t>(chunk_count) * 4ULL);
    uint64_t ct_total_size;
    if (is_v1) {
        ct_total_size = header.original_size;  // == stored_size post-norm
    } else {
        if (header.stored_size < offset_table_size) {
            throw std::runtime_error("stored_size too small for offset table");
        }
        ct_total_size = header.stored_size - offset_table_size;
    }
    if (ct_total_size > MAX_STORED_SIZE) {
        throw std::runtime_error("declared ciphertext region exceeds sanity cap");
    }

    // 4. Read the per-chunk sizes (`offsets`). For v2 this requires reading
    //    the trailing offset table AFTER the ciphertext region; for v1 we
    //    synthesise the legacy fixed-chunk geometry.
    //
    //    The ciphertext region is consumed sequentially by the worker
    //    pipeline below; the offset table (v2) and the trailing HMAC footer
    //    (v1 + v2) live AFTER it on disk. We seekg to those trailing regions
    //    here, read what we need, then seekg BACK to data_offset so the
    //    reader thread can consume the ciphertext sequentially.
    const std::streamoff data_off =
        static_cast<std::streamoff>(header.data_offset());

    std::vector<uint32_t> offsets(chunk_count);
    std::vector<unsigned char> offset_table_bytes(
        static_cast<size_t>(offset_table_size));
    if (!is_v1) {
        if (!offset_table_bytes.empty()) {
            in.seekg(data_off + static_cast<std::streamoff>(ct_total_size),
                     std::ios::beg);
            if (!in) {
                throw std::runtime_error("seek to offset table failed");
            }
            in.read(reinterpret_cast<char*>(offset_table_bytes.data()),
                    static_cast<std::streamsize>(offset_table_bytes.size()));
            if (static_cast<size_t>(in.gcount()) != offset_table_bytes.size()) {
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
            throw std::runtime_error(
                "offset table sum != ciphertext region size");
        }
    } else {
        // Synthesise v1 chunk geometry: each chunk i has size
        //   min(chunk_size, original_size - i*chunk_size)
        // (the legacy fixed-chunk layout). Sum-checked against original_size.
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

    // 5. Prefix-sum of ct start offsets (matches what encrypt wrote into
    //    derive_chunk_iv_v2's `total_ciphertext_bytes` argument). This is
    //    used to recover the EXACT per-chunk IV the encrypt side used.
    std::vector<uint64_t> ct_prefix(chunk_count == 0 ? 0 : chunk_count, 0ULL);
    {
        uint64_t running = 0;
        for (size_t i = 0; i < chunk_count; ++i) {
            ct_prefix[i] = running;
            running += offsets[i];
        }
    }

    // 6. Reconstruct the header bytes that encrypt HMACed. For v1 files this
    //    requires emitting the v1-shaped 112-byte fixed header layout and
    //    truncating the variable portion placement; v2 re-serialises to a
    //    full 124-byte layout. The exact byte stream must match what
    //    encrypt_file fed into HMAC.update(header_bytes), or the final
    //    comparison will fail on legitimate files.
    std::vector<unsigned char> header_bytes = HeaderWriter::serialise(header);
    if (is_v1) {
        const size_t var_size =
            header.filename_len + 4 + FILENAME_TAG_SIZE;
        if (header_bytes.size() < 12 + var_size) {
            throw std::runtime_error("internal: v1 header too short");
        }
        const size_t var_off_v2 = header_bytes.size() - var_size;
        std::memmove(header_bytes.data() + 112,
                     header_bytes.data() + var_off_v2,
                     var_size);
        header_bytes.resize(112 + var_size);
    }

    // 7. Read the trailing 32-byte HMAC footer NOW so we have everything we
    //    need to verify once the streaming HMAC is finalised. The footer
    //    sits at byte (data_offset + ct_total_size + offset_table_size),
    //    immediately after the ciphertext region and — for v2 — the offset
    //    table. After reading the footer we seekg BACK to data_offset so
    //    the reader thread can consume the ciphertext sequentially.
    {
        const std::streamoff footer_off = data_off
            + static_cast<std::streamoff>(ct_total_size)
            + static_cast<std::streamoff>(offset_table_size);
        in.seekg(footer_off, std::ios::beg);
        if (!in) {
            throw std::runtime_error("seek to HMAC footer failed");
        }
    }
    std::array<unsigned char, HMAC_SHA256_SIZE> stored_mac{};
    in.read(reinterpret_cast<char*>(stored_mac.data()),
            static_cast<std::streamsize>(HMAC_SHA256_SIZE));
    if (static_cast<size_t>(in.gcount()) != HMAC_SHA256_SIZE) {
        throw std::runtime_error("input file missing HMAC footer");
    }

    // Reposition the stream at the start of the ciphertext region for the
    // reader worker (it streams chunk i's CT sequentially from there).
    in.seekg(data_off, std::ios::beg);
    if (!in) {
        throw std::runtime_error("seekg back to data_offset failed");
    }

    // 8. Open the .tmp output file in the SAME directory as the final
    //    output_path so the final rename() is atomic (same-filesystem
    //    rename is POSIX-atomic; cross-filesystem rename is not guaranteed
    //    to be).
    const std::string tmp_path = output_path + ".lockdec.tmp";
    {
        // If a stale tmp from a previously interrupted decrypt exists, remove
        // it first so ofstream(trunc) doesn't open a same-named file from
        // another process. (Any error here is ignored — the trunc mode
        // below will clobber it if it's a regular file.)
        std::error_code rm_ec;
        std::filesystem::remove(tmp_path, rm_ec);
    }
    std::ofstream tmp_out(tmp_path,
                         std::ios::binary | std::ios::trunc);
    if (!tmp_out) {
        throw std::runtime_error("cannot open temp output file: " + tmp_path);
    }

    // 9. Start the streaming HMAC over the header bytes. All subsequent
    //    ct chunks (in strict on-disk order) and — for v2 — the offset
    //    table bytes are appended in update() calls below.
    StreamingHmac hmac(std::span<const unsigned char>(
        opts.hmac_key.data(), opts.hmac_key.size()));
    hmac.update(header_bytes.data(), header_bytes.size());

    // 10. Per-thread decrypt workers. Each worker owns a thread_local
    //     EVP_CIPHER_CTX (ctr_crypt_thread_local caches one per thread).
    const size_t hw = std::thread::hardware_concurrency();
    size_t nthreads = (opts.num_threads == 0) ? hw
                                              : static_cast<size_t>(opts.num_threads);
    if (nthreads == 0) nthreads = 1;
    if (nthreads > chunk_count && chunk_count > 0) nthreads = chunk_count;
    if (nthreads == 0) nthreads = 1;  // chunk_count == 0 case keeps main path

    // 11. Error channel + queues.
    ErrorChannel err;

    struct CtChunk {
        size_t                    i;
        std::vector<unsigned char> ct;
    };
    struct PtChunk {
        size_t                    i;
        std::vector<unsigned char> pt;
        std::vector<unsigned char> ct;  // kept alongside for HMAC ordering
    };

    BoundedQueue<CtChunk> read_queue(nthreads + 1);
    BoundedQueue<PtChunk> write_queue(nthreads + 1);

    // 12. Thread A: reader.
    auto reader = [&]() {
        std::vector<unsigned char> ct_buf;
        for (size_t i = 0; i < chunk_count; ++i) {
            if (err.failed.load(std::memory_order_relaxed)) break;
            const size_t this_ct = offsets[i];
            ct_buf.assign(static_cast<size_t>(this_ct), 0);
            if (this_ct > 0) {
                in.read(reinterpret_cast<char*>(ct_buf.data()),
                        static_cast<std::streamsize>(this_ct));
                if (static_cast<size_t>(in.gcount()) != this_ct) {
                    err.report_first("short read on ciphertext chunk "
                                     + std::to_string(i));
                    break;
                }
            }
            if (!read_queue.push(CtChunk{ i, std::move(ct_buf) })) {
                break;  // queue stopped (downstream failure)
            }
        }
        read_queue.stop();
    };

    // 13. N decrypt-then-decompress workers.
    const CompressionId cid =
        static_cast<CompressionId>(header.compression_id);
    auto worker = [&]() {
        for (;;) {
            auto item = read_queue.pop();
            if (!item.has_value()) break;
            if (err.failed.load(std::memory_order_relaxed)) continue;

            CtChunk& cc = *item;
            const size_t this_ct = cc.ct.size();

            std::array<unsigned char, IV_SIZE> chunk_iv;
            if (is_v1) {
                const uint64_t block_offset =
                    (static_cast<uint64_t>(cc.i) * cs) / AES_BLOCK_SIZE;
                chunk_iv = derive_chunk_iv(header.base_iv, block_offset);
            } else {
                chunk_iv = derive_chunk_iv_v2(header.base_iv,
                                                static_cast<uint64_t>(cc.i),
                                                ct_prefix[cc.i]);
            }

            std::vector<unsigned char> pt_compressed(this_ct);
            std::span<const unsigned char> key_span(opts.file_key.data(),
                                                      opts.file_key.size());
            std::span<unsigned char> out_span(pt_compressed.data(),
                                                pt_compressed.size());
            std::span<const unsigned char, IV_SIZE> iv_span(chunk_iv);
            if (!ctr_crypt_thread_local(key_span, iv_span,
                                         std::span<const unsigned char>(
                                             cc.ct.data(), cc.ct.size()),
                                         out_span)) {
                err.report_first("OpenSSL decrypt chunk "
                                 + std::to_string(cc.i)
                                 + " failed: " + openssl_last_error());
                continue;
            }

            // Expected plaintext (post-decompress) size for chunk i.
            const size_t pt_off = static_cast<size_t>(cc.i) * cs;
            const size_t remaining_pt =
                static_cast<size_t>(header.original_size) - pt_off;
            const size_t expected_pt = (cs < remaining_pt) ? cs : remaining_pt;

            std::vector<unsigned char> pt;
            try {
                pt = decompress_chunk(
                    cid,
                    std::span<const unsigned char>(pt_compressed.data(),
                                                     pt_compressed.size()),
                    expected_pt);
            } catch (const std::exception& e) {
                err.report_first(std::string("decompress chunk ")
                                + std::to_string(cc.i) + " failed: " + e.what());
                continue;
            }
            if (pt.size() != expected_pt) {
                err.report_first("decompressed chunk " + std::to_string(cc.i)
                                + " size mismatch (got "
                                + std::to_string(pt.size()) + ", expected "
                                + std::to_string(expected_pt) + ")");
                continue;
            }

            // Carry the raw ct alongside the pt so the writer can HMAC the
            // ct in the same on-disk order encrypt wrote it.
            PtChunk pc;
            pc.i  = cc.i;
            pc.pt = std::move(pt);
            pc.ct = std::move(cc.ct);
            if (!write_queue.push(std::move(pc))) {
                // Queue stopped; we can stop working.
                // (pt is already moved-from / dropped; main thread will
                // report the original downstream failure.)
            }
        }
    };

    // 14. Thread B: writer with strict-i ordering.
    //
    // Workers complete chunks out of order, so the writer must reorder in
    // chunk_index order before writing. A small hash map `pending` keyed on
    // index collects out-of-order results; whenever the next expected index
    // is in `pending` the writer flushes it, then the next, and so on.
    auto writer = [&]() {
        std::unordered_map<size_t, PtChunk> pending;
        pending.reserve(nthreads + 1);
        size_t next_i = 0;
        size_t pt_done = 0;

        for (;;) {
            auto item = write_queue.pop();
            if (!item.has_value()) break;  // queue stopped & drained
            PtChunk& pc = *item;
            if (err.failed.load(std::memory_order_relaxed)) {
                // Drain the rest without writing.
                continue;
            }
            const size_t idx = pc.i;
            pending.emplace(idx, std::move(pc));

            // Flush everything we can write in order.
            while (true) {
                auto it = pending.find(next_i);
                if (it == pending.end()) break;
                PtChunk& ready = it->second;
                if (!ready.pt.empty()) {
                    tmp_out.write(reinterpret_cast<const char*>(ready.pt.data()),
                                  static_cast<std::streamsize>(ready.pt.size()));
                    if (!tmp_out) {
                        err.report_first("write of plaintext chunk "
                                         + std::to_string(next_i) + " failed");
                        break;
                    }
                }
                // HMAC the ct (NOT pt) — exactly what encrypt did, in the
                // same on-disk order. ct[i] here corresponds to ct chunk
                // `next_i` in the on-disk stream.
                if (!ready.ct.empty()) {
                    hmac.update(ready.ct.data(), ready.ct.size());
                }

                pt_done += ready.pt.size();
                if (opts.progress) {
                    opts.progress(pt_done,
                                  static_cast<size_t>(header.original_size));
                }
                pending.erase(it);
                ++next_i;
            }
        }
        // After draining: if there are leftover pending chunks but no
        // failure was reported, that's a structural error (some chunk index
        // never made it through). The main thread will catch this when it
        // compares HMACs — a missing chunk makes the computed HMAC differ
        // from stored_mac — so we don't need to mark an error here.
    };

    // 15. Spawn and join. chunk_count == 0 skips the pool (nthreads is
    //     forced to 1 but reader/writer exit immediately because their loop
    //     body never runs).
    std::thread reader_th(reader);
    std::vector<std::thread> worker_pool;
    worker_pool.reserve(nthreads);
    for (size_t t = 0; t < nthreads; ++t) worker_pool.emplace_back(worker);
    std::thread writer_th(writer);
    reader_th.join();
    for (auto& w : worker_pool) w.join();
    // Stop write_queue too so the writer unblocks if it is still waiting.
    write_queue.stop();
    writer_th.join();

    if (err.failed.load(std::memory_order_acquire)) {
        tmp_out.close();
        std::error_code unlink_ec;
        std::filesystem::remove(tmp_path, unlink_ec);
        std::lock_guard<std::mutex> lk(err.err_mutex);
        throw std::runtime_error(err.err_msg);
    }

    // 16. v2: HMAC over the offset table bytes (exactly the same byte
    //     sequence encrypt wrote — chunk_count * be32). v1 has no offset
    //     table, so the HMAC over header || ct alone matches the legacy
    //     v1 contract.
    if (!offset_table_bytes.empty()) {
        hmac.update(offset_table_bytes.data(), offset_table_bytes.size());
    }

    // 17. Finalise + constant-time compare against the footer read earlier.
    std::array<unsigned char, HMAC_SHA256_SIZE> computed_mac = hmac.final_bytes();
    if (CRYPTO_memcmp(computed_mac.data(), stored_mac.data(),
                      HMAC_SHA256_SIZE) != 0) {
        tmp_out.close();
        std::error_code unlink_ec;
        std::filesystem::remove(tmp_path, unlink_ec);
        throw std::runtime_error(
            "HMAC verification failed - file is truncated or tampered");
    }

    // 18. HMAC OK — flush + close the tmp file, then atomically rename it
    //     to the final output_path. rename() on POSIX within the same
    //     filesystem is atomic, so a concurrent reader either sees the old
    //     state (no file) or the fully-written, authenticated plaintext —
    //     never a partial.
    tmp_out.flush();
    if (!tmp_out) {
        tmp_out.close();
        std::error_code unlink_ec;
        std::filesystem::remove(tmp_path, unlink_ec);
        throw std::runtime_error("flush of tmp output failed");
    }
    tmp_out.close();

    std::error_code rename_ec;
    std::filesystem::rename(tmp_path, output_path, rename_ec);
    if (rename_ec) {
        // Fall back to ::rename if std::filesystem::rename returned an error
        // (rare; std::filesystem::rename normally maps to the same call).
        if (std::rename(tmp_path.c_str(), output_path.c_str()) != 0) {
            std::error_code unlink_ec;
            std::filesystem::remove(tmp_path, unlink_ec);
            throw std::runtime_error("rename('" + tmp_path + "' -> '"
                                     + output_path + "') failed: "
                                     + rename_ec.message());
        }
    }

    // chunk_count == 0 path:	tmp_out is empty (writer never wrote
    // anything), HMAC over header_bytes (+ empty offset_table for v2)
    // matches what encrypt wrote, footer compares, and rename produces a
    // zero-length plaintext file at output_path. Progress callback for the
    // empty case is fired here (the worker pool spawned but did nothing).
    if (chunk_count == 0 && opts.progress) {
        opts.progress(0, 0);
    }
}

}  // namespace ae_locker
