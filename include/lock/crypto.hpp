#pragma once
#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>
#include <cstddef>
#include <span>
#include <lock/constants.hpp>
#include <lock/kdf.hpp>
#include <lock/container.hpp>

namespace lock {

// Progress callback: (bytes_processed_so_far, total_bytes).
// Called from *worker threads*; the subscriber MUST be thread-safe
// (use atomics or a mutex internally). The crypto module does no
// marshalling — every chunk boundary may invoke this from any worker.
using ProgressCallback = std::function<void(size_t bytes_done, size_t total)>;

// Encrypt the plaintext filename with AES-256-GCM. The result populates
// FileHeader.encrypted_filename and FileHeader.filename_tag.
//
// The GCM nonce is derived *deterministically* from the file_key:
//   nonce12 = SHA-256(file_key)[0..11]
// This is safe because every file gets a freshly generated file_key.
//
// AAD = SHA-256( magic || version_be32 || algorithm_id_be32 || salt ||
//                base_iv || original_size_be64 )
// i.e. a 32-byte digest that cryptographically binds the header fields to
// the filename ciphertext. Tampering with any bound field invalidates the
// GCM tag during decrypt_filename.
struct EncryptedFilename {
    std::vector<unsigned char> ciphertext;  // length == plaintext_filename.size()
    std::array<unsigned char, FILENAME_TAG_SIZE> tag;
};

[[nodiscard]] EncryptedFilename encrypt_filename(
    const std::array<unsigned char, AES_256_KEY_SIZE>& file_key,
    const FileHeader& header_for_aad,
    std::string_view original_filename);

// Decrypt a filename produced by encrypt_filename. The AAD is recomputed
// from `header` in exactly the same way, so any tampering of the header
// fields bound into the AAD digest causes a GCM tag mismatch and a
// std::runtime_error throw.
[[nodiscard]] std::string decrypt_filename(
    const std::array<unsigned char, AES_256_KEY_SIZE>& file_key,
    const FileHeader& header,
    std::string_view encrypted_filename_bytes,
    std::span<const unsigned char, FILENAME_TAG_SIZE> tag);

// Derive the per-chunk IV from the file's base_iv and the chunk's
// block_offset.
//
// base_iv is 16 bytes. Bytes 0..7 (the high 64 bits) are a per-file nonce
// and are copied verbatim. Bytes 8..15 (the low 64 bits, big-endian) are a
// block counter; for chunk i we set
//     counter = base_counter + block_offset
// where block_offset = (chunk_index * chunk_size) / AES_BLOCK_SIZE.
//
// This is the gocryptfs BlockIV() pattern: each chunk reuses the file nonce
// but advances the counter by the number of AES blocks already encrypted,
// so every keystream block across the whole file is unique.
//
// Used today for:
//   - v1 read path in decrypt_file (legacy files, uniform chunk_size, no
//     compression). Each chunk i calls derive_chunk_iv(base_iv,
//     i * chunk_size / AES_BLOCK_SIZE).
[[nodiscard]] std::array<unsigned char, IV_SIZE> derive_chunk_iv(
    const std::array<unsigned char, IV_SIZE>& base_iv,
    uint64_t block_offset) noexcept;

// Derive the per-chunk IV for the v2 file format. Unlike the v1
// `derive_chunk_iv`, this does NOT depend on chunk_size — v2 chunks vary in
// length (compression), so we cannot use `i * chunk_size / AES_BLOCK_SIZE`
// as the counter increment.
//
//   High 64 bits (iv[0..7])  := base_iv[0..7] XOR be64(chunk_index)
//                                — guarantees every chunk gets a UNIQUE
//                                  nonce within the file, independent of
//                                  its content or size.
//   Low  64 bits (iv[8..15]) := be64( base_counter
//                                     + total_ciphertext_bytes / AES_BLOCK_SIZE )
//                                — base_counter from base_iv[8..15]; the
//                                  increment is the number of AES blocks
//                                  already emitted across chunks 0..i-1.
//                                  Guarantees no keystream reuse within a
//                                  chunk, since each chunk starts at a
//                                  counter offset equal to its prefix CT size.
//
// Properties this satisfies:
//   (a) Each chunk's IV is unique within a file (chunk_index XOR'd into the
//       high nonce).
//   (b) Two files with the same plaintext produce different IVs (random
//       per-file base_iv).
//   (c) No keystream block reuse within a file: the low-64 counter advances
//       by total_ciphertext_bytes / 16 across the file, so even though the
//       high nonce repeats (only the chunk_index XOR differentiates), the
//       low counter never overlaps for two chunks (their prefixes differ in
//       size; if two chunks happened to map to the same (high,low) pair that
//       would imply identical chunk_index prefix + identical prefix CT size,
//       which is impossible for distinct chunks).
[[nodiscard]] std::array<unsigned char, IV_SIZE> derive_chunk_iv_v2(
    const std::array<unsigned char, IV_SIZE>& base_iv,
    uint64_t chunk_index,
    uint64_t total_ciphertext_bytes) noexcept;

// Encrypt a single chunk with AES-256-CTR. Pure function — the caller
// (each worker thread) is responsible for creating and owning its own
// EVP_CIPHER_CTX; this helper builds a fresh context per call. CTR is
// symmetric so encrypt and decrypt share this routine. `out` must be at
// least `in.size()` bytes. Returns true on success.
[[nodiscard]] bool encrypt_chunk_ctr(
    std::span<const unsigned char> key,
    std::span<const unsigned char, IV_SIZE> iv,
    std::span<const unsigned char> in,
    std::span<unsigned char> out) noexcept;

// Decrypt a single chunk (CTR is symmetric — identical to encrypt).
[[nodiscard]] bool decrypt_chunk_ctr(
    std::span<const unsigned char> key,
    std::span<const unsigned char, IV_SIZE> iv,
    std::span<const unsigned char> in,
    std::span<unsigned char> out) noexcept;

// Compute HMAC-SHA256(key, msg) -> 32 bytes. Implemented on top of
// OpenSSL's EVP_MAC (HMAC fetch) so the result is independent of any
// EVP_CIPHER_CTX state. Never throws — returns a zeroed array on failure
// (callers treat a zero HMAC as a verification failure).
[[nodiscard]] std::array<unsigned char, HMAC_SHA256_SIZE>
hmac_sha256(std::span<const unsigned char> key,
            std::span<const unsigned char> msg) noexcept;

// --- High-level file encrypt/decrypt ---------------------------------------

struct EncryptOptions {
    std::array<unsigned char, AES_256_KEY_SIZE> file_key;
    std::array<unsigned char, HMAC_SHA256_SIZE>  hmac_key;
    std::array<unsigned char, SALT_SIZE>          salt;
    std::array<unsigned char, IV_SIZE>            base_iv;

    // KDF parameters stored verbatim into the FileHeader so that decrypt
    // can re-derive the same key from the user's password. The crypto
    // module itself does NOT call the KDF — the caller already did — but
    // it still has to write these into the header for round-tripping.
    uint32_t kdf_N = (uint32_t)SCRYPT_DEFAULT_N;
    uint32_t kdf_r = SCRYPT_DEFAULT_R;
    uint32_t kdf_p = SCRYPT_DEFAULT_P;

    uint32_t chunk_size  = (uint32_t)DEFAULT_CHUNK_SIZE;
    uint32_t num_threads = 0;  // 0 -> std::thread::hardware_concurrency() (min 1)
    ProgressCallback progress;  // optional; invoked from worker threads

    // v2 compression options. Default NONE preserves wire-format compat
    // with v1 *readers* (which already see compression_id=NONE after
    // HeaderReader normalisation); the on-disk v2 layout still emits an
    // offset table even for NONE so decrypt has a single read path.
    CompressionId compression      = CompressionId::NONE;
    int           compression_level = 3;  // zstd 1..22; ignored for LZ4/NONE
};

// Encrypt `input_path` -> `output_path`.
//
// File layout written (v2):
//   [0, data_offset)                              : serialised FileHeader
//   [data_offset, data_offset + sum(chunk_ct))    : concatenated chunk CTs
//                                                  (variable size per chunk;
//                                                   for CompressionId::NONE
//                                                   each CT == chunk_size or
//                                                   the final remainder)
//   [.., +chunk_count * 4)                        : offset table (be32 per
//                                                  chunk = compressed ct size)
//   [.., +32)                                     : HMAC-SHA256 footer
//
// `header.stored_size` is set to (sum of chunk CT sizes) + (chunk_count * 4)
// so it covers everything from data_offset up to (but excluding) the footer.
//
// HMAC covers `header_serialised || concatenated_chunk_ciphertext ||
// offset_table_bytes` (everything from byte 0 up to the start of the footer).
// For CompressionId::NONE the offset table is still emitted (single read
// path). The HMAC is computed single-threaded after every worker has joined,
// so it never races with chunk encryption.
//
// Threading model:
//   - Reads the whole input file into RAM (caps at 64 GiB for safety).
//   - Spawns min(num_threads, chunk_count) worker threads.
//   - Each worker owns its own EVP_CIPHER_CTX (NEVER shared — OpenSSL
//     contexts are not thread-safe) and pulls chunk indices off an atomic
//     counter until exhausted.
//   - Workers compress (if enabled) then CTR-encrypt each chunk into a
//     thread-local std::vector<unsigned char>; results are moved into a
//     `std::vector<std::vector<unsigned char>> ct_per_chunk(chunk_count)`
//     indexed by chunk_index. Each index is dispatched to exactly one
//     worker, so ct_per_chunk[i] is written exactly once (no mutex needed
//     for the writes — only the existing err_mutex error channel).
//   - Progress is reported in PLAINTEXT bytes per chunk (not compressed
//     bytes) so the user-visible rate matches the file they handed us.
//   - Errors inside workers are captured in a std::atomic<bool> + a
//     mutex-guarded std::string and rethrown from the main thread after
//     join() — no exception ever crosses a thread boundary.
void encrypt_file(const std::string& input_path,
                  const std::string& output_path,
                  std::string_view original_filename_for_header,
                  const EncryptOptions& opts);

struct DecryptOptions {
    std::array<unsigned char, AES_256_KEY_SIZE> file_key;
    std::array<unsigned char, HMAC_SHA256_SIZE>  hmac_key;
    uint32_t num_threads = 0;
    ProgressCallback progress;
};

// Decrypt `input_path` -> `output_path`. Reverse of encrypt_file.
//
// - Reads + parses the FileHeader via HeaderReader::read. For v1 files the
//   reader normalises compression_id=NONE and stored_size=original_size; for
//   v2 files those fields come straight off disk.
// - Geometry validation differs by version:
//     v1: offset_table_size = 0, ct_total_size = original_size.
//         offsets are SYNTHESISED as min(chunk_size, original_size - i*chunk_size)
//         so v1 and v2 can share the same parallel decrypt loop body.
//     v2: offset_table_size = chunk_count * 4, ct_total_size =
//         stored_size - offset_table_size. The offset table is read off disk
//         and its entries sum-checked against ct_total_size.
// - Reads the ciphertext region into RAM, then (v2 only) the offset table.
// - Reads the trailing 32-byte HMAC footer and verifies it against
//   HMAC(hmac_key, header_serialised || ct_region || offset_table_bytes).
//   For v1 there is no offset table, so the HMAC inputs are
//   header_serialised || ct_region — exactly what the v1 encrypt wrote.
//   Mismatch -> throw std::runtime_error (truncation / tamper detected
//   before any plaintext is written to disk).
// - Parallel-decrypts the chunks (per-thread EVP_CIPHER_CTX, atomic chunk
//   dispatch, error capture via atomic + mutex). Each chunk is CTR-decrypted
//   to its "compressed plaintext" then (if compression_id != NONE) passed
//   through decompress_chunk before being written to its slot in pt_buffer.
// - Writes the resulting plaintext to `output_path`.
void decrypt_file(const std::string& input_path,
                  const std::string& output_path,
                  const DecryptOptions& opts);

}  // namespace lock
