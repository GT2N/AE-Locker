#include <ae-locker/container.hpp>
#include <ae-locker/endian.hpp>
#include <ae-locker/constants.hpp>
#include <stdexcept>
#include <fstream>
#include <vector>
#include <cstring>

namespace ae_locker {

// ---------------------------------------------------------------------------
// HeaderWriter
// ---------------------------------------------------------------------------

std::vector<unsigned char> HeaderWriter::serialise(const FileHeader& header) {
    std::vector<unsigned char> buf(header.serialised_size());
    size_t pos = 0;

    // --- Fixed portion (112 bytes) ---
    std::memcpy(buf.data() + 0, header.magic.data(), 16);
    pos = 16;
    endian::store_be32(buf.data() + 16, header.version);
    pos = 20;
    endian::store_be32(buf.data() + 20, header.algorithm_id);
    pos = 24;
    endian::store_be32(buf.data() + 24, header.kdf_id);
    pos = 28;
    endian::store_be32(buf.data() + 28, header.kdf_N);
    pos = 32;
    endian::store_be32(buf.data() + 32, header.kdf_r);
    pos = 36;
    endian::store_be32(buf.data() + 36, header.kdf_p);
    pos = 40;
    std::memcpy(buf.data() + 40, header.salt.data(), SALT_SIZE);  // 32
    pos = 72;
    std::memcpy(buf.data() + 72, header.base_iv.data(), IV_SIZE);  // 16
    endian::store_be32(buf.data() + 88,  header.flags);
    endian::store_be32(buf.data() + 92,  header.filename_len);
    endian::store_be64(buf.data() + 96,  header.original_size);
    endian::store_be32(buf.data() + 104, header.chunk_size);
    endian::store_be32(buf.data() + 108, header.chunk_count);
    // v2 fields serialised at offset 112 (compression_id) and 116 (stored_size).
    endian::store_be32(buf.data() + 112, header.compression_id);
    endian::store_be64(buf.data() + 116, header.stored_size);
    pos = 124;  // == HEADER_FIXED_SIZE (v2: last fixed field is stored_size be64 at 116..123)

    // --- Variable portion ---
    if (header.filename_len > 0) {
        if (header.encrypted_filename.size() < header.filename_len) {
            throw std::runtime_error("internal: encrypted_filename shorter than filename_len");
        }
        std::memcpy(buf.data() + pos, header.encrypted_filename.data(), header.filename_len);
        pos += header.filename_len;
    }
    endian::store_be32(buf.data() + pos, (uint32_t)FILENAME_TAG_SIZE);
    pos += 4;
    std::memcpy(buf.data() + pos, header.filename_tag.data(), FILENAME_TAG_SIZE);
    pos += FILENAME_TAG_SIZE;

    if (pos != buf.size()) {
        throw std::runtime_error("internal: serialisation size mismatch");
    }
    return buf;
}

void HeaderWriter::write(std::ofstream& out, const FileHeader& header) {
    std::vector<unsigned char> buf = serialise(header);
    out.write(reinterpret_cast<const char*>(buf.data()), (std::streamsize)buf.size());
    if (!out) {
        throw std::runtime_error("failed to write header");
    }
    // Stream is now positioned at header.data_offset() — chunks start here.
}

// ---------------------------------------------------------------------------
// HeaderReader
// ---------------------------------------------------------------------------

FileHeader HeaderReader::read(std::ifstream& in) {
    if (!in) {
        throw std::runtime_error("input stream is not open");
    }

    // Two-phase read so we can support both v1 (112-byte fixed header, no
    // compression_id / stored_size) and v2 (120-byte fixed header with both
    // new fields). Offsets 0..111 are identical across versions; v2 adds 8
    // more bytes at offsets 112..119. The on-disk layout for the shared
    // region is described in include/lock/container.hpp.
    unsigned char fixed124[124];

    // Phase A: read the first 20 bytes (magic + version).
    in.read(reinterpret_cast<char*>(fixed124), 20);
    if (in.gcount() != 20) {
        throw std::runtime_error("file too short: cannot read fixed header");
    }

    // Magic (offset 0, 16 bytes)
    if (std::memcmp(fixed124 + 0, MAGIC.data(), 16) != 0) {
        throw std::runtime_error("invalid magic; not a .locked file");
    }

    // Version (offset 16) — discriminator between v1 and v2.
    const uint32_t version = endian::load_be32(fixed124 + 16);

    FileHeader header;
    header.version = version;

    std::memcpy(header.magic.data(), fixed124 + 0, 16);

    // Phase B: read the remaining fixed bytes depending on the version.
    // Offsets 20..111 (92 bytes) are shared; v2 carries 4 more bytes (compression_id@112) + 8 more bytes (stored_size@116..123), totalling 104.
    if (version == 1) {
        in.read(reinterpret_cast<char*>(fixed124) + 20, 92);
        if (in.gcount() != 92) {
            throw std::runtime_error("file too short: cannot read v1 fixed header");
        }
        // v1 lacks compression_id / stored_size — normalise to the v2 shape so
        // downstream decryption code has a single code path. stored_size is
        // filled in below once original_size (offset 96) is known.
        header.compression_id = static_cast<uint32_t>(CompressionId::NONE);
        header.stored_size     = 0;  // overwritten after original_size is read
    } else if (version == 2) {
        in.read(reinterpret_cast<char*>(fixed124) + 20, 104);
        if (in.gcount() != 104) {
            throw std::runtime_error("file too short: cannot read v2 fixed header");
        }
        // v2 carries the new fields at offsets 112 and 116.
        header.compression_id = endian::load_be32(fixed124 + 112);
        header.stored_size    = endian::load_be64(fixed124 + 116);
    } else {
        throw std::runtime_error("unsupported version " + std::to_string(version) +
                                 " (this build only supports v1 and v2)");
    }

    const unsigned char* fixed = fixed124;

    // algorithm_id (offset 20)
    header.algorithm_id = endian::load_be32(fixed + 20);
    if (header.algorithm_id != (uint32_t)AlgorithmId::AES_256_CTR_HMAC_SHA256) {
        throw std::runtime_error("unsupported algorithm id " + std::to_string(header.algorithm_id));
    }

    // kdf_id (offset 24)
    header.kdf_id = endian::load_be32(fixed + 24);
    if (header.kdf_id != (uint32_t)KdfId::SCRYPT) {
        throw std::runtime_error("unsupported kdf id " + std::to_string(header.kdf_id));
    }

    // kdf params (offsets 28, 32, 36)
    header.kdf_N = endian::load_be32(fixed + 28);
    header.kdf_r = endian::load_be32(fixed + 32);
    header.kdf_p = endian::load_be32(fixed + 36);

    // salt (offset 40, 32 bytes)
    std::memcpy(header.salt.data(), fixed + 40, SALT_SIZE);

    // base_iv (offset 72, 16 bytes)
    std::memcpy(header.base_iv.data(), fixed + 72, IV_SIZE);

    // flags, filename_len, original_size, chunk_size, chunk_count
    // (offsets 88, 92, 96, 104, 108). compression_id and stored_size are
    // handled in the version branch above; for v1 files we still fill
    // stored_size with original_size so decryption has a single code path.
    header.flags         = endian::load_be32(fixed + 88);
    header.filename_len  = endian::load_be32(fixed + 92);
    header.original_size = endian::load_be64(fixed + 96);
    header.chunk_size    = endian::load_be32(fixed + 104);
    header.chunk_count   = endian::load_be32(fixed + 108);

    if (header.version == 1) {
        // v1 normalisation: stored_size == original_size (no compression, no
        // offset table — ciphertext region equals the original plaintext size).
        header.stored_size = header.original_size;
    } else {
        // v2: validate that compression_id is one of NONE / LZ4 / ZSTD.
        const uint32_t cid = header.compression_id;
        if (cid != static_cast<uint32_t>(CompressionId::NONE) &&
            cid != static_cast<uint32_t>(CompressionId::LZ4)  &&
            cid != static_cast<uint32_t>(CompressionId::ZSTD)) {
            throw std::runtime_error("unsupported compression_id " + std::to_string(cid));
        }
    }

    // --- Variable portion ---
    // Read encrypted_filename (filename_len bytes)
    if (header.filename_len > 0) {
        header.encrypted_filename.resize(header.filename_len);
        in.read(reinterpret_cast<char*>(header.encrypted_filename.data()),
                 (std::streamsize)header.filename_len);
        if (in.gcount() != (std::streamsize)header.filename_len) {
            throw std::runtime_error("file too short: cannot read encrypted filename");
        }
    }

    // Read filename_tag_len (4 bytes) — must equal FILENAME_TAG_SIZE (16)
    unsigned char tag_len_buf[4];
    in.read(reinterpret_cast<char*>(tag_len_buf), 4);
    if (in.gcount() != 4) {
        throw std::runtime_error("file too short: cannot read filename_tag_len");
    }
    uint32_t tag_len = endian::load_be32(tag_len_buf);
    if (tag_len != (uint32_t)FILENAME_TAG_SIZE) {
        throw std::runtime_error("unexpected tag length " + std::to_string(tag_len));
    }

    // Read filename_tag (16 bytes)
    unsigned char tag_buf[FILENAME_TAG_SIZE];
    in.read(reinterpret_cast<char*>(tag_buf), (std::streamsize)FILENAME_TAG_SIZE);
    if (in.gcount() != (std::streamsize)FILENAME_TAG_SIZE) {
        throw std::runtime_error("file too short: cannot read filename_tag");
    }
    std::memcpy(header.filename_tag.data(), tag_buf, FILENAME_TAG_SIZE);

    // Stream is now positioned at header.data_offset() — chunks start here.
    return header;
}

bool HeaderReader::is_locked_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    unsigned char first16[16];
    in.read(reinterpret_cast<char*>(first16), 16);
    if (in.gcount() != 16) {
        return false;  // file smaller than magic
    }
    return std::memcmp(first16, MAGIC.data(), 16) == 0;
}

}  // namespace ae_locker
