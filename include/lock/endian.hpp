#pragma once

#include <cstdint>

namespace lock::endian {

// Read/write big-endian integers from/to byte buffers.
// All fields in the .locked file are big-endian (network byte order).
//
// We deliberately widen to the *next* unsigned type before shifting so that
// integer promotion never yields a `signed int` (which would trigger
// -Wimplicit-int-conversion on the narrowing back to the result type).
// `static_cast<unsigned char>(...)` is used for stores because it documents
// intent and is free of C-style cast ambiguity under -Wpedantic.

inline uint16_t load_be16(const unsigned char* p) {
    return static_cast<uint16_t>(
        (static_cast<uint32_t>(p[0]) << 8) |
        static_cast<uint32_t>(p[1]));
}
inline uint32_t load_be32(const unsigned char* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           static_cast<uint32_t>(p[3]);
}
inline uint64_t load_be64(const unsigned char* p) {
    return (static_cast<uint64_t>(p[0]) << 56) |
           (static_cast<uint64_t>(p[1]) << 48) |
           (static_cast<uint64_t>(p[2]) << 40) |
           (static_cast<uint64_t>(p[3]) << 32) |
           (static_cast<uint64_t>(p[4]) << 24) |
           (static_cast<uint64_t>(p[5]) << 16) |
           (static_cast<uint64_t>(p[6]) << 8)  |
           static_cast<uint64_t>(p[7]);
}

inline void store_be16(unsigned char* p, uint16_t v) {
    p[0] = static_cast<unsigned char>(v >> 8);
    p[1] = static_cast<unsigned char>(v);
}
inline void store_be32(unsigned char* p, uint32_t v) {
    p[0] = static_cast<unsigned char>(v >> 24);
    p[1] = static_cast<unsigned char>(v >> 16);
    p[2] = static_cast<unsigned char>(v >> 8);
    p[3] = static_cast<unsigned char>(v);
}
inline void store_be64(unsigned char* p, uint64_t v) {
    p[0] = static_cast<unsigned char>(v >> 56);
    p[1] = static_cast<unsigned char>(v >> 48);
    p[2] = static_cast<unsigned char>(v >> 40);
    p[3] = static_cast<unsigned char>(v >> 32);
    p[4] = static_cast<unsigned char>(v >> 24);
    p[5] = static_cast<unsigned char>(v >> 16);
    p[6] = static_cast<unsigned char>(v >> 8);
    p[7] = static_cast<unsigned char>(v);
}

}  // namespace lock::endian
