
#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <typeinfo>

#ifndef HAVE_HTON_DEF
#define HAVE_HTON_DEF

#ifdef _WIN32

static constexpr bool host_little_endian = true;

/// returns an integer equal to x with its byte order reversed (from
/// little endian to big endian or vice-versa)
///
inline static uint16_t swap_byte_order(uint16_t x) { return _byteswap_ushort(x); }

/// returns an integer equal to x with its byte order reversed (from
/// little endian to big endian or vice-versa)
///
inline static uint32_t swap_byte_order(uint32_t x) { return _byteswap_ulong(x); }

/// returns an integer equal to x with its byte order reversed (from
/// little endian to big endian or vice-versa)
///
inline static uint64_t swap_byte_order(uint64_t x) { return _byteswap_uint64(x); }

#else

static constexpr bool host_little_endian = (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__);

/// returns an integer equal to x with its byte order reversed (from
/// little endian to big endian or vice-versa)
///
inline static uint16_t swap_byte_order(uint16_t x) { return __builtin_bswap16(x); }

/// returns an integer equal to x with its byte order reversed (from
/// little endian to big endian or vice-versa)
///
inline static uint32_t swap_byte_order(uint32_t x) { return __builtin_bswap32(x); }

/// returns an integer equal to x with its byte order reversed (from
/// little endian to big endian or vice-versa)
///
inline static uint64_t swap_byte_order(uint64_t x) { return __builtin_bswap64(x); }

#endif

/// when `x` is in network byte order, `ntoh(x)` returns the value of
/// `x` in host byte order
///
/// Given an unsigned integer variable `x` in network byte order, the
/// template function `ntoh(x)` returns an unsigned integer in host
/// byte order with the same type and value.
///
template <typename T>
inline static T ntoh(T x) { if (host_little_endian) { return swap_byte_order(x); } return x; }

/// when `x` is in host byte order, `hton(x)` returns the value of `x`
/// in network byte order
///
/// Given an unsigned variable `x` in host byte order, the template
/// function `hton(x)` returns an unsigned integer in network byte
/// order with the same type and value.
///
/// To apply `hton()` an unsigned literal, use the appropriate
/// template specialization.  For instance, `hton<uint16_t>(443)`
/// obtains a `uint16_t` in network byte order for the literal 443.  The
/// specialization must be used because otherwise a compiler error
/// will result from amiguity over the integer type.
///
template <typename T>
inline static T hton(T x) { if (host_little_endian) { return swap_byte_order(x); } return x; }

#endif


//uint32_t EXTRACT(unsigned int pos, unsigned int num, uint32_t str);

// Extract num bits from the bit string str starting at pos bit
//
// requires str to be in host endian byte order
// for the bit manipulation to work properly
//
template <typename T>
T EXTRACT(unsigned int pos, unsigned int num, T str) {
    constexpr unsigned int bits_in_T = sizeof(T) * 8;

    return (str << pos) >> (bits_in_T - num);
}

// remove the first p bits from string str
//
template <typename T>
T REMOVE(unsigned int p, T str) {
    return (str << p) >> p;
}

// pton(src, dst) parses a dotted quad IPv4 address
// out of the null-terminated character string s, sets addr to the
// host-byte-order representation of that address, and returns true on
// success.  If s does not contain a dotted quad, then the function
// returns false and addr should be ignored.
//
[[maybe_unused]] static int pton(const char *s,
                void *dst) {
    uint32_t *addr = (uint32_t *)dst;
    uint8_t d[4];
    int num_items_parsed = sscanf(s,
                                  "%hhu.%hhu.%hhu.%hhu",
                                  d, d+1, d+2, d+3);
    if (num_items_parsed == 4) {
        *addr = (uint32_t)d[3] | (uint32_t)d[2] << 8 | (uint32_t)d[1] << 16 | (uint32_t)d[0] << 24;
        *addr = ntoh(*addr);
        return 1;
    }
    return 0;
}

#define LCTRIE_AF_INET            2
#define LCTRIE_AF_INET6          10
#define LCTRIE_INET6_ADDRSTRLEN  46

// ntop(af, src, dst, size) writes a readable string representation of the
// address addr into the buffer at dst, if that buffer is large
// enough; size indicates the number of available bytes in that buffer
//
//    af should be LCTRIE_AF_INET or LCTRIE_AF_INET6
//
// return: null on failure; dst on success
//
[[maybe_unused]] static const char *ntop(int af,
                        const void *addr,
                        char *dst,
                        size_t size) {

    if (af != LCTRIE_AF_INET) {
        return nullptr; // we only support IPv4 for now
    }
    if (size < 16) {
        return nullptr; // error; we need at least INET_ADDRSTRLEN=16 bytes
    }
    uint8_t *a = (uint8_t *)addr;
    if (snprintf(dst, size, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]) > 0) {
        return dst;
    }
    return nullptr;
}

#ifndef _WIN32
// disable __uint128 based operations

// __uint128_t ntoh() is suitable for IPv6 addresses
//
inline __uint128_t ntoh(__uint128_t addr) {
    __uint128_t output = 0;
    uint16_t *in = (uint16_t *)&addr;
    uint16_t *out = (uint16_t *)&output;
    out[7] = ntoh(in[0]);
    out[6] = ntoh(in[1]);
    out[5] = ntoh(in[2]);
    out[4] = ntoh(in[3]);
    out[3] = ntoh(in[4]);
    out[2] = ntoh(in[5]);
    out[1] = ntoh(in[6]);
    out[0] = ntoh(in[7]);
    return output;
}
#endif

#endif // COMMON_H
