
#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <typeinfo>
#include "../datum.h"


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


#endif // COMMON_H
