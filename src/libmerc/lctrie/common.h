
#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <typeinfo>
#include <arpa/inet.h>

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

inline uint32_t hton(uint32_t addr) {
    return htonl(addr);
}

inline __uint128_t hton(__uint128_t addr) {
    __uint128_t output = 0;
    uint16_t *in = (uint16_t *)&addr;
    uint16_t *out = (uint16_t *)&output;
    out[7] = htons(in[0]);
    out[6] = htons(in[1]);
    out[5] = htons(in[2]);
    out[4] = htons(in[3]);
    out[3] = htons(in[4]);
    out[2] = htons(in[5]);
    out[1] = htons(in[6]);
    out[0] = htons(in[7]);
    return output;
}

inline uint32_t ntoh(uint32_t addr) {
    return ntohl(addr);
}

inline __uint128_t ntoh(__uint128_t addr) {
    __uint128_t output = 0;
    uint16_t *in = (uint16_t *)&addr;
    uint16_t *out = (uint16_t *)&output;
    out[7] = ntohs(in[0]);
    out[6] = ntohs(in[1]);
    out[5] = ntohs(in[2]);
    out[4] = ntohs(in[3]);
    out[3] = ntohs(in[4]);
    out[2] = ntohs(in[5]);
    out[1] = ntohs(in[6]);
    out[0] = ntohs(in[7]);
    return output;
}

#endif // COMMON_H
