#ifndef IPV6_LCTRIE_H
#define IPV6_LCTRIE_H

#include <stdint.h>
#include <typeinfo>

typedef struct ipv6_addr_lct {
    uint64_t a[2];

    // Default constructor
    ipv6_addr_lct() = default;

    // Constructor for initializing ipv6 address with 64 least significant bits
    explicit ipv6_addr_lct(uint64_t low) {
        a[0] = 0;
        a[1] = low;
    }

    // Copy constructor
    ipv6_addr_lct(const ipv6_addr_lct& other) 
        : a{other.a[0], other.a[1]} {}

    // Assignment operator
    ipv6_addr_lct& operator=(const ipv6_addr_lct& other) {
        a[0] = other.a[0];
        a[1] = other.a[1];
        return *this;
    }

    ipv6_addr_lct& operator=(const uint64_t& other) {
        a[0] = 0;
        a[1] = other;
        return *this;
    }
} ipv6_addr_lct;

inline void fprint_addr(FILE *f, const char* key, const ipv6_addr_lct *addr) {
    const uint8_t *n1 = (const uint8_t *)&addr->a[0];
    const uint8_t *n2 = (const uint8_t *)&addr->a[1];

    fprintf(f, "%s: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", key,
        n1[0], n1[1], n1[2], n1[3], n1[4], n1[5], n1[6], n1[7],
        n2[0], n2[1], n2[2], n2[3], n2[4], n2[5], n2[6], n2[7]);
}

inline void fprint_addr_rev(FILE *f, const char* key, const ipv6_addr_lct *addr) {
    const uint8_t *n1 = (const uint8_t *)&addr->a[0];
    const uint8_t *n2 = (const uint8_t *)&addr->a[1];

    fprintf(f, "%s: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", key,
        n1[7], n1[6], n1[5], n1[4], n1[3], n1[2], n1[1], n1[0],
        n2[7], n2[6], n2[5], n2[4], n2[3], n2[2], n2[1], n2[0]);
}

// comparison operators for ipv6_addr_lct
//
inline bool operator<(const ipv6_addr_lct &left, const ipv6_addr_lct &right) {
    if (left.a[0] == right.a[0]) {
        return left.a[1] < right.a[1];
    }
    return left.a[0] < right.a[0];
}

inline bool operator>(const ipv6_addr_lct &left, const ipv6_addr_lct &right) {
    return right < left;
}

inline bool operator==(const ipv6_addr_lct &left, const ipv6_addr_lct &right) {
    return left.a[0] == right.a[0] && left.a[1] == right.a[1];
}

inline bool operator!=(const ipv6_addr_lct &left, const ipv6_addr_lct &right) {
    return !(left == right);
}

// addition operator for ipv6_addr_lct
//
inline ipv6_addr_lct operator+(const ipv6_addr_lct &left, const uint64_t &right) {
    ipv6_addr_lct result;
    result.a[0] = left.a[0];
    if (left.a[1] == 0xFFFFFFFFFFFFFFFF) {
        result.a[1] = right;
        result.a[0]++;
    } else {
        result.a[1] = left.a[1] + right;
    }
    return result;
}

// bitwise logical operators for ipv6_addr_lct
//
inline ipv6_addr_lct operator^(const ipv6_addr_lct &left, const ipv6_addr_lct &right) {
    ipv6_addr_lct result;
    result.a[0] = left.a[0] ^ right.a[0];
    result.a[1] = left.a[1] ^ right.a[1];
    return result;
}

inline ipv6_addr_lct operator&(const ipv6_addr_lct &left, const ipv6_addr_lct &right) {
    ipv6_addr_lct result;
    result.a[0] = left.a[0] & right.a[0];
    result.a[1] = left.a[1] & right.a[1];
    return result;
}

inline ipv6_addr_lct operator~(const ipv6_addr_lct &addr) {
    ipv6_addr_lct result;
    result.a[0] = ~addr.a[0];
    result.a[1] = ~addr.a[1];
    return result;
}

inline ipv6_addr_lct operator<<(const ipv6_addr_lct &addr, unsigned int shift) {

    ipv6_addr_lct result;

    if (shift == 0) {
        return addr;
    }

    if (shift >= 128) {
        result.a[0] = 0;
        result.a[1] = 0;
        return result;
    }

    if (shift < 64) {
        result.a[0] = (addr.a[0] << shift) | (addr.a[1] >> (64 - shift));
        result.a[1] = addr.a[1] << shift;
    } else {
        result.a[0] = addr.a[1] << (shift - 64);
        result.a[1] = 0;
    }

    return result;
}

// Extract num bits from the bit string str starting at pos bit
//
inline ipv6_addr_lct EXTRACT(unsigned int pos, unsigned int num, ipv6_addr_lct str) {
    ipv6_addr_lct output;
    memset(output.a, 0, sizeof(ipv6_addr_lct));
    uint64_t *in = (uint64_t *)&str.a;
    uint64_t *out = (uint64_t *)&output.a;

    if (pos < 64 && pos + num <= 64) {
        out[0] = (in[0] << pos) >> (64 - num);
    } else if (pos < 64 && pos + num > 64) {
        unsigned int num1, num2;
        num1 = pos + num - 64;
        num2 = num - num1;
        out[0] = (in[0] << pos) >> (64 - num1);
        out[1] = (in[1] << 0) >> (64 - num2);
    } else {
        out[1] = (in[1] << pos) >> (64 - num);
    }

    return output;
}

// Extract num bits from the bit string str starting at pos bit
// This function is used for lctrie indexing during trie construction
//
inline uint64_t EXTRACT_IDX(unsigned int pos, unsigned int num, ipv6_addr_lct str) {

    if (num > 64) {
        return 0;
    }

    ipv6_addr_lct output;
    memset(output.a, 0, sizeof(ipv6_addr_lct));
    uint64_t *in = (uint64_t *)&str.a;
    uint64_t *out = (uint64_t *)&output;

    if (pos < 64 && pos + num <= 64) {
        out[0] = (in[0] << pos) >> (64 - num);
        return out[0];
    } else if (pos < 64 && pos + num > 64) {
        out[0] = (in[0] << pos) >> (64 - num);
        unsigned int num1, num2;
        num1 = pos + num - 64;
        num2 = num - num1;
        out[1] = (in[1] << 0) >> (64 - num2);
        return out[0] | out[1];
    } else {
        out[1] = (in[1] << pos) >> (64 - num);
        return out[1];
    }

    return 0;
}

// remove the first p bits from string str
//
inline ipv6_addr_lct REMOVE(unsigned int p, ipv6_addr_lct str) {
    ipv6_addr_lct output;
    memset(output.a, 0, sizeof(ipv6_addr_lct));
    uint64_t *in = (uint64_t *)&str.a;
    uint64_t *out = (uint64_t *)&output.a;

    if (p < 64) {
        out[0] = (in[0] << p) >> p;
        out[1] = in[1];
    } else {
        p = p - 64;
        out[0] = 0;
        out[1] = (in[1] << (p)) >> (p);
    }

    return output;
}

// ipv6_addr_lct ntoh() is suitable for IPv6 addresses
//
inline void ntoh(ipv6_addr_lct &addr) {
    ipv6_addr_lct output;
    output.a[0] = output.a[1] = 0;

    uint8_t *in1 = (uint8_t *)&addr.a[0];
    uint8_t *in2 = (uint8_t *)&addr.a[1];
    uint8_t *out1 = (uint8_t *)&output.a[0];
    uint8_t *out2 = (uint8_t *)&output.a[1];

    out1[0] = in1[7];
    out1[1] = in1[6];
    out1[2] = in1[5];
    out1[3] = in1[4];
    out1[4] = in1[3];
    out1[5] = in1[2];
    out1[6] = in1[1];
    out1[7] = in1[0];
    out2[0] = in2[7];
    out2[1] = in2[6];
    out2[2] = in2[5];
    out2[3] = in2[4];
    out2[4] = in2[3];
    out2[5] = in2[2];
    out2[6] = in2[1];
    out2[7] = in2[0];
    addr = output;
}

#endif  // IPV6_LCTRIE_H