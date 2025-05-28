#ifndef IPV6_LCTRIE_H
#define IPV6_LCTRIE_H

#include <stdint.h>
#include <typeinfo>

typedef struct ipv6_addr_t {
    uint64_t a[2];

    // Default constructor
    ipv6_addr_t() = default;

    // Copy constructor
    constexpr ipv6_addr_t(const ipv6_addr_t& other) noexcept 
        : a{other.a[0], other.a[1]} {}

    // Assignment operator
    constexpr ipv6_addr_t& operator=(const ipv6_addr_t& other) noexcept {
        if (this != &other) {
            a[0] = other.a[0];
            a[1] = other.a[1];
        }
        return *this;
    }
    
    constexpr ipv6_addr_t& operator=(const uint64_t& other) noexcept {
        a[0] = 0;
        a[1] = other;
        return *this;
    }
} ipv6_addr_t;

// comparison operators for ipv6_addr_t
//
inline bool operator<(const ipv6_addr_t &left, const ipv6_addr_t &right) {
    if (left.a[0] == right.a[0]) {
        return left.a[1] < right.a[1];
    }
    return left.a[0] < right.a[0];
}

inline bool operator>(const ipv6_addr_t &left, const ipv6_addr_t &right) {
    return right < left;
}

inline bool operator==(const ipv6_addr_t &left, const ipv6_addr_t &right) {
    return left.a[0] == right.a[0] && left.a[1] == right.a[1];
}

inline bool operator!=(const ipv6_addr_t &left, const ipv6_addr_t &right) {
    return !(left == right);
}

// increment operator for ipv6_addr_t
//
inline ipv6_addr_t operator++(const ipv6_addr_t &addr) {
    ipv6_addr_t result;
    if (addr.a[1] == 0xFFFFFFFFFFFFFFFF) {
        result.a[0] = addr.a[0] + 1;
    } else {
        result.a[0] = addr.a[0];
        result.a[1] = addr.a[1] + 1;
    }
    return result;
}

// bitwise logical operators for ipv6_addr_t
//
inline ipv6_addr_t operator^(const ipv6_addr_t &left, const ipv6_addr_t &right) {
    ipv6_addr_t result;
    result.a[0] = left.a[0] ^ right.a[0];
    result.a[1] = left.a[1] ^ right.a[1];
    return result;
}

inline ipv6_addr_t operator&(const ipv6_addr_t &left, const ipv6_addr_t &right) {
    ipv6_addr_t result;
    result.a[0] = left.a[0] & right.a[0];
    result.a[1] = left.a[1] & right.a[1];
    return result;
}

inline ipv6_addr_t operator~(const ipv6_addr_t &addr) {
    ipv6_addr_t result;
    result.a[0] = ~addr.a[0];
    result.a[1] = ~addr.a[1];
    return result;
}

inline ipv6_addr_t operator<<(const ipv6_addr_t &addr, unsigned int shift) {
    ipv6_addr_t result;
    if (shift < 64) {
        result.a[1] = addr.a[1] << shift;
        result.a[0] = (addr.a[0] << shift) | (addr.a[0] >> (64 - shift));
    } else {
        result.a[0] = addr.a[1] << (shift - 64);
        result.a[1] = 0;
    }
    return result;
}

// Extract num bits from the bit string str starting at pos bit
//
inline ipv6_addr_t EXTRACT(unsigned int pos, unsigned int num, ipv6_addr_t str) {
    ipv6_addr_t output;
    memset(output.a, 0, sizeof(ipv6_addr_t));
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
inline uint64_t EXTRACT_IDX(unsigned int pos, unsigned int num, ipv6_addr_t str) {

    if (num > 64) {
        return 0;
    }

    ipv6_addr_t output;
    memset(output.a, 0, sizeof(ipv6_addr_t));
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
inline ipv6_addr_t REMOVE(unsigned int p, ipv6_addr_t str) {
    ipv6_addr_t output;
    memset(output.a, 0, sizeof(ipv6_addr_t));
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

// ipv6_addr_t ntoh() is suitable for IPv6 addresses
//
inline ipv6_addr_t ntoh(ipv6_addr_t addr) {
    ipv6_addr_t output;
    output.a[0] = output.a[1] = 0;
    uint16_t *in = (uint16_t *)&addr.a;
    uint16_t *out = (uint16_t *)&output.a;

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

#endif  // IPV6_LCTRIE_H