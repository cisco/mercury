#ifndef IPV6_LCTRIE_H
#define IPV6_LCTRIE_H

#include <stdint.h>
#include <typeinfo>
#include <unordered_map>
#include "libmerc.h"

typedef struct ipv6_addr_lct {
    uint64_t a[2];

    // Default constructor
    ipv6_addr_lct() {
        a[0] = 0;
        a[1] = 0;
    };

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
    result.a[1] = left.a[1] + right;
    result.a[0] = left.a[0];

    if (result.a[1] < left.a[1]) {
        result.a[0]++;
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
        out[1] = (in[0] << pos) >> (64 - num);
    } else if (pos < 64 && pos + num > 64) {
        unsigned int num1, num2;
        num1 = pos + num - 64;
        num2 = num - num1;
        uint64_t bits_from_a0 = (in[0] << pos) >> (64 - num2);
        uint64_t bits_from_a1 = in[1] >> (64 - num1);
        out[1] = (bits_from_a0 << num1) | bits_from_a1;
    } else {
        out[1] = (in[1] << (pos - 64)) >> (64 - num);
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
        unsigned int num1, num2;
        num1 = pos + num - 64;
        num2 = num - num1;
        uint64_t bits_from_a0 = (in[0] << pos) >> (64 - num2);
        uint64_t bits_from_a1 = in[1] >> (64 - num1);
        return (bits_from_a0 << num1) | bits_from_a1;
    } else {
        out[1] = (in[1] << (pos - 64)) >> (64 - num);
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

namespace std {
    template <>
    struct hash<ipv6_addr_lct> {
        std::size_t operator()(const ipv6_addr_lct& addr) const {
            std::size_t hash1 = std::hash<uint64_t>()(addr.a[0]);
            std::size_t hash2 = std::hash<uint64_t>()(addr.a[1]);
            return hash1 ^ (hash2 << 1);
        }
    };
};

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

inline bool is_private_address(const ipv6_addr_lct &addr) {
    uint8_t first_byte = ((const uint8_t *)&addr.a[0])[0];
    return first_byte == 0xFC || first_byte == 0xFD;
}

static inline bool ipv6_address_lct_unit_test(FILE *f = nullptr) {

    // Test case 1: Copy constructor and default constructor
    {
        ipv6_addr_lct addr1;
        ipv6_addr_lct addr2 = addr1;
        if (f) fprintf(f, "Test case 1: Copy constructor\n");
        if (addr2.a[0] != 0 || addr2.a[1] != 0) {
            if (f) fprintf(f, "Failed: Copy constructor did not copy correctly\n");
            return false;
        }
    }

    // Test case 2: Assignment operator
    {
        ipv6_addr_lct addr1;
        addr1 = 1;
        if (f) fprintf(f, "Test case 2: Assignment operator\n");
        if (addr1.a[0] != 0 || addr1.a[1] != 1) {
            if (f) fprintf(f, "Failed: Assignment operator did not assign correctly\n");
            return false;
        }
    }

    // Test case 3: Comparison operators
    {
        ipv6_addr_lct addr1, addr2;
        addr1 = 1;
        addr2 = 2;
        if (f) fprintf(f, "Test case 3: Comparison operators\n");
        if (!(addr1 < addr2) || !(addr2 > addr1) || (addr1 == addr2) || !(addr1 != addr2)) {
            if (f) fprintf(f, "Failed: Comparison operators did not work correctly\n");
            return false;
        }
    }

    // Test case 4: Addition operator
    {
        ipv6_addr_lct addr1;
        addr1 = 1;
        ipv6_addr_lct addr2 = addr1 + 1;
        if (f) fprintf(f, "Test case 4: Addition operator\n");
        if (addr2.a[0] != 0 || addr2.a[1] != 2) {
            if (f) fprintf(f, "Failed: Addition operator did not add correctly\n");
            return false;
        }
    }

    // Test case 5: Bitwise logical operators
    {
        ipv6_addr_lct addr1, addr2;
        addr1.a[0] = 0x0F0F0F0F0F0F0F0F;
        addr1.a[1] = 0x0F0F0F0F0F0F0F0F;
        addr2.a[0] = 0x3333333333333333;
        addr2.a[1] = 0x3333333333333333;
        ipv6_addr_lct addr_and = addr1 & addr2;
        ipv6_addr_lct addr_xor = addr1 ^ addr2;
        if (f) fprintf(f, "Test case 5: Bitwise logical operators\n");
        if (addr_and.a[0] != 0x0303030303030303 || addr_and.a[1] != 0x0303030303030303) {
            if (f) fprintf(f, "Failed: Bitwise AND operator did not work correctly\n");
            return false;
        }
        if (addr_xor.a[0] != 0x3C3C3C3C3C3C3C3C || addr_xor.a[1] != 0x3C3C3C3C3C3C3C3C) {
            if (f) fprintf(f, "Failed: Bitwise XOR operator did not work correctly\n");
            return false;
        }
    }

    // Test case 6: EXTRACT and EXTRACT_IDX functions
    {
        ipv6_addr_lct addr;
        addr.a[0] = 0xFFFFFFFFFFFFFFFF;
        addr.a[1] = 0xFFFFFFFFFFFFFFFF;

        // extract 8 bits starting at 48
        ipv6_addr_lct extracted1 = EXTRACT(48, 8, addr);
        if (f) fprintf(f, "Test case 6a: EXTRACT function\n");
        if (extracted1.a[0] != 0x0000000000000000 || extracted1.a[1] != 0x00000000000000FF) {
            if (f) fprintf(f, "Failed: EXTRACT function did not extract correctly\n");
            return false;
        }

        ipv6_addr_lct extracted = EXTRACT(60, 8, addr);
        uint64_t extracted_idx = EXTRACT_IDX(60, 8, addr);
        if (f) fprintf(f, "Test case 6: EXTRACT and EXTRACT_IDX functions\n");
        if (extracted.a[0] != 0x0000000000000000 || extracted.a[1] != 0x00000000000000FF) {
            printf_err(log_err, "extracted: %016lx %016lx\n", extracted.a[0], extracted.a[1]);
            if (f) fprintf(f, "Failed: EXTRACT function did not extract correctly\n");
            return false;
        }
        if (extracted_idx != 0xFF) {
            if (f) fprintf(f, "Failed: EXTRACT_IDX function did not extract index correctly\n");
            return false;
        }
    }

    // Test case 7: REMOVE function
    {
        ipv6_addr_lct addr;
        addr.a[0] = 0xFFFFFFFFFFFFFFFF;
        addr.a[1] = 0xFFFFFFFFFFFFFFFF;
        ipv6_addr_lct removed = REMOVE(64, addr);
        if (f) fprintf(f, "Test case 7: REMOVE function\n");
        if (removed.a[0] != 0x0000000000000000 || removed.a[1] != 0xFFFFFFFFFFFFFFFF) {
            if (f) fprintf(f, "Failed: REMOVE function did not remove correctly\n");
            return false;
        }
    }

    // Test case 8: Left shift operator
    {
        ipv6_addr_lct addr;
        addr.a[0] = 0x0000000000000000;
        addr.a[1] = 0x0000000000000001;

        // shift from lower word to upper word
        ipv6_addr_lct shifted = addr << 65;
        if (f) fprintf(f, "Test case 8: Left shift operator\n");
        if (shifted.a[0] != 0x0000000000000002 || shifted.a[1] != 0x0000000000000000) {
            if (f) fprintf(f, "Failed: Left shift operator did not shift correctly\n");
            return false;
        }

        // shift beyond 128 bits
        ipv6_addr_lct shifted2 = addr << 130;
        if (shifted2.a[0] != 0x0000000000000000 || shifted2.a[1] != 0x0000000000000000) {
            if (f) fprintf(f, "Failed: Left shift operator did not handle large shift correctly\n");
            return false;
        }

        // shift within lower 64 bits
        ipv6_addr_lct addr2;
        addr2.a[0] = 0x0000000000000001;
        addr2.a[1] = 0x0000000000000001;
        ipv6_addr_lct shifted3 = addr2 << 4;
        if (f) fprintf(f, "Test case 8: Left shift operator within 64 bits\n");
        if (shifted3.a[0] != 0x0000000000000010 || shifted3.a[1] != 0x0000000000000010) {
            if (f) fprintf(f, "Failed: Left shift operator did not shift within 64 bits correctly\n");
            return false;
        }
    }

    return true;
}

#endif  // IPV6_LCTRIE_H