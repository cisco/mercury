/*
 * match.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef MATCH_H
#define MATCH_H

#include <stdint.h>
#include <stdlib.h>

unsigned int uint16_match(uint16_t x,
                          const uint16_t *ulist,
                          unsigned int num);

unsigned int u32_compare_masked_data_to_value(const void *data,
                                              const void *mask,
                                              const void *value);

unsigned int u64_compare_masked_data_to_value(const void *data,
                                              const void *mask,
                                              const void *value);

template <size_t N>
class mask_and_value {
    uint8_t mask[N];
    uint8_t value[N];
public:
    constexpr mask_and_value(std::array<uint8_t, N> m, std::array<uint8_t, N> v) : mask{}, value{} {
        for (size_t i=0; i<N; i++) {
            mask[i] = m[i];
            value[i] = v[i];
        }
    }

    bool matches(const uint8_t tcp_data[N]) const {
        if (N == 8 || N == 4) {
            return u32_compare_masked_data_to_value(tcp_data, mask, value);
        } else {
            return u64_compare_masked_data_to_value(tcp_data, mask, value);
        }
    }

    bool matches(const uint8_t *data, size_t length) const {
        if (data == nullptr || length < N) {
            return false;
        }
        return matches(data);
    }

    constexpr size_t length() const { return N; }

    static unsigned int u32_compare_masked_data_to_value(const void *data_in,
                                                         const void *mask_in,
                                                         const void *value_in) {
        const uint32_t *d = (const uint32_t *)data_in;
        const uint32_t *m = (const uint32_t *)mask_in;
        const uint32_t *v = (const uint32_t *)value_in;
        
        if (N == 4) {
            return ((d[0] & m[0]) == v[0]);
        }

        return ((d[0] & m[0]) == v[0]) && ((d[1] & m[1]) == v[1]);
    }

    static unsigned int u64_compare_masked_data_to_value(const void *data,
                                                         const void *mask,
                                                         const void *value) {
        const uint64_t *d = (const uint64_t *)data;
        const uint64_t *m = (const uint64_t *)mask;
        const uint64_t *v = (const uint64_t *)value;

        return ((d[0] & m[0]) == v[0]) && ((d[1] & m[1]) == v[1]);
    }

    // nonmatching(data) returns an array of uint8_t that indicates
    // the bit positions in the bytes {data, data+len} that do not
    // match the mask and value
    //
    std::array<uint8_t, N> nonmatching(const uint8_t *data, size_t len) const {
        std::array<uint8_t, N> output{};
        if (len < N) {
            return output;
        }
        for (size_t i=0; i<N; i++) {
            output[i] = (data[i] & mask[i]) ^ value[i];
        }
        return output;
    }

};

template <size_t N>
class mask_value_and_offset : public mask_and_value<N> {
    size_t offset;

public:
   constexpr mask_value_and_offset (std::array<uint8_t, N> m, std::array<uint8_t, N> v, size_t off) : mask_and_value<N>(m,v), offset{off} {}

    bool matches_at_offset(const uint8_t *data, size_t length) const {
        if (data == nullptr || (length + offset) < N) {
            return false;
        }
        return mask_and_value<N>::matches(data+offset);
    }

};

#endif /* MATCH_H */
