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
#include <array>
#include <cstdint>

inline unsigned int uint16_match(uint16_t x,
                                 const uint16_t *ulist,
                                 unsigned int num)
{
    const uint16_t *ulist_end = ulist + num;

    while (ulist < ulist_end) {
        if (x == *ulist++) {
            return 1;
        }
    }
    return 0;
}

inline unsigned int u32_compare_masked_data_to_value(const void *data,
                                                     const void *mask,
                                                     const void *value)
{
    const uint32_t *d = (const uint32_t *)data;
    const uint32_t *m = (const uint32_t *)mask;
    const uint32_t *v = (const uint32_t *)value;

    return ((d[0] & m[0]) == v[0]) && ((d[1] & m[1]) == v[1]);
}

inline unsigned int u64_compare_masked_data_to_value(const void *data,
                                                     const void *mask,
                                                     const void *value)
{
    const uint64_t *d = (const uint64_t *)data;
    const uint64_t *m = (const uint64_t *)mask;
    const uint64_t *v = (const uint64_t *)value;

    return ((d[0] & m[0]) == v[0]) && ((d[1] & m[1]) == v[1]);
}


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
        if (data == nullptr || length < (offset + N)) {
            return false;
        }
        return mask_and_value<N>::matches(data+offset);
    }

};

#ifndef NDEBUG
// LCOV_EXCL_START

// Unit test for mask_value_and_offset bounds check.
// The check must reject any length < (offset + N).
namespace mask_value_and_offset_unit_test {

    inline bool unit_test() {
        static constexpr mask_value_and_offset<8> matcher{
            {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            3
        };
        uint8_t buf[11] = {0};

        // lengths 0..10 must all be rejected 
        for (size_t len = 0; len <= 10; len++) {
            if (matcher.matches_at_offset(buf, len) != false) {
                return false;
            }
        }

        // 11 is the minimum valid length; should match (all zeros)
        if (matcher.matches_at_offset(buf, 11) != true) {
            return false;
        }

        return true;
    }

} // namespace mask_value_and_offset_unit_test

namespace match_packet_safety_unit_test {

    inline bool is_aligned_to(const void *ptr, size_t alignment) {
        return reinterpret_cast<std::uintptr_t>(ptr) % alignment == 0;
    }

    template <size_t StorageSize, size_t PacketSize>
    inline const uint8_t *copy_with_unaligned_field(std::array<uint8_t, StorageSize> &storage,
                                                    const std::array<uint8_t, PacketSize> &packet,
                                                    size_t field_offset,
                                                    size_t alignment) {
        if (alignment <= 1 || field_offset >= packet.size() || packet.size() + alignment > storage.size()) {
            return nullptr;
        }

        for (size_t offset = 1; offset <= alignment; offset++) {
            uint8_t *candidate = storage.data() + offset;
            if (!is_aligned_to(candidate + field_offset, alignment)) {
                storage.fill(0);
                for (size_t i = 0; i < packet.size(); i++) {
                    candidate[i] = packet[i];
                }
                return candidate;
            }
        }
        return nullptr;
    }

    inline bool unit_test() {
        static constexpr mask_and_value<8> tls_client_hello_matcher{
            { 0xff, 0xff, 0xfc, 0x00, 0x00, 0xff, 0x00, 0x00 },
            { 0x16, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 }
        };
        static constexpr std::array<uint8_t, 8> tls_record_prefix = {
            0x16, 0x03, 0x01, 0x00, 0x2d, 0x01, 0x00, 0x00
        };
        std::array<uint8_t, tls_record_prefix.size() + alignof(uint32_t)> storage{};

        const uint8_t *data = copy_with_unaligned_field(storage,
                                                        tls_record_prefix,
                                                        0,
                                                        alignof(uint32_t));
        if (data == nullptr) {
            return false;
        }
        return tls_client_hello_matcher.matches(data, tls_record_prefix.size());
    }

} // namespace match_packet_safety_unit_test
// LCOV_EXCL_STOP
#endif // NDEBUG

#endif /* MATCH_H */
