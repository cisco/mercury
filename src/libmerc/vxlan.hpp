// vxlan.hpp
//
// VXLAN encapsulation


#ifndef VXLAN_HPP
#define VXLAN_HPP
#include "eth.h"
#include "json_object.h"
#include "protocol.h"

// VXLAN packet header
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |R|R|R|R|I|R|R|R|            Reserved                           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                VXLAN Network Identifier (VNI) |   Reserved    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class vxlan {
    struct key k;
    encoded<uint8_t> flags;
    datum reserved1;
    datum vni;
    datum reserved2;
    bool valid = true;
    bool next_valid = false;

public:
    static constexpr uint16_t dst_port = 4789;

    vxlan(datum &d, struct key &_k) :
        k{_k},
        flags(d),
        reserved1(d, 3),
        vni(d, 3),
        reserved2(d, 1) {
        /* A valid VXLAN packet should have the I bit in flags
         * always set to 1.
         */
        if(flags.bit<4>() == 0) {
            valid = false;
            return;
        }

        if (!eth::get_ip(d)) {
            return;
        }
        next_valid = true;
    }

    bool is_not_empty() const {
        return valid;
    }

    bool is_next_header() const {
        return next_valid;
    }

    void write_json(struct json_array &a) const {
        if (!valid) {
            return;
        }

        struct json_object rec{a};
        rec.print_key_string("type", "vxlan");
        k.write_ip_address(rec);
        rec.close();
    }
};

[[maybe_unused]] inline int vxlan_fuzz_test(const uint8_t *data, size_t size) {
    key k;
    struct datum packet_data{data, data+size};
    vxlan pkt{packet_data, k};
    if (pkt.is_not_empty()) {
        char buffer[8192];
        struct buffer_stream buf_json(buffer, sizeof(buffer));
        struct json_array record(&buf_json);
        pkt.write_json(record);
    }
    return 0;
}

namespace vxlan_test {
#ifndef NDEBUG
    inline bool unit_test() {
        uint8_t vxlan_valid[] = {
            0x08, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x08, 0x00,
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
            0xc0, 0xa8, 0x01, 0x02
        };
        key k1;
        datum d1{vxlan_valid, vxlan_valid + sizeof(vxlan_valid)};
        vxlan pkt1{d1, k1};
        if (!pkt1.is_not_empty() || !pkt1.is_next_header()) return false;

        uint8_t vxlan_invalid[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00 };
        key k2;
        datum d2{vxlan_invalid, vxlan_invalid + sizeof(vxlan_invalid)};
        vxlan pkt2{d2, k2};
        if (pkt2.is_not_empty()) return false;

        return true;
    }
#endif
} // namespace vxlan_test

#endif  // VXLAN_HPP
