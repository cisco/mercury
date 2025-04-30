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
            valid = true;
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

#endif  // VXLAN_HPP
