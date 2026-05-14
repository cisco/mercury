// gre.h
//
// Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
// https://github.com/cisco/mercury/blob/master/LICENSE


#ifndef GRE_H
#define GRE_H

#include "datum.h"
#include "ip.h"
#include "eth.h"
#include "json_object.h"

//
//  Generic Routing Encapsulation (GRE) as per RFC 2784
//
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |C|       Reserved0       | Ver |         Protocol Type         |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |      Checksum (optional)      |       Reserved1 (Optional)    |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//  Note: RFC 1701 defines an obsolete and more elaborate earlier
//  variant of the GRE header, which is little seen on modern
//  networks.
//
class gre_header {
    struct key k;
    encoded<uint16_t> c_reserved_ver;
    encoded<uint16_t> protocol_type;
    bool next_valid = false;

public:
    static constexpr uint16_t dst_port = 4754;

    gre_header(struct datum &d, struct key &_k) :
        k{_k},
        c_reserved_ver{d},
        protocol_type{d} {
        if (c_reserved_ver.bit<0>()) {
            d.skip(4);  // skip over Checksum and Reserved1 fields
        }
        if (d.is_null()) {
            protocol_type = 0x0000; // ETH_TYPE_NONE
            return;
        }
        switch(protocol_type) {
        case ETH_TYPE_IP:
        case ETH_TYPE_IPV6:
            next_valid = true;
            break;
        default:
            break;
        }
    }

    // get_protocol_type() returns the protocol_type value in the GRE
    // header, if there were no errors, and otherwise returns
    // ETH_TYPE_NONE (0x0000).  The protocol_type field should be
    // interpreted as an ETHERTYPE, as defined at
    // https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml.
    //
    uint16_t get_protocol_type() const { return protocol_type; }

    bool is_next_header() const { return next_valid; }

    void write_json(struct json_array &a) const {
        struct json_object rec{a};
        rec.print_key_string("type", "gre");
        k.write_ip_address(rec);
        rec.print_key_uint16("protocol_type", protocol_type.value());
        rec.close();
    }
};

[[maybe_unused]] inline int gre_header_fuzz_test(const uint8_t *data, size_t size) {
    key k;
    struct datum packet_data{data, data+size};
    gre_header pkt{packet_data, k};
    char buffer[8192];
    struct buffer_stream buf_json(buffer, sizeof(buffer));
    struct json_array record(&buf_json);
    pkt.write_json(record);
    return 0;
}

namespace gre_test {
#ifndef NDEBUG
    inline bool unit_test() {
        char buffer[2048];

        uint8_t gre_ipv4[] = { 0x00, 0x00, 0x08, 0x00 };
        key k1;
        datum d1{gre_ipv4, gre_ipv4 + sizeof(gre_ipv4)};
        gre_header pkt1{d1, k1};
        if (pkt1.get_protocol_type() != ETH_TYPE_IP || !pkt1.is_next_header()) return false;
        {
            buffer_stream buf{buffer, sizeof(buffer)};
            json_array arr{&buf};
            pkt1.write_json(arr);
            arr.close();
            buf.write_char('\0');
            if (!strstr(buffer, "gre")) return false;
        }

        uint8_t gre_ipv6[] = { 0x00, 0x00, 0x86, 0xdd };
        key k2;
        datum d2{gre_ipv6, gre_ipv6 + sizeof(gre_ipv6)};
        gre_header pkt2{d2, k2};
        if (pkt2.get_protocol_type() != ETH_TYPE_IPV6 || !pkt2.is_next_header()) return false;

        uint8_t gre_checksum[] = { 0x80, 0x00, 0x08, 0x00, 0x12, 0x34, 0x00, 0x00 };
        key k3;
        datum d3{gre_checksum, gre_checksum + sizeof(gre_checksum)};
        gre_header pkt3{d3, k3};
        if (pkt3.get_protocol_type() != ETH_TYPE_IP) return false;

        uint8_t gre_unknown[] = { 0x00, 0x00, 0x00, 0x00 };
        key k4;
        datum d4{gre_unknown, gre_unknown + sizeof(gre_unknown)};
        gre_header pkt4{d4, k4};
        if (pkt4.is_next_header()) return false;

        return true;
    }
#endif
} // namespace gre_test

#endif
