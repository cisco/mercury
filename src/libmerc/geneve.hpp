// geneve.hpp
//
// Geneve encapsulation


#ifndef GENEVE_HPP
#define GENEVE_HPP
#include "eth.h"
#include "json_object.h"
#include "loopback.hpp"
#include "protocol.h"

//  Geneve Header:
//      0                   1                   2                   3
//      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |        Virtual Network Identifier (VNI)       |    Reserved   |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                    Variable Length Options                    |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
class geneve {
    struct key k;
    encoded<uint8_t> first_byte;
    ignore<encoded<uint8_t>> flags_and_rsrvdbits;
    encoded<uint16_t> protocol_type;
    datum vni;
    ignore<encoded<uint8_t>> reserved;
    datum options;
    bool next_valid = false;

public:
    static constexpr uint16_t ethernet = 0x6558;
    static constexpr uint16_t dst_port = 6081;

    geneve(datum &d, struct key &_k) :
        k{_k},
        first_byte(d),
        flags_and_rsrvdbits(d),
        protocol_type(d),
        vni(d, 3),
        reserved(d),
        options(d, 4 * first_byte.slice<2, 8>()) {
        switch(protocol_type) {
            case geneve::ethernet:
                if (!eth::get_ip(d)) {
                    break;   // not an IP packet
                }
                next_valid = true;
                break;

            case ETH_TYPE_IP:
            case ETH_TYPE_IPV6:
                next_valid = true;
                break;
            case ETH_TYPE_NONE: // nonstandard: no official EtherType for BSD loopback
                {
                    loopback_header loopback{d};  // bsd-style loopback encapsulation
                    if (d.is_not_null()) {
                        switch(loopback.get_protocol_type()) {
                        case ETH_TYPE_IP:
                        case ETH_TYPE_IPV6:
                            next_valid = true;
                            break;
                        default:
                            break;
                        }
                    }
                }
            default:
                break;
            }
    }

    uint16_t get_protocol_type() const {
        return protocol_type;
    }

    bool is_next_header() const {
        return next_valid;
    }

    void write_json(struct json_array &a) const {
        struct json_object rec{a};
        rec.print_key_string("type", "geneve");
        k.write_ip_address(rec);
        rec.print_key_uint16("protocol_type", protocol_type.value());
        rec.close();
    }
};

[[maybe_unused]] inline int geneve_fuzz_test(const uint8_t *data, size_t size) {
    key k;
    struct datum packet_data{data, data+size};
    geneve pkt{packet_data, k};
    char buffer[8192];
    struct buffer_stream buf_json(buffer, sizeof(buffer));
    struct json_array record(&buf_json);
    pkt.write_json(record);
    return 0;
}
#endif  // GENEVE_HPP
