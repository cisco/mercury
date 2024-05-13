// geneve.hpp
//
// Geneve encapsulation


#ifndef GENEVE_HPP
#define GENEVE_HPP
//  Geneve Header:
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |        Virtual Network Identifier (VNI)       |    Reserved   |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                    Variable Length Options                    |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
class geneve {
    encoded<uint8_t> first_byte;
    uint32_t opt_len;
    skip_bytes<1> flags_and_rsrvdbits;
    encoded<uint16_t> protocol_type;
    datum vni;
    skip_bytes<1> reserved;
    datum options;

public:
    static constexpr uint16_t ethernet = 0x6558;
    static constexpr uint16_t dst_port = 6081;

    geneve(datum &d) :
        first_byte(d),
        opt_len(first_byte.slice<2, 8>()),
        flags_and_rsrvdbits(d),
        protocol_type(d),
        vni(d, 3),
        reserved(d) {
        opt_len = opt_len * 4;
        options.parse(d,opt_len);
    }

    uint16_t get_protocol_type() {
        return protocol_type;
    }
};

#endif  // GENEVE_HPP
