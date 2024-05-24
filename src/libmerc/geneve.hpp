// geneve.hpp
//
// Geneve encapsulation


#ifndef GENEVE_HPP
#define GENEVE_HPP
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
    encoded<uint8_t> first_byte;
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
        flags_and_rsrvdbits(d),
        protocol_type(d),
        vni(d, 3),
        reserved(d),
        options(d, 4 * first_byte.slice<2, 8>()) {}

    uint16_t get_protocol_type() {
        return protocol_type;
    }
};

#endif  // GENEVE_HPP
