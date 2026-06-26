// loopback.hpp

#ifndef LOOPBACK_HPP
#define LOOPBACK_HPP

#include "datum.h"
#include "eth.h"

// The protocol type field is in the host byte order of the machine on
// which the capture was done. The values for that field are:
//
// 2  - payload is an IPv4 packet;
// 24 - payload is an IPv6 packet;
// 28 - payload is an IPv6 packet;
// 30 - payload is an IPv6 packet;
// 7  - payload is an OSI packet;
// 23 - payload is an IPX packet.
//
// Note that we must handle both big-endian and little-endian values.
//
// References:
// https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html
// https://wiki.wireshark.org/NullLoopback


class loopback_header {
    encoded<uint32_t> protocol_type;

public:

    loopback_header(datum &d) : protocol_type{d} { }

    uint16_t get_protocol_type() const {
        switch(protocol_type.value()) {
        case 0x00000002: // 2
        case 0x02000000:
            return ETH_TYPE_IP; // IPv4
        case 0x00000018: // 24
        case 0x18000000:
        case 0x0000001c: // 28
        case 0x1c000000:
        case 0x0000001e: // 30
        case 0x1e000000:
            return ETH_TYPE_IPV6; // IPv6
        case 0x00000007: // 7
        case 0x07000000:
            // actually OSI packets
        case 0x00000017: // 23
        case 0x17000000:
            // actually IPX packets
        default:
            ;
        }
        return ETH_TYPE_NONE;
    }

};

namespace loopback_unit_test {
#ifndef NDEBUG
    inline bool unit_test() {
        uint8_t ipv4_le[] = { 0x02, 0x00, 0x00, 0x00 };
        datum d1{ipv4_le, ipv4_le + sizeof(ipv4_le)};
        loopback_header h1{d1};
        if (h1.get_protocol_type() != ETH_TYPE_IP) return false;

        uint8_t ipv4_be[] = { 0x00, 0x00, 0x00, 0x02 };
        datum d2{ipv4_be, ipv4_be + sizeof(ipv4_be)};
        loopback_header h2{d2};
        if (h2.get_protocol_type() != ETH_TYPE_IP) return false;

        uint8_t ipv6_24[] = { 0x18, 0x00, 0x00, 0x00 };
        datum d3{ipv6_24, ipv6_24 + sizeof(ipv6_24)};
        loopback_header h3{d3};
        if (h3.get_protocol_type() != ETH_TYPE_IPV6) return false;

        uint8_t ipv6_28[] = { 0x1c, 0x00, 0x00, 0x00 };
        datum d4{ipv6_28, ipv6_28 + sizeof(ipv6_28)};
        loopback_header h4{d4};
        if (h4.get_protocol_type() != ETH_TYPE_IPV6) return false;

        uint8_t ipv6_30[] = { 0x1e, 0x00, 0x00, 0x00 };
        datum d5{ipv6_30, ipv6_30 + sizeof(ipv6_30)};
        loopback_header h5{d5};
        if (h5.get_protocol_type() != ETH_TYPE_IPV6) return false;

        uint8_t unknown[] = { 0xff, 0x00, 0x00, 0x00 };
        datum d6{unknown, unknown + sizeof(unknown)};
        loopback_header h6{d6};
        if (h6.get_protocol_type() != ETH_TYPE_NONE) return false;

        return true;
    }
#endif
} // namespace loopback_unit_test

#endif // LOOPBACK_HPP
