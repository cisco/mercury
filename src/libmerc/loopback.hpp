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
            return ETH_TYPE_IP; // IPv6
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

#endif // LOOPBACK_HPP
