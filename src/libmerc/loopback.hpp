// loopback.hpp

#ifndef LOOPBACK_HPP
#define LOOPBACK_HPP

#include "datum.h"
#include "eth.h"

// The protocol type field is in the host byte order of the machine on
// which the capture was done. The values for that field are:
//
// 2 - payload is an IPv4 packet;
// 24 - payload is an IPv6 packet;
// 28 - payload is an IPv6 packet;
// 30 - payload is an IPv6 packet;
// 7 - payload is an OSI packet;
// 23 - payload is an IPX packet.

class loopback_header {
    encoded<uint32_t> protocol_type;

public:

    loopback_header(datum &d) : protocol_type{d} { }

    uint16_t get_protocol_type() const {
        switch(protocol_type.value()) {
        case 2:
            return ETH_TYPE_IP;
        case 24:
        case 28:
        case 30:
            return ETH_TYPE_IP;
        case 7:
            // actually OSI packets
        case 23:
            // actually IPX packets
        default:
            ;
        }
        return ETH_TYPE_NONE;
    }

};

#endif // LOOPBACK_HPP
