#ifndef LINUX_SLL2_HPP
#define LINUX_SLL2_HPP

#include "datum.h"
#include "eth.h"
// LINKTYPE_LINUX_SLL2 encapsulation structure (following
// https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html)
//
//
//    +---------------------------+
//    |        Protocol type      |
//    |         (2 Octets)        |
//    +---------------------------+
//    |       Reserved (MBZ)      |
//    |         (2 Octets)        |
//    +---------------------------+
//    |       Interface index     |
//    |         (4 Octets)        |
//    +---------------------------+
//    |        ARPHRD_ type       |
//    |         (2 Octets)        |
//    +---------------------------+
//    |         Packet type       |
//    |         (1 Octet)         |
//    +---------------------------+
//    | Link-layer address length |
//    |         (1 Octet)         |
//    +---------------------------+
//    |    Link-layer address     |
//    |         (8 Octets)        |
//    +---------------------------+
//    |           Payload         |
//    |                           |
//    +---------------------------+
//
class linux_sll2 {
    encoded<uint16_t> protocol_type;
    encoded<uint16_t> reserved;
    encoded<uint32_t> interface_index;
    encoded<uint16_t> arphrd_type;
    encoded<uint8_t> packet_type;
    encoded<uint8_t> address_length;
    datum link_layer_address;

public:
    /// parses a linux_sll2 header from datum \param d
    ///
    linux_sll2(datum &d):
        protocol_type{d},
        reserved{d},
        interface_index{d},
        arphrd_type{d},
        packet_type{d},
        address_length{d},
        link_layer_address{d, 8}    // note: hardcoded length
    { }

    /// reads and skips over a linux_sll2 encapsulation header in
    /// \param d, if `d` contains an IPv4 or IPv6 packet; otherwise,
    /// `d` is set to `null`.
    ///
    static void skip_to_ip(datum &d) {
        linux_sll2 sll2{d};
        if (d.is_not_null()) {
            if (sll2.is_ip()) {
                return;
            }
        }
        d.set_null(); // not an IP packet
    }

    /// returns `true` if this \ref linux_sll2 encapsulation header is
    /// followed by an IPv4 or IPv6 packet, and false otherwise
    ///
    bool is_ip() const {
        if ((arphrd_type == arphrd::ETHER or arphrd_type == arphrd::LOOPBACK)
            and (protocol_type == ETH_TYPE_IP or protocol_type == ETH_TYPE_IPV6)) {
            return true;
        }
        return false;
    }

    enum arphrd : uint16_t {
        ETHER       =     1, // ethernet 10/100mbps
        LOOPBACK    =   772  // loopback device
    };

    static constexpr const size_t length = 20;
};

#endif
