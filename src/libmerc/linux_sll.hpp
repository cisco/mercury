// linux_sll.hpp
//
// Linux "cooked" capture encapsulation, used when capturing packets
// from multiple interfaces of different types

#ifndef LINUX_SLL_HPP
#define LINUX_SLL_HPP

#include "datum.h"

// LINKTYPE_LINUX_SLL encapsulation structure (following
// https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html)
//
//   +---------------------------+
//   |         Packet type       |
//   |         (2 Octets)        |
//   +---------------------------+
//   |        ARPHRD_ type       |
//   |         (2 Octets)        |
//   +---------------------------+
//   | Link-layer address length |
//   |         (2 Octets)        |
//   +---------------------------+
//   |    Link-layer address     |
//   |         (8 Octets)        |
//   +---------------------------+
//   |        Protocol type      |
//   |         (2 Octets)        |
//   +---------------------------+
//
class linux_sll {
    encoded<uint16_t> packet_type;
    encoded<uint16_t> arphrd_type;
    encoded<uint16_t> link_layer_address_length;
    datum link_layer_address;
    encoded<uint16_t> protocol_type;

public:

    /// parses a linux_ssl header from datum \param d
    ///
    linux_sll(datum &d) :
        packet_type{d},
        arphrd_type{d},
        link_layer_address_length{d},
        link_layer_address{d, 8},     // note: hardcoded length
        protocol_type{d}
    {  }

    /// reads and skips over a linux_sll encapsulation header in
    /// \param d, if `d` contains an IPv4 or IPv6 packet; otherwise,
    /// `d` is set to `null`.
    ///
    static void skip_to_ip(datum &d) {
        linux_sll sll{d};
        if (d.is_not_null()) {
            if (sll.is_ip()) {
                return;
            }
        }
        d.set_null();  // not an IP packet
    }

    /// returns `true` if this \ref linux_ssl encapsulation header is
    /// followed by an IPv4 or IPv6 packet, and false otherwise
    ///
    bool is_ip() const {
        if ((arphrd_type == arphrd::ETHER or arphrd_type == arphrd::LOOPBACK)
            and (protocol_type == ETH_TYPE_IP or protocol_type == ETH_TYPE_IPV6)) {
            return true;
        }
        return false;
    }

    /// protocol types identified by the arphrd_type code
    ///
    enum arphrd : uint16_t {
        ETHER       =     1, // ethernet 10/100mbps
        LOOPBACK    =   772  // loopback device
    };

    /// total bytes in an \ref linux_sll encapsulation header
    ///
    static constexpr const size_t length = 16;

};

#endif
