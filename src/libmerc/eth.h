/*
 * eth.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef ETH_H
#define ETH_H

#include <stdint.h>
#include <algorithm>
#include <array>
#include "datum.h"
#include "cdp.h"
#include "ppp.h"
#include "ppoe.hpp"

struct eth_addr : public datum {
    static const unsigned int bytes_in_addr = 6;

    eth_addr(datum &d) : datum{} {
        datum::parse(d, bytes_in_addr);
    }

    /// write a textual representation of this ethernet address into
    /// \param b
    ///
    void write(buffer_stream &b) const {
        if (datum::is_not_null()) {
            b.write_mac_addr(data);
        }
    }
};

#define ETH_ADDR_LEN 6

#ifdef _WIN32
#pragma pack(1)
struct eth_hdr {
    uint8_t  dhost[ETH_ADDR_LEN];
    uint8_t  shost[ETH_ADDR_LEN];
    uint16_t ether_type;
};

struct eth_dot1q_tag {
    uint16_t tci;
    uint16_t ether_type;
};

struct eth_dot1ad_tag {
    uint16_t inner_tci;
    uint16_t ether_type;
};
#pragma pack()

#else

struct eth_hdr {
  uint8_t  dhost[ETH_ADDR_LEN];
  uint8_t  shost[ETH_ADDR_LEN];
  uint16_t ether_type;
} __attribute__ ((__packed__));

struct eth_dot1q_tag {
    uint16_t tci;
    uint16_t ether_type;
} __attribute__ ((__packed__));

struct eth_dot1ad_tag {
    uint16_t inner_tci;
    uint16_t ether_type;
} __attribute__ ((__packed__));

#endif // #ifdef _WIN32

#define MPLS_HDR_LEN 4
#define MPLS_BOTTOM_OF_STACK 0x100
#define ETH_MAX_ENCAP_DEPTH 5

/*
 * big-endian ETHERTYPE definitions
 */
#define ETH_TYPE_NONE          0x0000

#define ETH_TYPE_MIN           0x0600  // smallest ethertype

#define ETH_TYPE_PUP           0x0200
#define ETH_TYPE_SPRITE        0x0500
#define ETH_TYPE_IP            0x0800
#define ETH_TYPE_ARP           0x0806
#define ETH_TYPE_REVARP        0x8035
#define ETH_TYPE_AT            0x809B
#define ETH_TYPE_AARP          0x80F3
#define ETH_TYPE_VLAN          0x8100
#define ETH_TYPE_IPX           0x8137
#define ETH_TYPE_IPV6          0x86dd
#define ETH_TYPE_1AD           0x88a8
#define ETH_TYPE_LOOPBACK      0x9000
#define ETH_TYPE_TRAIL         0x1000
#define ETH_TYPE_MPLS          0x8847
#define ETH_TYPE_PPOE          0x8864
#define ETH_TYPE_LLDP          0x88cc
#define ETH_TYPE_CMD           0x8909
#define ETH_TYPE_CDP           0xffff  // overload reserved type for CDP

/*
 * ethernet (including .1q)
 *
 */

class eth {
    uint16_t ethertype = ETH_TYPE_NONE;

 public:

    static bool get_ip(datum &pkt) {
        eth ethernet_frame{pkt};
        uint16_t ethertype = ethernet_frame.get_ethertype();
        switch(ethertype) {
        case ETH_TYPE_IP:
        case ETH_TYPE_IPV6:
            return true;
        case ETH_TYPE_PPOE:
        {
            ppoe ppoe_pkt(pkt);
            if(ppp::is_ip(pkt)) {
                return true;
            }
            break;
        }
        default:
            ;
        }
        return false;  // not an IP packet
    }

    uint16_t get_ethertype() const { return ethertype; }

    eth(struct datum &p) {

        //mercury_debug("%s: processing ethernet (len %td)\n", __func__, p.length());

        p.skip(ETH_ADDR_LEN * 2);
        if (!p.read_uint16(&ethertype)) {
            ethertype = ETH_TYPE_NONE;
            return;
        }

        if (ethertype < ETH_TYPE_MIN) {
            if (p.matches(cdp::prefix)) {
                ethertype = ETH_TYPE_CDP;
                return;
            }
        }

        for (uint8_t depth = 0; depth < ETH_MAX_ENCAP_DEPTH; depth++) {
            if (ethertype == ETH_TYPE_VLAN ||
                   ethertype == ETH_TYPE_1AD) {
                p.skip(sizeof(uint16_t));  // TCI
                if (!p.read_uint16(&ethertype)) {
                    ethertype = ETH_TYPE_NONE;
                    return;
                }
            }
            else if (ethertype == ETH_TYPE_CMD) {
                p.skip(6);  // Cisco MetaData
                if (!p.read_uint16(&ethertype)) {
                    ethertype = ETH_TYPE_NONE;
                    return;
                }
            }
            else {
                break;
            }
        }

        if (ethertype == ETH_TYPE_VLAN ||
            ethertype == ETH_TYPE_1AD  ||
            ethertype == ETH_TYPE_CMD) {
            ethertype = ETH_TYPE_NONE;   // encapsulation depth limit exceeded
            p.set_null();
            return;
        }

        if (ethertype == ETH_TYPE_MPLS) {
            uint32_t mpls_label = 0;

            while (!(mpls_label & MPLS_BOTTOM_OF_STACK)) {
                if (!p.read_uint32(&mpls_label)) {
                    ethertype = ETH_TYPE_NONE;
                    return;
                }
            }
            ethertype = ETH_TYPE_IP;   // assume caller will check IP version field
        }

        return;
    }

};

// LCOV_EXCL_START
namespace eth_unit_test {

#ifndef NDEBUG

    // each test frame starts with destination and source addresses
    //
    static constexpr uint8_t addrs[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
    };

    template <size_t N>
    inline uint16_t ethertype_of(const std::array<uint8_t, N> &tail) {
        std::array<uint8_t, sizeof(addrs) + N> frame{};
        std::copy(std::begin(addrs), std::end(addrs), frame.begin());
        std::copy(tail.begin(), tail.end(), frame.begin() + sizeof(addrs));

        datum d{frame};
        eth ethernet_frame{d};
        return ethernet_frame.get_ethertype();
    }

    inline bool unit_test() {

        // untagged
        //
        if (ethertype_of(std::array<uint8_t, 2>{ 0x08, 0x00 }) != ETH_TYPE_IP) {
            return false;
        }

        // 802.1ad S-tag followed by 802.1Q C-tag
        //
        if (ethertype_of(std::array<uint8_t, 10>{
                    0x88, 0xa8, 0x00, 0x64,
                    0x81, 0x00, 0x00, 0xc8,
                    0x86, 0xdd }) != ETH_TYPE_IPV6) {
            return false;
        }

        // Cisco MetaData followed by 802.1Q tag
        //
        if (ethertype_of(std::array<uint8_t, 14>{
                    0x89, 0x09, 0x01, 0x01, 0x00, 0x01, 0x00, 0x64,
                    0x81, 0x00, 0x00, 0x64,
                    0x08, 0x00 }) != ETH_TYPE_IP) {
            return false;
        }

        // 802.1Q tag followed by Cisco MetaData
        //
        if (ethertype_of(std::array<uint8_t, 14>{
                    0x81, 0x00, 0x00, 0x64,
                    0x89, 0x09, 0x01, 0x01, 0x00, 0x01, 0x00, 0x64,
                    0x08, 0x00 }) != ETH_TYPE_IP) {
            return false;
        }

        // one tag beyond ETH_MAX_ENCAP_DEPTH is rejected
        //
        if (ethertype_of(std::array<uint8_t, 26>{
                    0x81, 0x00, 0x00, 0x64,
                    0x81, 0x00, 0x00, 0x64,
                    0x81, 0x00, 0x00, 0x64,
                    0x81, 0x00, 0x00, 0x64,
                    0x81, 0x00, 0x00, 0x64,
                    0x81, 0x00, 0x00, 0x64,
                    0x08, 0x00 }) != ETH_TYPE_NONE) {
            return false;
        }

        // truncated ethertype
        //
        if (ethertype_of(std::array<uint8_t, 1>{ 0x08 }) != ETH_TYPE_NONE) {
            return false;
        }

        // 802.1Q tag with no inner ethertype
        //
        if (ethertype_of(std::array<uint8_t, 4>{
                    0x81, 0x00, 0x00, 0x64 }) != ETH_TYPE_NONE) {
            return false;
        }

        // Cisco MetaData with no inner ethertype
        //
        if (ethertype_of(std::array<uint8_t, 8>{
                    0x89, 0x09, 0x01, 0x01, 0x00, 0x01, 0x00, 0x64 }) != ETH_TYPE_NONE) {
            return false;
        }

        // 802.3 length field followed by the CDP prefix
        //
        if (ethertype_of(std::array<uint8_t, 10>{
                    0x01, 0x30,
                    0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00 }) != ETH_TYPE_CDP) {
            return false;
        }

        // 802.3 length field without the CDP prefix
        //
        if (ethertype_of(std::array<uint8_t, 10>{
                    0x01, 0x30,
                    0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x21, 0x00 }) == ETH_TYPE_CDP) {
            return false;
        }

        // MPLS label with the bottom of stack bit set
        //
        if (ethertype_of(std::array<uint8_t, 6>{
                    0x88, 0x47,
                    0x00, 0x01, 0x01, 0xff }) != ETH_TYPE_IP) {
            return false;
        }

        // MPLS label stack that never reaches the bottom of stack
        //
        if (ethertype_of(std::array<uint8_t, 6>{
                    0x88, 0x47,
                    0x00, 0x01, 0x00, 0xff }) != ETH_TYPE_NONE) {
            return false;
        }

        return true;
    }

#endif // NDEBUG

} // namespace eth_unit_test
// LCOV_EXCL_STOP

#endif  /* ETH_H */
