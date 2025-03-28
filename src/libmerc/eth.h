/*
 * eth.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef ETH_H
#define ETH_H

#include <stdint.h>
#include "datum.h"
#include "cdp.h"

struct eth_addr : public datum {
    static const unsigned int bytes_in_addr = 6;

    eth_addr(datum &d) : datum{} {
        datum::parse(d, bytes_in_addr);
    }

    void fingerprint(struct buffer_stream &b) const {
        if (datum::is_not_null()) {
            b.write_mac_addr(data);
        }
    }
};

#define ETH_ADDR_LEN 6

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

#define MPLS_HDR_LEN 4
#define MPLS_BOTTOM_OF_STACK 0x100

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
            break;
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
        if (ethertype == ETH_TYPE_1AD) {
            p.skip(sizeof(uint16_t));  // TCI
            if (!p.read_uint16(&ethertype)) {
                ethertype = ETH_TYPE_NONE;
                return;
            }
        }
        if (ethertype == ETH_TYPE_VLAN) {
            p.skip(sizeof(uint16_t));  // TCI
            if (!p.read_uint16(&ethertype)) {
                ethertype = ETH_TYPE_NONE;
                return;
            }
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
        if (ethertype == ETH_TYPE_CMD) {
            p.skip(6);  // Cisco MetaData
            if (!p.read_uint16(&ethertype)) {
                ethertype = ETH_TYPE_NONE;
                return;
            }
        }

        return;
    }

};


#endif  /* ETH_H */

