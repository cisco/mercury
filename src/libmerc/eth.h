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

/*
 * ethernet (including .1q)
 *
 * frame format is outlined in the file eth.h
 */

class eth {
    size_t ethertype = ETH_TYPE_NONE;

 public:

    uint16_t get_ethertype() const { return ethertype; }

    eth(struct datum &p) {

        //mercury_debug("%s: processing ethernet (len %td)\n", __func__, datum_get_data_length(p));

        if (datum_skip(&p, ETH_ADDR_LEN * 2) == status_err) {
            return;
        }
        if (datum_read_and_skip_uint(&p, sizeof(uint16_t), &ethertype) == status_err) {
            return;
        }
        if (ethertype == ETH_TYPE_1AD) {
            if (datum_skip(&p, sizeof(uint16_t)) == status_err) { // TCI
                return;
            }
            if (datum_read_and_skip_uint(&p, sizeof(uint16_t), &ethertype) == status_err) {
                return;
            }
        }
        if (ethertype == ETH_TYPE_VLAN) {
            if (datum_skip(&p, sizeof(uint16_t)) == status_err) { // TCI
                return;
            }
            if (datum_read_and_skip_uint(&p, sizeof(uint16_t), &ethertype) == status_err) {
                return;
            }
        }
        if (ethertype == ETH_TYPE_MPLS) {
            size_t mpls_label = 0;

            while (!(mpls_label & MPLS_BOTTOM_OF_STACK)) {
                if (datum_read_and_skip_uint(&p, sizeof(uint32_t), &mpls_label) == status_err) {
                    return;
                }
            }
            ethertype = ETH_TYPE_IP;   // assume IPv4 for now (TODO: check IP version)
        }

        return;
    }

};


#endif  /* ETH_H */
