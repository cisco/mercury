/*
 * eth.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef ETH_H
#define ETH_H

#include <stdint.h>

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

#endif  /* ETH_H */
