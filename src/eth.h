/*
 * eth.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef ETH_H
#define ETH_H

#include <stdint.h>
#include <endian.h>

#define ETH_ADDR_LEN 6

struct eth_hdr {
  uint8_t  dhost[ETH_ADDR_LEN];
  uint8_t  shost[ETH_ADDR_LEN];
  uint16_t ether_type;               
} __attribute__ ((__packed__));

struct eth_dot1q_hdr {
    struct eth_hdr eth_hdr;  /* eth_hdr.ether_type == VLAN */
    uint16_t tci;
    uint16_t ether_type;
} __attribute__ ((__packed__));

struct eth_dot1ad_hdr {
    struct eth_hdr eth_hdr;
    uint16_t outer_tci;
    uint16_t inner_tpid;
    uint16_t inner_tci;
    uint16_t ether_type;
} __attribute__ ((__packed__));


#if __BYTE_ORDER == __LITTLE_ENDIAN

#define ETH_TYPE_NONE          0x0000

#define ETH_TYPE_PUP           0x0002          
#define ETH_TYPE_SPRITE        0x0005          
#define ETH_TYPE_IP            0x0008          
#define ETH_TYPE_ARP           0x0608          
#define ETH_TYPE_REVARP        0x3580          
#define ETH_TYPE_AT            0x9B80          
#define ETH_TYPE_AARP          0xF380          
#define ETH_TYPE_VLAN          0x0081          
#define ETH_TYPE_IPX           0x3781          
#define ETH_TYPE_IPV6          0xdd86          
#define ETH_TYPE_LOOPBACK      0x0090          
#define ETH_TYPE_TRAIL         0x0010          

#elif __BYTE_ORDER == __BIG_ENDIAN

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
#define ETH_TYPE_LOOPBACK      0x9000          
#define ETH_TYPE_TRAIL         0x1000          

#endif


#endif  /* ETH_H */
