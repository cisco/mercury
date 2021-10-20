/*
 * packet.c
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "eth.h"
#include "packet.h"
#include "utils.h"
#include "buffer_stream.h"


void eth_skip(uint8_t **packet, size_t *length, uint16_t *ether_type) {
    struct eth_hdr *eth_hdr = (struct eth_hdr *) *packet;
    *ether_type = eth_hdr->ether_type;

    *packet += sizeof(struct eth_hdr);
    *length -= sizeof(struct eth_hdr);

    /*
     * handle 802.1q and 802.1ad (q-in-q) frames
     */
    if (ntohs(*ether_type) == ETH_TYPE_1AD) {
        /*
         * 802.1ad (q-in-q)
         */
        struct eth_dot1ad_tag *eth_dot1ad_tag = (struct eth_dot1ad_tag *)*packet;
        *ether_type = eth_dot1ad_tag->ether_type;
        *packet += sizeof(struct eth_dot1ad_tag);
        *length -= sizeof(struct eth_dot1ad_tag);

    }
    if (ntohs(*ether_type) == ETH_TYPE_VLAN) {
        /*
         * 802.1q
         */
        struct eth_dot1q_tag *eth_dot1q_tag = (struct eth_dot1q_tag *)*packet;
        *ether_type = eth_dot1q_tag->ether_type;
        *packet += sizeof(struct eth_dot1q_tag);
        *length -= sizeof(struct eth_dot1q_tag);

    }
    if (ntohs(*ether_type) == ETH_TYPE_MPLS) {
        /*
         * MPLS
         */
        *ether_type = htons(ETH_TYPE_IP);  // assume IPv4
        *packet += MPLS_HDR_LEN;
        *length -= MPLS_HDR_LEN;

    }

}

#ifdef USE_FLOWHASH

/*
 * flowhash is an experimental function that computes a representation
 * of a (unidirectional or bidirectional) flow key and timestamp that
 * can be included in the data records of network monitoring systems
 * to enable matching and joins across disparate data sets.  Time is
 * included to better disambiguate between irrelevant flow key
 * collisions, and uses an integer representation to facilitate
 * searching across time ranges.
 */

#define multiplier 2862933555777941757  // source: https://nuclear.llnl.gov/CNP/rng/rngman/node3.html
// #define multiplier 65537

uint64_t flowhash(const struct flow_key &k, uint32_t time_in_sec) {

    uint64_t x;
    if (k.type == ipv4) {
        uint32_t sa = k.value.v4.src_addr;
        uint32_t da = k.value.v4.dst_addr;
        uint16_t sp = k.value.v4.src_port;
        uint16_t dp = k.value.v4.dst_port;
        uint8_t  pr = k.value.v4.protocol;
        x = ((uint64_t) sp * da) + ((uint64_t) dp * sa);
        x *= multiplier;
        x += sa + da + sp + dp + pr;
        x *= multiplier;
    } else {
        uint64_t *sa = (uint64_t *)&k.value.v6.src_addr;
        uint64_t *da = (uint64_t *)&k.value.v6.dst_addr;
        uint16_t sp = k.value.v6.src_port;
        uint16_t dp = k.value.v6.dst_port;
        uint8_t  pr = k.value.v6.protocol;
        x = ((uint64_t) sp * da[0] * da[1]) + ((uint64_t) dp * sa[0] * sa[1]);
        x *= multiplier;
        x += sa[0] + sa[1] + da[0] + da[1] + sp + dp + pr;
        x *= multiplier;
    }

    return (0xffffffffff000000L & x) | (0x00ffffff & time_in_sec);

}

#endif // USE_FLOWHASH
