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

struct ipv4_hdr {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t source_address;
    uint32_t destination_address;
};

#define IPV6_ADDR_LEN 16

struct ipv6_hdr {
    uint8_t version_tc_hi;
    uint8_t tc_lo_flow_label_hi;
    uint16_t flow_label_lo;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t source_address[IPV6_ADDR_LEN];
    uint8_t destination_address[IPV6_ADDR_LEN];
} __attribute__ ((__packed__));

struct ipv6_header_extension {
    uint8_t next_header;
    uint8_t length;
    uint8_t data[6];  /* 6 is *minimim* data size */
};

/*
 * both tcp and udp have a port pair in the format used by struct
 * ports
 */
struct ports {
    uint16_t source;
    uint16_t destination;
};

void packet_fprintf(FILE *f, uint8_t *packet, size_t length, unsigned int sec, unsigned int usec) {
    uint16_t ether_type;

    eth_skip(&packet, &length, &ether_type);

    switch(ntohs(ether_type)) {
    case ETH_TYPE_IP:
        if (length < 40) {
            fprintf(f, "ipv4/[tcp,udp] packet too short (length: %zu)\n", length);
            return;
        } else {
            uint32_t *ipv4 = (uint32_t *)packet;
            uint8_t uint32s_in_ipv4_header = (((uint8_t *)packet)[0] & 0x0f);
            uint32_t *src_addr = ipv4 + 3;
            uint32_t *dst_addr = ipv4 + 4;
            uint8_t  *src_addr_char = (uint8_t *)src_addr;
            uint8_t  *dst_addr_char = (uint8_t *)dst_addr;
            uint8_t  *protocol = (uint8_t *)packet + 9;
            uint32_t *tcp = ipv4 + uint32s_in_ipv4_header;
            uint16_t *src_port = (uint16_t *)tcp;
            uint16_t *dst_port = src_port + 1;
            const char *format __attribute__((unused))= "%u.%u.%u.%u, %u.%u.%u.%u, %u, %u, %u\n";
            const char *json_format = "{\"src_ip\":\"%u.%u.%u.%u\",\"dst_ip\":\"%u.%u.%u.%u\",\"protocol\":%u,\"src_port\":%u,\"dst_port\":%u,\"len\":%u,\"t\":%u.%06u}\n";

            fprintf(f, json_format,
                    src_addr_char[0],
                    src_addr_char[1],
                    src_addr_char[2],
                    src_addr_char[3],
                    dst_addr_char[0],
                    dst_addr_char[1],
                    dst_addr_char[2],
                    dst_addr_char[3],
                    *protocol,
                    ntohs(*src_port),
                    ntohs(*dst_port),
                    length,
                    sec,
                    usec);
        }
        break;
    case ETH_TYPE_IPV6:
        if (length < sizeof(struct ipv6_hdr)) {
            fprintf(f, "ipv6 packet too short\n");
            return;
        } else {
            struct ipv6_hdr *ipv6_hdr = (struct ipv6_hdr *)packet;
            uint8_t *s = ipv6_hdr->source_address;
            uint8_t *d = ipv6_hdr->destination_address;
            const char *v6_json_format =
                "{\"src_ip\":\"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\","
                "\"dst_ip\":\"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\","
                "\"src_port\":%u,\"dst_port\":%u,\"len\":%u,\"t\":%u.%06u}\n";

            fprintf(f, v6_json_format,
                    s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15],
                    d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15],
                    0, 0, length, sec, usec);
        }
        break;
    default:
        fprintf(f, "not an ip packet (ethertype: %04x)\n", htons(ether_type));
    }

}


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

