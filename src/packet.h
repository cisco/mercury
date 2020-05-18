/*
 * packet.h
 * 
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at 
 * https://github.com/cisco/mercury/blob/master/LICENSE 
 */

#ifndef PACKET_H
#define PACKET_H

#define IPV6_ADDR_LEN 16

struct ipv4_flow_key {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
};

struct ipv6_flow_key {
    uint8_t src_addr[IPV6_ADDR_LEN];
    uint8_t dst_addr[IPV6_ADDR_LEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
};

enum flow_type {
    none = 0,
    ipv4 = 1,
    ipv6 = 2
};

union ip_flow_key {
    struct ipv4_flow_key v4;
    struct ipv6_flow_key v6;
};

struct flow_key {
    enum flow_type type;
    union ip_flow_key value;
};

/*
 * the initializer below may trigger a spurious gcc "warning: missing braces"
 */
#define flow_key_init() { none, { 0, 0, 0, 0, 0 } }

void flow_key_set_from_packet(struct flow_key *k,
			      uint8_t *packet,
			      size_t length);

void packet_fprintf(FILE *f, uint8_t *packet, size_t length, unsigned int sec, unsigned int usec);

void packet_fprintf_flow_key(FILE *f, uint8_t *packet, size_t length);

void write_packet_flow_key(struct buffer_stream &buf, uint8_t *packet, size_t length);

uint64_t flowhash(const struct flow_key &k, uint32_t time_in_sec);

#endif /* PACKET_H */
