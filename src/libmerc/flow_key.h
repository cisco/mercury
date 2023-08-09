/*
 * flow_key.h
 *
 * Copyright (c) 2019-2023 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef FLOW_KEY_H
#define FLOW_KEY_H

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

uint64_t flowhash(const struct flow_key &k, uint32_t time_in_sec);

#endif // FLOW_KEY_H
