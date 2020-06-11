/*
 * proto_identify.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

/**
 * \file proto_identify.h
 *
 * \brief Protocol identification (header)
 */

#ifndef JOY_PROTO_IDENTIFY_H
#define JOY_PROTO_IDENTIFY_H

#include <stdint.h>

/* Values indicating direction of the flow */
#define DIR_UNKNOWN 0
#define DIR_CLIENT 1
#define DIR_SERVER 2


/* destination port numbers for common protocols */

#define HTTP_PORT         80
#define HTTPS_PORT       443
#define SSH_PORT          22
#define SSH_KEX           23
#define DHCP_CLIENT_PORT  67
#define DHCP_SERVER_PORT  68
#define DTLS_PORT         99
#define DNS_PORT          53
#define WIREGUARD_PORT 51820

/**
 * \brief Protocol Inference container
 */
struct pi_container {
    uint8_t dir;  /**< Flow direction */
    uint16_t app; /**< Application protocol prediction */
};

int proto_identify_init(void);
void proto_identify_cleanup(void);

const struct pi_container *proto_identify_tcp(const uint8_t *tcp_data,
                                              unsigned int len);

const struct pi_container *proto_identify_udp(const uint8_t *udp_data,
                                              unsigned int len);

#endif /* JOY_PROTO_IDENTIFY_H */
