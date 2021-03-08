/*
 * udp.c
 *
 * UDP protocol processing
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */


#include "extractor.h"
#include "proto_identify.h"
#include "match.h"
#include "utils.h"

/* DTLS Client */
unsigned char dtls_client_hello_mask[] = {
    0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00
};

unsigned char dtls_client_hello_value[] = {
    0x16, 0xfe, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
};

// DTLSv1.0 version: { 254, 255 } == { 0xfe, 0xff }
// DTLSv1.2 version: { 254, 253 } == { 0xfe, 0xfd }

struct pi_container dtls_client = {
    DIR_CLIENT,
    DTLS_PORT
};


/* DTLS Server */
unsigned char dtls_server_hello_mask[] = {
    0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

unsigned char dtls_server_hello_value[] = {
    0x16, 0xfe, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00
};

struct pi_container dtls_server = {
    DIR_SERVER,
    DTLS_PORT
};


/* dhcp client */
unsigned char dhcp_client_value[] = {
    0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00
};

unsigned char dhcp_client_mask[] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00
};

struct pi_container dhcp_client = {
    DIR_CLIENT,
    DHCP_CLIENT_PORT
};

/*
 * dns server
 */
unsigned char dns_server_mask[] = {
    0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff, 0x00
};
unsigned char dns_server_value[] = {
    0x00, 0x00, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00
};
struct pi_container dns_server = {
    DIR_SERVER,
    DNS_PORT
};

unsigned char dns_client_mask[] = {
    0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff, 0x00
};
unsigned char dns_client_value[] = {
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
};

/*
 * wireguard
 */
unsigned char wireguard_mask[] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00
};
unsigned char wireguard_value[] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
struct pi_container wireguard = {
    DIR_CLIENT,
    WIREGUARD_PORT
};

/*
 * quic
 */
unsigned char quic_mask[] = {
    0xf0, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00
};
unsigned char quic_value[] = {
    0xc0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
struct pi_container quic = {
    DIR_UNKNOWN,
    QUIC_PORT
};

enum udp_msg_type udp_get_message_type(const uint8_t *udp_data,
                                   unsigned int len) {

    if (len < sizeof(dhcp_client_mask)) {
        return udp_msg_type_unknown;
    }

    /* note: udp_data will be 32-bit aligned as per the standard */

    mercury_debug("%s: udp data: %02x%02x%02x%02x%02x%02x%02x%02x\n", __func__,
                    udp_data[0], udp_data[1], udp_data[2], udp_data[3], udp_data[4], udp_data[5], udp_data[6], udp_data[7]);

    if (u32_compare_masked_data_to_value(udp_data,
                                         dhcp_client_mask,
                                         dhcp_client_value)) {
        return udp_msg_type_dhcp;
    }

    if (u32_compare_masked_data_to_value(udp_data,
                                         dtls_client_hello_mask,
                                         dtls_client_hello_value)) {
        return udp_msg_type_dtls_client_hello;
    }
    if (u64_compare_masked_data_to_value(udp_data,
                                         dtls_server_hello_mask,
                                         dtls_server_hello_value)) {
        return udp_msg_type_dtls_server_hello;
    }
    if (u64_compare_masked_data_to_value(udp_data,
                                         dns_server_mask,
                                         dns_server_value)) {
        return udp_msg_type_dns;
    }
    if (u64_compare_masked_data_to_value(udp_data,
                                         dns_client_mask,
                                         dns_client_value)) {
        return udp_msg_type_dns;
    }
    if (u64_compare_masked_data_to_value(udp_data,
                                         wireguard_mask,
                                         wireguard_value)) {
        return udp_msg_type_wireguard;
    }
    if (u64_compare_masked_data_to_value(udp_data,
                                         quic_mask,
                                         quic_value)) {
        return udp_msg_type_quic;
    }

    return udp_msg_type_unknown;
}

/*
 * UDP header (from RFC 768)
 *
 *                0      7 8     15 16    23 24    31
 *               +--------+--------+--------+--------+
 *               |     Source      |   Destination   |
 *               |      Port       |      Port       |
 *               +--------+--------+--------+--------+
 *               |                 |                 |
 *               |     Length      |    Checksum     |
 *               +--------+--------+--------+--------+
 *               |
 *               |          data octets ...
 *               +---------------- ...
 *
 * Length is the length in octets of this user datagram including this
 * header and the data.  (This means the minimum value of the length
 * is eight.)
 *
 * Checksum is the 16-bit one's complement of the one's complement sum
 * of a pseudo header of information from the IP header, the UDP
 * header, and the data, padded with zero octets at the end (if
 * necessary) to make a multiple of two octets.
 *
 * If the computed checksum is zero, it is transmitted as all ones
 * (the equivalent in one's complement arithmetic).  An all zero
 * transmitted checksum value means that the transmitter generated no
 * checksum (for debugging or for higher level protocols that don't
 * care).
 *
 */

#define L_udp_src_port 2
#define L_udp_dst_port 2
#define L_udp_length   2
#define L_udp_checksum 2


#if 0
#define VXLAN_PORT 4789
/*
 *  VXLAN Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |R|R|R|R|I|R|R|R|            Reserved                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                VXLAN Network Identifier (VNI) |   Reserved    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define VXLAN_HDR_LEN 8

unsigned int packet_filter_process_vxlan(struct packet_filter *pf, struct key *k) {
    struct datum *p = &pf->p;
    if (parser_skip(p, VXLAN_HDR_LEN) != status_ok) {
        return 0;
    }
    /*
     * note: we ignore the VXLAN Network Identifier for now, which
     * makes little difference as long as they are all identical
     */
    return packet_filter_process_packet(pf, k);
}
#endif // 0
