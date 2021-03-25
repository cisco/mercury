/*
 * extractor.cc
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <string.h>   /* for memcpy()   */
#include <ctype.h>    /* for tolower()  */
#include <stdio.h>
#include <arpa/inet.h>  /* for htons()  */

#include "extractor.h"
#include "utils.h"
#include "proto_identify.h"
#include "eth.h"
#include "tcp.h"
#include "pkt_proc.h"
#include "udp.h"
#include "match.h"
#include "buffer_stream.h"
#include "json_object.h"

/*
 * The mercury_debug macro is useful for debugging (but quite verbose)
 */
#ifndef DEBUG
#define mercury_debug(...)
#else
#define mercury_debug(...)  (fprintf(stdout, __VA_ARGS__))
#endif


/* protocol identification, adapted from joy */

/*
 * Hex strings for TLS ClientHello (which appear at the start of the
 * TCP Data field):
 *
 *    16 03 01  *  * 01   v1.0 data
 *    16 03 02  *  * 01   v1.1 data
 *    16 03 03  *  * 01   v1.2 data
 *    ---------------------------------------
 *    ff ff fc 00 00 ff   mask
 *    16 03 00 00 00 01   value = data & mask
 *
 */

unsigned char tls_client_hello_mask[] = {
    0xff, 0xff, 0xfc, 0x00, 0x00, 0xff, 0x00, 0x00
};

unsigned char tls_client_hello_value[] = {
    0x16, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
};

struct pi_container https_client = {
    DIR_CLIENT,
    HTTPS_PORT
};

#define tls_server_hello_mask tls_client_hello_mask

unsigned char tls_server_hello_value[] = {
    0x16, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00
};

struct pi_container https_server = {
    DIR_SERVER,
    HTTPS_PORT
};

#define tls_server_cert_mask tls_client_hello_mask

unsigned char tls_server_cert_value[] = {
    0x16, 0x03, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00
};

unsigned char tls_server_cert_embedded_mask[] = {
    0xff, 0xff, 0x00, 0x00, 0xff, 0x00, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff
};

unsigned char tls_server_cert_embedded_value[] = {
    0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x82
};

struct pi_container https_server_cert = {
    DIR_UNKNOWN,
    HTTPS_PORT
};

unsigned char http_client_mask[] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00
};

unsigned char http_client_value[] = {
    0x47, 0x45, 0x54, 0x20, 0x00, 0x00, 0x00, 0x00
};

unsigned char http_client_post_mask[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00
};

unsigned char http_client_post_value[] = {
    'P', 'O', 'S', 'T', ' ', 0x00, 0x00, 0x00
};

unsigned char http_client_connect_mask[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

unsigned char http_client_connect_value[] = {
    'C', 'O', 'N', 'N', 'E', 'C', 'T', ' '
};

unsigned char http_client_put_mask[] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00
};

unsigned char http_client_put_value[] = {
    'P', 'U', 'T', ' ', 0x00, 0x00, 0x00, 0x00
};

unsigned char http_client_head_mask[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00
};

unsigned char http_client_head_value[] = {
    'H', 'E', 'A', 'D', ' ', 0x00, 0x00, 0x00
};

struct pi_container http_client = {
    DIR_CLIENT,
    HTTP_PORT
};

/* http server matching value: HTTP/1 */

unsigned char http_server_mask[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00
};

unsigned char http_server_value[] = {
    'H', 'T', 'T', 'P', '/', '1', 0x00, 0x00
};

struct pi_container http_server = {
    DIR_SERVER,
    HTTP_PORT
};

/* SSH matching value: "SSH-2." */

unsigned char ssh_mask[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00
};

unsigned char ssh_value[] = {
    'S', 'S', 'H', '-', '2', '.', 0x00, 0x00
};

struct pi_container ssh = {
    DIR_CLIENT,
    SSH_PORT
};

/* SSH KEX matching value */

unsigned char ssh_kex_mask[] = {
    0xff, 0xff, 0xf0, 0x00, // packet length
    0x00,                   // padding length
    0xff,                   // KEX code
    0x00, 0x00              // ...
};

unsigned char ssh_kex_value[] = {
    0x00, 0x00, 0x00, 0x00, // packet length
    0x00,                   // padding length
    0x14,                   // KEX code
    0x00, 0x00              // ...
};

struct pi_container ssh_kex = {
    DIR_CLIENT,
    SSH_KEX
};

/* SMTP server matching value */

unsigned char smtp_server_mask[] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00
};

unsigned char smtp_server_value[] = {
    0x32, 0x35, 0x30, 0x2d, 0x00, 0x00, 0x00, 0x00
};

struct pi_container smtp_server = {
    DIR_SERVER,
    SMTP_PORT
};

enum tcp_msg_type get_message_type(const uint8_t *tcp_data,
                                   unsigned int len) {

    if (len < sizeof(tls_client_hello_mask)) {
        return tcp_msg_type_unknown;
    }

    // debug_print_u8_array(tcp_data);

    /* note: tcp_data will be 32-bit aligned as per the standard */

    if (u32_compare_masked_data_to_value(tcp_data,
                                         tls_client_hello_mask,
                                         tls_client_hello_value)) {
        return tcp_msg_type_tls_client_hello;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
                                         tls_server_hello_mask,
                                         tls_server_hello_value)) {
        return tcp_msg_type_tls_server_hello;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
                                         tls_server_cert_mask,
                                         tls_server_cert_value)) {
        return tcp_msg_type_tls_certificate;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
                                         http_client_mask,
                                         http_client_value)) {
        return tcp_msg_type_http_request;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
                                         http_client_post_mask,
                                         http_client_post_value)) {
        return tcp_msg_type_http_request;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
                                         http_client_connect_mask,
                                         http_client_connect_value)) {
        return tcp_msg_type_http_request;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
                                         http_client_put_mask,
                                         http_client_put_value)) {
        return tcp_msg_type_http_request;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
                                         http_client_head_mask,
                                         http_client_head_value)) {
        return tcp_msg_type_http_request;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
                                         http_server_mask,
                                         http_server_value)) {
        return tcp_msg_type_http_response;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
                                         ssh_mask,
                                         ssh_value)) {
        return tcp_msg_type_ssh;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
                                         ssh_kex_mask,
                                         ssh_kex_value)) {
        return tcp_msg_type_ssh_kex;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
                                         smtp_server_mask,
                                         smtp_server_value)) {
        return tcp_msg_type_smtp_server;
    }
    return tcp_msg_type_unknown;
}

/*
 * IP header parsing and fingerprinting
 */

/*
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Version|  IHL  |Type of Service|          Total Length         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Identification        |Flags|      Fragment Offset    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Time to Live |    Protocol   |         Header Checksum       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Source Address                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Destination Address                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Options                    |    Padding    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

#define L_ip_version_ihl    1
#define L_ip_tos            1
#define L_ip_total_length   2
#define L_ip_identification 2
#define L_ip_flags_frag_off 2
#define L_ip_ttl            1
#define L_ip_protocol       1
#define L_ip_hdr_cksum      2
#define L_ip_src_addr       4
#define L_ip_dst_addr       4

unsigned int datum_process_ipv4(struct datum *p, size_t *transport_protocol, struct key *k) {
    size_t version_ihl;
    uint8_t *transport_data;

    mercury_debug("%s: processing packet (len %td)\n", __func__, datum_get_data_length(p));

    if (datum_read_uint(p, L_ip_version_ihl, &version_ihl) == status_err) {
        return 0;
    }
    if (!(version_ihl & 0x40)) {
        return 0;  /* version is not IPv4 */
    }
    version_ihl &= 0x0f;
    if (version_ihl < 5) {
        return 0;  /* invalid IP header length */
    }
    /*
     * tcp/udp headers are 4 * IHL bytes from start of ip headers
     */
    transport_data = (uint8_t *)p->data + (version_ihl << 2);
    if (datum_skip(p, L_ip_version_ihl + L_ip_tos) == status_err) {
        return 0;
    }
    /*
     *  check ip_total_length field, and trim data from parser if appropriate
     */
    size_t ip_total_length;
    if (datum_read_and_skip_uint(p, L_ip_total_length, &ip_total_length) == status_err) {
        return 0;
    }
    datum_set_data_length(p, ip_total_length - (L_ip_version_ihl + L_ip_tos + L_ip_total_length));
    if (datum_skip(p, L_ip_identification + L_ip_flags_frag_off + L_ip_ttl) == status_err) {
        return 0;
    }
    if (datum_read_and_skip_uint(p, L_ip_protocol, transport_protocol) == status_err) {
        return 0;
    }
    if (datum_skip(p, L_ip_hdr_cksum) == status_err) {
        return 0;
    }
    if (datum_read_and_skip_byte_string(p, L_ip_src_addr, (uint8_t *)&k->addr.ipv4.src) == status_err) {
        return 0;
    }
    if (datum_read_and_skip_byte_string(p, L_ip_dst_addr, (uint8_t *)&k->addr.ipv4.dst) == status_err) {
        return 0;
    }
    if (datum_skip_to(p, transport_data) == status_err) {
        return 0;
    }
    k->ip_vers = 4;  // ipv4
    k->protocol = 6; // tcp

    return 0;  /* we don't extract any data, but this is not a failure */
}

/*
 *
 * ipv6 fixed header format (from RFC 2460)
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Version| Traffic Class |           Flow Label                  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Payload Length        |  Next Header  |   Hop Limit   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +                         Source Address                        +
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +                      Destination Address                      +
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 * ipv6 extension header format (from RFC 6564)
 *
 *      0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Next Header  |  Hdr Ext Len  |                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *  |                                                               |
 *  .                                                               .
 *  .                  Header Specific Data                         .
 *  .                                                               .
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  Next Header          8-bit selector.  Identifies the type of header
 *                       immediately following the extension header.
 *                       Uses the same values as the IPv4 Protocol field
 *                       [IANA_IP_PARAM].
 *
 *  Hdr Ext Len          8-bit unsigned integer.  Length of the extension
 *                       header in 8-octet units, not including the first
 *                       8 octets.
 *
 *  Header Specific      Variable length.  Fields specific to the
 *  Data                 extension header.
 *
 */

#define L_ipv6_version_tc_hi         1
#define L_ipv6_tc_lo_flow_label_hi   1
#define L_ipv6_flow_label_lo         2
#define L_ipv6_payload_length        2
#define L_ipv6_next_header           1
#define L_ipv6_hop_limit             1
#define L_ipv6_source_address       16
#define L_ipv6_destination_address  16
#define L_ipv6_hdr_ext_len           1
#define L_ipv6_ext_hdr_base          8

unsigned int datum_process_ipv6(struct datum *p, size_t *transport_protocol, struct key *k) {
    size_t version_tc_hi;
    size_t payload_length;
    size_t next_header;

    mercury_debug("%s: processing packet (len %td)\n", __func__, datum_get_data_length(p));

    if (datum_read_uint(p, L_ipv6_version_tc_hi, &version_tc_hi) == status_err) {
        return 0;
    }
    if (!(version_tc_hi & 0x60)) {
        return 0;  /* version is not IPv6 */
    }
    if (datum_skip(p, L_ipv6_version_tc_hi + L_ipv6_tc_lo_flow_label_hi + L_ipv6_flow_label_lo) == status_err) {
        return 0;
    }
    if (datum_read_uint(p, L_ipv6_payload_length, &payload_length) == status_err) {
        return 0;
    }
    if (datum_skip(p, L_ipv6_payload_length) == status_err) {
        return 0;
    }
    /*
     * should we check the payload length here?
     */
    if (datum_read_uint(p, L_ipv6_next_header, &next_header) == status_err) {
        return 0;
    }
    if (datum_skip(p, L_ipv6_next_header + L_ipv6_hop_limit) == status_err) {
        return 0;
    }
    if (datum_read_and_skip_byte_string(p, L_ipv6_source_address, (uint8_t *)&k->addr.ipv6.src) == status_err) {
        return 0;
    }
    if (datum_read_and_skip_byte_string(p, L_ipv6_destination_address, (uint8_t *)&k->addr.ipv6.dst) == status_err) {
        return 0;
    }
    k->ip_vers = 6;  // ipv6
    k->protocol = 6; // tcp

    /* loop over extensions headers until we find an upper layer protocol */
    unsigned int not_done = 1;
    while (not_done) {
        size_t ext_hdr_len;

        switch (next_header) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_FRAGMENT:
        case IPPROTO_ESP:
        case IPPROTO_AH:
        case IPPROTO_DSTOPTS:
            if (datum_read_uint(p, L_ipv6_next_header, &next_header) == status_err) {
                return 0;
            }
            if (datum_skip(p, L_ipv6_next_header) == status_err) {
                return 0;
            }
            if (datum_read_uint(p, L_ipv6_hdr_ext_len, &ext_hdr_len) == status_err) {
                return 0;
            }
            if (datum_skip(p, L_ipv6_ext_hdr_base + ext_hdr_len*8 - L_ipv6_next_header) == status_err) {
                return 0;
            }

            break;

        case IPPROTO_NONE:
        default:
            not_done = 0;
            break;
        }
    }
    *transport_protocol = next_header;

    return 0;  /* we don't extract any data, but this is not a failure */
}


/*
 * ethernet (including .1q)
 *
 * frame format is outlined in the file eth.h
 */

unsigned int datum_process_eth(struct datum *p, size_t *ethertype) {

    mercury_debug("%s: processing ethernet (len %td)\n", __func__, datum_get_data_length(p));

    *ethertype = ETH_TYPE_NONE;

    if (datum_skip(p, ETH_ADDR_LEN * 2) == status_err) {
        return 0;
    }
    if (datum_read_and_skip_uint(p, sizeof(uint16_t), ethertype) == status_err) {
        return 0;
    }
    if (*ethertype == ETH_TYPE_1AD) {
        if (datum_skip(p, sizeof(uint16_t)) == status_err) { // TCI
            return 0;
        }
        if (datum_read_and_skip_uint(p, sizeof(uint16_t), ethertype) == status_err) {
            return 0;
        }
    }
    if (*ethertype == ETH_TYPE_VLAN) {
        if (datum_skip(p, sizeof(uint16_t)) == status_err) { // TCI
            return 0;
        }
        if (datum_read_and_skip_uint(p, sizeof(uint16_t), ethertype) == status_err) {
            return 0;
        }
    }
    if (*ethertype == ETH_TYPE_MPLS) {
        size_t mpls_label = 0;

        while (!(mpls_label & MPLS_BOTTOM_OF_STACK)) {
            if (datum_read_and_skip_uint(p, sizeof(uint32_t), &mpls_label) == status_err) {
                return 0;
            }
        }
        *ethertype = ETH_TYPE_IP;   // assume IPv4 for now
    }

    return 0;  /* we don't extract any data, but this is not a failure */
}



