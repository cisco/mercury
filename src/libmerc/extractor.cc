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
#include "proto_identify.h"
#include "match.h"

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


/* SMTP client matching value */

unsigned char smtp_client_mask[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00
};

unsigned char smtp_client_value[] = {
    0x45, 0x48, 0x4c, 0x4f, 0x20, 0x00, 0x00, 0x00
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
                                         smtp_client_mask,
                                         smtp_client_value)) {
        return tcp_msg_type_smtp_client;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
                                         smtp_server_mask,
                                         smtp_server_value)) {
        return tcp_msg_type_smtp_server;
    }
    return tcp_msg_type_unknown;
}



