/*
 * extractor.c
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <string.h>   /* for memcpy()   */
#include <ctype.h>    /* for tolower()  */
#include <stdio.h>
#include <arpa/inet.h>  /* for htons()  */
#include <algorithm>
#include <map>

#include "ept.h"
#include "extractor.h"
#include "utils.h"
#include "proto_identify.h"
#include "eth.h"
#include "tcp.h"
#include "pkt_proc.h"
#include "udp.h"
#include "match.h"
#include "buffer_stream.h"
#include "asn1/x509.h"
#include "json_object.h"

/*
 * The extractor_debug macro is useful for debugging (but quite verbose)
 */
#ifndef DEBUG
#define extractor_debug(...)
#else
#define extractor_debug(...)  (fprintf(stdout, __VA_ARGS__))
#endif

/*
 * select_tcp_syn selects TCP SYNs for extraction
 */
bool select_tcp_syn = 1;

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

const struct pi_container *proto_identify_tcp(const uint8_t *tcp_data,
                                              unsigned int len) {

    if (len < sizeof(tls_client_hello_mask)) {
        return NULL;
    }

    // debug_print_u8_array(tcp_data);

    /* note: tcp_data will be 32-bit aligned as per the standard */

    if (u32_compare_masked_data_to_value(tcp_data,
                                         tls_client_hello_mask,
                                         tls_client_hello_value)) {
        return &https_client;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
                                         tls_server_hello_mask,
                                         tls_server_hello_value)) {
        return &https_server;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
					 tls_server_cert_mask,
					 tls_server_cert_value)) {
	return &https_server_cert;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
					 http_client_mask,
					 http_client_value)) {
	return &http_client;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
					 http_client_post_mask,
					 http_client_post_value)) {
	return &http_client;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
                                         http_server_mask,
                                         http_server_value)) {
        return &http_server;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
                                         ssh_mask,
                                         ssh_value)) {
        return &ssh;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
                                         ssh_kex_mask,
                                         ssh_kex_value)) {
        return &ssh_kex;
    }
    return NULL;
}


/* packet data methods */

void packet_data_set(struct packet_data *pd,
                     enum packet_data_type type,
                     size_t length,
                     const uint8_t *value) {
    pd->type = type;
    pd->length = length;
    pd->value = value;

}

void packet_data_init(struct packet_data *pd) {
    packet_data_set(pd, packet_data_type_none, 0, NULL);
}

/* extractor methods */

void extractor_init(struct extractor *x,
                    unsigned char *output,
                    unsigned int output_len) {

    //bzero(output, output_len); /* initialize the output buffer */
    x->proto_state.proto = PROTO_UNKNOWN;
    x->proto_state.dir = DIR_UNKNOWN;
    x->proto_state.state = state_start;
    x->output = output;
    x->output_start = x->output;
    x->output_end = output + output_len;

    x->fingerprint_type = fingerprint_type_unknown;
    x->last_capture = NULL;

    packet_data_init(&x->packet_data);
    x->transport_data.data = NULL;
    x->transport_data.data_end = NULL;
}

void parser_init(struct parser *p,
                 const unsigned char *data,
                 unsigned int data_len) {

    p->data = data;
    p->data_end = data + data_len;

    extractor_debug("%s: initialized with %td bytes\n", __func__, p->data_end - p->data);
}

void parser_init_from_outer_parser(struct parser *p,
                                   const struct parser *outer,
                                   unsigned int data_len) {
    const unsigned char *inner_data_end = outer->data + data_len;

    p->data = outer->data;
    p->data_end = inner_data_end > outer->data_end ? outer->data_end : inner_data_end;

    extractor_debug("%s: initialized with %td bytes\n", __func__, p->data_end - p->data);
}

void parser_pop(struct parser *inner, struct parser *outer) {
    outer->data = inner->data;
    extractor_debug("%s: outer parser now has %td bytes\n", __func__, outer->data_end - outer->data);
}

enum status parser_set_data_length(struct parser *p,
                                   unsigned int data_len) {

    extractor_debug("%s: set_data_length from %ld to %u\n", __func__, p->data_end - p->data, data_len);

    if (p->data + data_len <= p->data_end) {
        p->data_end = p->data + data_len;
        return status_ok;
    }
    return status_err;
}

enum status parser_skip(struct parser *p,
                        unsigned int len) {
    extractor_debug("%s: skipping %u bytes (%02x...)\n", __func__, len, p->data[0]);

    if (p->data + len <= p->data_end) {
        p->data = p->data + len;
        return status_ok;
    }
    extractor_debug("%s: error; tried to skip %u, only %td remaining\n", __func__, len, p->data_end - p->data);
    return status_err;
}

enum status parser_skip_to(struct parser *p,
                           const unsigned char *location) {

    if (location <= p->data_end) {
        p->data = location;
        return status_ok;
    }
    extractor_debug("%s: error; tried to skip %td, only %td remaining\n", __func__, location - p->data_end, p->data_end - p->data);
    return status_err;
}

enum status parser_read_uint(struct parser *p,
                             unsigned int num_bytes,
                             size_t *output) {

    if (p->data + num_bytes <= p->data_end) {
        size_t tmp = 0;
        const unsigned char *c;

        for (c = p->data; c < p->data + num_bytes; c++) {
            tmp = (tmp << 8) + *c;
        }
        *output = tmp;
        extractor_debug("%s: num_bytes: %u, value (hex) %08x (decimal): %zd\n", __func__, num_bytes, (unsigned)tmp, tmp);
        return status_ok;
    }
    return status_err;
}

enum status parser_read_and_skip_uint(struct parser *p,
                                      unsigned int num_bytes,
                                      size_t *output) {

    if (p->data && p->data + num_bytes <= p->data_end) {
        size_t tmp = 0;
        const unsigned char *c;

        for (c = p->data; c < p->data + num_bytes; c++) {
            tmp = (tmp << 8) + *c;
        }
        *output = tmp;
        p->data += num_bytes;
        extractor_debug("%s: num_bytes: %u, value (hex) %08x (decimal): %zu\n", __func__, num_bytes, (unsigned) tmp, tmp);
        return status_ok;
    }
    return status_err;
}

enum status parser_read_and_skip_byte_string(struct parser *p,
                                             unsigned int num_bytes,
                                             uint8_t *output_string) {

    if (p->data + num_bytes <= p->data_end) {
        const unsigned char *c;

        for (c = p->data; c < p->data + num_bytes; c++) {
            *output_string++ = *c;
        }
        p->data += num_bytes;
        extractor_debug("%s: num_bytes: %u\n", __func__, num_bytes);
        return status_ok;
    }
    return status_err;
}

enum status parser_extractor_copy(struct parser *p,
                                  struct extractor *x,
                                  unsigned int len) {

    extractor_debug("%s: copying %u bytes (%02x%02x...)\n", __func__, len, p->data[0], p->data[1]);

    if (p->data + len <= p->data_end && x->output + len + 2 <= x->output_end) {
        x->last_capture = x->output;
        encode_uint16(x->output, len);
        x->output += 2;
        memcpy(x->output, p->data, len);
        p->data += len;
        x->output += len;
        return status_ok;
    }
    extractor_debug("%s: error\n", __func__);
    return status_err;
}


enum status extractor_reserve(struct extractor *x,
                              unsigned char **data,
                              size_t length) {

    if (x->output + length <= x->output_end) {
        //  encode_uint16(x->output, len);
        *data = x->output;
        x->output += length;
        return status_ok;
    }
    extractor_debug("%s: error\n", __func__);
    return status_err;
}



enum status parser_extractor_copy_append(struct parser *p,
                                         struct extractor *x,
                                         unsigned int len) {

    if (p->data + len <= p->data_end && x->output + len <= x->output_end) {
        /*
         * add len into the previously encoded length in the output buffer
         */
        uint16_t tmp = decode_uint16(x->last_capture);
        encode_uint16(x->last_capture, tmp + len);

        /*
         * copy data to output buffer
         */
        memcpy(x->output, p->data, len);
        p->data += len;
        x->output += len;
        return status_ok;
    }
    extractor_debug("%s: error\n", __func__);
    return status_err;
}

enum status extractor_strip_last_capture(struct extractor *x) {

    if (x->last_capture) {
        uint16_t tmp = decode_uint16(x->last_capture);
        if (tmp == 0) {
            return status_err;
        }
        encode_uint16(x->last_capture, tmp - 1);
        x->output -= 1;
        return status_ok;
    }
    extractor_debug("%s: error\n", __func__);
    return status_err;
}

/*
 * parser_extractor_copy_append_upto_delim(p, x, d) will copy data
 * from the parser p to the extractor x, until it reaches the
 * delimiter d or the end of the data in the parser, whichever comes
 * first
 */
enum status parser_extractor_copy_append_upto_delim(struct parser *p,
                                                    struct extractor *x,
                                                    const unsigned char delim[2]) {
    const unsigned char *data = p->data;
    const unsigned char *data_end = p->data_end - 1;
    ptrdiff_t len;

    /* find delimiter, if present */
    while (1) {
        if (data >= data_end) {
            break;
        }
        if (*data == delim[0]) {
            data++;
            if (*data == delim[1]) {
                break;
            }
        }
        data++;
    }
    len = data - p->data - 1;

    if (*data == delim[1]) {
        /* copy_append data up to delimiter */
        if (parser_extractor_copy_append(p, x, len) == status_err) {
            extractor_debug("%s: error (at end of delimiter)\n", __func__);
            return status_err;
        }

        /* skip delimiter */
        return parser_skip(p, 2);
    } else {
        /* copy_append data up to data_end */
        if (parser_extractor_copy_append(p, x, data - p->data + 1) == status_err) {
            extractor_debug("%s: error (at end of data)\n", __func__);
            return status_err;
        }
    }
    return status_ok;
}

/*
 * parser_find_delim(p, d, l) looks for the delimiter d with length l
 * in the parser p's data buffer, until it reaches the delimiter d or
 * the end of the data in the parser, whichever comes first.  In the
 * first case, the function returns the number of bytes to the
 * delimiter; in the second case, the function returns the number of
 * bytes to the end of the data buffer.
 */
int parser_find_delim(struct parser *p,
                      const unsigned char *delim,
                      size_t length) {

    /* find delimiter, if present */
    const unsigned char *data = p->data;
    const unsigned char *pattern = delim;
    const unsigned char *pattern_end = delim + length;
    while (pattern < pattern_end && data < p->data_end) {
        extractor_debug("%s: data index: %lu\tpattern index: %lu\n", __func__, data - p->data, pattern - delim);
        extractor_debug("%s: data: %02x, pattern: %02x\n", __func__, *data, *pattern);
        if (*data != *pattern) {
            pattern = delim - 1; /* reset pattern to the start of the delimeter string */
        }
        data++;
        pattern++;
    }
    if (pattern == pattern_end) {
        return data - p->data;
    }
    return - (data - p->data);
}

enum status parser_skip_upto_delim(struct parser *p,
                                   const unsigned char delim[],
                                   size_t length) {

    int delim_index = parser_find_delim(p, delim, length);

    extractor_debug("%s: length: %zu, index: %d\n", __func__, length, delim_index);

    if (delim_index >= 0) {
        return parser_skip(p, delim_index);

    }
    extractor_debug("%s: error\n", __func__);
    return status_err;
}

enum status parser_extractor_copy_upto_delim(struct parser *p,
                                             struct extractor *x,
                                             const unsigned char delim[],
                                             size_t length) {

    int delim_index = parser_find_delim(p, delim, length);

    extractor_debug("%s: delim length: %zu, index: %d\n", __func__, length, delim_index);

    if (delim_index >= 0) {
        return parser_extractor_copy(p, x, delim_index - length);
    } else {
        return parser_extractor_copy(p, x, - delim_index);
    }
    extractor_debug("%s: error\n", __func__);
    return status_err;
}


#define FP_RAW_BUF_LEN 512

size_t extract_fp_from_tls_client_hello(uint8_t *data,
                                        size_t data_len,
                                        uint8_t *outbuf,
                                        size_t outbuf_len) {
    struct parser p;
    struct extractor x;
    uint8_t extractor_buffer[FP_RAW_BUF_LEN];
    size_t bytes_extracted;
    size_t bytes_in_outbuf = 0;

    extractor_init(&x, extractor_buffer, FP_RAW_BUF_LEN);
    parser_init(&p, data, data_len);
    bytes_extracted = parser_extractor_process_tls(&p, &x);

    if (bytes_extracted > 0) {
	switch(x.fingerprint_type) {
	case fingerprint_type_tls:
	    bytes_in_outbuf = sprintf_binary_ept_as_paren_ept(extractor_buffer, bytes_extracted, outbuf, outbuf_len);
	    break;
	default:
	    break;
	}
    }

    return bytes_in_outbuf;
}

ptrdiff_t parser_get_data_length(struct parser *p) {
    return p->data_end - p->data;
}

ptrdiff_t extractor_get_output_length(const struct extractor *x) {
    return x->output - x->output_start;
}

/*
 * parser_match(x, value, value_len, mask) returns status_ok if
 * (x->data & mask) == value, and returns status_err otherwise
 * It advances p->data by value_len when it returns status_ok
 */
unsigned int parser_match(struct parser *p,
                          const unsigned char *value,
                          size_t value_len,
                          const unsigned char *mask) {

    if (p->data + value_len <= p->data_end) {
        unsigned int i;

        if (mask) {
            for (i = 0; i < value_len; i++) {
                if ((p->data[i] & mask[i]) != value[i]) {
                    return status_err;
                }
            }
        } else { /* mask == NULL */
            for (i = 0; i < value_len; i++) {
                if (p->data[i] != value[i]) {
                    return status_err;
                }
            }
        }
        p->data += value_len;
        return status_ok;
    }
    return status_err;
}

/*
 * extractor_keyword_match_last_capture(x, keywords) returns status_ok
 * if the extractor x's last capture matches a keyword, and returns
 * status_err if it does not match, or if there was no last capture
 */
unsigned int extractor_keyword_match_last_capture(struct extractor *x,
                                                  const keyword_matcher_t *keywords) {

    unsigned char *last_capture = x->last_capture;
    size_t last_capture_len;

    if (last_capture == NULL) {
        return status_err;
    }

    /* read length of capture, then advance over length field */
    last_capture_len = decode_uint16(last_capture);  /* cache this length? */
    last_capture += 2;

    return keyword_matcher_check(keywords, last_capture, last_capture_len);
}

/*
 * extractor_delete_last_capture(x) removes the last capture (if any)
 * from the extractor, returning status_ok to indicate that the
 * previous capture was deleted, or returning status_err to indicate
 * that there was no previous capture that could be deleted.  If this
 * function is called two or more times successively, all invocations
 * after the first will return status_err, because the extractor does
 * not remember *all* previous captures, but only the most recent.
 */
enum status extractor_delete_last_capture(struct extractor *x) {

    if (x->last_capture != NULL) {
        x->output = x->last_capture;
        x->last_capture = NULL;
        return status_ok;
    }
    return status_err;
}

/*
 * TCP fingerprinting
 *
 * The following data are extracted from the SYN packet: the ordered
 * list of all TCP option kinds, with repeated values allowed in the
 * list.  The length and data for the MSS and WS TCP options are
 * included, but are not for other option kinds.
 */

/*
 * TCP header as per RFC 793
 *
 *    0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Source Port          |       Destination Port        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                        Sequence Number                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Acknowledgment Number                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Data |       |C|E|U|A|P|R|S|F|                               |
 *  | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
 *  |       |       |R|E|G|K|H|T|N|N|                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           Checksum            |         Urgent Pointer        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Options                    |    Padding    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                             data                              |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/*
 * TCP macros
 *
 * The following macros indicate the lengths of each field in the TCP
 * header, in the same order of appearance as on the wire.  The needed
 * option kinds (EOL, NOP, MSS, and WS) are defined, as is the value
 * of the Flag field for a SYN pakcet (TCP_SYN).
 */

#define L_src_port      2
#define L_dst_port      2
#define L_tcp_seq       4
#define L_tcp_ack       4
#define L_tcp_offrsv    1
#define L_tcp_flags     1
#define L_tcp_win       2
#define L_tcp_csm       2
#define L_tcp_urp       2
#define L_option_kind   1
#define L_option_length 1

#define TCP_OPT_EOL     0
#define TCP_OPT_NOP     1
#define TCP_OPT_MSS     2
#define TCP_OPT_WS      3

#define TCP_FIN      0x01
#define TCP_SYN      0x02
#define TCP_RST      0x04
#define TCP_PSH      0x08
#define TCP_ACK      0x10
#define TCP_URG      0x20
#define TCP_ECE      0x40
#define TCP_CWR      0x80

#define TCP_FIXED_HDR_LEN 20

#define tcp_offrsv_get_length(offrsv) ((offrsv >> 4) * 4)

/*
 * The function extractor_process_tcp processes a TCP packet.  The
 * extractor MUST have previously been initialized with its data
 * pointer set to the initial octet of a TCP header.
 */

unsigned int tcp_message_filter_cutoff = 0;

unsigned int packet_filter_process_tcp(struct packet_filter *pf, struct key *k) {
    size_t flags, offrsv;
    const uint8_t *data = pf->p.data;
    struct parser *p = &pf->p;
    struct extractor *x = &pf->x;

    extractor_debug("%s: processing packet (len %td)\n", __func__, parser_get_data_length(p));

    const struct tcp_header *tcp = (const struct tcp_header *)data;
    if (pf->tcp_init_msg_filter) {
        return pf->tcp_init_msg_filter->apply(*k, tcp, parser_get_data_length(p));
    }

    size_t tmp;
    if (parser_read_and_skip_uint(p, L_src_port, &tmp) == status_err) {
        return 0;
    }
    k->src_port = tmp;
    if (parser_read_and_skip_uint(p, L_dst_port, &tmp) == status_err) {
        return 0;
    }
    k->dst_port = tmp;
    if (parser_skip(p, L_tcp_seq + L_tcp_ack) == status_err) {
        return 0;
    }
    if (parser_read_uint(p, L_tcp_offrsv, &offrsv) == status_err) {
        return 0;
    }
    if (parser_skip(p, L_tcp_offrsv) == status_err) {
        return 0;
    }
    if (parser_read_uint(p, L_tcp_flags, &flags) == status_err) {
        return 0;
    }
    if ((flags & TCP_SYN) == 0) {
        /*
         * process the TCP Data payload
         */
        if (parser_skip_to(p, data + tcp_offrsv_get_length(offrsv)) == status_err) {
            return 0;
        }
        return parser_extractor_process_tcp_data(p, x);

    }
    if (flags & TCP_ACK) {
        return 0;   // we ignore SYN/ACK packets
    }

    if (parser_skip(p, L_tcp_flags) == status_err) {
	return 0;
    }
    if (parser_extractor_copy(p, x, L_tcp_win) == status_err) {
	return 0;
    }
    if (parser_skip(p, L_tcp_csm + L_tcp_urp) == status_err) {
	return 0;
    }
    if (parser_set_data_length(p, tcp_offrsv_get_length(offrsv) - TCP_FIXED_HDR_LEN)) {
        return 0;
    }

    if (select_tcp_syn == 0) {
        return 0; /* packet filter configuration does not want TCP SYN packets */
    }

    /* set fingerprint type TCP, since we succeeded in parsing the header up to the options */
    x->fingerprint_type = fingerprint_type_tcp;

    while (parser_get_data_length(p) > 0) {
        size_t option_kind, option_length;

        if (parser_read_uint(p, L_option_kind, &option_kind) == status_err) {
            break;
        }
        if (parser_extractor_copy(p, x, L_option_kind) == status_err) {
            break;
        }

        if (option_kind == TCP_OPT_EOL || option_kind == TCP_OPT_NOP) {

            /* note: no option_length field is present for these kinds */
            ;

        } else {
            if (parser_read_uint(p, L_option_length, &option_length) == status_err) {
                break;
            }
            if (option_kind == TCP_OPT_MSS || option_kind == TCP_OPT_WS) {

                if (parser_extractor_copy_append(p, x, option_length - L_option_kind) == status_err) {
                    break;
                }
            } else {

                if (parser_skip(p, option_length - L_option_kind) == status_err) {
                    break;
                }
            }
        }
    }

    x->proto_state.state = state_done;

    return extractor_get_output_length(x);
}


/*
 * TLS fingerprint extraction
 */

uint16_t degrease_uint16(uint16_t x) {
    switch(x) {
    case 0x0a0a:
    case 0x1a1a:
    case 0x2a2a:
    case 0x3a3a:
    case 0x4a4a:
    case 0x5a5a:
    case 0x6a6a:
    case 0x7a7a:
    case 0x8a8a:
    case 0x9a9a:
    case 0xaaaa:
    case 0xbaba:
    case 0xcaca:
    case 0xdada:
    case 0xeaea:
    case 0xfafa:
        return 0x0a0a;
        break;
    default:
        return x;
    }
    return x;
}

void degrease_octet_string(void *data, ssize_t len) {
    if (len < 0) {
        return;
    }

    uint16_t *x = (uint16_t *)data;
    uint16_t *end = x + (len/2);

    while (x < end) {
        *x = degrease_uint16(*x);
        x++;
    }

}

/* TLS Constants */

#define L_ContentType              1
#define L_ProtocolVersion          2
#define L_RecordLength             2
#define L_HandshakeType            1
#define L_HandshakeLength          3
#define L_ProtocolVersion          2
#define L_Random                  32
#define L_SessionIDLength          1
#define L_CipherSuiteVectorLength  2
#define L_CompressionMethodsLength 1
#define L_ExtensionsVectorLength   2
#define L_ExtensionType            2
#define L_ExtensionLength          2

#define L_NamedGroupListLen        2
#define L_ProtocolVersionListLen   1

/*
 * expanded set of static extensions
 */
#define num_static_extension_types 34

/*
 * extension types used in normalization
 */
#define type_sni                0x0000
#define type_supported_groups   0x000a
#define type_supported_versions 0x002b

uint16_t old_static_extension_types[7] __attribute__((unused)) = {
	5,         /* status_request                         */
	10,        /* supported_groups                       */
	11,        /* ec_point_formats                       */
	13,        /* signature_algorithms                   */
	16,        /* application_layer_protocol_negotiation */
	43,        /* supported_versions                     */
	45         /* psk_key_exchange_modes                 */
    };

uint16_t static_extension_types[num_static_extension_types] = {
        1,         /* max fragment length                    */
        5,         /* status_request                         */
        7,         /* client authz                           */
        8,         /* server authz                           */
        9,         /* cert type                              */
        10,        /* supported_groups                       */
        11,        /* ec_point_formats                       */
        13,        /* signature_algorithms                   */
        15,        /* heartbeat                              */
        16,        /* application_layer_protocol_negotiation */
        17,        /* status request v2                      */
        24,        /* token binding                          */
        27,        /* compressed certificate                 */
        28,        /* record size limit                      */
        43,        /* supported_versions                     */
        45,        /* psk_key_exchange_modes                 */
        50,        /* signature algorithms cert              */
        2570,      /* GREASE                                 */
        6682,      /* GREASE                                 */
        10794,     /* GREASE                                 */
        14906,     /* GREASE                                 */
        19018,     /* GREASE                                 */
        21760,     /* token binding (old)                    */
        23130,     /* GREASE                                 */
        27242,     /* GREASE                                 */
        31354,     /* GREASE                                 */
        35466,     /* GREASE                                 */
        39578,     /* GREASE                                 */
        43690,     /* GREASE                                 */
        47802,     /* GREASE                                 */
        51914,     /* GREASE                                 */
        56026,     /* GREASE                                 */
        60138,     /* GREASE                                 */
        64250      /* GREASE                                 */
    };


/*
 * The function extractor_process_tls processes a TLS packet.  The
 * extractor MUST have previously been initialized with its data
 * pointer set to the initial octet of the TCP header of the TLS
 * packet.
 */
unsigned int parser_extractor_process_tls(struct parser *p, struct extractor *x) {
    size_t tmp_len;
    //struct extractor y;
    struct parser ext_parser;
    const uint8_t *sni_data = NULL;
    size_t sni_length = 0;
    unsigned char *ext_len_slot = NULL;

    extractor_debug("%s: processing packet\n", __func__);

    /*
     * verify that we are looking at a TLS ClientHello
     */
    if (parser_match(p,
                     tls_client_hello_value,
                     L_ContentType +    L_ProtocolVersion + L_RecordLength + L_HandshakeType,
                     tls_client_hello_mask) == status_err) {
        return 0; /* not a clientHello */
    }

#if 0 /* REMOVED during adaptation from joy*/
    uint16_t tls_proto_number = htons(HTTPS_PORT);
    if (extractor_write_to_output(x, (unsigned char *)&tls_proto_number, sizeof(tls_proto_number)) == status_err) {
        return 0;
    }
#endif
    x->fingerprint_type = fingerprint_type_tls;

    /*
     * skip over initial fields
     */
    if (parser_skip(p, L_HandshakeLength) == status_err) {
        return 0;
    }

    /*
     * copy clientHello.ProtocolVersion
     */
    if (parser_extractor_copy(p, x, L_ProtocolVersion) == status_err) {
        goto bail;
    }

    /*
     * skip over Random
     */
    if (parser_skip(p, L_Random) == status_err) {
        goto bail;
    }

    /* skip over SessionID and SessionIDLen */
    if (parser_read_uint(p, L_SessionIDLength, &tmp_len) == status_err) {
        goto bail;
    }
    if (parser_skip(p, tmp_len + L_SessionIDLength) == status_err) {
        goto bail;
    }

    /* copy ciphersuite offer vector */
    if (parser_read_uint(p, L_CipherSuiteVectorLength, &tmp_len) == status_err) {
        goto bail;
    }
    if (parser_skip(p, L_CipherSuiteVectorLength) == status_err) {
        goto bail;
    }
    if (parser_extractor_copy(p, x, tmp_len) == status_err) {
        goto bail;
    }
    degrease_octet_string(x->last_capture + 2, tmp_len);

    /* skip over compression methods */
    if (parser_read_uint(p, L_CompressionMethodsLength, &tmp_len) == status_err) {
        goto bail;
    }
    if (parser_skip(p, tmp_len + L_CompressionMethodsLength) == status_err) {
        goto bail;
    }

    /*
     * parse extensions vector
     */
    /*
     * reserve slot in output for length of extracted extensions
     */
    if (extractor_reserve(x, &ext_len_slot, sizeof(uint16_t))) {
        goto bail;
    }

    /*  extensions length */
    if (parser_read_and_skip_uint(p, L_ExtensionsVectorLength, &tmp_len)) {
        goto bail;
    }
    parser_init_from_outer_parser(&ext_parser, p, tmp_len);
    while (parser_get_data_length(&ext_parser) > 0) {
        size_t tmp_type;

        if (parser_read_uint(&ext_parser, L_ExtensionType, &tmp_type) == status_err) {
            break;
        }
        if (tmp_type == type_sni) {
            /*
             * grab Server Name Indication so that we can report it separately
             */
            sni_data = ext_parser.data;
        }

        if (parser_extractor_copy(&ext_parser, x, L_ExtensionType) == status_err) {
            break;
        }
        /* degrease extracted type code */
        degrease_octet_string(x->last_capture + 2, L_ExtensionType);

        if (parser_read_uint(&ext_parser, L_ExtensionLength, &tmp_len) == status_err) {
            break;
        }
        if (tmp_type == type_sni) {
            /*
             * grab Server Name Indication length
             */
            sni_length = tmp_len + L_ExtensionLength + L_ExtensionType;
            if (sni_data + sni_length > p->data_end) {
                sni_length = p->data_end - sni_data;   /* trim to fit in packet */
            }
        }

        if (uint16_match(tmp_type, static_extension_types, num_static_extension_types) == status_err) {
            if (parser_extractor_copy_append(&ext_parser, x, tmp_len + L_ExtensionLength) == status_err) {
                break;
            }
            if (tmp_type == type_supported_groups) {
                degrease_octet_string(x->last_capture + 2 + L_ExtensionLength + L_ExtensionType + L_NamedGroupListLen,
                                      tmp_len - L_NamedGroupListLen);
            }
            if (tmp_type == type_supported_versions) {
                degrease_octet_string(x->last_capture + 2 + L_ExtensionLength + L_ExtensionType + L_ProtocolVersionListLen,
                                      tmp_len - L_ProtocolVersionListLen);
            }

        } else {

            if (parser_skip(&ext_parser, tmp_len + L_ExtensionLength) == status_err) {
                break;
            }
        }
    }

    /*
     * write the length of the extracted extensions into the reserved slot
     */
    //size_t ext_len_value = (x->output - ext_len_slot) | PARENT_NODE_INDICATOR;
    encode_uint16(ext_len_slot, (x->output - ext_len_slot - sizeof(uint16_t)) | PARENT_NODE_INDICATOR);

    if (sni_data) {
        packet_data_set(&x->packet_data, packet_data_type_tls_sni, sni_length, sni_data);
    }

    x->proto_state.state = state_done;

    return extractor_get_output_length(x);

 bail:
    /*
     * handle possible packet parsing errors
     */
    extractor_debug("%s: warning: TLS clientHello processing did not fully complete\n", __func__);
    return extractor_get_output_length(x);

}


/*
 * field lengths used in serverHello parsing
 */
#define L_CipherSuite              2
#define L_CompressionMethod        1
#define L_CertificateLength        3
#define L_CertificateListLength    3

enum status parser_extractor_process_certificate(struct parser *p, struct extractor *x) {
    size_t tmp_len;

    extractor_debug("%s: processing new tls certificate list \n", __func__);

    /* get total certificate length */
    if (parser_read_and_skip_uint(p, L_CertificateListLength, &tmp_len) == status_err) {
	    return status_err;
    }

    if (tmp_len > (unsigned)parser_get_data_length(p)) {
        tmp_len = parser_get_data_length(p);
    }
    
    /* we have some certificate data in this packet */
    packet_data_set(&x->packet_data,
                    packet_data_type_tls_cert,
                    tmp_len,
                    p->data);

    parser_skip(p, tmp_len);  
    
    extractor_debug("%s: completed \n", __func__);

    return status_ok;
}

/**
 * Extract and print binary certificate(s) as base64 encoded string(s).
 */

void write_extract_certificates(struct json_array &a, const unsigned char *data, size_t data_len) {
    size_t tmp_len;
    struct parser cert_list;
    parser_init(&cert_list, data, data_len);

    while (parser_get_data_length(&cert_list) > 0) {
        /* get certificate length */
        if (parser_read_and_skip_uint(&cert_list, L_CertificateLength, &tmp_len) == status_err) {
	        return;
        }

        if (tmp_len > (unsigned)parser_get_data_length(&cert_list)) {
            tmp_len = parser_get_data_length(&cert_list); /* truncate */
        }

        if (tmp_len == 0) {
            return; /* don't bother printing out a partial cert if it has a length of zero */
        }

        struct json_object o{a};
        struct parser cert_parser{cert_list.data, cert_list.data + tmp_len};
        o.print_key_base64("base64", cert_parser);
        o.close();

        /*
         * advance parser over certificate data
         */
        if (parser_skip(&cert_list, tmp_len) == status_err) {
	        return;
        }
    }

}

void write_extract_cert_full(struct json_array &a, const unsigned char *data, size_t data_len) {
    size_t tmp_len;
    struct parser cert_list;
    parser_init(&cert_list, data, data_len);

    while (parser_get_data_length(&cert_list) > 0) {
        /* get certificate length */
        if (parser_read_and_skip_uint(&cert_list, L_CertificateLength, &tmp_len) == status_err) {
	        return;
        }

        if (tmp_len > (unsigned)parser_get_data_length(&cert_list)) {
            tmp_len = parser_get_data_length(&cert_list); /* truncate */
        }

        if (tmp_len == 0) {
            return; /* don't bother printing out a partial cert if it has a length of zero */
        }

        struct json_object o{a};
        struct json_object_asn1 cert{o, "cert"};
        struct x509_cert c;
        c.parse(cert_list.data, tmp_len);
        c.print_as_json(cert, {});
        cert.close();
        o.close();

        break; // only report first certificate for now
    }

}


enum status parser_extractor_process_tls_server_hello(struct parser *record, struct extractor *x) {
    size_t tmp_len;
    size_t tmp_type;
    unsigned char *ext_len_slot = NULL;

    extractor_debug("%s: processing server_hello with %td bytes\n", __func__, record->data_end - record->data);

    /* set fingerprint type */
    x->fingerprint_type = fingerprint_type_tls_server;

    /*
     * copy serverHello.ProtocolVersion
     */
    if (parser_extractor_copy(record, x, L_ProtocolVersion) == status_err) {
	    goto bail;
    }

    /*
     * skip over Random
     */
    if (parser_skip(record, L_Random) == status_err) {
	    goto bail;
    }

    /* skip over SessionID and SessionIDLen */
    if (parser_read_uint(record, L_SessionIDLength, &tmp_len) == status_err) {
	    goto bail;
    }
    if (parser_skip(record, tmp_len + L_SessionIDLength) == status_err) {
	    goto bail;
    }

    if (parser_extractor_copy(record, x, L_CipherSuite) == status_err) {
	    goto bail;
    }

    /* skip over compression method */
    if (parser_skip(record, L_CompressionMethod) == status_err) {
	    goto bail;
    }

    /*
     * reserve slot in output for length of extracted extensions
     */
    if (extractor_reserve(x, &ext_len_slot, sizeof(uint16_t))) {
        goto bail;
    }

    /*
     * parse extensions vector (if present)
     */
    if (parser_get_data_length(record) > 0) {

        extractor_debug("%s: parsing extensions vector\n", __func__);

        /*  extensions length */
        if (parser_read_and_skip_uint(record, L_ExtensionsVectorLength, &tmp_len)) {
            goto bail;
        }

        struct parser ext_parser;
        parser_init_from_outer_parser(&ext_parser, record, tmp_len);

        while (parser_get_data_length(&ext_parser) > 0)  {

            if (parser_read_uint(&ext_parser, L_ExtensionType, &tmp_type) == status_err) {
                break;
            }
            if (parser_extractor_copy(&ext_parser, x, L_ExtensionType) == status_err) {
                break;
            }
            if (parser_read_uint(&ext_parser, L_ExtensionLength, &tmp_len) == status_err) {
                break;
            }
            if (uint16_match(tmp_type, static_extension_types, num_static_extension_types) == status_err)  {
                if (parser_extractor_copy_append(&ext_parser, x, tmp_len + L_ExtensionLength) == status_err)  {
                    break;
                }
            }
            else {
                if (parser_skip(&ext_parser, tmp_len + L_ExtensionLength) == status_err) {
                    break;
                }
            }
        }

        extractor_debug("%s: ext_parser has %td bytes\n", __func__, ext_parser.data_end - ext_parser.data);

        parser_pop(&ext_parser, record);

        extractor_debug("%s: record has %td bytes\n", __func__, record->data_end - record->data);

    } 

    /*
     * write the length of the extracted extensions (if any) into the reserved slot
     */
    encode_uint16(ext_len_slot, (x->output - ext_len_slot - sizeof(uint16_t)) | PARENT_NODE_INDICATOR);

    return status_ok;

 bail:
    return status_err;
}

/*
 * The function parser_process_tls_server processes a TLS
 * serverHello packet.  The parser MUST have previously been
 * initialized with its data pointer set to the initial octet of the
 * TCP header of the TLS packet.
 */
unsigned int parser_extractor_process_tls_server(struct parser *p, struct extractor *x) {
    size_t tmp_len;
    size_t tmp_type;

    extractor_debug("%s: processing packet with %td bytes\n", __func__, p->data_end - p->data);

    /*
     * verify that we are looking at a TLS record
     */
    if (parser_read_and_skip_uint(p, L_ContentType, &tmp_type) == status_err) {
        goto bail;
    }
    if (tmp_type != 0x16) {
        goto bail;    /* not a handshake record */
    }
    if (parser_skip(p, L_ProtocolVersion) == status_err) {
	    goto bail;
    }
    if (parser_read_and_skip_uint(p, L_RecordLength, &tmp_len) == status_err) {
      goto bail;
    }
    extractor_debug("%s: got a record\n", __func__);
    struct parser record;
    parser_init_from_outer_parser(&record, p, tmp_len);

    if (parser_read_and_skip_uint(&record, L_HandshakeType, &tmp_type) == status_err) {
	    goto bail;
    }
    if (tmp_type != 0x02) {
        goto bail;     /* not a serverHello */
    }

    if (parser_read_and_skip_uint(&record, L_HandshakeLength, &tmp_len) == status_err) {
	    goto bail;
    }
    extractor_debug("%s: got a handshake\n", __func__);
    struct parser handshake;
    parser_init_from_outer_parser(&handshake, &record, tmp_len);
    if (parser_extractor_process_tls_server_hello(&handshake, x) != status_ok) {
        goto bail;
    }
    parser_pop(&handshake, &record);

    if (parser_get_data_length(&record) > 0) {

        extractor_debug("%s: expecting another handshake structure\n", __func__);
        size_t tmp_type;
        if (parser_read_and_skip_uint(&record, L_HandshakeType, &tmp_type) == status_err) {
            goto bail;
        }
        if (tmp_type != 11) { /* certificate */
            goto done;
        }
        if (parser_skip(&record, L_HandshakeLength) == status_err) {
            goto done;
        }
        if (parser_extractor_process_certificate(&record, x) == status_err) {
            goto done;
        }
    }
    parser_pop(&record, p);

    extractor_debug("%s: outermost parser has %td bytes\n", __func__, p->data_end - p->data);

    /* process data as a new record */
    if (parser_get_data_length(p) > 0) {

        extractor_debug("%s: expecting another record\n", __func__);

        if (parser_read_and_skip_uint(p, L_ContentType, &tmp_type) == status_err) {
            goto done;
        }
        if (tmp_type != 0x16) {
            goto done;    /* not a handshake record */
        }
        if (parser_skip(p, L_ProtocolVersion) == status_err) {
            goto done;
        }
        if (parser_read_and_skip_uint(p, L_RecordLength, &tmp_len) == status_err) {
            goto done;
        }
        struct parser record;
        parser_init_from_outer_parser(&record, p, tmp_len);

        extractor_debug("%s: new record has %td bytes\n", __func__, record.data_end - record.data);

        size_t tmp_type;
        if (parser_read_and_skip_uint(&record, L_HandshakeType, &tmp_type) == status_err) {
            goto done;
        }
        if (tmp_type == 11) { /* certificate */
            if (parser_skip(&record, L_HandshakeLength) == status_err) {
                goto done;
            }
            if (parser_extractor_process_certificate(&record, x) == status_err) {
                goto done;
            }
        }
    }

 done:
    x->proto_state.state = state_done;

    extractor_debug("%s: extractor_output_length: %td bytes\n", __func__, extractor_get_output_length(x));

    return extractor_get_output_length(x);

 bail:
    /*
     * handle possible packet parsing errors
     */
    extractor_debug("%s: warning: TLS serverHello processing did not fully complete\n", __func__);
    return 0;

}

unsigned int parser_extractor_process_tls_server_cert(struct parser *p, struct extractor *x) {

    extractor_debug("%s: Processing server certificate at the beginning, len = %lu, output len = %lu\n",
            __func__, parser_get_data_length(p), extractor_get_output_length(x));

    int skip_len = (L_ContentType + L_ProtocolVersion + L_RecordLength + L_HandshakeType + L_CertificateLength);

    if (parser_skip(p, skip_len) == status_err) {
        goto bail;
    }

    if (parser_extractor_process_certificate(p, x) == status_err) {
        goto bail;
    }

    return 0; 

bail:
    /*
     * handle possible packet parsing errors
     */
    extractor_debug("%s: warning: processing did not complete\n", __func__);
    return 0;
}


/*
 * The function parser_extractor_process_http processes an HTTP
 * packet.  The parser MUST have previously been initialized with its
 * data pointer set to the initial octet of a TCP header.
 */

#define http_value_len 4

unsigned int parser_extractor_process_http(struct parser *p, struct extractor *x) {
    keyword_t user_agent_keyword[2] = {
        keyword_init("user-agent"),
        keyword_init("")
    };
    keyword_matcher_t user_agent_keyword_matcher = {
        user_agent_keyword,
        NULL
    };
    //unsigned char http_mask[http_value_len] = {
    //  0xff, 0xff, 0xff, 0xff
    //};
    //unsigned char http_value[http_value_len] = {
    //  0x47, 0x45, 0x54, 0x20
    //};
    // unsigned char sl[1] = { '/' };
    unsigned char sp[1] = { ' ' };
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };
    keyword_t http_static_name_and_value[] = {
        keyword_init("accept"),
        keyword_init("accept-encoding"),
        keyword_init("connection"),
        keyword_init("dnt"),
        keyword_init("dpr"),
        keyword_init("upgrade-insecure-requests"),
        keyword_init("x-requested-with"),
        keyword_init("")
    };
    keyword_t http_static_name[] = {
        keyword_init("accept-charset"),
        keyword_init("accept-language"),
        keyword_init("authorization"),
        keyword_init("cache-control"),
        keyword_init("host"),
        keyword_init("if-modified-since"),
        keyword_init("keep-alive"),
        keyword_init("user-agent"),
        keyword_init("x-flash-version"),
        keyword_init("x-p2p-peerdist"),
        keyword_init("")
    };
    keyword_matcher_t matcher_http_static_name_and_value = {
        http_static_name_and_value, /* case insensitive */
        NULL                        /* case sensitive   */
    };
    keyword_matcher_t matcher_http_static_name = {
        http_static_name,           /* case insensitive */
        NULL                        /* case sensitive   */
    };
    extractor_debug("%s: processing packet\n", __func__);

#if 0
    uint16_t http_proto_number = htons(HTTP_PORT);
    if (extractor_write_to_output(x, (unsigned char *)&http_proto_number, sizeof(http_proto_number)) == status_err) {
        return 0;
    }
#endif /* REMOVED during port from joy */

    /*
     * verify that we are looking at HTTP
     */
    //if (parser_match(x, http_value, http_value_len, http_mask) == status_err) {
    //  return 0; /* not an HTTP GET */
    //}
    x->fingerprint_type = fingerprint_type_http;

    /* process request line */
    if (parser_extractor_copy_upto_delim(p, x, sp, sizeof(sp)) == status_err) {
        return extractor_get_output_length(x);
    }
    if (parser_skip(p, sizeof(sp)) == status_err) {
        return extractor_get_output_length(x);
    }
    if (parser_skip_upto_delim(p, sp, sizeof(sp)) == status_err) {
        return extractor_get_output_length(x);
    }
    //    if (extractor_skip_upto_delim(x, sl, sizeof(sl)) == status_err) {
    //  return extractor_get_output_length(x);
    //}
    if (parser_extractor_copy_upto_delim(p, x, crlf, sizeof(crlf)) == status_err) {
        return extractor_get_output_length(x);
    }
    if (parser_skip(p, sizeof(crlf)) == status_err) {
        return extractor_get_output_length(x);
    }

    while (parser_get_data_length(p) > 0) {
        if (parser_match(p, crlf, sizeof(crlf), NULL) == status_ok) {
            break;  /* at end of headers */
        }
        if (parser_extractor_copy_upto_delim(p, x, csp, sizeof(csp)) == status_err) {
            return extractor_get_output_length(x);
        }
        if (extractor_keyword_match_last_capture(x, &matcher_http_static_name_and_value) == status_ok) {
            if (parser_extractor_copy_append_upto_delim(p, x, crlf) == status_err) {
                return extractor_get_output_length(x);
            }
        } else {
            const uint8_t *user_agent_string = NULL;
            if (extractor_keyword_match_last_capture(x, &user_agent_keyword_matcher) == status_ok) {
                /* store user agent value */
                if (parser_skip_upto_delim(p, csp, sizeof(csp)) == status_err) {
                    return extractor_get_output_length(x);
                }
                user_agent_string = p->data;
            }

            if (extractor_keyword_match_last_capture(x, &matcher_http_static_name) != status_ok) {
                extractor_delete_last_capture(x);
            }

            if (parser_skip_upto_delim(p, crlf, sizeof(crlf)) == status_err) {
                return extractor_get_output_length(x);
            }
            if (user_agent_string) {
                size_t ua_len = p->data - user_agent_string;
                ua_len = ua_len > sizeof(crlf) ? ua_len - sizeof(crlf) : 0;
                packet_data_set(&x->packet_data,
                                packet_data_type_http_user_agent,
                                ua_len,
                                user_agent_string);
            }
        }
    }

    extractor_debug("%s: http DONE\n", __func__);

    x->proto_state.state = state_done;

    return extractor_get_output_length(x);
}

/*
 * http server processing
 */

keyword_t http_server_static_name[] = {
    keyword_init("appex-activity-id"),
    keyword_init("cdnuuid"),
    keyword_init("cf-ray"),
    keyword_init("content-range"),
    keyword_init("content-type"),
    keyword_init("date"),
    keyword_init("etag"),
    keyword_init("expires"),
    keyword_init("flow_context"),
    keyword_init("ms-cv"),
    keyword_init("msregion"),
    keyword_init("ms-requestid"),
    keyword_init("request-id"),
    keyword_init("vary"),
    keyword_init("x-amz-cf-pop"),
    keyword_init("x-amz-request-id"),
    keyword_init("x-azure-ref-originshield"),
    keyword_init("x-cache"),
    keyword_init("x-cache-hits"),
    keyword_init("x-ccc"),
    keyword_init("x-diagnostic-s"),
    keyword_init("x-feserver"),
    keyword_init("x-hw"),
    keyword_init("x-msedge-ref"),
    keyword_init("x-ocsp-responder-id"),
    keyword_init("x-requestid"),
    keyword_init("x-served-by"),
    keyword_init("x-timer"),
    keyword_init("x-trace-context"),
    keyword_init("")
};

keyword_t http_server_static_name_and_value[] = {
    keyword_init("access-control-allow-credentials"),
    keyword_init("access-control-allow-headers"),
    keyword_init("access-control-allow-methods"),
    keyword_init("access-control-expose-headers"),
    keyword_init("cache-control"),
    keyword_init("code"),
    keyword_init("connection"),
    keyword_init("content-language"),
    keyword_init("content-transfer-encoding"),
    keyword_init("p3p"),
    keyword_init("pragma"),
    keyword_init("reason"),
    keyword_init("server"),
    keyword_init("strict-transport-security"),
    keyword_init("version"),
    keyword_init("x-aspnetmvc-version"),
    keyword_init("x-aspnet-version"),
    keyword_init("x-cid"),
    keyword_init("x-ms-version"),
    keyword_init("x-xss-protection"),
    keyword_init("")
};
keyword_matcher_t matcher_http_server_static_name_and_value = {
    http_server_static_name_and_value, /* case insensitive */
    NULL                               /* case sensitive   */
};
keyword_matcher_t matcher_http_server_static_name = {
    http_server_static_name,           /* case insensitive */
    NULL                               /* case sensitive   */
};

unsigned int parser_extractor_process_http_server(struct parser *p, struct extractor *x) {
    unsigned char sp[1] = { ' ' };
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };

    extractor_debug("%s: processing packet\n", __func__);

#if 0
    uint16_t http_proto_number = htons(HTTP_PORT);
    if (extractor_write_to_output(x, (unsigned char *)&http_proto_number, sizeof(http_proto_number)) == status_err) {
        return 0;
    }
#endif /* REMOVED during port from joy */

    x->fingerprint_type = fingerprint_type_http_server;

    /*
     * process status line
     */
    /* copy HTTP version */
    if (parser_extractor_copy_upto_delim(p, x, sp, sizeof(sp)) == status_err) {
        return extractor_get_output_length(x);
    }
    if (parser_skip(p, sizeof(sp)) == status_err) {
        return extractor_get_output_length(x);
    }
    /* copy status code */
    if (parser_extractor_copy_upto_delim(p, x, sp, sizeof(sp)) == status_err) {
        return extractor_get_output_length(x);
    }
    if (parser_skip(p, sizeof(sp)) == status_err) {
        return extractor_get_output_length(x);
    }
    /* copy reason phrase */
    if (parser_extractor_copy_upto_delim(p, x, crlf, sizeof(crlf)) == status_err) {
        return extractor_get_output_length(x);
    }
    if (parser_skip(p, sizeof(crlf)) == status_err) {
        return extractor_get_output_length(x);
    }

    /* process headers */
    while (parser_get_data_length(p) > 0) {
        if (parser_match(p, crlf, sizeof(crlf), NULL) == status_ok) {
            break;  /* at end of headers */
        }
        if (parser_extractor_copy_upto_delim(p, x, csp, sizeof(csp)) == status_err) {
            return extractor_get_output_length(x);
        }
        if (extractor_keyword_match_last_capture(x, &matcher_http_server_static_name_and_value) == status_ok) {
            if (parser_extractor_copy_append_upto_delim(p, x, crlf) == status_err) {
                return extractor_get_output_length(x);
            }
        } else {
            if (extractor_keyword_match_last_capture(x, &matcher_http_server_static_name) != status_ok) {
                extractor_delete_last_capture(x);
            }
            if (parser_skip_upto_delim(p, crlf, sizeof(crlf)) == status_err) {
                return extractor_get_output_length(x);
            }
        }
    }

    extractor_debug("%s: http server DONE\n", __func__);

    x->proto_state.state = state_done;

    return extractor_get_output_length(x);
}



/*
 * The function extractor_process_ssh processes an SSH packet.  The
 * extractor MUST have previously been initialized with its data
 * pointer set to the initial octet of a TCP header.
 */

#define L_ssh_version_string                   8
#define L_ssh_packet_length                    4
#define L_ssh_padding_length                   1
#define L_ssh_payload                          1
#define L_ssh_cookie                          16
#define L_ssh_kex_algo_len                     4
#define L_ssh_server_host_key_algos_len        4
#define L_ssh_enc_algos_client_to_server_len   4
#define L_ssh_enc_algos_server_to_client_len   4
#define L_ssh_mac_algos_client_to_server_len   4
#define L_ssh_mac_algos_server_to_client_len   4
#define L_ssh_comp_algos_client_to_server_len  4
#define L_ssh_comp_algos_server_to_client_len  4
#define L_ssh_languages_client_to_server_len   4
#define L_ssh_languages_server_to_client_len   4

enum ssh_state {
    ssh_state_done          = state_done,
    ssh_state_start         = state_start,
    ssh_state_got_first_msg = 2
};

unsigned int parser_extractor_process_ssh(struct parser *p, struct extractor *x) {
    size_t packet_length, padding_length, payload, tmp;
    // uint16_t ssh_proto_number = htons(SSH_PORT);
    const unsigned char ssh_first_packet[] = {
        'S', 'S', 'H', '-', '2', '.', '0', '-'
    };
    unsigned char lf[] = {
        '\n'    /* CRLF is required by RFC, but leagcy clients use just LF */
    };
    unsigned char sp[] = { ' ' };

    extractor_debug("%s: processing packet\n", __func__)
    x->fingerprint_type = fingerprint_type_ssh;

    if (parser_match(p, ssh_first_packet, sizeof(ssh_first_packet), NULL) == status_ok) {

        /* first packet */
        if (parser_find_delim(p, sp, sizeof(sp)) < 0) {  
            /* dir == DIR_SERVER; skip this packet as we are only interested in clients */
            // return 0;
        }

    //if (extractor_write_to_output(x, (unsigned char *)&ssh_proto_number, sizeof(ssh_proto_number)) == status_err) {
    //       return 0;
    //  }
        if (parser_extractor_copy_upto_delim(p, x, lf, sizeof(lf)) == status_err) {
            return extractor_get_output_length(x);
        }
        if (extractor_strip_last_capture(x) == status_err) {
            return extractor_get_output_length(x);
        }

        x->proto_state.state = ssh_state_got_first_msg;

        if (parser_get_data_length(p) == 1) {
            return extractor_get_output_length(x);
        }
        if (parser_skip(p, 1) == status_err) {
            return extractor_get_output_length(x);
        }

    } else {

        //    if (x->proto_state.state == ssh_state_got_first_msg) {

        /* parse as if second (KEX) packet */

        extractor_debug("%s: parsing KEX\n", __func__);

        if (parser_read_uint(p, L_ssh_packet_length, &packet_length) == status_err) {
            goto bail;
        }
        if (parser_skip(p, L_ssh_packet_length) == status_err) {
            goto bail;
        }
        if (parser_read_uint(p, L_ssh_padding_length, &padding_length) == status_err) {
            goto bail;
        }
        if (parser_skip(p, L_ssh_padding_length) == status_err) {
            goto bail;
        }
        if (parser_read_uint(p, L_ssh_payload, &payload) == status_err) {
            goto bail;
        }
        if (payload != 0x14) { /* KEX_INIT */
            goto bail;
        }
        if (parser_skip(p, L_ssh_payload) == status_err) {
            goto bail;
        }
        if (parser_skip(p, L_ssh_cookie) == status_err) {
            goto bail;
        }

        if (parser_read_and_skip_uint(p, L_ssh_kex_algo_len, &tmp) == status_err) {
            goto bail;
        }
        if (parser_extractor_copy(p, x, tmp) == status_err) {
            goto bail;
        }
        if (parser_read_and_skip_uint(p, L_ssh_server_host_key_algos_len, &tmp) == status_err) {
            goto bail;
        }
        if (parser_extractor_copy(p, x, tmp) == status_err) {
            goto bail;
        }
        if (parser_read_and_skip_uint(p, L_ssh_enc_algos_client_to_server_len, &tmp) == status_err) {
            goto bail;
        }
        if (parser_extractor_copy(p, x, tmp) == status_err) {
            goto bail;
        }
        if (parser_read_and_skip_uint(p, L_ssh_enc_algos_server_to_client_len, &tmp) == status_err) {
            goto bail;
        }
        if (parser_extractor_copy(p, x, tmp) == status_err) {
            goto bail;
        }
        if (parser_read_and_skip_uint(p, L_ssh_mac_algos_client_to_server_len, &tmp) == status_err) {
            goto bail;
        }
        if (parser_extractor_copy(p, x, tmp) == status_err) {
            goto bail;
        }
        if (parser_read_and_skip_uint(p, L_ssh_mac_algos_server_to_client_len, &tmp) == status_err) {
            goto bail;
        }
        if (parser_extractor_copy(p, x, tmp) == status_err) {
            goto bail;
        }
        if (parser_read_and_skip_uint(p, L_ssh_comp_algos_client_to_server_len, &tmp) == status_err) {
            goto bail;
        }
        if (parser_extractor_copy(p, x, tmp) == status_err) {
            goto bail;
        }
        if (parser_read_and_skip_uint(p, L_ssh_comp_algos_server_to_client_len, &tmp) == status_err) {
            goto bail;
        }
        if (parser_extractor_copy(p, x, tmp) == status_err) {
            goto bail;
        }
        if (parser_read_and_skip_uint(p, L_ssh_languages_client_to_server_len, &tmp) == status_err) {
            goto bail;
        }
        if (parser_extractor_copy(p, x, tmp) == status_err) {
            goto bail;
        }
        if (parser_read_and_skip_uint(p, L_ssh_languages_server_to_client_len, &tmp) == status_err) {
            goto bail;
        }
        if (parser_extractor_copy(p, x, tmp) == status_err) {
            goto bail;
        }
    }

    extractor_debug("%s: done parsing KEX (output length: %td)\n", __func__, extractor_get_output_length(x));

    x->proto_state.state = state_done;

 bail:
    return extractor_get_output_length(x);
}

unsigned int parser_extractor_process_ssh_kex(struct parser *p, struct extractor *x) {
    size_t packet_length, padding_length, payload, tmp;

    extractor_debug("%s: processing packet\n", __func__)
    x->fingerprint_type = fingerprint_type_ssh_kex;

    /* parse as if second (KEX) packet */

    extractor_debug("%s: parsing KEX\n", __func__);

    if (parser_read_uint(p, L_ssh_packet_length, &packet_length) == status_err) {
        goto bail;
    }
    if (parser_skip(p, L_ssh_packet_length) == status_err) {
        goto bail;
    }
    if (parser_read_uint(p, L_ssh_padding_length, &padding_length) == status_err) {
        goto bail;
    }
    if (parser_skip(p, L_ssh_padding_length) == status_err) {
        goto bail;
    }
    if (parser_read_uint(p, L_ssh_payload, &payload) == status_err) {
        goto bail;
    }
    if (payload != 0x14) { /* KEX_INIT */
        goto bail;
    }
    if (parser_skip(p, L_ssh_payload) == status_err) {
        goto bail;
    }
    if (parser_skip(p, L_ssh_cookie) == status_err) {
        goto bail;
    }

    if (parser_read_and_skip_uint(p, L_ssh_kex_algo_len, &tmp) == status_err) {
        goto bail;
    }
    if (parser_extractor_copy(p, x, tmp) == status_err) {
        goto bail;
    }
    if (parser_read_and_skip_uint(p, L_ssh_server_host_key_algos_len, &tmp) == status_err) {
        goto bail;
    }
    if (parser_extractor_copy(p, x, tmp) == status_err) {
        goto bail;
    }
    if (parser_read_and_skip_uint(p, L_ssh_enc_algos_client_to_server_len, &tmp) == status_err) {
        goto bail;
    }
    if (parser_extractor_copy(p, x, tmp) == status_err) {
        goto bail;
    }
    if (parser_read_and_skip_uint(p, L_ssh_enc_algos_server_to_client_len, &tmp) == status_err) {
        goto bail;
    }
    if (parser_extractor_copy(p, x, tmp) == status_err) {
        goto bail;
    }
    if (parser_read_and_skip_uint(p, L_ssh_mac_algos_client_to_server_len, &tmp) == status_err) {
        goto bail;
    }
    if (parser_extractor_copy(p, x, tmp) == status_err) {
        goto bail;
    }
    if (parser_read_and_skip_uint(p, L_ssh_mac_algos_server_to_client_len, &tmp) == status_err) {
        goto bail;
    }
    if (parser_extractor_copy(p, x, tmp) == status_err) {
        goto bail;
    }
    if (parser_read_and_skip_uint(p, L_ssh_comp_algos_client_to_server_len, &tmp) == status_err) {
        goto bail;
    }
    if (parser_extractor_copy(p, x, tmp) == status_err) {
        goto bail;
    }
    if (parser_read_and_skip_uint(p, L_ssh_comp_algos_server_to_client_len, &tmp) == status_err) {
        goto bail;
    }
    if (parser_extractor_copy(p, x, tmp) == status_err) {
        goto bail;
    }
    if (parser_read_and_skip_uint(p, L_ssh_languages_client_to_server_len, &tmp) == status_err) {
        goto bail;
    }
    if (parser_extractor_copy(p, x, tmp) == status_err) {
        goto bail;
    }
    if (parser_read_and_skip_uint(p, L_ssh_languages_server_to_client_len, &tmp) == status_err) {
        goto bail;
    }
    if (parser_extractor_copy(p, x, tmp) == status_err) {
        goto bail;
    }

    extractor_debug("%s: done parsing KEX (output length: %td)\n", __func__, extractor_get_output_length(x));

    x->proto_state.state = state_done;

 bail:
    return extractor_get_output_length(x);
}


unsigned int parser_extractor_process_tcp_data(struct parser *p, struct extractor *x) {

    x->transport_data = *p;
    const struct pi_container *pi;
    struct pi_container dummy = { 0, 0 };
    pi = proto_identify_tcp(p->data, parser_get_data_length(p));

    if (pi == NULL) {
        pi = &dummy;
    }

    switch(pi->app) {
    case HTTP_PORT:
        if (pi->dir == DIR_CLIENT) {
            return parser_extractor_process_http(p, x);
        } else {
            return parser_extractor_process_http_server(p, x);
        }
        break;
    case HTTPS_PORT:
	if (pi->dir == DIR_CLIENT) {
	    return parser_extractor_process_tls(p, x);
	} else if (pi->dir == DIR_SERVER) {
        /* we have Server Hello and possibly Server Certificate */
	    return parser_extractor_process_tls_server(p, x);
	} else if (pi->dir == DIR_UNKNOWN) {
        /* we have Server Certificate only */
	    return parser_extractor_process_tls_server_cert(p, x);
    }
	break;
    case SSH_PORT:
        return parser_extractor_process_ssh(p, x);
        break;
    case SSH_KEX:
        return parser_extractor_process_ssh_kex(p, x);
        break;
    default:
        ;
    }

    return 0; /* if we get here, we have nothing to report */
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

unsigned int parser_process_ipv4(struct parser *p, size_t *transport_protocol, struct key *k) {
    size_t version_ihl;
    uint8_t *transport_data;

    extractor_debug("%s: processing packet (len %td)\n", __func__, parser_get_data_length(p));

    if (parser_read_uint(p, L_ip_version_ihl, &version_ihl) == status_err) {
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
    if (parser_skip(p, L_ip_version_ihl + L_ip_tos) == status_err) {
        return 0;
    }
    /*
     *  check ip_total_length field, and trim data from parser if appropriate
     */
    size_t ip_total_length;
    if (parser_read_and_skip_uint(p, L_ip_total_length, &ip_total_length) == status_err) {
        return 0;
    }
    parser_set_data_length(p, ip_total_length - (L_ip_version_ihl + L_ip_tos + L_ip_total_length));
    if (parser_skip(p, L_ip_identification + L_ip_flags_frag_off + L_ip_ttl) == status_err) {
        return 0;
    }
    if (parser_read_and_skip_uint(p, L_ip_protocol, transport_protocol) == status_err) {
        return 0;
    }
    if (parser_skip(p, L_ip_hdr_cksum) == status_err) {
        return 0;
    }
    if (parser_read_and_skip_byte_string(p, L_ip_src_addr, (uint8_t *)&k->addr.ipv4.src) == status_err) {
        return 0;
    }
    if (parser_read_and_skip_byte_string(p, L_ip_dst_addr, (uint8_t *)&k->addr.ipv4.dst) == status_err) {
        return 0;
    }
    if (parser_skip_to(p, transport_data) == status_err) {
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

unsigned int parser_process_ipv6(struct parser *p, size_t *transport_protocol, struct key *k) {
    size_t version_tc_hi;
    size_t payload_length;
    size_t next_header;

    extractor_debug("%s: processing packet (len %td)\n", __func__, parser_get_data_length(p));

    if (parser_read_uint(p, L_ipv6_version_tc_hi, &version_tc_hi) == status_err) {
        return 0;
    }
    if (!(version_tc_hi & 0x60)) {
        return 0;  /* version is not IPv6 */
    }
    if (parser_skip(p, L_ipv6_version_tc_hi + L_ipv6_tc_lo_flow_label_hi + L_ipv6_flow_label_lo) == status_err) {
        return 0;
    }
    if (parser_read_uint(p, L_ipv6_payload_length, &payload_length) == status_err) {
        return 0;
    }
    if (parser_skip(p, L_ipv6_payload_length) == status_err) {
        return 0;
    }
    /*
     * should we check the payload length here?
     */
    if (parser_read_uint(p, L_ipv6_next_header, &next_header) == status_err) {
        return 0;
    }
    if (parser_skip(p, L_ipv6_next_header + L_ipv6_hop_limit) == status_err) {
        return 0;
    }
    if (parser_read_and_skip_byte_string(p, L_ipv6_source_address, (uint8_t *)&k->addr.ipv6.src) == status_err) {
        return 0;
    }
    if (parser_read_and_skip_byte_string(p, L_ipv6_destination_address, (uint8_t *)&k->addr.ipv6.dst) == status_err) {
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
            if (parser_read_uint(p, L_ipv6_next_header, &next_header) == status_err) {
                return 0;
            }
            if (parser_skip(p, L_ipv6_next_header) == status_err) {
                return 0;
            }
            if (parser_read_uint(p, L_ipv6_hdr_ext_len, &ext_hdr_len) == status_err) {
                return 0;
            }
            if (parser_skip(p, L_ipv6_ext_hdr_base + ext_hdr_len) == status_err) {
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

unsigned int parser_process_eth(struct parser *p, size_t *ethertype) {

    extractor_debug("%s: processing ethernet (len %td)\n", __func__, parser_get_data_length(p));

    *ethertype = ETH_TYPE_NONE;

    if (parser_skip(p, ETH_ADDR_LEN * 2) == status_err) {
        return 0;
    }
    if (parser_read_and_skip_uint(p, sizeof(uint16_t), ethertype) == status_err) {
        return 0;
    }
    if (*ethertype == ETH_TYPE_1AD) {
        if (parser_skip(p, sizeof(uint16_t)) == status_err) { // TCI
            return 0;
        }
        if (parser_read_and_skip_uint(p, sizeof(uint16_t), ethertype) == status_err) {
            return 0;
        }
    }
    if (*ethertype == ETH_TYPE_VLAN) {
        if (parser_skip(p, sizeof(uint16_t)) == status_err) { // TCI
            return 0;
        }
        if (parser_read_and_skip_uint(p, sizeof(uint16_t), ethertype) == status_err) {
            return 0;
        }
    }
    if (*ethertype == ETH_TYPE_MPLS) {
        size_t mpls_label = 0;

        while (!(mpls_label & MPLS_BOTTOM_OF_STACK)) {
            if (parser_read_and_skip_uint(p, sizeof(uint32_t), &mpls_label) == status_err) {
                return 0;
            }
        }
        *ethertype = ETH_TYPE_IP;   // assume IPv4 for now
    }

    return 0;  /* we don't extract any data, but this is not a failure */
}

unsigned int packet_filter_process_packet(struct packet_filter *pf, struct key *k) {
    size_t transport_proto = 0;
    size_t ethertype = 0;

    parser_process_eth(&pf->p, &ethertype);
    switch(ethertype) {
    case ETH_TYPE_IP:
        parser_process_ipv4(&pf->p, &transport_proto, k);
        break;
    case ETH_TYPE_IPV6:
        parser_process_ipv6(&pf->p, &transport_proto, k);
        break;
    default:
        ;
    }
    if (transport_proto == 6) {
        return packet_filter_process_tcp(pf, k);

    } else if (transport_proto == 17) {
        return packet_filter_process_udp(pf, k);
    }

    return 0;
}

/*
 * The function parser_process_tcp processes a TCP packet.  The
 * parser MUST have previously been initialized with its data
 * pointer set to the initial octet of a TCP header.
 */

unsigned int parser_process_tcp(struct parser *p) {
    size_t flags, offrsv;
    const uint8_t *data = p->data;
    // size_t init_len = parser_get_data_length(p);

    extractor_debug("%s: processing packet (len %td)\n", __func__, parser_get_data_length(p));

    if (parser_skip(p, L_src_port + L_dst_port + L_tcp_seq + L_tcp_ack) == status_err) {
        return 0;
    }
    if (parser_read_uint(p, L_tcp_offrsv, &offrsv) == status_err) {
        return 0;
    }
    if (parser_skip(p, L_tcp_offrsv) == status_err) {
        return 0;
    }
    if (parser_read_uint(p, L_tcp_flags, &flags) == status_err) {
        return 0;
    }
    if ((flags & TCP_SYN) == 0) {
        /*
         * skip over TCP options, then process the TCP Data payload
         */
        if (parser_skip_to(p, data + ((offrsv >> 4) * 4)) == status_err) {
            return 0;
        }
        unsigned char extractor_buffer[2048];
        struct extractor x;
        extractor_init(&x, extractor_buffer, 2048);
        return parser_extractor_process_tcp_data(p, &x);

    } else if ((flags & (TCP_SYN|TCP_ACK)) == TCP_SYN) {
        return 100;
    }
    return 0;
}


/*
 * struct packet_filter implements a packet metadata filter
 */
enum status packet_filter_init(struct packet_filter *pf, const char *config_string) {

    enum status status = proto_ident_config(config_string);
    if (status) {
        return status;
    }
    if (tcp_message_filter_cutoff) {
        pf->tcp_init_msg_filter = new tcp_initial_message_filter;
        pf->tcp_init_msg_filter->tcp_initial_message_filter_init();
    } else {
        pf->tcp_init_msg_filter = NULL;
    }
    return status_ok;
}

size_t packet_filter_extract(struct packet_filter *pf, struct key *k, uint8_t *packet, size_t length) {

    extractor_init(&pf->x, pf->extractor_buffer, sizeof(packet_filter::extractor_buffer));
    parser_init(&pf->p, (unsigned char *)packet, length);
    return packet_filter_process_packet(pf, k);
}

bool packet_filter_apply(struct packet_filter *pf, uint8_t *packet, size_t length) {
    extern unsigned int packet_filter_threshold;
    struct key k;
    size_t bytes_extracted = packet_filter_extract(pf, &k, packet, length);
    if (bytes_extracted > packet_filter_threshold) {
        return true;
    }
    return false;
}

/*
 * configuration for protocol identification
 */

extern unsigned char dhcp_client_mask[8];  /* udp.c */
extern unsigned char dns_server_mask[8];   /* udp.c */
extern unsigned char wireguard_mask[8];    /* udp.c */


enum status proto_ident_config(const char *config_string) {
    if (config_string == NULL) {
        return status_ok;    /* use the default configuration */
    }

    std::map<std::string, bool> protocols{
        { "all",         false },
        { "dhcp",        false },
        { "dns",         false },
        { "dtls",        false },
        { "http",        false },
        { "ssh",         false },
        { "tcp",         false },
        { "tcp.message", false },
        { "tls",         false },
        { "wireguard",   false },
    };

    std::string s{config_string};
    std::string delim{","};
    size_t pos = 0;
    std::string token;
    while ((pos = s.find(delim)) != std::string::npos) {
        token = s.substr(0, pos);
        token.erase(std::remove_if(token.begin(), token.end(), isspace), token.end());
        s.erase(0, pos + delim.length());

        auto pair = protocols.find(token);
        if (pair != protocols.end()) {
            pair->second = true;
        } else {
            fprintf(stderr, "error: unrecognized filter command \"%s\"\n", token.c_str());
            return status_err;
        }
    }
    token = s.substr(0, pos);
    s.erase(std::remove_if(s.begin(), s.end(), isspace), s.end());
    auto pair = protocols.find(token);
    if (pair != protocols.end()) {
        pair->second = true;
    } else {
        fprintf(stderr, "error: unrecognized filter command \"%s\"\n", token.c_str());
        return status_err;
    }

    if (protocols["all"] == true) {
        return status_ok;
    }
    if (protocols["dhcp"] == false) {
        bzero(dhcp_client_mask, sizeof(dhcp_client_mask));
    }
    if (protocols["dns"] == false) {
        bzero(dns_server_mask, sizeof(dns_server_mask));
    }
    if (protocols["http"] == false) {
        bzero(http_client_mask, sizeof(http_client_mask));
        bzero(http_client_post_mask, sizeof(http_client_post_mask));
        bzero(http_server_mask, sizeof(http_server_mask));
    }
    if (protocols["ssh"] == false) {
        bzero(ssh_kex_mask, sizeof(ssh_kex_mask));
        bzero(ssh_mask, sizeof(ssh_mask));
    }
    if (protocols["tcp"] == false) {
        select_tcp_syn = 0;
    }
    if (protocols["tcp.message"] == true) {
        select_tcp_syn = 0;
        tcp_message_filter_cutoff = 1;
    }
    if (protocols["tls"] == false) {
        bzero(tls_client_hello_mask, sizeof(tls_client_hello_mask));
        bzero(tls_server_cert_embedded_mask, sizeof(tls_client_hello_mask));
    }
    if (protocols["wireguard"] == false) {
        bzero(wireguard_mask, sizeof(wireguard_mask));
    }
    return status_ok;
}


// new packet metadata catpure

void tls_extensions::print(struct json_object &o, const char *key) const {

    struct parser ext_parser{this->data, this->data_end};

    struct json_array array{o, key};

    while (parser_get_data_length(&ext_parser) > 0) {
        size_t tmp_len = 0;
        size_t tmp_type;

        const uint8_t *data = ext_parser.data;
        if (parser_read_and_skip_uint(&ext_parser, L_ExtensionType, &tmp_type) == status_err) {
            break;
        }
        if (parser_read_and_skip_uint(&ext_parser, L_ExtensionLength, &tmp_len) == status_err) {
            break;
        }
        if (parser_skip(&ext_parser, tmp_len) == status_err) {
            break;
        }

        struct parser ext{data, ext_parser.data};
        array.print_hex(ext);

    }

    array.close();
}

void tls_extensions::print_server_name(struct json_object &o, const char *key) const {

    struct parser ext_parser{this->data, this->data_end};

    while (parser_get_data_length(&ext_parser) > 0) {
        size_t tmp_len = 0;
        size_t tmp_type;

        const uint8_t *data = ext_parser.data;
        if (parser_read_and_skip_uint(&ext_parser, L_ExtensionType, &tmp_type) == status_err) {
            break;
        }
        if (parser_read_and_skip_uint(&ext_parser, L_ExtensionLength, &tmp_len) == status_err) {
            break;
        }
        if (parser_skip(&ext_parser, tmp_len) == status_err) {
            break;
        }

        if (tmp_type == type_sni) {
            struct parser ext{data, ext_parser.data};
            //            tls.print_key_json_string("server_name", pf.x.packet_data.value + SNI_HDR_LEN, pf.x.packet_data.length - SNI_HDR_LEN);
            o.print_key_json_string(key, ext.data + SNI_HDR_LEN, ext.length() - SNI_HDR_LEN);
        }
    }

}

void tls_client_hello::parse(struct parser &p) {
    size_t tmp_len;

    extractor_debug("%s: processing packet\n", __func__);

    /*
     * verify that we are looking at a TLS ClientHello
     */
    if (parser_match(&p,
                     tls_client_hello_value,
                     L_ContentType +    L_ProtocolVersion + L_RecordLength + L_HandshakeType,
                     tls_client_hello_mask) == status_err) {
        return; /* not a clientHello */
    }

    /*
     * skip over initial fields
     */
    if (parser_skip(&p, L_HandshakeLength) == status_err) {
        return;
    }

    // parse clientHello.ProtocolVersion
    protocol_version.parse(p, L_ProtocolVersion);

    // parse clientHello.Random
    random.parse(p, L_Random);

    // parse SessionID
    if (parser_read_and_skip_uint(&p, L_SessionIDLength, &tmp_len) == status_err) {
        goto bail;
    }
    session_id.parse(p, tmp_len);

    // parse clientHello.Ciphersuites
    if (parser_read_and_skip_uint(&p, L_CipherSuiteVectorLength, &tmp_len)) {
        goto bail;
    }
    ciphersuite_vector.parse(p, tmp_len);
    // degrease_octet_string(x->last_capture + 2, tmp_len);

    // parse compression methods
    if (parser_read_and_skip_uint(&p, L_CompressionMethodsLength, &tmp_len) == status_err) {
        goto bail;
    }
    compression_methods.parse(p, tmp_len);

    // parse extensions vector
    if (parser_read_and_skip_uint(&p, L_ExtensionsVectorLength, &tmp_len)) {
        goto bail;
    }
    extensions.parse(p, tmp_len);

    return; 

 bail:
    /*
     * handle possible packet parsing errors
     */
    extractor_debug("%s: warning: TLS clientHello processing did not fully complete\n", __func__);
    return; // extractor_get_output_length(x);

}

void tls_server_hello::parse(struct parser &p, struct extractor *x) {
    size_t tmp_len;
    size_t tmp_type;

    extractor_debug("%s: processing packet with %td bytes\n", __func__, p->data_end - p->data);

    /*
     * verify that we are looking at a TLS record
     */
    if (parser_read_and_skip_uint(&p, L_ContentType, &tmp_type) == status_err) {
        goto bail;
    }
    if (tmp_type != 0x16) {
        goto bail;    /* not a handshake record */
    }
    if (parser_skip(&p, L_ProtocolVersion) == status_err) {
	    goto bail;
    }
    if (parser_read_and_skip_uint(&p, L_RecordLength, &tmp_len) == status_err) {
      goto bail;
    }
    extractor_debug("%s: got a record\n", __func__);
    struct parser record;
    parser_init_from_outer_parser(&record, &p, tmp_len);

    if (parser_read_and_skip_uint(&record, L_HandshakeType, &tmp_type) == status_err) {
	    goto bail;
    }
    if (tmp_type != 0x02) {
        goto bail;     /* not a serverHello */
    }

    if (parser_read_and_skip_uint(&record, L_HandshakeLength, &tmp_len) == status_err) {
	    goto bail;
    }
    extractor_debug("%s: got a handshake\n", __func__);
    struct parser handshake;
    parser_init_from_outer_parser(&handshake, &record, tmp_len);
    if (parse_tls_server_hello(handshake, NULL) != status_ok) {
        goto bail;
    }
    parser_pop(&handshake, &record);

    if (parser_get_data_length(&record) > 0) {

        extractor_debug("%s: expecting another handshake structure\n", __func__);
        size_t tmp_type;
        if (parser_read_and_skip_uint(&record, L_HandshakeType, &tmp_type) == status_err) {
            goto bail;
        }
        if (tmp_type != 11) { /* certificate */
            goto done;
        }
        if (parser_skip(&record, L_HandshakeLength) == status_err) {
            goto done;
        }
        if (parser_extractor_process_certificate(&record, x) == status_err) {
            goto done;
        }
    }
    parser_pop(&record, &p);

    extractor_debug("%s: outermost parser has %td bytes\n", __func__, p->data_end - p->data);

    /* process data as a new record */
    if (parser_get_data_length(&p) > 0) {

        extractor_debug("%s: expecting another record\n", __func__);

        if (parser_read_and_skip_uint(&p, L_ContentType, &tmp_type) == status_err) {
            goto done;
        }
        if (tmp_type != 0x16) {
            goto done;    /* not a handshake record */
        }
        if (parser_skip(&p, L_ProtocolVersion) == status_err) {
            goto done;
        }
        if (parser_read_and_skip_uint(&p, L_RecordLength, &tmp_len) == status_err) {
            goto done;
        }
        struct parser record;
        parser_init_from_outer_parser(&record, &p, tmp_len);

        extractor_debug("%s: new record has %td bytes\n", __func__, record.data_end - record.data);

        size_t tmp_type;
        if (parser_read_and_skip_uint(&record, L_HandshakeType, &tmp_type) == status_err) {
            goto done;
        }
        if (tmp_type == 11) { /* certificate */
            if (parser_skip(&record, L_HandshakeLength) == status_err) {
                goto done;
            }
            // TODO: properly parse cert
            //            if (parser_extractor_process_certificate(&record, x) == status_err) {
            //    goto done;
            // }
        }
    }

 done:

    return; // extractor_get_output_length(x);

 bail:
    /*
     * handle possible packet parsing errors
     */
    extractor_debug("%s: warning: TLS serverHello processing did not fully complete\n", __func__);
    return; // 0;

}

enum status tls_server_hello::parse_tls_server_hello(struct parser &record, struct extractor *x) {
    size_t tmp_len;
    size_t tmp_type;
    unsigned char *ext_len_slot = NULL;

    extractor_debug("%s: processing server_hello with %td bytes\n", __func__, record.data_end - record.data);

    protocol_version.parse(record, L_ProtocolVersion);
    random.parse(record, L_Random);

    /* skip over SessionID and SessionIDLen */
    if (parser_read_uint(&record, L_SessionIDLength, &tmp_len) == status_err) {
	    goto bail;
    }
    if (parser_skip(&record, tmp_len + L_SessionIDLength) == status_err) {
	    goto bail;
    }

    ciphersuite_vector.parse(record, L_CipherSuite);

    return status_ok;

    /* skip over compression method */
    if (parser_skip(&record, L_CompressionMethod) == status_err) {
	    goto bail;
    }

    /*
     * reserve slot in output for length of extracted extensions
     */
    if (extractor_reserve(x, &ext_len_slot, sizeof(uint16_t))) {
        goto bail;
    }

    /*
     * parse extensions vector (if present)
     */
    if (parser_get_data_length(&record) > 0) {

        extractor_debug("%s: parsing extensions vector\n", __func__);

        /*  extensions length */
        if (parser_read_and_skip_uint(&record, L_ExtensionsVectorLength, &tmp_len)) {
            goto bail;
        }

        struct parser ext_parser;
        parser_init_from_outer_parser(&ext_parser, &record, tmp_len);

        while (parser_get_data_length(&ext_parser) > 0)  {

            if (parser_read_uint(&ext_parser, L_ExtensionType, &tmp_type) == status_err) {
                break;
            }
            if (parser_extractor_copy(&ext_parser, x, L_ExtensionType) == status_err) {
                break;
            }
            if (parser_read_uint(&ext_parser, L_ExtensionLength, &tmp_len) == status_err) {
                break;
            }
            if (uint16_match(tmp_type, static_extension_types, num_static_extension_types) == status_err)  {
                if (parser_extractor_copy_append(&ext_parser, x, tmp_len + L_ExtensionLength) == status_err)  {
                    break;
                }
            }
            else {
                if (parser_skip(&ext_parser, tmp_len + L_ExtensionLength) == status_err) {
                    break;
                }
            }
        }

        extractor_debug("%s: ext_parser has %td bytes\n", __func__, ext_parser.data_end - ext_parser.data);

        parser_pop(&ext_parser, &record);

        extractor_debug("%s: record has %td bytes\n", __func__, record.data_end - record.data);

    }

    /*
     * write the length of the extracted extensions (if any) into the reserved slot
     */
    encode_uint16(ext_len_slot, (x->output - ext_len_slot - sizeof(uint16_t)) | PARENT_NODE_INDICATOR);

    return status_ok;

 bail:
    return status_err;
}

void http_request::parse(struct parser &p) {
    unsigned char crlf[2] = { '\r', '\n' };

    /* process request line */
    method.parse_up_to_delim(p, ' ');
    p.skip(1);
    uri.parse_up_to_delim(p, ' ');
    p.skip(1);
    protocol.parse_up_to_delim(p, '\r');
    p.skip(2);

    headers.data = p.data;
    while (parser_get_data_length(&p) > 0) {
        if (parser_match(&p, crlf, sizeof(crlf), NULL) == status_ok) {
            break;  /* at end of headers */
        }
        if (parser_skip_upto_delim(&p, crlf, sizeof(crlf)) == status_err) {
            break;
        }
    }
    headers.data_end = p.data;

    return;
}

void http_headers::print_host(struct json_object &o, const char *key) const {
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };

    struct parser p{this->data, this->data_end};

    while (parser_get_data_length(&p) > 0) {
        if (parser_match(&p, crlf, sizeof(crlf), NULL) == status_ok) {
            break;  /* at end of headers */
        }

        struct parser keyword{p.data, NULL};
        if (parser_skip_upto_delim(&p, csp, sizeof(csp)) == status_err) {
            return;
        }
        keyword.data_end = p.data;
        bool print_value = false;

        uint8_t h[] = { 'h', 'o', 's', 't', ':', ' ' };
        struct parser host{h, h+sizeof(h)};
        if (host.case_insensitive_match(keyword)) {
            print_value = true;
        }
        const uint8_t *value_start = p.data;
        if (parser_skip_upto_delim(&p, crlf, sizeof(crlf)) == status_err) {
            return;
        }
        const uint8_t *value_end = p.data - 2;
        if (print_value) {
            o.print_key_json_string(key, value_start, value_end - value_start);
            break;
        }
    }
}

void http_headers::print_matching_name(struct json_object &o, const char *key, struct parser &name) const {
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };

    struct parser p{this->data, this->data_end};

    while (parser_get_data_length(&p) > 0) {
        if (parser_match(&p, crlf, sizeof(crlf), NULL) == status_ok) {
            break;  /* at end of headers */
        }

        struct parser keyword{p.data, NULL};
        if (parser_skip_upto_delim(&p, csp, sizeof(csp)) == status_err) {
            return;
        }
        keyword.data_end = p.data;
        bool print_value = false;

        if (name.case_insensitive_match(keyword)) {
            print_value = true;
        }
        const uint8_t *value_start = p.data;
        if (parser_skip_upto_delim(&p, crlf, sizeof(crlf)) == status_err) {
            return;
        }
        const uint8_t *value_end = p.data - 2;
        if (print_value) {
            o.print_key_json_string(key, value_start, value_end - value_start);
            break;
        }
    }
}

void http_headers::print_matching_names(struct json_object &o, std::list<std::pair<struct parser, std::string>> &name_list) const {
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };

    struct parser p{this->data, this->data_end};

    while (parser_get_data_length(&p) > 0) {
        if (parser_match(&p, crlf, sizeof(crlf), NULL) == status_ok) {
            break;  /* at end of headers */
        }

        struct parser keyword{p.data, NULL};
        if (parser_skip_upto_delim(&p, csp, sizeof(csp)) == status_err) {
            return;
        }
        keyword.data_end = p.data;
        const char *header_name = NULL;

        for (const auto &name : name_list) {
            if (name.first.case_insensitive_match(keyword)) {
                header_name = (const char *)name.second.c_str();
            }
        }
        const uint8_t *value_start = p.data;
        if (parser_skip_upto_delim(&p, crlf, sizeof(crlf)) == status_err) {
            return;
        }
        const uint8_t *value_end = p.data - 2;
        if (header_name) {
            o.print_key_json_string(header_name, value_start, value_end - value_start);
        }
    }
}
