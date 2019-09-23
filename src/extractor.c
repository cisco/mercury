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

#include "ept.h"
#include "extractor.h"
#include "utils.h"
#include "proto_identify.h"
#include "eth.h"

/*
 * The extractor_debug macro is useful for debugging (but quite verbose)
 */
#ifndef DEBUG
    #define extractor_debug(...)
#else
    #define extractor_debug(...)  (fprintf(stdout, __VA_ARGS__))
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

unsigned char http_client_mask[] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00
};

unsigned char http_client_value[] = {
    0x47, 0x45, 0x54, 0x20, 0x00, 0x00, 0x00, 0x00
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

unsigned int u32_compare_masked_data_to_value(const void *data,
					      const void *mask,
					      const void *value) {
    const uint32_t *d = (const uint32_t *)data;
    const uint32_t *m = (const uint32_t *)mask;
    const uint32_t *v = (const uint32_t *)value;

    return ((d[0] & m[0]) == v[0]) && ((d[1] & m[1]) == v[1]);
}

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
					 http_client_mask,
					 http_client_value)) {
	return &http_client;
    }
    if (u32_compare_masked_data_to_value(tcp_data,
					 http_server_mask,
					 http_server_value)) {
	return &http_server;
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

    x->proto_state.proto = PROTO_UNKNOWN;
    x->proto_state.dir = DIR_UNKNOWN;
    x->proto_state.state = state_start;
    x->output = output;
    x->output_start = x->output;
    x->output_end = output + output_len;

    x->fingerprint_type = fingerprint_type_unknown;
    x->last_capture = NULL;

    packet_data_init(&x->packet_data);
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

    if (p->data + num_bytes <= p->data_end) {
	size_t tmp = 0;
	const unsigned char *c;

	for (c = p->data; c < p->data + num_bytes; c++) {
	    tmp = (tmp << 8) + *c;
	}
	*output = tmp;
	p->data += num_bytes;
	extractor_debug("%s: num_bytes: %u, value (hex) %08x (decimal): %zd\n", __func__, num_bytes, (unsigned) tmp, tmp);
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

enum status extractor_write_to_output(struct extractor *x,
				      const unsigned char *data,
				      unsigned int len) {

    if (x->output + len + 2 <= x->output_end) {
	x->last_capture = NULL;
	encode_uint16(x->output, len);
	x->output += 2;
	memcpy(x->output, data, len);
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
	//	encode_uint16(x->output, len);
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

enum status parser_extractor_copy_append_upto_delim(struct parser *p,
						    struct extractor *x,
						    const unsigned char delim[2]) {
    const unsigned char *data = p->data;
    ptrdiff_t len;

    /* find delimiter, if present */
    while (1) {
	if (data >= p->data_end) {
	    return status_err;
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

    /* copy_append data up to delimiter */
    if (parser_extractor_copy_append(p, x, len) == status_err) {
	extractor_debug("%s: error\n", __func__);
	return status_err;
    }

    /* skip delimiter */
    return parser_skip(p, 2);
}

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
    return -1;
    
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

    if (bytes_extracted > 16) {
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
 * keyword_matcher performs multiple string matching the
 * straightforward way.  It should be robust and maintainable, and
 * possibly useful for very short keyword lists, but its worst-case
 * and average case performance are not great (linear in the number of
 * keywords).
 *
 * This code will be replaced with a finite automaton keyword matcher
 * in the near future (once that code is tuned, tested, and debugged).
 *
 */

#define keyword_init(s) { s, sizeof(s)-1 }

typedef struct keyword {
    const char *value;
    size_t len;
} keyword_t;

typedef struct keyword_matcher {
    keyword_t *case_insensitive;
    keyword_t *case_sensitive;
} keyword_matcher_t;

#define match_all_keywords NULL

enum status keyword_matcher_check(const keyword_matcher_t *keywords,
				  unsigned char *string,
				  size_t len) {
    keyword_t *k;
    size_t i;

    if (keywords == match_all_keywords) {
	return status_ok;  /* by convention, NULL pointer corresponds to 'match all keywords' */
    }
    
    k = keywords->case_insensitive;
    while (k->len != 0) {
	if (len == k->len) {
	    for (i = 0; i < len; i++) {
		if (tolower(string[i]) != k->value[i]) {
		    break;
		}
	    }
	    if (i >= len) {       /* end of string; match found */
		return status_ok;
	    }
	}
	k++;
    }

    k = keywords->case_sensitive;
    while (k->len != 0) {
	if (len == k->len) {
	    for (i = 0; i < len; i++) {
		if (string[i] != k->value[i]) {
		    break;
		}
	    }
	    if (i >= len) {       /* end of string; match found */
		return status_ok;
	    }
	}
	k++;
    }

    return status_err;
}

/*
 * extractor_keyword_match_last_capture_lowercase(x, value, value_len) returns
 * status_ok if lower(x->data) == value, and returns status_err
 * otherwise
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

unsigned int uint16_match(uint16_t x,
			  const uint16_t *ulist,
			  unsigned int num) {
    const uint16_t *ulist_end = ulist + num;

    while (ulist < ulist_end) {
	if (x == *ulist++) {
	    return 1;
	}
    }
    return 0;
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
 *  |  Data |           |U|A|P|R|S|F|                               |
 *  | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 *  |       |           |G|K|H|T|N|N|                               |
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

#define TCP_SYN      0x02

#define TCP_FIXED_HDR_LEN 20

#define tcp_offrsv_get_length(offrsv) (((offrsv) & 0xf0) >> 2)

/*
 * The function extractor_process_tcp processes a TCP packet.  The
 * extractor MUST have previously been initialized with its data
 * pointer set to the initial octet of a TCP header.
 */

unsigned int parser_extractor_process_tcp(struct parser *p, struct extractor *x) {
    size_t flags, offrsv;
    const uint8_t *data = p->data;

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
    if (flags != TCP_SYN) {
	/*
	 * process the TCP Data payload 
	 */
	if (parser_skip_to(p, data + ((offrsv >> 4) * 4)) == status_err) {
	    return 0;
	}
	return parser_extractor_process_tcp_data(p, x);

    }
    if (parser_skip(p, L_tcp_flags + L_tcp_win + L_tcp_csm + L_tcp_urp) == status_err) {
	return 0;
    }
    if (parser_set_data_length(p, tcp_offrsv_get_length(offrsv) - TCP_FIXED_HDR_LEN)) {
	return 0;
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

    extractor_debug("%s: processing packet\n", __func__);
    
    /*
     * verify that we are looking at a TLS ClientHello
     */
    if (parser_match(p,
		     tls_client_hello_value,
		     L_ContentType +	L_ProtocolVersion + L_RecordLength + L_HandshakeType,
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
    unsigned char *ext_len_slot;
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
 * The function parser_process_tls processes a TLS packet.  The
 * parser MUST have previously been initialized with its data
 * pointer set to the initial octet of the TCP header of the TLS
 * packet.
 */
unsigned int parser_process_tls(struct parser *p) {
    size_t tmp_len;
    struct parser ext_parser;
    extractor_debug("%s: processing packet\n", __func__);
    
    /*
     * verify that we are looking at a TLS ClientHello
     */
    if (parser_match(p,
		     tls_client_hello_value,
		     L_ContentType +	L_ProtocolVersion + L_RecordLength + L_HandshakeType,
		     tls_client_hello_mask) == status_err) {
	return 0; /* not a clientHello */
    }

    /*
     * skip over initial fields
     */
    if (parser_skip(p, L_HandshakeLength) == status_err) {
	return 0;
    }

    /*
     * copy clientHello.ProtocolVersion
     */
    if (parser_skip(p, L_ProtocolVersion) == status_err) {
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
    if (parser_skip(p, tmp_len) == status_err) {
	goto bail;
    }
    
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
    /*  extensions length */
    if (parser_read_and_skip_uint(p, L_ExtensionsVectorLength, &tmp_len)) {
	return status_err;
    }
    parser_init_from_outer_parser(&ext_parser, p, tmp_len);
    while (parser_get_data_length(&ext_parser) > 0) {
	size_t tmp_type;

	if (parser_read_uint(&ext_parser, L_ExtensionType, &tmp_type) == status_err) {
	    break;
	}
	
	if (parser_skip(&ext_parser, L_ExtensionType) == status_err) {
	    break;
	}
	
	if (parser_read_uint(&ext_parser, L_ExtensionLength, &tmp_len) == status_err) {
	    break;
	}
		
	if (parser_skip(&ext_parser, tmp_len + L_ExtensionLength) == status_err) {
	    break;
	}
    }

    return 100; /* indicate success */

 bail:
    /*
     * handle possible packet parsing errors
     */
    extractor_debug("%s: warning: TLS clientHello processing did not fully complete\n", __func__);
    return 0;   /* indicate failure */

}

/*
 * field lengths used in serverHello parsing
 */
#define L_CipherSuite              2
#define L_CompressionMethod        1

/*
 * The function parser_process_tls_server processes a TLS
 * serverHello packet.  The parser MUST have previously been
 * initialized with its data pointer set to the initial octet of the
 * TCP header of the TLS packet.
 */
unsigned int parser_extractor_process_tls_server(struct parser *p, struct extractor *x) {
    size_t tmp_len;
    
    extractor_debug("%s: processing packet\n", __func__);

    /*
     * verify that we are looking at a TLS ServerHello
     */
    if (parser_match(p,
		     tls_server_hello_value,
		     L_ContentType + L_ProtocolVersion + L_RecordLength + L_HandshakeType,
		     tls_server_hello_mask) == status_err) {
	return 0; /* not a serverHello */
    }

    /*
     * skip over initial fields
     */
    if (parser_skip(p, L_HandshakeLength) == status_err) {
	return 0;
    }

    /* set fingerprint type */
    x->fingerprint_type = fingerprint_type_tls_server;
    
    /*
     * copy clientHello.ProtocolVersion
     */
    if (parser_skip(p, L_ProtocolVersion) == status_err) {
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

    /* skip over ciphersuite  */
    if (parser_skip(p, L_CipherSuite) == status_err) {
	goto bail;
    }
    
    /* skip over compression methods */
    if (parser_skip(p, L_CompressionMethod) == status_err) {
	goto bail;
    }

    /*
     * parse extensions vector
     */
    if (parser_read_and_skip_uint(p, L_ExtensionsVectorLength, &tmp_len)) {
	return status_err;
    }
    struct parser ext_parser;
    parser_init_from_outer_parser(&ext_parser, p, tmp_len);
    while (parser_get_data_length(&ext_parser) > 0) {
	size_t tmp_type;

	if (parser_read_and_skip_uint(&ext_parser, L_ExtensionType, &tmp_type) == status_err) {
	    break;
	}
	if (parser_read_and_skip_uint(&ext_parser, L_ExtensionLength, &tmp_len) == status_err) {
	    break;
	}
	
	if (parser_skip(&ext_parser, tmp_len + L_ExtensionLength) == status_err) {
	    break;
	}
    }

    return 100; // INDICATE SUCCESS (> 16)

 bail:
    /*
     * handle possible packet parsing errors
     */
    extractor_debug("%s: warning: TLS serverHello processing did not fully complete\n", __func__);
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
    keyword_t nil_keyword[1] = {
	keyword_init("")
    };
    keyword_matcher_t user_agent_keyword_matcher = {
	user_agent_keyword,
	nil_keyword
    };
    //unsigned char http_mask[http_value_len] = {
    //	0xff, 0xff, 0xff, 0xff
    //};
    //unsigned char http_value[http_value_len] = {
    //	0x47, 0x45, 0x54, 0x20
    //};
    // unsigned char sl[1] = { '/' };
    unsigned char sp[1] = { ' ' };
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };
    keyword_t case_insensitive_static_headers[13] = {
	// keyword_init("user-agent"),
	keyword_init("upgrade-insecure-requests"),
	keyword_init("dnt"),
	keyword_init("accept-language"),
	keyword_init("connection"),
	keyword_init("x-requested-with"),
	keyword_init("accept-encoding"),
	keyword_init("content-length"),
	keyword_init("accept"),
	keyword_init("viewport-width"),
	keyword_init("intervention"),
	keyword_init("dpr"),
	keyword_init("cache-control"),
        keyword_init("")
    };
    keyword_t case_sensitive_static_headers[3] = {
        keyword_init("content-type"),
	keyword_init("origin"),
        keyword_init("")
    };
    keyword_matcher_t static_header_keywords = {
	case_insensitive_static_headers,
	case_sensitive_static_headers
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
    //	return 0; /* not an HTTP GET */
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
    //	return extractor_get_output_length(x);
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
	if (extractor_keyword_match_last_capture(x, &static_header_keywords) == status_ok) {
	    if (parser_extractor_copy_append_upto_delim(p, x, crlf) == status_err) {
		return extractor_get_output_length(x);
	    }
	} else {
	    const uint8_t *user_agent_string = NULL;
	    if (extractor_keyword_match_last_capture(x, &user_agent_keyword_matcher) == status_ok) {
		user_agent_string = p->data;
	    } 
	    if (parser_skip_upto_delim(p, crlf, sizeof(crlf)) == status_err) {
		return extractor_get_output_length(x);
	    }
	    if (user_agent_string) {
		packet_data_set(&x->packet_data,
				packet_data_type_http_user_agent,
				p->data - user_agent_string - 1,
				user_agent_string);
	    }
	}
    }

    extractor_debug("%s: http DONE\n", __func__);

    x->proto_state.state = state_done;

    return extractor_get_output_length(x);
}

keyword_t http_response_case_insensitive_static_headers[16] = {
    keyword_init("access-control-allow-headers"), 
    keyword_init("access-control-allow-methods"), 
    keyword_init("code"), 
    keyword_init("connection"), 
    keyword_init("content-encoding"), 
    keyword_init("pragma"), 
    keyword_init("reason"), 
    keyword_init("referrer-policy"), 
    keyword_init("server"), 
    keyword_init("strict-transport-security"), 
    keyword_init("vary"), 
    keyword_init("version"), 
    keyword_init("x-cache"), 
    keyword_init("x-powered-by"), 
    keyword_init("x-xss-protection"), 
    keyword_init("")
};
keyword_t http_response_case_sensitive_static_headers[3] = {
    keyword_init("")
};
keyword_matcher_t http_response_static_header_keywords = {
    http_response_case_insensitive_static_headers,
    http_response_case_sensitive_static_headers
};

struct parser_spec_http_server {
    keyword_matcher_t static_header_keywords;
};

struct parser_spec_http_server parser_spec_http_server_default = {
    {
	http_response_case_insensitive_static_headers,
	http_response_case_sensitive_static_headers    
    }
};

keyword_t empty_keyword_list[1] = {
    keyword_init("")
};

struct parser_spec_http_server parser_spec_http_server_no_headers = {
    {
	empty_keyword_list,
	empty_keyword_list
    }
};

#define parser_spec_http_server_all_headers match_all_keywords

// struct parser_spec_http_server *parser_spec_http_server = &parser_spec_http_server_default;
//struct parser_spec_http_server *parser_spec_http_server = &parser_spec_http_server_no_headers;
struct parser_spec_http_server *parser_spec_http_server = parser_spec_http_server_all_headers;

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
	if (extractor_keyword_match_last_capture(x, &parser_spec_http_server->static_header_keywords) == status_ok) {
	    if (parser_extractor_copy_append_upto_delim(p, x, crlf) == status_err) {
		return extractor_get_output_length(x);
	    }
	} else {
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
    uint16_t ssh_proto_number = htons(SSH_PORT);
    const unsigned char ssh_first_packet[] = {
	'S', 'S', 'H', '-', '2', '.', '0', '-'
    };
    unsigned char lf[] = {
	'\n'    /* CRLF is required by RFC, but leagcy clients use just LF */
    };
    unsigned char sp[] = { ' ' };

    extractor_debug("%s: processing packet\n", __func__);

    if (parser_match(p, ssh_first_packet, sizeof(ssh_first_packet), NULL) == status_ok) {

	/* first packet */
	if (parser_find_delim(p, sp, sizeof(sp)) != -1) {
	    /* dir == DIR_SERVER; skip this packet as we are only interested in clients */
	    // return 0;
	}

	if (extractor_write_to_output(x, (unsigned char *)&ssh_proto_number, sizeof(ssh_proto_number)) == status_err) {
	    return 0;
	}
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

    }

    if (x->proto_state.state == ssh_state_got_first_msg) {

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



unsigned int parser_extractor_process_tcp_data(struct parser *p, struct extractor *x) {
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
	} else {
	    return parser_extractor_process_tls_server(p, x);
	}
	break;
    case SSH_PORT:
	return parser_extractor_process_ssh(p, x);
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

unsigned int parser_process_ipv4(struct parser *p, size_t *transport_protocol) {
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
    if (parser_skip(p, L_ip_version_ihl + L_ip_tos + L_ip_total_length + L_ip_identification + L_ip_flags_frag_off + L_ip_ttl) == status_err) {
	return 0;
    }
    if (parser_read_uint(p, L_ip_protocol, transport_protocol) == status_err) {
	return 0;
    }
    if (parser_skip_to(p, transport_data) == status_err) {
	return 0;
    }

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

unsigned int parser_process_ipv6(struct parser *p, size_t *transport_protocol) {
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
    if (parser_skip(p, L_ipv6_next_header + L_ipv6_hop_limit + L_ipv6_source_address + L_ipv6_destination_address) == status_err) {
	return 0;
    }

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
    if (parser_read_uint(p, sizeof(uint16_t), ethertype) == status_err) {
	return 0;
    }
    if (parser_skip(p, sizeof(uint16_t)) == status_err) {
	return 0;
    }

    return 0;  /* we don't extract any data, but this is not a failure */
}

#include <net/ethernet.h>

unsigned int parser_extractor_process_packet(struct parser *p, struct extractor *x) {
    size_t transport_proto = 0;
    size_t ethertype = 0;

    parser_process_eth(p, &ethertype);
    switch(ethertype) {
    case ETHERTYPE_IP:
	parser_process_ipv4(p, &transport_proto);
	break;
    case ETHERTYPE_IPV6:
	parser_process_ipv6(p, &transport_proto);
	break;
    default:
	;
    }
    if (transport_proto == 6) {
	return parser_extractor_process_tcp(p, x);
    }

    return 0;
}




/*
 * The function extractor_process_tcp processes a TCP packet.  The
 * extractor MUST have previously been initialized with its data
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
    if (flags != TCP_SYN) {
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

    } else if (flags == TCP_SYN) {
	return 100;
    }
    return 0;
}

unsigned int parser_process_packet(struct parser *p) {
    size_t transport_proto = 0;
    size_t ethertype = 0;

    parser_process_eth(p, &ethertype);
    switch(ethertype) {
    case ETHERTYPE_IP:
	parser_process_ipv4(p, &transport_proto);
	break;
    case ETHERTYPE_IPV6:
	parser_process_ipv6(p, &transport_proto);
	break;
    default:
	;
    }
    if (transport_proto == 6) {
	return parser_process_tcp(p);
    }

    return 0;
}


/*
 * struct packet_filter implements a packet metadata filter
 */
enum status packet_filter_init(struct packet_filter *pf, const char *config_string) {
    (void)pf;
    fprintf(stderr, "debug: configuring packet_filter with config_string \"%s\"\n", config_string);
    return proto_ident_config(config_string);
}

bool packet_filter_apply(struct packet_filter *pf, uint8_t *packet, size_t length) {

    extractor_init(&pf->x, pf->extractor_buffer, 2048);
    parser_init(&pf->p, (unsigned char *)packet, length);
    size_t bytes_extracted = parser_extractor_process_packet(&pf->p, &pf->x);

    if (bytes_extracted > 16) {
	return true;
    }
    return false;
}


/*
 * configuration for protocol identification
 */

enum status proto_ident_config(const char *config_string) {

    if (config_string == NULL) {
	return status_ok;
    }
    if (strncmp("all", config_string, sizeof("all")) == 0) {
	return status_ok;
    }
    if (strncmp("http", config_string, sizeof("http")) == 0) {
	bzero(tls_client_hello_mask, sizeof(tls_client_hello_mask));
    }
    if (strncmp("tls", config_string, sizeof("tls")) == 0) {
	bzero(http_client_mask, sizeof(http_client_mask));
	bzero(http_server_mask, sizeof(http_server_mask));
    }
    if (strncmp("tcp", config_string, sizeof("tcp")) == 0) {
	bzero(tls_client_hello_mask, sizeof(tls_client_hello_mask));
	bzero(http_client_mask, sizeof(http_client_mask));
	bzero(http_server_mask, sizeof(http_server_mask));
    }
    return status_err;
}
