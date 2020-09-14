/*
 * extractor.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef EXTRACTOR_H
#define EXTRACTOR_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>      /* for FILE */
#include <list>
#include "datum.h"
#include "mercury.h"
#include "tcp.h"
#include "proto_identify.h"


enum fingerprint_type {
    fingerprint_type_unknown     = 0,
    fingerprint_type_tcp         = 1,
    fingerprint_type_tls         = 2,
    fingerprint_type_tls_sni     = 3,
    fingerprint_type_tls_server  = 4,
    fingerprint_type_http        = 5,
    fingerprint_type_http_server = 6,
    fingerprint_type_dhcp_client = 7,
    fingerprint_type_dtls        = 8,
    fingerprint_type_dtls_server = 9,
    fingerprint_type_ssh         = 10,
    fingerprint_type_ssh_kex     = 11
};

struct protocol_state {
    uint16_t proto;   /* protocol IANA number */
    uint16_t dir;     /* DIR_CLIENT, DIR_SERVER, DIR_UNKNOWN */
    uint32_t state;   /* protocol-specific state */
};

/*
 * An extractor is an object that parses data in one buffer, selects
 * some of the data fields and writes them into a second output
 * buffer.  An extractor maintains a pointers into the data buffer
 * (from where the next byte will be read) and into the output buffer
 * (to where the next copied byte will be written).  Its method
 * functions perform all of the necessary bounds checking to ensure
 * that all of the reading and writing operations respect buffer
 * bounaries.  Some operations advance both the data and output
 * pointers, while others advance just the data pointer or just the
 * output pointer, and others advance neither.
 *
 * Some data formats require the parsing of a variable-length data
 * field, whose length is encoded in the data.  To facilitate this, a
 * second 'inner' extractor can be pushed on top of an extractor with
 * the extractor_push function, which initializes the inner extractor
 * to read from the data buffer defined by the variable-length field.
 * After the inner data has been read, a call to extractor_pop updates
 * the outer extractor appropriately.
 *
 * For protocol fingerprinting, the data copied into the output buffer
 * should contain enough information that it can be parsed without the
 * help of any additional information.
 *
 */
struct extractor {
    enum fingerprint_type fingerprint_type;
    unsigned char *output_start;        /* buffer for output         */
    unsigned char *output;              /* buffer for output         */
    unsigned char *output_end;          /* end of output buffer      */
    unsigned char *last_capture;        /* last cap in output stream */
    struct datum tcp;                  // NEW
    struct datum transport_data;       // NEW
    enum msg_type msg_type;             // NEW
};


/*
 * extractor_init(x) initializes the state machine associated with x,
 * and an output buffer (to which selected data will be copied)
 *
 */
void extractor_init(struct extractor *x,
		    unsigned char *output,
		    unsigned int output_len);

/*
 * parser_init initializes a parser object with a data buffer
 * (holding the data to be parsed)
 */
void parser_init(struct datum *p,
		 const unsigned char *data,
		 unsigned int data_len);


unsigned int parser_match(struct datum *p,
                          const unsigned char *value,
                          size_t value_len,
                          const unsigned char *mask);

enum status extractor_reserve(struct extractor *x,
                              unsigned char **data,
                              size_t length);

void parser_init_from_outer_parser(struct datum *p,
                                   const struct datum *outer,
                                   unsigned int data_len);

enum status parser_set_data_length(struct datum *p,
                                   unsigned int data_len);

uint16_t degrease_uint16(uint16_t x);

void degrease_octet_string(void *data, ssize_t len);


/*
 * extractor_skip advances the data pointer by len bytes, but does not
 * advance the output pointer.  It does not copy any data.
 */
enum status extractor_skip(struct extractor *x,
			   unsigned int len);

/*
 * extractor_skip_to advances the data pointer to the location
 * provided as input, but does not advance the output pointer.  It
 * does not copy any data.
 */
enum status extractor_skip_to(struct extractor *x,
			      const unsigned char *location);

/*
 * extractor_copy_append copies data from the data buffer to the
 * output buffer, after updating the length of the previously copied
 * data, then advances both the data pointer and the output pointer.
 */
enum status extractor_copy_append(struct extractor *x,
				  unsigned int len);

 /*
 * extractor_read_uint reads the next num_bytes from the data buffer,
 * interprets them as an unsigned integer in network byte (big endian)
 * order, and writes the resulting value into the size_t at
 * uint_output.  Neither the data pointer nor output pointer are
 * advanced.
 */
enum status extractor_read_uint(struct extractor *x,
				unsigned int num_bytes,
				size_t *uint_output);

/*
 * extractor_get_data_length returns the number of bytes remaining in
 * the data buffer.  Callers should expect that the value returned may
 * be negative.
 */
ptrdiff_t extractor_get_data_length(struct extractor *x);

/*
 * extractor_get_output_length returns the number of bytes of output
 * that have been written into the output buffer.
 */
ptrdiff_t extractor_get_output_length(const struct extractor *x);

unsigned int extractor_match(struct extractor *x,
			     const unsigned char *value,
			     size_t value_len,
			     const unsigned char *mask);


/*
 * new functions for mercury
 */

unsigned int parser_extractor_process_packet(struct datum *p, struct extractor *x);

unsigned int parser_extractor_process_tls(struct datum *p, struct extractor *x);

unsigned int parser_process_tls_server(struct datum *p);

void extract_certificates(FILE *file, const unsigned char *data, size_t data_len);

void write_extract_certificates(struct json_array &buf, const unsigned char *data, size_t data_len);

void write_extract_cert_prefix(struct buffer_stream &buf, const unsigned char *data, size_t data_len);

void write_extract_cert_full(struct json_array &a, const unsigned char *data, size_t data_len);

enum status parser_read_and_skip_uint(struct datum *p,
                                      unsigned int num_bytes,
                                      size_t *output);

enum status parser_skip(struct datum *p,
                        unsigned int len);

unsigned int parser_extractor_process_ssh(struct datum *p, struct extractor *x);


enum status parser_extractor_copy(struct datum *p,
                                  struct extractor *x,
                                  unsigned int len);

enum status parser_read_uint(struct datum *p,
                             unsigned int num_bytes,
                             size_t *output);

enum status parser_extractor_copy_append(struct datum *p,
                                         struct extractor *x,
                                         unsigned int len);


void parser_init_packet(struct datum *p, const unsigned char *data, unsigned int length);


/*
 * struct packet_filter implements packet metadata filtering
 */
struct packet_filter {
    struct tcp_initial_message_filter *tcp_init_msg_filter;
    struct datum p;
    struct extractor x;
    unsigned char extractor_buffer[2048];
};

/*
 * packet_filter_init(pf, s) initializes a packet filter, using the
 * configuration string s passed as input
 */
enum status packet_filter_init(struct packet_filter *pf,
			       const char *config_string);

/*
 * packet_filter_apply(pf, p, len) applies the packet
 * filter pf to the packet p of length len, and returns
 * true if the packet should be kept, and false if the
 * packet should be dropped
 */

bool packet_filter_apply(struct packet_filter *pf,
			 uint8_t *packet,
			 size_t length);

size_t packet_filter_extract(struct packet_filter *pf,
                             struct key *k,
                             uint8_t *packet,
                             size_t length);

unsigned int packet_filter_process_packet(struct packet_filter *pf, struct key *k);

typedef unsigned int (*parser_extractor_func)(struct datum *p, struct extractor *x);

#define proto_ident_mask_len 8

struct proto_dispatch_entry {
    uint8_t mask[proto_ident_mask_len];
    uint8_t value[proto_ident_mask_len];
    parser_extractor_func func;
};

#define proto_dispatch_max 8

struct proto_dispatch {
    struct proto_dispatch_entry entry[proto_dispatch_max];
    unsigned int num_entries;
};

void proto_dispatch_init(struct proto_dispatch *pd);

enum status proto_dispatch_add(struct proto_dispatch *pd,
			       const struct proto_dispatch_entry *pde);


enum status proto_ident_config(const char *config_string);

ptrdiff_t parser_get_data_length(struct datum *p);

enum msg_type get_message_type(const uint8_t *tcp_data,
                               unsigned int len);

#endif /* EXTRACTOR_H */
