/*
 * utils.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef UTILS_H
#define UTILS_H

#include <time.h>
#include <stdarg.h>
#include "mercury.h"
#include "packet.h"
#include "analysis.h"

/*
 * obsolete macros
 */
#define PARENT_NODE_INDICATOR 0x8000
#define LENGTH_MASK           0x7fff

/* utility functions */

void encode_uint16(uint8_t *p, uint16_t x);

uint16_t decode_uint16(const void *x);

void packet_handler_null(uint8_t *ignore,
			 const struct pcap_pkthdr *pcap_pkthdr,
			 const uint8_t *packet);

void packet_handler_printf(uint8_t *ignore,
			   const struct pcap_pkthdr *pcap_pkthdr,
			   const uint8_t *packet);

size_t hex_to_raw(const void *output,
		       size_t output_buf_len,
		       const char *null_terminated_hex_string);

void fprintf_json_hex_string(FILE *file,
                            const unsigned char *data,
                            unsigned int len);

void fprintf_raw_as_hex(FILE *f, const uint8_t *data, unsigned int len);

void fprintf_json_hex_string(FILE *f, const char *key, const uint8_t *data, unsigned int len);


void fprintf_json_string(FILE *f, const char *key, const uint8_t *data, unsigned int len);

enum status drop_root_privileges(const char *username, const char *directory);

int copy_string_into_buffer(char *dst, size_t dst_len, const char *src, size_t max_src_len);

void fprintf_json_base64_string(FILE *file, const unsigned char *data, size_t input_length);

void printf_raw_as_hex(const uint8_t *data, unsigned int len);

/*
 * get_readable_number_float() provides an imprecise but
 * human-understandable representation of a (potentially very large)
 * number, for printing out
 */

void get_readable_number_float(double power,
                               double input,
                               double *num_output,
                               char **str_output);


enum status filename_append(char dst[MAX_FILENAME],
			    const char *src,
			    const char *delim,
			    const char *tail);

struct timer {
    struct timespec before;
    struct timespec after;
};

void timer_start(struct timer *t);
uint64_t timer_stop(struct timer *t);

#endif /* UTILS_H */
