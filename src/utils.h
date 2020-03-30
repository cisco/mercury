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

void packet_handler_null(uint8_t *ignore,
			 const struct pcap_pkthdr *pcap_pkthdr,
			 const uint8_t *packet);

void packet_handler_printf(uint8_t *ignore,
			   const struct pcap_pkthdr *pcap_pkthdr,
			   const uint8_t *packet);


size_t hex_to_raw(const void *output,
		       size_t output_buf_len,
		       const char *null_terminated_hex_string);

int append_snprintf(char *dstr, int *doff, int dlen, int *trunc,
                    const char *fmt, ...);

int append_strncpy(char *dstr, int *doff, int dlen, int *trunc,
                   const char *sstr);

int append_putc(char *dstr, int *doff, int dlen, int *trunc,
                char schr);

int append_json_string_escaped(char *dstr, int *doff, int dlen, int *trunc,
                               const char *key, const uint8_t *data, unsigned int len);

void fprintf_json_string_escaped(FILE *f, const char *key, const uint8_t *data, unsigned int len);

int append_json_hex_string(char *dstr, int *doff, int dlen, int *trunc,
                           const uint8_t *data, unsigned int len);

int append_json_hex_string(char *dstr, int *doff, int dlen, int *trunc,
                           const char *key, const uint8_t *data, unsigned int len);

// TBD: merge the above functions

void fprintf_json_hex_string(FILE *file,
                            const unsigned char *data,
                            unsigned int len);

int append_raw_as_hex(char *dstr, int *doff, int dlen, int *trunc,
                      const uint8_t *data, unsigned int len);

void fprintf_raw_as_hex(FILE *f, const uint8_t *data, unsigned int len);

void fprintf_json_hex_string(FILE *f, const char *key, const uint8_t *data, unsigned int len);

int append_json_string(char *dstr, int *doff, int dlen, int *trunc,
                       const char *key, const uint8_t *data, unsigned int len);

void fprintf_json_string(FILE *f, const char *key, const uint8_t *data, unsigned int len);

enum status drop_root_privileges(const char *username, const char *directory);

int copy_string_into_buffer(char *dst, size_t dst_len, const char *src, size_t max_src_len);

int append_json_base64_string(char *dstr, int *doff, int dlen, int *trunc,
                              const unsigned char *data,
                              size_t input_length);

int append_memcpy(char *dstr, int *doff, int dlen, int *trunc, const void *src, ssize_t length);

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

/*
 * buffer_stream
 */

struct buffer_stream {
    char *dstr;
    int doff;
    int dlen;
    int trunc;

    buffer_stream(char *dstr, int dlen) : dstr{dstr}, doff{0}, dlen{dlen}, trunc{0} {};

    int snprintf(const char *fmt, ...) {
        va_list args;
        va_start(args, fmt);
        int retval = append_snprintf(dstr, &doff, dlen, &trunc, fmt, args); 
        va_end(args);
        return retval;
    }

    int strncpy(const char *sstr) {
        return append_strncpy(dstr, &doff, dlen, &trunc, sstr);
    }

    int putc(char schr) {
        return append_putc(dstr, &doff, dlen, &trunc, schr);
    }

    int json_string(const char *key, const uint8_t *data, unsigned int len) {
        return append_json_string(dstr, &doff, dlen, &trunc, key, data, len);
    }

    int json_string_escaped(const char *key, const uint8_t *data, unsigned int len) {
        return append_json_string_escaped(dstr, &doff, dlen, &trunc, key, data, len);
    }

    int json_hex_string(const uint8_t *data, unsigned int len) {
        return append_json_hex_string(dstr, &doff, dlen, &trunc, data, len);
    }

    int raw_as_hex(const uint8_t *data, unsigned int len) {
        return append_raw_as_hex(dstr, &doff, dlen, &trunc, data, len);
    }

    int json_base64_string(const unsigned char *data, size_t input_length) {
        return append_json_base64_string(dstr, &doff, dlen, &trunc, data, input_length);
    }

    int memcpy(const void *src, ssize_t length) {
        return append_memcpy(dstr, &doff, dlen, &trunc, src, length);
    }

};


#endif /* UTILS_H */
