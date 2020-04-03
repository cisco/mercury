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
#include "ept.h"
#include "extractor.h"
#include "packet.h"
#include "analysis.h"

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

    size_t length() { return doff; }

    int snprintf(const char *fmt, ...) {

        /* Check to make sure the offset isn't already longer than the length */
        if (doff >= dlen) {
            trunc = 1;
            return 0;
        }

        va_list args;
        va_start(args, fmt);
        int r = vsnprintf(&(dstr[doff]), dlen - doff, fmt, args);
        va_end(args);

        /* Check for truncation */
        if (r >= dlen - doff) {
            fprintf(stderr, "Truncation occurred in substr_snprintf(...). Space available: %d; needed: %d\n",
                    dlen - doff, r);

            doff = dlen;
            trunc = 1;
        } else {
            doff = doff + r;
            trunc = 0;
        }

        return r;
    }

    void strncpy(const char *sstr) {
        append_strncpy(dstr, &doff, dlen, &trunc, sstr);
    }

    void putc(char schr) {
        append_putc(dstr, &doff, dlen, &trunc, schr);
    }

    void json_string(const char *key, const uint8_t *data, unsigned int len) {
        append_json_string(dstr, &doff, dlen, &trunc, key, data, len);
    }

    void json_string_escaped(const char *key, const uint8_t *data, unsigned int len) {
        append_json_string_escaped(dstr, &doff, dlen, &trunc, key, data, len);
    }

    void json_hex_string(const uint8_t *data, unsigned int len) {
        append_json_hex_string(dstr, &doff, dlen, &trunc, data, len);
    }

    void raw_as_hex(const uint8_t *data, unsigned int len) {
        append_raw_as_hex(dstr, &doff, dlen, &trunc, data, len);
    }

    void json_base64_string(const unsigned char *data, size_t input_length) {
        append_json_base64_string(dstr, &doff, dlen, &trunc, data, input_length);
    }

    void memcpy(const void *src, ssize_t length) {
        append_memcpy(dstr, &doff, dlen, &trunc, src, length);
    }

    void write_binary_ept_as_paren_ept(const unsigned char *data, unsigned int length) {
        append_binary_ept_as_paren_ept(dstr, &doff, dlen, &trunc, data, length);
    }

    void write_timestamp(struct timespec *ts) {
        append_snprintf(dstr, &doff, dlen, &trunc, ",\"event_start\":%u.%06u", ts->tv_sec, ts->tv_nsec / 1000);
    }

    void write_extract_certificates(const unsigned char *data, size_t data_len) {
        append_extract_certificates(dstr, &doff, dlen, &trunc, data, data_len);
    }

    void write_packet_flow_key(uint8_t *packet, size_t length) {
        append_packet_flow_key(dstr, &doff, dlen, &trunc, packet, length);
    }

    void write_analysis_from_extractor_and_flow_key(const struct extractor *x, const struct flow_key *key) {
        append_analysis_from_extractor_and_flow_key(dstr, &doff, dlen, &trunc, x, key);
    }

};


#endif /* UTILS_H */
