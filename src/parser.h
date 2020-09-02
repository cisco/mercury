/*
 * parser.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef PARSER_H
#define PARSER_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>      /* for FILE */
#include <string>
#include "mercury.h"
#include "tcp.h"

/*
 * The extractor_debug macro is useful for debugging (but quite verbose)
 */
#ifndef DEBUG
#define extractor_debug(...)
#else
#define extractor_debug(...)  (fprintf(stdout, __VA_ARGS__))
#endif

inline uint8_t lowercase(uint8_t x) {
    if (x >= 'A' && x <= 'Z') {
        return x + ('a' - 'A');
    }
    return x;
}

struct parser {
    const unsigned char *data;          /* data being parsed/copied  */
    const unsigned char *data_end;      /* end of data buffer        */

    //parser() : data{NULL}, data_end{NULL} {}
    //parser(const unsigned char *d, const unsigned char *e) : data{d}, data_end{e} {}
    //parser(const unsigned char *d, size_t length) : data{d}, data_end{d+length} {}
    const std::string get_string() const { std::string s((char *)data, (int) (data_end - data)); return s;  }
    const std::basic_string<uint8_t> get_bytestring() const { std::basic_string<uint8_t> s((uint8_t *)data, (int) (data_end - data)); return s;  }
    bool is_not_null() const { return data == NULL; }
    bool is_not_empty() const { return data != NULL && data < data_end; }
    bool is_not_readable() const { return data == NULL || data == data_end; }
    void set_empty() { data = data_end; }
    void set_null() { data = data_end = NULL; }
    ssize_t length() const { return data_end - data; }
    void parse(struct parser &r, size_t num_bytes) {
        if (r.length() < (ssize_t)num_bytes) {
            r.set_null();
        }
        data = r.data;
        data_end = r.data + num_bytes;
        r.data += num_bytes;
    }
    void parse_soft_fail(struct parser &r, size_t num_bytes) {
        if (r.length() < (ssize_t)num_bytes) {
            num_bytes = r.length();  // only parse bytes that are available
        }
        data = r.data;
        data_end = r.data + num_bytes;
        r.data += num_bytes;
    }
    void parse_up_to_delim(struct parser &r, uint8_t delim) {
        data = r.data;
        while (r.data <= r.data_end) {
            if (*r.data == delim) { // found delimeter
                data_end = r.data;
                return;
            }
            r.data++;
        }
    }
    uint8_t parse_up_to_delimeters(struct parser &r, uint8_t delim1, uint8_t delim2) {
        data = r.data;
        while (r.data <= r.data_end) {
            if (*r.data == delim1) { // found first delimeter
                data_end = r.data;
                return delim1;
            }
            if (*r.data == delim2) { // found second delimeter
                data_end = r.data;
                return delim2;
            }
            r.data++;
        }
        return 0;
    }
    void skip(size_t length) {
        data += length;
        if (data > data_end) {
            data = data_end;
        }
    }
    void trim(size_t length) {
        data_end -= length;
        if (data_end < data) {
            data_end = data;
        }
    }
    bool case_insensitive_match(const struct parser r) const {
        if (length() != r.length()) {
            return false;
        } else {
            const uint8_t *tmp_l = data;
            const uint8_t *tmp_r = r.data;
            while (tmp_l < data_end) {
                if (*tmp_l++ != lowercase(*tmp_r++)) {
                    return false;
                }
            }
            return true;
        }
    }
    bool operator==(const parser &p) const {
        return (length() == p.length()) && memcmp(data, p.data, length()) == 0;
    }
    unsigned int bits_in_data() const {                  // for use with (ASN1) integers
        unsigned int bits = (data_end - data) * 8;
        const unsigned char *d = data;
        while (d < data_end) {
            for (unsigned char c = 0x80; c > 0; c=c>>1) {
                if (*d & c) {
                    return bits;
                }
                bits--;
            }
            d++;
        }
        return bits;
    }

    // read_uint8() reads a uint8_t in network byte order, and advances the data pointer
    //
    bool read_uint8(uint8_t *output) {
        if (data_end > data) {
            *output = *data;
            data += 1;
            return true;
        }
        *output = 0;
        return false;
    }

    // read_uint16() reads a uint16_t in network byte order, and advances the data pointer
    //
    bool read_uint16(uint16_t *output) {
        if (length() >= (int)sizeof(uint16_t)) {
            uint16_t *tmp = (uint16_t *)data;
            *output = ntohs(*tmp);
            data += sizeof(uint16_t);
            return true;
        }
        *output = 0;
        return false;
    }

    // read_uint32() reads a uint32_t in network byte order, and advances the data pointer
    //
    bool read_uint32(uint32_t *output) {
        if (length() >= (int)sizeof(uint32_t)) {
            uint32_t *tmp = (uint32_t *)data;
            *output = ntohl(*tmp);
            data += sizeof(uint32_t);
            return true;
        }
        *output = 0;
        return false;
    }

    // read_uint() reads a length num_bytes uint in network byte order, and advances the data pointer
    //
    bool read_uint(size_t *output, unsigned int num_bytes) {

        if (data && data + num_bytes <= data_end) {
            size_t tmp = 0;
            const unsigned char *c;

            for (c = data; c < data + num_bytes; c++) {
                tmp = (tmp << 8) + *c;
            }
            *output = tmp;
            data = c;
            extractor_debug("%s: num_bytes: %u, value (hex) %08x (decimal): %zd\n", __func__, num_bytes, (unsigned)tmp, tmp);
            return true;
        }
        *output = 0;
        return false;
    }

    bool set_uint(size_t *output, unsigned int num_bytes) {

        if (data && data + num_bytes <= data_end) {
            size_t tmp = 0;
            const unsigned char *c;

            for (c = data; c < data + num_bytes; c++) {
                tmp = (tmp << 8) + *c;
            }
            *output = tmp;
            return true;
        }
        return false;
    }

    void init_from_outer_parser(struct parser *outer,
                                unsigned int data_len) {
        const unsigned char *inner_data_end = outer->data + data_len;

        data = outer->data;
        data_end = inner_data_end > outer->data_end ? outer->data_end : inner_data_end;
        outer->data = data_end; // PROVISIONAL; NEW APPROACH
    }

};

/*
 * parser_init initializes a parser object with a data buffer
 * (holding the data to be parsed)
 */
void parser_init(struct parser *p,
		 const unsigned char *data,
		 unsigned int data_len);


unsigned int parser_match(struct parser *p,
                          const unsigned char *value,
                          size_t value_len,
                          const unsigned char *mask);

void parser_init_from_outer_parser(struct parser *p,
                                   const struct parser *outer,
                                   unsigned int data_len);

enum status parser_set_data_length(struct parser *p,
                                   unsigned int data_len);

unsigned int parser_process_tls_server(struct parser *p);

enum status parser_read_and_skip_uint(struct parser *p,
                                      unsigned int num_bytes,
                                      size_t *output);

enum status parser_skip(struct parser *p,
                        unsigned int len);

enum status parser_read_uint(struct parser *p,
                             unsigned int num_bytes,
                             size_t *output);

void parser_init_packet(struct parser *p, const unsigned char *data, unsigned int length);


ptrdiff_t parser_get_data_length(struct parser *p);

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
                      size_t length);

enum status parser_skip_to(struct parser *p,
                           const unsigned char *location);

void parser_pop(struct parser *inner, struct parser *outer);

enum status parser_skip_upto_delim(struct parser *p,
                                   const unsigned char delim[],
                                   size_t length);

enum status parser_read_and_skip_uint(struct parser *p,
                                      unsigned int num_bytes,
                                      size_t *output);

enum status parser_read_and_skip_byte_string(struct parser *p,
                                             unsigned int num_bytes,
                                             uint8_t *output_string);


/*
 * start of protocol parsing functions
 */

unsigned int parser_process_eth(struct parser *p, size_t *ethertype);

/*
 * The function parser_process_tcp processes a TCP packet.  The
 * parser MUST have previously been initialized with its data
 * pointer set to the initial octet of a TCP header.
 */

unsigned int parser_process_tcp(struct parser *p);

unsigned int parser_process_ipv4(struct parser *p, size_t *transport_protocol, struct key *k);

unsigned int parser_process_ipv6(struct parser *p, size_t *transport_protocol, struct key *k);

unsigned int parser_process_packet(struct parser *p);


#endif /* PARSER_H */
