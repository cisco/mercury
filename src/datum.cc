/*
 * datum.cc
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include "datum.h"

void datum_init(struct datum *p,
                 const unsigned char *data,
                 unsigned int data_len) {

    p->data = data;
    p->data_end = data + data_len;

    mercury_debug("%s: initialized with %td bytes\n", __func__, p->data_end - p->data);
}

void datum_init_from_outer_parser(struct datum *p,
                                   const struct datum *outer,
                                   unsigned int data_len) {
    const unsigned char *inner_data_end = outer->data + data_len;

    p->data = outer->data;
    p->data_end = inner_data_end > outer->data_end ? outer->data_end : inner_data_end;

    mercury_debug("%s: initialized with %td bytes\n", __func__, p->data_end - p->data);
}

enum status datum_set_data_length(struct datum *p,
                                   unsigned int data_len) {

    mercury_debug("%s: set_data_length from %ld to %u\n", __func__, p->data_end - p->data, data_len);

    if (p->data + data_len <= p->data_end) {
        p->data_end = p->data + data_len;
        return status_ok;
    }
    return status_err;
}

enum status datum_skip(struct datum *p,
                        unsigned int len) {
    mercury_debug("%s: skipping %u bytes (%02x...)\n", __func__, len, p->data[0]);

    if (p->data + len <= p->data_end) {
        p->data = p->data + len;
        return status_ok;
    }
    mercury_debug("%s: error; tried to skip %u, only %td remaining\n", __func__, len, p->data_end - p->data);
    return status_err;
}

enum status datum_skip_to(struct datum *p,
                           const unsigned char *location) {

    if (location <= p->data_end) {
        p->data = location;
        return status_ok;
    }
    mercury_debug("%s: error; tried to skip %td, only %td remaining\n", __func__, location - p->data_end, p->data_end - p->data);
    return status_err;
}

enum status datum_read_uint(struct datum *p,
                             unsigned int num_bytes,
                             size_t *output) {

    if (p->data + num_bytes <= p->data_end) {
        size_t tmp = 0;
        const unsigned char *c;

        for (c = p->data; c < p->data + num_bytes; c++) {
            tmp = (tmp << 8) + *c;
        }
        *output = tmp;
        mercury_debug("%s: num_bytes: %u, value (hex) %08x (decimal): %zd\n", __func__, num_bytes, (unsigned)tmp, tmp);
        return status_ok;
    }
    return status_err;
}

enum status datum_read_and_skip_uint(struct datum *p,
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
        mercury_debug("%s: num_bytes: %u, value (hex) %08x (decimal): %zu\n", __func__, num_bytes, (unsigned) tmp, tmp);
        return status_ok;
    }
    return status_err;
}

enum status datum_read_and_skip_byte_string(struct datum *p,
                                             unsigned int num_bytes,
                                             uint8_t *output_string) {

    if (p->data + num_bytes <= p->data_end) {
        const unsigned char *c;

        for (c = p->data; c < p->data + num_bytes; c++) {
            *output_string++ = *c;
        }
        p->data += num_bytes;
        mercury_debug("%s: num_bytes: %u\n", __func__, num_bytes);
        return status_ok;
    }
    return status_err;
}

/*
 * datum_find_delim(p, d, l) looks for the delimiter d with length l
 * in the parser p's data buffer, until it reaches the delimiter d or
 * the end of the data in the parser, whichever comes first.  In the
 * first case, the function returns the number of bytes to the
 * delimiter; in the second case, the function returns the number of
 * bytes to the end of the data buffer.
 */
int datum_find_delim(struct datum *p,
                      const unsigned char *delim,
                      size_t length) {

    /* find delimiter, if present */
    const unsigned char *data = p->data;
    const unsigned char *pattern = delim;
    const unsigned char *pattern_end = delim + length;
    while (pattern < pattern_end && data < p->data_end) {
        mercury_debug("%s: data index: %lu\tpattern index: %lu\n", __func__, data - p->data, pattern - delim);
        mercury_debug("%s: data: %02x, pattern: %02x\n", __func__, *data, *pattern);
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

enum status datum_skip_upto_delim(struct datum *p,
                                   const unsigned char delim[],
                                   size_t length) {

    int delim_index = datum_find_delim(p, delim, length);

    mercury_debug("%s: length: %zu, index: %d\n", __func__, length, delim_index);

    if (delim_index >= 0) {
        return datum_skip(p, delim_index);

    }
    mercury_debug("%s: error\n", __func__);
    return status_err;
}

ptrdiff_t datum_get_data_length(struct datum *p) {
    return p->data_end - p->data;
}


/*
 * datum_match(x, value, value_len, mask) returns status_ok if
 * (x->data & mask) == value, and returns status_err otherwise
 * It advances p->data by value_len when it returns status_ok
 */
unsigned int datum_match(struct datum *p,
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
