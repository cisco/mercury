/*
 * buffer_stream.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef BUFFER_STREAM_H
#define BUFFER_STREAM_H

#include <string.h>  /* for memcpy() */
#include "utils.h"


/* append_null(...)
 * This is a special append function because all other append_...() functions
 * leave room for a null in the buffer but don't actually put a null there.
 * Provided the buffer isn't zero in size this function should always be able
 * to put a null into the buffer even if the truncation flag is already set.
 */
static inline void append_null(char *dstr, int *doff, int dlen, int *trunc) {

    /* Check to make sure the offset isn't already longer than the length */
    if (*doff >= dlen) {
        *trunc = 1;
    }

    dstr[*doff] = '\0';
}


/* append_snprintf
 * takes the base address of a string, the offset in the string, total length, and a truncation flag
 * and stores the desired snprintf() content at that offset.
 *
 * return: the amount stored (or needed to be stored in case of truncation)
 */
static inline int append_snprintf(char *dstr, int *doff, int dlen, int *trunc,
                                  const char *fmt, ...) {

    if (*trunc == 1) {
        return 0;
    }

    /* Check to make sure the offset isn't already longer than the length */
    if (*doff >= dlen) {
        *trunc = 1;
        return 0;
    }

    va_list args;
    va_start(args, fmt);
    int r = vsnprintf(&(dstr[*doff]), dlen - *doff, fmt, args);
    va_end(args);

    /* Check for truncation */
    if (r >= dlen - *doff) {
        fprintf(stderr, "Truncation occurred in substr_snprintf(...). Space available: %d; needed: %d\n",
                dlen - *doff, r);

        r = (dlen - *doff) - 1;
        if (r < 0) {
            r = 0;
        }

        *doff = dlen;
        *trunc = 1;
    } else {
        *doff = *doff + r;
        *trunc = 0;
    }

    return r;
}

static inline int append_strncpy(char *dstr, int *doff, int dlen, int *trunc,
                   const char *sstr) {

    if (*trunc == 1) {
        return 0;
    }

    /* Check to make sure the offset isn't already longer than the length */
    if (*doff >= dlen) {
        *trunc = 1;
        return 0;
    }

    int gn = 0; /* got a null */
    int i = 0;
    while (*doff + i < dlen - 1) {
        if (sstr[i] != '\0') {
            dstr[*doff + i] = sstr[i];
            i++;
        } else {
            gn = 1;
            break;
        }
    }

    /* Detect truncation */
    if (gn != 1) {
        *trunc = 1;
    }

    /* adjust the offset */
    *doff = *doff + i;

    return i; /* i doesn't count the null, just like in snprintf */
}

static inline int append_putc(char *dstr, int *doff, int dlen, int *trunc,
                char schr) {

    if (*trunc == 1) {
        return 0;
    }

    /* Check to make sure the offset isn't already longer than the length */
    if (*doff >= dlen) {
        *trunc = 1;
        return 0;
    }

    if (*doff < dlen - 1) {
        dstr[*doff] = schr;
        *doff = *doff + 1;
        return 1;
    } else {
        *trunc = 1;
        return 0;
    }
}

static inline int append_memcpy(char *dstr, int *doff, int dlen, int *trunc, const void *s, ssize_t length) {
    const uint8_t *src = (const uint8_t *)s;

    if (*trunc == 1) {
        return 0;
    }

    /* Check to make sure the offset isn't already longer than the length */
    if (*doff >= dlen) {
        *trunc = 1;
        return 0;
    }

    if (*doff < (dlen - 1) - length) {   // TBD: over/under flow?
        memcpy(dstr + *doff, src, length);
        *doff = *doff + length;
        return length;
    } else {
        *trunc = 1;
        return 0;
    }
}

static char hex_table[] = {'0', '1', '2', '3',
                           '4', '5', '6', '7',
                           '8', '9', 'a', 'b',
                           'c', 'd', 'e', 'f'};

static inline int append_raw_as_hex(char *dstr, int *doff, int dlen, int *trunc,
                                    const uint8_t *data, unsigned int len) {

    if (*trunc == 1) {
        return 0;
    }

    int r = 0;
    char outb[256]; /* A local buffer of up to 256 hex chars at a time */
    int oi = 0;    /* The index into the output buffer */

    for (unsigned int i = 0; (i < len) && (*trunc == 0); i++) {
        outb[oi]     = hex_table[(data[i] & 0xf0) >> 4];
        outb[oi + 1] = hex_table[data[i] & 0x0f];

        if (oi < 254) {
            oi += 2;
        } else {
            r += append_memcpy(dstr, doff, dlen, trunc,
                               outb, 256);
            oi = 0;
        }
    }

    if (oi > 0) {
        r += append_memcpy(dstr, doff, dlen, trunc,
                           outb, oi);
    }

    return r;
}


static inline int append_json_hex_string(char *dstr, int *doff, int dlen, int *trunc,
                                         const char *key, const uint8_t *data, unsigned int len) {

    if (*trunc == 1) {
        return 0;
    }

    int r = 0;

    r += append_putc(dstr, doff, dlen, trunc, '"');
    r += append_strncpy(dstr, doff, dlen, trunc, key);
    r += append_strncpy(dstr, doff, dlen, trunc, "\":\"0x");
    r += append_raw_as_hex(dstr, doff, dlen, trunc,
                           data, len);
    r += append_putc(dstr, doff, dlen, trunc, '"');

    return r;
}

static inline int append_json_hex_string(char *dstr, int *doff, int dlen, int *trunc,
                                         const uint8_t *data, unsigned int len) {

    if (*trunc == 1) {
        return 0;
    }

    int r = 0;

    r += append_putc(dstr, doff, dlen, trunc,
                     '"');
    r += append_raw_as_hex(dstr, doff, dlen, trunc,
                           data, len);
    r += append_putc(dstr, doff, dlen, trunc, '"');

    return r;
}


static inline int append_timestamp(char *dstr, int *doff, int dlen, int *trunc,
                                   struct timespec *ts) {

    if (*trunc == 1) {
        return 0;
    }

    int r = 0;
    char outs[10 + 1 + 6]; /* 10 sec digits, 1 decimal, 6 usec */

    /* First we convert the seconds to a string which requires
     * that we identify and skip leading zeros */
    int i = 0; /* outs index */
    int leadin = 1; /* We're still getting leading zeros */

    uint64_t secs = ts->tv_sec;
    for (int p = 1000000000; p >= 10; p /= 10) {
        int d = secs / p;
        secs %= p;

        if ((d == 0) && (leadin == 1)) {
            continue;
        }

        leadin = 0;
        outs[i] = '0' + d;
        i++;
    }
    /* Store the final digit which can be 0 */
    outs[i] = '0' + secs;
    i++;

    /* Now store the decimal point */
    outs[i] = '.';
    i++;

    /* And finally we write the decimal digits which should have leading zeros */
    uint64_t usecs = ts->tv_nsec / 1000;
    for (int p = 100000; p >= 1; p /= 10) {
        int d = usecs / p;
        usecs %= p;

        outs[i] = '0' + d;
        i++;
    }

    r += append_memcpy(dstr, doff, dlen, trunc,
                       outs, i);

    return r;
}


static inline int append_uint8(char *dstr, int *doff, int dlen, int *trunc,
                               uint8_t n) {

    if (*trunc == 1) {
        return 0;
    }

    int r = 0;
    char outs[3]; /* 3 digits */

    int i = 0; /* outs index */
    int leadin = 1; /* We're still getting leading zeros */

    for (int p = 100; p >= 10; p /= 10) {
        int d = n / p;
        n %= p;

        if ((d == 0) && (leadin == 1)) {
            continue;
        }

        leadin = 0;
        outs[i] = '0' + d;
        i++;
    }
    /* Store the final digit which can be 0 */
    outs[i] = '0' + n;
    i++;

    r += append_memcpy(dstr, doff, dlen, trunc,
                       outs, i);

    return r;
}


static inline int append_uint16(char *dstr, int *doff, int dlen, int *trunc,
                                uint16_t n) {

    if (*trunc == 1) {
        return 0;
    }

    int r = 0;
    char outs[5]; /* 5 digits */

    int i = 0; /* outs index */
    int leadin = 1; /* We're still getting leading zeros */

    for (int p = 10000; p >= 10; p /= 10) {
        int d = n / p;
        n %= p;

        if ((d == 0) && (leadin == 1)) {
            continue;
        }

        leadin = 0;
        outs[i] = '0' + d;
        i++;
    }
    /* Store the final digit which can be 0 */
    outs[i] = '0' + n;
    i++;

    r += append_memcpy(dstr, doff, dlen, trunc,
                       outs, i);

    return r;
}


static inline int append_uint16_hex(char *dstr, int *doff, int dlen, int *trunc,
                                    uint16_t n) {

    if (*trunc == 1) {
        return 0;
    }

    int r = 0;
    char outs[4]; /* 4 hex chars */

    outs[0] = hex_table[(n & 0xf000) >> 12];
    outs[1] = hex_table[(n & 0x0f00) >> 8];
    outs[2] = hex_table[(n & 0x00f0) >> 4];
    outs[3] = hex_table[n & 0x000f];

    r += append_memcpy(dstr, doff, dlen, trunc,
                       outs, 4);

    return r;
}


static inline int append_ipv6_addr(char *dstr, int *doff, int dlen, int *trunc,
                                    const uint8_t *v6) {

    if (*trunc == 1) {
        return 0;
    }

    int r = 0;
    char outs[(4 * 8) + (1 * 7)]; /* 8 groups of 4 hex chars; 7 colons */

    outs[0] = hex_table[(v6[0] & 0xf0) >> 4];
    outs[1] = hex_table[v6[0] & 0x0f];
    outs[2] = hex_table[(v6[1] & 0xf0) >> 4];
    outs[3] = hex_table[v6[1] & 0x0f];
    outs[4] = ':';
    outs[5] = hex_table[(v6[2] & 0xf0) >> 4];
    outs[6] = hex_table[v6[2] & 0x0f];
    outs[7] = hex_table[(v6[3] & 0xf0) >> 4];
    outs[8] = hex_table[v6[3] & 0x0f];
    outs[9] = ':';
    outs[10] = hex_table[(v6[4] & 0xf0) >> 4];
    outs[11] = hex_table[v6[4] & 0x0f];
    outs[12] = hex_table[(v6[5] & 0xf0) >> 4];
    outs[13] = hex_table[v6[5] & 0x0f];
    outs[14] = ':';
    outs[15] = hex_table[(v6[6] & 0xf0) >> 4];
    outs[16] = hex_table[v6[6] & 0x0f];
    outs[17] = hex_table[(v6[7] & 0xf0) >> 4];
    outs[18] = hex_table[v6[7] & 0x0f];
    outs[19] = ':';
    outs[20] = hex_table[(v6[8] & 0xf0) >> 4];
    outs[21] = hex_table[v6[8] & 0x0f];
    outs[22] = hex_table[(v6[9] & 0xf0) >> 4];
    outs[23] = hex_table[v6[9] & 0x0f];
    outs[24] = ':';
    outs[25] = hex_table[(v6[10] & 0xf0) >> 4];
    outs[26] = hex_table[v6[10] & 0x0f];
    outs[27] = hex_table[(v6[11] & 0xf0) >> 4];
    outs[28] = hex_table[v6[11] & 0x0f];
    outs[29] = ':';
    outs[30] = hex_table[(v6[12] & 0xf0) >> 4];
    outs[31] = hex_table[v6[12] & 0x0f];
    outs[32] = hex_table[(v6[13] & 0xf0) >> 4];
    outs[33] = hex_table[v6[13] & 0x0f];
    outs[34] = ':';
    outs[35] = hex_table[(v6[14] & 0xf0) >> 4];
    outs[36] = hex_table[v6[14] & 0x0f];
    outs[37] = hex_table[(v6[15] & 0xf0) >> 4];
    outs[38] = hex_table[v6[15] & 0x0f];

    r += append_memcpy(dstr, doff, dlen, trunc,
                       outs, 39);

    return r;
}


static inline int append_ipv4_addr(char *dstr, int *doff, int dlen, int *trunc,
                                   const uint8_t *v4) {

    if (*trunc == 1) {
        return 0;
    }

    int r = 0;

    r += append_uint8(dstr, doff, dlen, trunc,
                      v4[0]);
    r += append_putc(dstr, doff, dlen, trunc,
                     '.');
    r += append_uint8(dstr, doff, dlen, trunc,
                      v4[1]);
    r += append_putc(dstr, doff, dlen, trunc,
                     '.');
    r += append_uint8(dstr, doff, dlen, trunc,
                      v4[2]);
    r += append_putc(dstr, doff, dlen, trunc,
                     '.');
    r += append_uint8(dstr, doff, dlen, trunc,
                      v4[3]);

    return r;
}


static inline int append_json_string_escaped(char *dstr, int *doff, int dlen, int *trunc,
                                             const char *key, const uint8_t *data, unsigned int len) {

    if (*trunc == 1) {
        return 0;
    }

    int r = 0;

    r += append_putc(dstr, doff, dlen, trunc, '"');
    r += append_strncpy(dstr, doff, dlen, trunc, key);
    r += append_strncpy(dstr, doff, dlen, trunc, "\":\"");

    for (unsigned int i = 0; (i < len) && (*trunc == 0); i++) {
        if ((data[i] < 0x20) || /* escape control characters   */
            (data[i] > 0x7f)) { /* escape non-ASCII characters */
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\\u00");
            r += append_putc(dstr, doff, dlen, trunc,
                             hex_table[(data[i] & 0xf0) >> 4]);
            r += append_putc(dstr, doff, dlen, trunc,
                             hex_table[data[i] & 0x0f]);
        } else {
            if (data[i] == '"' || data[i] == '\\') { /* escape special characters   */
                r += append_putc(dstr, doff, dlen, trunc,
                                 '\\');
            }
            r += append_putc(dstr, doff, dlen, trunc,
                             data[i]);
        }
    }

    r += append_putc(dstr, doff, dlen, trunc,
                     '"');

    return r;
}

static inline unsigned int string_is_nonascii(const uint8_t *data, size_t len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

    uint8_t sum = 0;
    while (x < end) {
        sum |= *x;
        x++;
    }
    return sum & 0x80; /* return 0 if no high bits are set */
}

static inline bool string_starts_with_0x(const uint8_t *data, size_t len) {
    if (len > 2 && data[0] == '0' && data[1] == 'x') {
        return true;
    }
    return false;
}

static inline int append_json_string(char *dstr, int *doff, int dlen, int *trunc,
                                     const char *key, const uint8_t *data, unsigned int len) {

    int r;
    if (string_is_nonascii(data, len) || string_starts_with_0x(data, len)) {
        r = append_json_hex_string(dstr, doff, dlen, trunc,
                                   key, data, len);
    } else {
        r = append_json_string_escaped(dstr, doff, dlen, trunc,
                                       key, data, len);
    }

    return r;
}


static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};


static inline int append_raw_as_base64(char *dstr, int *doff, int dlen, int *trunc,
                                       const unsigned char *data,
                                       size_t input_length) {

    if (*trunc == 1) {
        return 0;
    }

    int r = 0;
    size_t i = 0;
    size_t rem = input_length % 3; /* so it can be 0, 1 or 2 */
    size_t len = input_length - rem; /* always a multiple of 3 */
    uint32_t oct_a, oct_b, oct_c, trip;

    char outb[256]; /* A local buffer of up to 256 hex chars at a time */
    int oi = 0;    /* The index into the output buffer */

    r += append_putc(dstr, doff, dlen, trunc,
                '"');
    while ((i < len) && (*trunc == 0)) {

        oct_a = data[i++];
        oct_b = data[i++];
        oct_c = data[i++];

        trip = (oct_a << 0x10) + (oct_b << 0x08) + oct_c;

        outb[oi]     = encoding_table[(trip >> (3 * 6)) & 0x3F];
        outb[oi + 1] = encoding_table[(trip >> (2 * 6)) & 0x3F];
        outb[oi + 2] = encoding_table[(trip >> (1 * 6)) & 0x3F];
        outb[oi + 3] = encoding_table[(trip >> (0 * 6)) & 0x3F];

        if (oi < 252) {
            oi += 4;
        } else {
            r += append_memcpy(dstr, doff, dlen, trunc,
                               outb, 256);
            oi = 0;

            if (*trunc == 1) {
                return r;
            }
        }
    }

    if (oi > 0) {
        r += append_memcpy(dstr, doff, dlen, trunc,
                           outb, oi);
    }

    if (rem > 0) {
        oct_a = data[i++];
        oct_b = (i < input_length)? data[i++] : 0;
        oct_c = (i < input_length)? data[i++] : 0;

        trip = (oct_a << 0x10) + (oct_b << 0x08) + oct_c;

        /**
         * if remainder is zero, we are done.
         * if remainder is 1, we need to get one more byte from data.
         * if remainder is 2, we need to get two more bytes from data.
         * Afterwards, we need to pad the encoded_data with '=' appropriately.
         */
        if (rem == 1) {
            /* This one byte spans 2 bytes in encoded_data */
            /* Pad the last 2 bytes */
            r += append_putc(dstr, doff, dlen, trunc,
                             encoding_table[(trip >> (3 * 6)) & 0x3F]);
            r += append_putc(dstr, doff, dlen, trunc,
                             encoding_table[(trip >> (2 * 6)) & 0x3F]);
            r += append_strncpy(dstr, doff, dlen, trunc,
                                (char *)"==");
        } else if (rem == 2) {
            /* These two bytes span 3 bytes in encoded_data */
            /* Pad the remaining last byte */
            r += append_putc(dstr, doff, dlen, trunc,
                             encoding_table[(trip >> (3 * 6)) & 0x3F]);
            r += append_putc(dstr, doff, dlen, trunc,
                             encoding_table[(trip >> (2 * 6)) & 0x3F]);
            r += append_putc(dstr, doff, dlen, trunc,
                             encoding_table[(trip >> (1 * 6)) & 0x3F]);
            r += append_putc(dstr, doff, dlen, trunc,
                             '=');
        }
    }
    r += append_putc(dstr, doff, dlen, trunc,
                     '"');

    return r;
}


/*
 * struct buffer_stream
 */

struct buffer_stream {
    char *dstr;
    int doff;
    int dlen;
    int trunc;

    buffer_stream(char *dstr, int dlen) : dstr{dstr}, doff{0}, dlen{dlen}, trunc{0} {};

    size_t write(FILE *f) {
        return fwrite(dstr, 1, doff, f);
    }
    size_t write_line(FILE *f) {
        write_char('\n');
        return write(f);
    }

    size_t length() { return doff; }

    void add_null() {
        append_null(dstr, &doff, dlen, &trunc);
    }

    int snprintf(const char *fmt, ...) {

        if (trunc == 1) {
            return 0;
        }

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

            r = (dlen - doff) - 1;
            if (r < 0) {
                r = 0;
            }

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

    void puts(const char *sstr) {
        append_strncpy(dstr, &doff, dlen, &trunc, sstr);
    }

    void write_char(char schr) {
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

    void raw_as_base64(const unsigned char *data, size_t input_length) {
        append_raw_as_base64(dstr, &doff, dlen, &trunc, data, input_length);
    }

    void memcpy(const void *src, ssize_t length) {
        append_memcpy(dstr, &doff, dlen, &trunc, src, length);
    }

    void write_timestamp(struct timespec *ts) {
        append_strncpy(dstr, &doff, dlen, &trunc, ",\"event_start\":");
        append_timestamp(dstr, &doff, dlen, &trunc, ts);
    }

    void write_uint8(uint8_t n) {
        append_uint8(dstr, &doff, dlen, &trunc, n);
    }

    void write_uint16(uint16_t n) {
        append_uint16(dstr, &doff, dlen, &trunc, n);
    }

    void write_hex_uint16(uint16_t n) {
        append_uint16_hex(dstr, &doff, dlen, &trunc, n);
    }

    void write_ipv6_addr(const uint8_t *v6) {
        append_ipv6_addr(dstr, &doff, dlen, &trunc, v6);
    }

    void write_ipv4_addr(const uint8_t *v4) {
        append_ipv4_addr(dstr, &doff, dlen, &trunc, v4);
    }


#if 0
    void write_extract_certificates(const unsigned char *data, size_t data_len) {
        append_extract_certificates(dstr, &doff, dlen, &trunc, data, data_len);
    }

    void write_binary_ept_as_paren_ept(const unsigned char *data, unsigned int length) {
        append_binary_ept_as_paren_ept(dstr, &doff, dlen, &trunc, data, length);
    }
    void write_packet_flow_key(uint8_t *packet, size_t length) {
        append_packet_flow_key(dstr, &doff, dlen, &trunc, packet, length);
    }
    void write_analysis_from_extractor_and_flow_key(const struct extractor *x, const struct flow_key *key) {
        append_analysis_from_extractor_and_flow_key(dstr, &doff, dlen, &trunc, x, key);
    }
#endif // 0


};

#endif /* BUFFER_STREAM_H */
