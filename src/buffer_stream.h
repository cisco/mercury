/*
 * buffer_stream.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef BUFFER_STREAM_H
#define BUFFER_STREAM_H

#include "utils.h"

/* append_snprintf
 * takes the base address of a string, the offset in the string, total length, and a truncation flag
 * and stores the desired snprintf() content at that offset.
 *
 * return: the amount stored (or needed to be stored in case of truncation)
 */
static inline int append_snprintf(char *dstr, int *doff, int dlen, int *trunc,
                                  const char *fmt, ...) {

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
            dstr[*doff + i] = sstr[i];
            gn = 1;
            break;
        }
    }

    /* Always put a null even when truncating */
    if (gn != 1) {
        dstr[*doff + i] = '\0';
        *trunc = 1;
    }

    /* adjust the offset */
    *doff = *doff + i;

    return i; /* i doesn't count the null, just like in snprintf */
}

static inline int append_putc(char *dstr, int *doff, int dlen, int *trunc,
                char schr) {

    /* Check to make sure the offset isn't already longer than the length */
    if (*doff >= dlen) {
        *trunc = 1;
        return 0;
    }

    if (*doff < dlen - 1) {
        dstr[*doff] = schr;
        *doff = *doff + 1;
        dstr[*doff] = '\0';

        return 1;
    } else {
        *trunc = 1;
        /* Always put a null even when truncating */
        dstr[*doff] = '\0';

        return 0;
    }
}

static inline int append_memcpy(char *dstr, int *doff, int dlen, int *trunc, const void *s, ssize_t length) {
    const uint8_t *src = (const uint8_t *)s;

    /* Check to make sure the offset isn't already longer than the length */
    if (*doff >= dlen) {
        *trunc = 1;
        return 0;
    }

    if (*doff < dlen - length) {   // TBD: over/under flow?
        memcpy(dstr + *doff, src, length);
        *doff = *doff + length;
        return length;
    } else {
        *trunc = 1;
        return 0;
    }
}

static inline int append_raw_as_hex(char *dstr, int *doff, int dlen, int *trunc,
                      const uint8_t *data, unsigned int len) {
    *trunc = 0;
    int r = 0;
    for (unsigned int i = 0; (i < len) && (*trunc == 0); i++) {
        r += append_snprintf(dstr, doff, dlen, trunc,
                             "%02x", data[i]);
    }

    return r;
}


static inline int append_json_hex_string(char *dstr, int *doff, int dlen, int *trunc,
                                  const char *key, const uint8_t *data, unsigned int len) {
    *trunc = 0;
    int r = 0;

    r += append_snprintf(dstr, doff, dlen, trunc,
                         "\"%s\":\"0x", key);
    for (unsigned int i = 0; (i < len) && (*trunc == 0); i++) {
        r += append_snprintf(dstr, doff, dlen, trunc,
                             "%02x", data[i]);
    }
    r += append_putc(dstr, doff, dlen, trunc, '"');

    return r;
}


static inline int append_json_hex_string(char *dstr, int *doff, int dlen, int *trunc,
                                  const uint8_t *data, unsigned int len) {
    *trunc = 0;
    int r = 0;

    r += append_putc(dstr, doff, dlen, trunc,
                     '"');
    for (unsigned int i = 0; (i < len) && (*trunc == 0); i++) {
        r += append_snprintf(dstr, doff, dlen, trunc,
                             "%02x", data[i]);
    }
    r += append_putc(dstr, doff, dlen, trunc, '"');

    return r;
}

static inline int append_json_string_escaped(char *dstr, int *doff, int dlen, int *trunc,
                                             const char *key, const uint8_t *data, unsigned int len) {
    *trunc = 0;
    int r = 0;

    r += append_snprintf(dstr, doff, dlen, trunc,
                         "\"%s\":\"", key);

    for (unsigned int i = 0; (i < len) && (*trunc == 0); i++) {
        if (data[i] < 0x20) {                   /* escape control characters   */
            r += append_snprintf(dstr, doff, dlen, trunc,
                                 "\\u%04x", data[i]);
        } else if (data[i] > 0x7f) {            /* escape non-ASCII characters */
            r += append_snprintf(dstr, doff, dlen, trunc,
                                 "\\u%04x", data[i]);
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

/* macro for fputc */
#define FPUTC(C, F)                                     \
    if (fputc((int)C, F) == EOF) {                      \
        perror("Error while printing base64 char\n");   \
        return;                                         \
    }

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};


static inline int append_json_base64_string(char *dstr, int *doff, int dlen, int *trunc,
                              const unsigned char *data,
                              size_t input_length) {

    *trunc = 0;
    int r = 0;
    size_t i = 0;
    size_t rem = input_length % 3; /* so it can be 0, 1 or 2 */
    size_t len = input_length - rem; /* always a multiple of 3 */
    uint32_t oct_a, oct_b, oct_c, trip;

    r += append_putc(dstr, doff, dlen, trunc,
                '"');
    while ((i < len) && (*trunc == 0)) {

        oct_a = data[i++];
        oct_b = data[i++];
        oct_c = data[i++];

        trip = (oct_a << 0x10) + (oct_b << 0x08) + oct_c;

        r += append_putc(dstr, doff, dlen, trunc,
                         encoding_table[(trip >> (3 * 6)) & 0x3F]);
        r += append_putc(dstr, doff, dlen, trunc,
                         encoding_table[(trip >> (2 * 6)) & 0x3F]);
        r += append_putc(dstr, doff, dlen, trunc,
                         encoding_table[(trip >> (1 * 6)) & 0x3F]);
        r += append_putc(dstr, doff, dlen, trunc,
                         encoding_table[(trip >> (0 * 6)) & 0x3F]);
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
        buffer_stream::putc('\n');
        return write(f);
    }

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

    void puts(const char *sstr) {
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

    void write_timestamp(struct timespec *ts) {
        append_snprintf(dstr, &doff, dlen, &trunc, ",\"event_start\":%u.%06u", ts->tv_sec, ts->tv_nsec / 1000);
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
