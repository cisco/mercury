/*
 * asn1.cc
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */


#include <unordered_map>
#include <string>
#include "asn1.h"

void fprintf_json_string_escaped(struct buffer_stream &buf, const char *key, const uint8_t *data, unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

    buf.snprintf("\"%s\":\"", key);
    while (x < end) {
        if (*x < 0x20) {                   /* escape control characters   */
            buf.snprintf("\\u%04x", *x);
        } else if (*x >= 0x80) {           /* escape non-ASCII characters */

            uint32_t codepoint = 0;
            if (*x >= 0xc0) {

                if (*x >= 0xe0) {
                    if (*x >= 0xf0) {
                        codepoint = (*x++ & 0x07);
                        codepoint = (*x++ & 0x3f) | (codepoint << 6);
                        codepoint = (*x++ & 0x3f) | (codepoint << 6);
                        codepoint = (*x   & 0x3f) | (codepoint << 6);

                    } else {
                        codepoint = (*x++ & 0x0F);
                        codepoint = (*x++ & 0x3f) | (codepoint << 6);
                        codepoint = (*x   & 0x3f) | (codepoint << 6);
                    }

                } else {
                    codepoint = ((*x++ & 0x1f) << 6);
                    codepoint |= *x & 0x3f;
                }

            } else {
                codepoint = *x & 0x7f;
            }
            if (codepoint < 0x10000) {
                // basic multilingual plane
                if (codepoint < 0xd800) {
                    buf.snprintf("\\u%04x", codepoint);
                } else {
                    // error: invalid or private codepoint
                    buf.snprintf("\\ue000", codepoint); // indicate error with private use codepoint
                }
            } else {
                // surrogate pair
                codepoint -= 0x10000;
                uint32_t hi = (codepoint >> 10) + 0xd800;
                uint32_t lo = (codepoint & 0x3ff) + 0xdc00;
                buf.snprintf("\\u%04x", hi);
                buf.snprintf("\\u%04x", lo);
            }

        } else {
            if (*x == '"' || *x == '\\') { /* escape special characters   */
                buf.snprintf("\\");
            }
            buf.snprintf("%c", *x);
        }
        x++;
    }
    buf.snprintf("\"");

}

void fprintf_json_char_escaped(FILE *f, unsigned char x) {
    if (x < 0x20) {                   /* escape control characters   */
        fprintf(f, "\\u%04x", x);
    } else if (x > 0x7f) {            /* escape non-ASCII characters */
        fprintf(f, "\\u%04x", x);
    } else {
        if (x == '"' || x == '\\') { /* escape special characters   */
            fprintf(f, "\\");
        }
        fprintf(f, "%c", x);
    }
}

void fprintf_json_char_escaped(struct buffer_stream &buf, unsigned char x) {
    if (x < 0x20) {                   /* escape control characters   */
        buf.snprintf("\\u%04x", x);
    } else if (x > 0x7f) {            /* escape non-ASCII characters */
        buf.snprintf("\\u%04x", x);
    } else {
        if (x == '"' || x == '\\') { /* escape special characters   */
            buf.snprintf("\\");
        }
        buf.snprintf("%c", x);
    }
}

void fprintf_ip_address(FILE *f, const uint8_t *buffer, size_t length) {
    const uint8_t *b = buffer;
    if (length == 4) {
        fprintf(f, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    } else if (length == 16) {
        fprintf(f, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    } else {
        fprintf(f, "malformed (length: %zu)", length);
    }
}

void fprintf_ip_address(struct buffer_stream &buf, const uint8_t *buffer, size_t length) {
    const uint8_t *b = buffer;
    if (length == 4) {
        buf.snprintf("%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    } else if (length == 16) {
        buf.snprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    } else {
        buf.snprintf("malformed (length: %zu)", length);
    }
}

/*
 * UTCTime (Coordinated Universal Time) consists of 13 bytes that
 * encode the Greenwich Mean Time in the format YYMMDDhhmmssZ.  For
 * instance, the bytes 17 0d 31 35 31 30 32 38 31 38 35 32 31 32 5a
 * encode the string "151028185212Z", which represents the time
 * "2015-10-28 18:52:12"
 */
void fprintf_json_utctime(FILE *f, const char *key, const uint8_t *data, unsigned int len) {

    fprintf(f, "\"%s\":\"", key);
    if (len != 13) {
        fprintf(f, "malformed\"");
        return;
    }
    if (data[0] < '5') {
        fprintf(f, "20");
    } else {
       fprintf(f, "19");
    }
    fprintf_json_char_escaped(f, data[0]);
    fprintf_json_char_escaped(f, data[1]);
    fprintf(f, "-");
    fprintf_json_char_escaped(f, data[2]);
    fprintf_json_char_escaped(f, data[3]);
    fprintf(f, "-");
    fprintf_json_char_escaped(f, data[4]);
    fprintf_json_char_escaped(f, data[5]);
    fprintf(f, " ");
    fprintf_json_char_escaped(f, data[6]);
    fprintf_json_char_escaped(f, data[7]);
    fprintf(f, ":");
    fprintf_json_char_escaped(f, data[8]);
    fprintf_json_char_escaped(f, data[9]);
    fprintf(f, ":");
    fprintf_json_char_escaped(f, data[10]);
    fprintf_json_char_escaped(f, data[11]);

    fprintf(f, "\"");
}

/*
 *  For the purposes of [RFC 5280], GeneralizedTime values MUST be
 *  expressed in Greenwich Mean Time (Zulu) and MUST include seconds
 *  (i.e., times are YYYYMMDDHHMMSSZ), even where the number of
 *  seconds is zero.
 */
void fprintf_json_generalized_time(FILE *f, const char *key, const uint8_t *data, unsigned int len) {

    fprintf(f, "\"%s\":\"", key);
    if (len != 15) {
        fprintf(f, "malformed (length %u)\"", len);
        return;
    }
    fprintf_json_char_escaped(f, data[0]);
    fprintf_json_char_escaped(f, data[1]);
    fprintf_json_char_escaped(f, data[2]);
    fprintf_json_char_escaped(f, data[3]);
    fprintf(f, "-");
    fprintf_json_char_escaped(f, data[4]);
    fprintf_json_char_escaped(f, data[5]);
    fprintf(f, "-");
    fprintf_json_char_escaped(f, data[6]);
    fprintf_json_char_escaped(f, data[7]);
    fprintf(f, " ");
    fprintf_json_char_escaped(f, data[8]);
    fprintf_json_char_escaped(f, data[9]);
    fprintf(f, ":");
    fprintf_json_char_escaped(f, data[10]);
    fprintf_json_char_escaped(f, data[11]);
    fprintf(f, ":");
    fprintf_json_char_escaped(f, data[12]);
    fprintf_json_char_escaped(f, data[13]);

    fprintf(f, "\"");
}

/*
 * UTCTime (Coordinated Universal Time) consists of 13 bytes that
 * encode the Greenwich Mean Time in the format YYMMDDhhmmssZ.  For
 * instance, the bytes 17 0d 31 35 31 30 32 38 31 38 35 32 31 32 5a
 * encode the string "151028185212Z", which represents the time
 * "2015-10-28 18:52:12"
 */
void fprintf_json_utctime(struct buffer_stream &buf, const char *key, const uint8_t *data, unsigned int len) {

    buf.snprintf("\"%s\":\"", key);
    if (len != 13) {
        buf.snprintf("malformed\"");
        return;
    }
    if (data[0] < '5') {
        buf.snprintf("20");
    } else {
       buf.snprintf("19");
    }
    fprintf_json_char_escaped(buf, data[0]);
    fprintf_json_char_escaped(buf, data[1]);
    buf.write_char('-');
    fprintf_json_char_escaped(buf, data[2]);
    fprintf_json_char_escaped(buf, data[3]);
    buf.write_char('-');
    fprintf_json_char_escaped(buf, data[4]);
    fprintf_json_char_escaped(buf, data[5]);
    buf.write_char(' ');
    fprintf_json_char_escaped(buf, data[6]);
    fprintf_json_char_escaped(buf, data[7]);
    buf.write_char(':');
    fprintf_json_char_escaped(buf, data[8]);
    fprintf_json_char_escaped(buf, data[9]);
    buf.write_char(':');
    fprintf_json_char_escaped(buf, data[10]);
    fprintf_json_char_escaped(buf, data[11]);
    buf.write_char('\"');
}


/*
 *  For the purposes of [RFC 5280], GeneralizedTime values MUST be
 *  expressed in Greenwich Mean Time (Zulu) and MUST include seconds
 *  (i.e., times are YYYYMMDDHHMMSSZ), even where the number of
 *  seconds is zero.
 */
void fprintf_json_generalized_time(struct buffer_stream &buf, const char *key, const uint8_t *data, unsigned int len) {

    buf.snprintf("\"%s\":\"", key);
    if (len != 15) {
        buf.snprintf("malformed (length %u)\"", len);
        return;
    }
    fprintf_json_char_escaped(buf, data[0]);
    fprintf_json_char_escaped(buf, data[1]);
    fprintf_json_char_escaped(buf, data[2]);
    fprintf_json_char_escaped(buf, data[3]);
    buf.snprintf("-");
    fprintf_json_char_escaped(buf, data[4]);
    fprintf_json_char_escaped(buf, data[5]);
    buf.snprintf("-");
    fprintf_json_char_escaped(buf, data[6]);
    fprintf_json_char_escaped(buf, data[7]);
    buf.snprintf(" ");
    fprintf_json_char_escaped(buf, data[8]);
    fprintf_json_char_escaped(buf, data[9]);
    buf.snprintf(":");
    fprintf_json_char_escaped(buf, data[10]);
    fprintf_json_char_escaped(buf, data[11]);
    buf.snprintf(":");
    fprintf_json_char_escaped(buf, data[12]);
    fprintf_json_char_escaped(buf, data[13]);

    buf.snprintf("\"");
}

/*
 * generalized_time_gt(d1, l1, d2, l2) compares two strings at
 * locations d1 and d2 with lengths l1 and l2 assuming that they are
 * in generalized time format (YYYYMMDDHHMMSSZ), and returns 1
 * if d1 > d2, returns -1 if d1 < d2, and returns 0 if they are equal.
 */

int generalized_time_gt(const uint8_t *d1, unsigned int l1,
                        const uint8_t *d2, unsigned int l2) {

    if (l1 != 15 || l2 != 15) {
        return -1;  // malformed input
    }
    for (int i=0; i<15; i++) {
        if (d1[i] < d2[i]) {
            return -1;
        } else if (d1[i] > d2[i]) {
            return 1;
        }
    }
    return 0;
}

int utctime_to_generalized_time(uint8_t *gt, size_t gt_len, const uint8_t *utc_time, size_t utc_len) {
    if (gt_len != 15) {
        return -1;  // error: wrong output buffer size
    }
    if (utc_len != 12) {
        return -1;  // error: wrong input buffer size
    }
    if (utc_time[0] < '5') {
        gt[0] = '2';
        gt[1] = '0';
    } else {
        gt[0] = '1';
        gt[1] = '9';
    }
    memcpy(gt+2, utc_time, 12);
    return 0;
}

inline uint8_t hex_to_raw(const char *hex) {
    int value = 0;
    if(*hex >= '0' && *hex <= '9') {
        value = (*hex - '0');
    } else if (*hex >= 'A' && *hex <= 'F') {
        value = (10 + (*hex - 'A'));
    } else if (*hex >= 'a' && *hex <= 'f') {
        value = (10 + (*hex - 'a'));
    }
    value = value << 4;
    hex++;
    if(*hex >= '0' && *hex <= '9') {
        value |= (*hex - '0');
    } else if (*hex >= 'A' && *hex <= 'F') {
        value |= (10 + (*hex - 'A'));
    } else if (*hex >= 'a' && *hex <= 'f') {
        value |= (10 + (*hex - 'a'));
    }

    return value;
}

void hex_string_print_as_oid(FILE *f, const char *c, size_t length) {
    if (length & 1) {
        return;  // error: odd number of characters in hex string
    }
    uint32_t component = hex_to_raw(c);
    uint32_t div = component / 40;
    uint32_t rem = component - (div * 40);
    if (div > 2 || rem > 39) {
        return; // error: invalid input
    }
    fprintf(f, "%u.%u", div, rem);

    c += 2;
    component = 0;
    for (unsigned int i=2; i<length; i += 2) {
        uint8_t tmp = hex_to_raw(c);
        if (tmp & 0x80) {
            component = component * 128 + (tmp & 0x7f);
        } else {
            component = component * 128 + tmp;
            fprintf(f, ".%u", component);
            component = 0;
        }
        c += 2;
    }
}

void raw_string_print_as_oid(FILE *f, const uint8_t *raw, size_t length) {
    if (raw == NULL) {
        return;  // error: invalid input
    }
    uint32_t component = *raw;
    uint32_t div = component / 40;
    uint32_t rem = component - (div * 40);
    if (div > 2 || rem > 39) {
        return; // error: invalid input
    }
    fprintf(f, "%u.%u", div, rem);

    raw++;
    component = 0;
    for (unsigned int i=1; i<length; i++) {
        uint8_t tmp = *raw++;
        if (tmp & 0x80) {
            component = component * 128 + (tmp & 0x7f);
        } else {
            component = component * 128 + tmp;
            fprintf(f, ".%u", component);
            component = 0;
        }
    }
}

void raw_string_print_as_oid(struct buffer_stream &buf, const uint8_t *raw, size_t length) {
    if (raw == NULL) {
        return;  // error: invalid input
    }
    uint32_t component = *raw;
    uint32_t div = component / 40;
    uint32_t rem = component - (div * 40);
    if (div > 2 || rem > 39) {
        return; // error: invalid input
    }
    buf.snprintf("%u.%u", div, rem);

    raw++;
    component = 0;
    for (unsigned int i=1; i<length; i++) {
        uint8_t tmp = *raw++;
        if (tmp & 0x80) {
            component = component * 128 + (tmp & 0x7f);
        } else {
            component = component * 128 + tmp;
            buf.snprintf(".%u", component);
            component = 0;
        }
    }
}

json_object_asn1::json_object_asn1(struct json_array &array) : json_object(array) { }
