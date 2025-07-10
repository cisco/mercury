/*
 * asn1.cc
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */


#include <unordered_map>
#include <string>
#include "asn1.h"


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
