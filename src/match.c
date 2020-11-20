/*
 * match.c
 *
 * Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <ctype.h>    // for tolower()
#include "mercury.h"  // for mercury_debug()
#include "match.h"

unsigned int uint16_match(uint16_t x,
                          const uint16_t *ulist,
                          unsigned int num) {
    const uint16_t *ulist_end = ulist + num;

    while (ulist < ulist_end) {
        if (x == *ulist++) {
            return 1;
        }
    }
    return 0;
}

unsigned int u32_compare_masked_data_to_value(const void *data,
                                              const void *mask,
                                              const void *value) {
    const uint32_t *d = (const uint32_t *)data;
    const uint32_t *m = (const uint32_t *)mask;
    const uint32_t *v = (const uint32_t *)value;

    mercury_debug("%s: data: %x, mask: %x, value: %x\n", __func__, d[0], m[0], v[0]);

    return ((d[0] & m[0]) == v[0]) && ((d[1] & m[1]) == v[1]);
}

unsigned int u64_compare_masked_data_to_value(const void *data,
                                              const void *mask,
                                              const void *value) {
    const uint64_t *d = (const uint64_t *)data;
    const uint64_t *m = (const uint64_t *)mask;
    const uint64_t *v = (const uint64_t *)value;

    mercury_debug("%s: data: %lx, mask: %lx, value: %lx\n", __func__, d[0], m[0], v[0]);
    // fprintf(stderr, "%s: data: %016lx, mask: %016lx, value: %016lx\n", __func__, d[0], m[0], v[0]);

    return ((d[0] & m[0]) == v[0]);
}

