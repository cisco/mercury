/*
 * match.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef MATCH_H
#define MATCH_H

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

    extractor_debug("%s: data: %x, mask: %x, value: %x\n", __func__, d[0], m[0], v[0]);

    return ((d[0] & m[0]) == v[0]) && ((d[1] & m[1]) == v[1]);
}

unsigned int u64_compare_masked_data_to_value(const void *data,
                                              const void *mask,
                                              const void *value) {
    const uint64_t *d = (const uint64_t *)data;
    const uint64_t *m = (const uint64_t *)mask;
    const uint64_t *v = (const uint64_t *)value;

    extractor_debug("%s: data: %lx, mask: %lx, value: %lx\n", __func__, d[0], m[0], v[0]);
    // fprintf(stderr, "%s: data: %016lx, mask: %016lx, value: %016lx\n", __func__, d[0], m[0], v[0]);

    return ((d[0] & m[0]) == v[0]);
}


/*
 * keyword_matcher performs multiple string matching the
 * straightforward way.  It should be robust and maintainable, and
 * possibly useful for very short keyword lists, but its worst-case
 * and average case performance are not great (linear in the number of
 * keywords).
 *
 * This code will be replaced with a finite automaton keyword matcher
 * in the near future (once that code is tuned, tested, and debugged).
 *
 */

#define keyword_init(s) { s, sizeof(s)-1 }

typedef struct keyword {
    const char *value;
    size_t len;
} keyword_t;

typedef struct keyword_matcher {
    keyword_t *case_insensitive;
    keyword_t *case_sensitive;
} keyword_matcher_t;

#define match_all_keywords NULL

enum status keyword_matcher_check(const keyword_matcher_t *keywords,
                                  unsigned char *string,
                                  size_t len) {
    keyword_t *k;
    size_t i;

    if (keywords == match_all_keywords) {
        return status_ok;  /* by convention, NULL pointer corresponds to 'match all keywords' */
    }

    k = keywords->case_insensitive;
    if (k != NULL) {
        while (k->len != 0) {
            if (len == k->len) {
                for (i = 0; i < len; i++) {
                    if (tolower(string[i]) != k->value[i]) {
                        break;
                    }
                }
                if (i >= len) {       /* end of string; match found */
                    return status_ok;
                }
            }
            k++;
        }
    }

    k = keywords->case_sensitive;
    if (k != NULL) {
        while (k->len != 0) {
            if (len == k->len) {
                for (i = 0; i < len; i++) {
                    if (string[i] != k->value[i]) {
                        break;
                    }
                }
                if (i >= len) {       /* end of string; match found */
                    return status_ok;
                }
            }
            k++;
        }
    }

    return status_err;
}

#endif /* MATCH_H */
