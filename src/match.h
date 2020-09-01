/*
 * match.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef MATCH_H
#define MATCH_H

#include <stdint.h>
#include <stdlib.h>

unsigned int uint16_match(uint16_t x,
                          const uint16_t *ulist,
                          unsigned int num);

unsigned int u32_compare_masked_data_to_value(const void *data,
                                              const void *mask,
                                              const void *value);

unsigned int u64_compare_masked_data_to_value(const void *data,
                                              const void *mask,
                                              const void *value);

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

bool keyword_matcher_check(const keyword_matcher_t *keywords,
                           const unsigned char *string,
                           size_t len);
#endif /* MATCH_H */
