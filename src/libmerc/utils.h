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
#include <stdio.h>
#include "flow_key.h"
#include "libmerc.h" // for enum status
#include "buffer_stream.h"

/* utility functions */

size_t hex_to_raw(const void *output,
		       size_t output_buf_len,
		       const char *null_terminated_hex_string);

void fprintf_raw_as_hex(FILE *f, const uint8_t *data, unsigned int len);

extern "C" LIBMERC_DLL_EXPORTED
enum status drop_root_privileges(const char *username, const char *directory);

extern "C" LIBMERC_DLL_EXPORTED
int copy_string_into_buffer(char *dst, size_t dst_len, const char *src, size_t max_src_len);

/*
 * get_readable_number_float() provides an imprecise but
 * human-understandable representation of a (potentially very large)
 * number, for printing out
 */
extern "C" LIBMERC_DLL_EXPORTED
void get_readable_number_float(double power,
                               double input,
                               double *num_output,
                               char **str_output);

extern "C" LIBMERC_DLL_EXPORTED
enum status filename_append(char dst[FILENAME_MAX],
                            const char *src,
                            const char *delim,
                            const char *tail);

struct timer {
    struct timespec before;
    struct timespec after;
};

extern "C" LIBMERC_DLL_EXPORTED
void timer_start(struct timer *t);

extern "C" LIBMERC_DLL_EXPORTED
uint64_t timer_stop(struct timer *t);

#endif /* UTILS_H */
