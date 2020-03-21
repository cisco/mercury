/*
 * output.h
 */

#ifndef OUTPUT_H
#define OUTPUT_H

#include <pthread.h>
#include "mercury.h"
#include "llq.h"


void init_t_queues(int n);

void destroy_thread_queues(struct thread_queues *tqs);

void *output_thread_func(void *arg);

int output_thread_init(pthread_t &output_thread, struct output_file &out_ctx, const struct mercury_config &cfg);

#endif /* OUTPUT_H */
