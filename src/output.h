/*
 * output.h
 */

#ifndef OUTPUT_H
#define OUTPUT_H

#include <pthread.h>
#include "mercury.h"
#include "llq.h"

enum file_type { unknown=0, json, pcap };

struct output_file {
    FILE *file;
    int64_t record_countdown;
    int64_t max_records;
    uint32_t file_num;
    char *outfile_name;
    const char *mode;
    enum file_type type;
    int t_output_p;
    pthread_cond_t t_output_c;
    pthread_mutex_t t_output_m;
    struct thread_queues *qs;
};

void init_t_queues(int n);

void destroy_thread_queues(struct thread_queues *tqs);

void *output_thread_func(void *arg);

int output_thread_init(pthread_t &output_thread, struct output_file &out_ctx, const struct mercury_config &cfg);

#endif /* OUTPUT_H */
