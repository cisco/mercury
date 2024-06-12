/*
 * output.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc.  All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef OUTPUT_H
#define OUTPUT_H

#include <atomic>

#include <pthread.h>
#include "mercury.h"
#include "llq.h"

enum file_type {
   file_type_unknown=0,
   file_type_json,
   file_type_pcap,
   file_type_stdout
};

struct output_file {
    pid_t kpid;
    pthread_t tid;
    FILE *file_pri = nullptr;
    FILE *file_sec = nullptr;
    FILE *file_used = nullptr;
    std::atomic<bool> rotation_req = (false);
    std::atomic<bool> time_rotation_req = (false);
    std::atomic<bool> file_error = (false);
    int64_t record_countdown;
    uint64_t max_records;
    uint64_t rotate_time;
    uint32_t file_num = 0;
    char *outfile_name;
    const char *mode;
    enum file_type type;
    int t_output_p;
    pthread_cond_t t_output_c;
    pthread_mutex_t t_output_m;
    struct thread_queues qs;
    int sig_stop_output = 0;
    uint64_t output_drops = 0;
    int from_network = 0;
};

void *output_thread_func(void *arg);

int output_thread_init(struct output_file &out_ctx, const struct mercury_config &cfg);

void output_thread_finalize(struct output_file *out_file);

char *stdout_string();

enum status output_file_rotate(struct output_file *ojf);

enum status open_outfile(struct output_file *ojf, bool is_pri);

#endif /* OUTPUT_H */
