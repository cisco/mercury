/*
 * output.c
 *
 * Copyright (c) 2021 Cisco Systems, Inc.  All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

/* The following provides gettid (or a stub function) on all platforms. */
#if defined(__gnu_linux__) /* Linux */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE    /* Needed for gettid() definition from unistd.h */
#endif /* _GNU_SOURCE */
#include <unistd.h>
/* Use system call if gettid() is not available, e.g., before glibc 2.30 */
#if (!HAVE_GETTID)
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#endif /* (!HAVE_GETTID) */
#elif defined(__APPLE__) && defined(__MACH__)  /* macOS */
#define gettid() 0     /* TODO: return a meaningful value on macOS */
#elif defined(_WIN32) /* defined for both Windows 32-bit and 64-bit */
#define gettid() 0     /* TODO: return a meaningful value on Windows */
#else /* Unknown operating system */
#define gettid() 0
#endif /* defined(__gnu_linux__) */

#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include "output.h"
#include "pcap_file_io.h"  // for write_pcap_file_header()
#include "libmerc/utils.h"


#define output_file_needs_rotation(ojf, n) ((((ojf)->record_countdown) -= (n)) <= 0)

void thread_queues_init(struct thread_queues *tqs, int n, float frac) {

    uint64_t desired_memory = (uint64_t) sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE) * frac;

    /* Total output queue size is our desired memory divided by the number of queues
     * but queue length must account for LLQ_MSG_SIZE
     */
    uint64_t qlen = desired_memory / n;

    if (n * qlen < desired_memory) {
        fprintf(stderr, "Notice: requested output queue memory %" PRIu64 " will be less than desired memory %" PRIu64 "\n",
                n * qlen, desired_memory);
    }

    if (qlen < 8 * LLQ_MAX_MSG_SIZE) {
        fprintf(stderr, "Only able to allocate output queue lengths of %lu (minimum %d)\n", qlen, 8 * LLQ_MAX_MSG_SIZE);
        exit(255);
    }

    tqs->qnum = n;
    tqs->queue = (struct ll_queue *)calloc(n, sizeof(struct ll_queue));

    if (tqs->queue == NULL) {
        fprintf(stderr, "Failed to allocate memory for thread queues\n");
        exit(255);
    }

    for (int i = 0; i < n; i++) {
        tqs->queue[i].qnum = i; /* only needed for debug output */
        tqs->queue[i].llq_len = qlen;
        tqs->queue[i].ridx = 0;
        tqs->queue[i].widx = 0;
        tqs->queue[i].drops = 0;
        tqs->queue[i].drops_trunc = 0;

        tqs->queue[i].rbuf = (uint8_t *)calloc(tqs->queue[i].llq_len, sizeof(uint8_t));

        if (tqs->queue[i].rbuf == NULL) {
            fprintf(stderr, "Failed to allocate memory for thread queue %d ringbuffer\n", i);
            exit(255);
        }

    }
}


void thread_queues_free(struct thread_queues *tqs) {

    for (int i = 0; i < tqs->qnum; i++) {
        free(tqs->queue[i].rbuf);
    }

    free(tqs->queue);
    tqs->queue = NULL;
    tqs->qnum = 0;
}


int time_less(struct timespec *tsl, struct timespec *tsr) {

    if ((tsl->tv_sec < tsr->tv_sec) || ((tsl->tv_sec == tsr->tv_sec) && (tsl->tv_nsec < tsr->tv_nsec))) {
        return 1;
    } else {
        return 0;
    }
}


void time_subtract_ns(struct timespec *ts, int64_t ns_interval) {
    const int64_t ONE_SECOND_IN_NS = 1000000000;
    if (ts->tv_nsec >= ns_interval) { // fastest path
        ts->tv_nsec -= ns_interval;
    } else if (ns_interval < ONE_SECOND_IN_NS) { // relatively fast path
        ts->tv_sec -= 1;
        ts->tv_nsec += (ONE_SECOND_IN_NS - ns_interval);
    } else { // slow path
        int64_t whole_seconds = ns_interval / ONE_SECOND_IN_NS;
        int64_t ns_remaining = ns_interval % ONE_SECOND_IN_NS;
        ts->tv_sec -= whole_seconds;
        if (ts->tv_nsec >= ns_remaining) {
            ts->tv_nsec -= ns_remaining;
        } else {
            ts->tv_sec -= 1;
            ts->tv_nsec += (ONE_SECOND_IN_NS - ns_remaining);
        }
    }
}



enum status open_outfile(struct output_file *ojf, bool is_pri) {
    char outfile[FILENAME_MAX];
    char file_num[MAX_HEX];

    snprintf(file_num, MAX_HEX, "%x", ojf->file_num++);
    enum status status = filename_append(outfile, ojf->outfile_name, "-", file_num);
    if (status) {
        ojf->file_error = true;
        return status;
    }

    char time_str[128];
    struct timeval now;
    gettimeofday(&now, NULL);
    strftime(time_str, sizeof(time_str) - 1, "%Y%m%d%H%M%S", localtime(&now.tv_sec));
    status = filename_append(outfile, outfile, "-", time_str);
    if (status) {
        ojf->file_error = true;
        return status;
    }

    FILE* file = fopen(outfile, ojf->mode);
    if (file == NULL) {
        perror("error: could not open fingerprint output file");
        ojf->file_error = true;
        return status_err;
    }

    if (is_pri) {
        ojf->file_pri = file;
    }
    else {
        ojf->file_sec = file;
    }

    return status_ok;

}

enum status output_file_rotate(struct output_file *ojf) {
    if (ojf->type == file_type_stdout) {
        ojf->file_pri = stdout;
        ojf->file_sec = stdout;
        return status_ok;
    }

    enum status status = status_ok;

    if (ojf->max_records == UINT64_MAX && ojf->rotate_time == UINT64_MAX) {
        char outfile[FILENAME_MAX];
        strncpy(outfile, ojf->outfile_name, FILENAME_MAX - 1);
        ojf->file_pri = fopen(outfile, ojf->mode);
        if (ojf->file_pri == NULL) {
            perror("error: could not open fingerprint output file");
            ojf->file_error = true;
            return status_err;
        }

        if (ojf->type == file_type_pcap) {
            status = write_pcap_file_header(ojf->file_pri);
            if (status) {
                perror("error: could not write pcap file header");
                ojf->file_error = true;
                return status_err;
            }
        }
    }
    else {
        /*
         * create filename that includes sequence number and date/timestamp
         */
        if (ojf->file_pri == nullptr) {
            status = open_outfile(ojf, true);
            if (status) {
                return status_err;
            }

            status = open_outfile(ojf, false);
            if (status) {
                return status_err;
            }

            if (ojf->type == file_type_pcap) {
                status = write_pcap_file_header(ojf->file_pri);
                if (status) {
                    perror("error: could not write pcap file header");
                    ojf->file_error = true;
                    return status_err;
                }

                status = write_pcap_file_header(ojf->file_sec);
                if (status) {
                    perror("error: could not write pcap file header");
                    ojf->file_error = true;
                    return status_err;
                }
            }
        }
        else {
            status = open_outfile(ojf, false);
            if (status) {
                return status_err;
            }

            if (ojf->type == file_type_pcap) {
                status = write_pcap_file_header(ojf->file_sec);
                if (status) {
                    perror("error: could not write pcap file header");
                    ojf->file_error = true;
                    return status_err;
                }
            }
        }
    }

    //set state before blocking io call
    ojf->rotation_req = false;

    if (ojf->file_used) {
        // printf("closing used output files\n");
        if (fclose(ojf->file_used) != 0) {
            perror("could not close json file");
        }
        ojf->file_used = nullptr;
    }

    return status_ok;
}

enum status swap_rotated_files(struct output_file* out_ctx) {
    if (out_ctx->file_error.load() == true) {
        return status_err;
    }

    out_ctx->file_used = out_ctx->file_pri;
    out_ctx->file_pri = out_ctx->file_sec;
    out_ctx->file_sec = nullptr;
    out_ctx->rotation_req = true;
    out_ctx->record_countdown = out_ctx->max_records;

    if (out_ctx->file_pri == nullptr) {
        return status_err;
    }

    return status_ok;
}

void close_outfiles (struct output_file* out_ctx) {
    if (out_ctx->file_pri) {
        if (fclose(out_ctx->file_pri) != 0 ) {
        perror("could not close primary json file");
        }
    }

    if (out_ctx->file_sec) {
        if (fclose(out_ctx->file_sec) != 0 ) {
        perror("could not close secondary json file");
        }
    }

    if (out_ctx->file_used) {
        if (fclose(out_ctx->file_used) != 0 ) {
        perror("could not close used json file");
        }
    }
}

enum status limit_rotate (output_file* out_ctx) {
    if (out_ctx->max_records == UINT64_MAX) {
        out_ctx->record_countdown = out_ctx->max_records;
        return status_ok;
    }

    if (out_ctx->file_sec != nullptr) {
        return swap_rotated_files(out_ctx);
    }
    else {
        while (out_ctx->file_sec == nullptr) {
            out_ctx->rotation_req = true;
            usleep (10000);
            if (out_ctx->file_error.load() == true) {
                return status_err;
            }
        }
            return swap_rotated_files(out_ctx);
    }

    return status_ok;
}

enum status time_rotate (output_file* out_ctx) {
    if (out_ctx->rotation_req.load() == false) {
        enum status status = swap_rotated_files(out_ctx);
        if (status) {
            return status_err;
        }
        out_ctx->time_rotation_req = false;
    }
    else {
        out_ctx->time_rotation_req = false; //just rotated, skip
    }

    return status_ok;
}

void *output_thread_func(void *arg) {

    struct output_file *out_ctx = (struct output_file *)arg;

    out_ctx->kpid = gettid();

    if (out_ctx->from_network == 1) {
        fprintf(stderr, "[OUTPUT] Thread with pthread id %lu (PID %u) started...\n", out_ctx->tid, out_ctx->kpid);
    }

    int err;
    err = pthread_mutex_lock(&(out_ctx->t_output_m));
    if (err != 0) {
        fprintf(stderr, "%s: error locking output start mutex for stats thread\n", strerror(err));
        exit(255);
    }
    while (out_ctx->t_output_p != 1) {
        err = pthread_cond_wait(&(out_ctx->t_output_c), &(out_ctx->t_output_m));
        if (err != 0) {
            fprintf(stderr, "%s: error waiting on output start condition for stats thread\n", strerror(err));
            exit(255);
        }
    }
    err = pthread_mutex_unlock(&(out_ctx->t_output_m));
    if (err != 0) {
        fprintf(stderr, "%s: error unlocking output start mutex for stats thread\n", strerror(err));
        exit(255);
    }

    // note: we wait until we get an output start condition before we
    // open any output files, so that drop_privileges() can be called
    // before file creation
    while (out_ctx->file_pri == nullptr)
    {
        out_ctx->rotation_req = true;
        usleep(10000);
        if (out_ctx->file_error.load() == true) {
            exit(EXIT_FAILURE);
        }
    }
    out_ctx->record_countdown = out_ctx->max_records;

    /* We just got started and there are likely messages from
     * packet processing and even drops sitting in the output queue
     * from before we were ready to handle them. Flush output and
     * zero out drop counters so we get a "fair" start and don't
     * report drops from before everything was even started
     */
    if (out_ctx->from_network == 1) {
        for (int q = 0; q < out_ctx->qs.qnum; q++) {
            struct llq_msg *msg;
            while (1) {
                msg = out_ctx->qs.queue[q].try_read();

                if (msg != nullptr) {
                    out_ctx->qs.queue[q].complete_read();
                } else {
                    break;
                }
            }
            __atomic_store_n(&(out_ctx->qs.queue[q].drops), 0, __ATOMIC_RELAXED);
            __atomic_store_n(&(out_ctx->qs.queue[q].drops_trunc), 0, __ATOMIC_RELAXED);
        }
    }

    int all_output_done = 0;
    uint64_t total_drops = 0;
    uint64_t total_drops_trunc = 0;
    enum status status = status_ok;
    while (all_output_done == 0) {

        int got_msgs;
        do {
            got_msgs = 0;

            for (int q = 0; q < out_ctx->qs.qnum; q++) {
                struct llq_msg *msg;
                msg = out_ctx->qs.queue[q].try_read();

                if (msg != nullptr) {
                    got_msgs++;

                    fwrite(msg->buf, msg->len, 1, out_ctx->file_pri);

                    out_ctx->qs.queue[q].complete_read();
                }
            }

            /* Handle rotating file if needed */
            if (output_file_needs_rotation(out_ctx, got_msgs)) {
                status = limit_rotate(out_ctx);
                if (status) {
                    break;
                }
            }

            if (out_ctx->time_rotation_req.load() == true) {
                status = time_rotate(out_ctx);
                if (status) {
                    break;
                }
            }

        } while (got_msgs > 0);

        /* Do output drop accounting */
        for (int q = 0; q < out_ctx->qs.qnum; q++) {
            uint64_t drops = __atomic_load_n(&(out_ctx->qs.queue[q].drops), __ATOMIC_RELAXED);
            uint64_t drops_trunc = __atomic_load_n(&(out_ctx->qs.queue[q].drops_trunc), __ATOMIC_RELAXED);

            if (drops > 0) {
                total_drops += drops;
                fprintf(stderr, "[OUTPUT] Output queue %d reported %lu drops\n", q, drops);

                /* Subtract all the drops we just counted */
                __sync_sub_and_fetch(&(out_ctx->qs.queue[q].drops), drops);

            }

            if (drops_trunc > 0) {
                total_drops_trunc += drops_trunc;
                fprintf(stderr, "[OUTPUT] Output queue %d reported %lu truncations\n", q, drops_trunc);

                /* Subtract all the drops we just counted */
                __sync_sub_and_fetch(&(out_ctx->qs.queue[q].drops_trunc), drops_trunc);

            }
        }

        /* This is how we detect no more output is coming */
        if (out_ctx->sig_stop_output != 0) {
            all_output_done = 1;
        }


        /* This sleep slows us down so we don't spin the CPU.
         * We probably could afford to call fflush() here
         * the first time instead of sleeping and only sleep
         * if we really aren't recieving any messages on
         * any queues.
         */
        usleep(1000);
    }


    /* Report total drops */
    out_ctx->output_drops = total_drops;
    out_ctx->output_drops_trunc = total_drops_trunc;

    if (out_ctx->type != file_type_stdout) {
        close_outfiles(out_ctx);
    }

    if (out_ctx->from_network == 1) {
        fprintf(stderr, "[OUTPUT] Thread with pthread id %lu (PID %u) exiting...\n", out_ctx->tid, out_ctx->kpid);
    }

    return NULL;
}


int output_thread_init(struct output_file &out_ctx, const struct mercury_config &cfg) {

    /* make the thread queues */
    thread_queues_init(&out_ctx.qs, cfg.num_threads, cfg.buffer_fraction * (1.0 - cfg.io_balance_frac));

    /* init the output context */
    if (pthread_cond_init(&(out_ctx.t_output_c), NULL) != 0) {
        perror("Unabe to initialize output condition");
        return -1;
    }
    if (pthread_mutex_init(&(out_ctx.t_output_m), NULL) != 0) {
        perror("Unabe to initialize output mutex");
        return -1;
    }
    out_ctx.t_output_p = 0;

    //fprintf(stderr, "DEBUG: fingerprint filename: %s\n", cfg.fingerprint_filename);
    //fprintf(stderr, "DEBUG: max records: %ld\n", out_ctx.out_jf.max_records);

    /* Start the output thread */
    int err = pthread_create(&(out_ctx.tid), NULL, output_thread_func, &out_ctx);
    if (err != 0) {
        perror("error creating output thread");
        return -1;
    }
    return 0;
}

void output_thread_finalize(struct output_file *out_file) {
    out_file->sig_stop_output = 1;
    pthread_join(out_file->tid, NULL);
    thread_queues_free(&out_file->qs);
}
