/*
 * output.c
 *
 * Copyright (c) 2021 Cisco Systems, Inc.  All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include "output.h"
#include "pcap_file_io.h"  // for write_pcap_file_header()
#include "libmerc/utils.h"


#define output_file_needs_rotation(ojf) (--((ojf)->record_countdown) == 0)

void thread_queues_init(struct thread_queues *tqs, int n) {
    tqs->qnum = n;
    tqs->queue = (struct ll_queue *)calloc(n, sizeof(struct ll_queue));

    if (tqs->queue == NULL) {
        fprintf(stderr, "Failed to allocate memory for thread queues\n");
        exit(255);
    }

    for (int i = 0; i < n; i++) {
        tqs->queue[i].qnum = i; /* only needed for debug output */
        tqs->queue[i].ridx = 0;
        tqs->queue[i].widx = 0;

        for (int j = 0; j < LLQ_DEPTH; j++) {
            tqs->queue[i].msgs[j].used = 0;
        }
    }
}


void thread_queues_free(struct thread_queues *tqs) {
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


int queue_less(int ql, int qr, struct tourn_tree *t_tree, const struct thread_queues *tqs) {

    /* returns 1 if the time of ql < qr and 0 otherwise
     * Also sets t_tree->stalled = 1 if needed.
     *
     * WARNING: This function is NOT thread safe!
     *
     * Meaning the access to the 'used' member in the queue
     * struct happens and then later the access to the
     * struct timespec happens.
     * This function must be called by the output thread
     * and ONLY the output thread because if
     * queues are changed while this function is going
     * shit will hit the fan!
     */

    int ql_used = 0; /* The (l)eft queue in the tree */
    int qr_used = 0; /* The (r)ight queue in the tree */

    /* check for a queue stall before we return anything otherwise
     * we could short-circuit logic before realizing one of the
     * queues was stalled
     */
    if ((ql >= 0) && (ql < tqs->qnum)) {
        ql_used = tqs->queue[ql].msgs[tqs->queue[ql].ridx].used;
        if (ql_used == 0) {
            t_tree->stalled = 1;
        }
    }
    if ((qr >= 0) && (qr < tqs->qnum)) {
        qr_used = tqs->queue[qr].msgs[tqs->queue[qr].ridx].used;
        if (qr_used == 0) {
            t_tree->stalled = 1;
        }
    }

    /* If the queue numbers here are -1 that means we've spilled
     * over into the portion of the tournament tree that isn't
     * populated by queues because the number of queues wasn't a
     * power-of-two
     *
     * Don't blindly combine this into the above statements as an else
     * without realising that both qr and ql must be checked for
     * a stall before any return is done
     */
    if (ql == -1) {
        return 0;
    } else if (qr == -1) {
        return 1;
    }

    /* The t_tree is built as though the number of queues is
     * a power-of-two however it doesn't actually have to be
     * that way so if the computed queue number spills over past
     * the actual number of queues we just fill the tree with -1
     * to indicate that portion of the tree shouldn't be use
     * in the tournament (and any real queue compared to a -1 queue
     * automatically "wins").
     */
    if (ql >= tqs->qnum) {
        return 0;
    } else if (qr >= tqs->qnum) {
        return 1;
    }

    /* This is where we do the actual less comparison */
    if (ql_used == 0) {
        return 0;
    } else if (qr_used == 0) {
        return 1;
    } else {
        struct timespec *tsl = &(tqs->queue[ql].msgs[tqs->queue[ql].ridx].ts);
        struct timespec *tsr = &(tqs->queue[qr].msgs[tqs->queue[qr].ridx].ts);

        return time_less(tsl, tsr);
    }
}


int lesser_queue(int ql, int qr, struct tourn_tree *t_tree, const struct thread_queues *tqs) {

    if (queue_less(ql, qr, t_tree, tqs) == 1) {
        return ql;
    } else {
        return qr;
    }
}


void run_tourn_for_queue(struct tourn_tree *t_tree, int q, const struct thread_queues *tqs) {

    /*
     * The leaf index in the tree for a particular queue
     * is the queue's index in the tree minus 1 (or 2) divided by 2
     * however we don't bother to store the bottem-most layer in the
     * the tree and also, by clearing the least significant bit in
     * the q number we can reduce the minus 1 or 2 to just minus 1.
     */

    int ql = (q % 2 == 0)? q : q - 1; /* the even q is (l)eft */
    int qr = ql + 1;                  /* the odd q is (r)ight */
    int lidx = ((ql + t_tree->qp2) - 1) / 2;

    t_tree->tree[lidx] = lesser_queue(ql, qr, t_tree, tqs);

    /* This "walks" back up the tree to the root node (0) */
    while (lidx > 0) {
        lidx = (lidx - 1) / 2; /* Up up a level in the tree */
        ql = t_tree->tree[(lidx * 2) + 1]; /* (l)eft child queue */
        qr = t_tree->tree[(lidx * 2) + 2]; /* (r)ight child queue */

        /* Run the tournament between ql and qr */
        t_tree->tree[lidx] = lesser_queue(ql, qr, t_tree, tqs);
    }
}



void run_tourn_for_entire_tree(struct tourn_tree *t_tree, const struct thread_queues *tqs) {

    /* We can run the tournament faster for the entire tree by
     * visiting each index in the tree once rather than running
     * the tournament for each queue because that will re-visit
     * the top of the tree over and over.
     */

    int ql, qr, lidx;

    /* First run the tournament for each pair to fill in the bottom
     * row of the tree
     */
    for (ql = 0; ql < tqs->qnum; ql += 2) {
        qr = ql + 1;
        lidx = ((ql + t_tree->qp2) - 1) / 2;

        t_tree->tree[lidx] = lesser_queue(ql, qr, t_tree, tqs);
    }

    /* Now we can run through each tree index once */
    for (lidx = (t_tree->qp2 / 2) - 2; lidx >= 0; lidx--) {
        ql = t_tree->tree[(lidx * 2) + 1]; /* (l)eft child queue */
        qr = t_tree->tree[(lidx * 2) + 2]; /* (r)ight child queue */

        t_tree->tree[lidx] = lesser_queue(ql, qr, t_tree, tqs);
    }


}


void debug_print_tour_tree(struct tourn_tree *t_tree, const struct thread_queues *tqs) {

    fprintf(stderr, "Tourn Tree size: %d\n", (t_tree->qp2 - 1));
    int i = 0;
    int l = 2;
    while (i < (t_tree->qp2 - 1)) {
        for (; i < l - 1; i++) {
            fprintf(stderr, "%d ", t_tree->tree[i]);
        }
        fprintf(stderr, "\n");
        l *= 2;
    }

    fprintf(stderr, "Ready queues:\n");
    for (int q = 0; q < t_tree->qnum; q++) {
        if (tqs->queue[q].msgs[tqs->queue[q].ridx].used == 1) {
            fprintf(stderr, "%d ", q);
        }
    }
    fprintf(stderr, "\n");
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
            sleep (1);
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
        sleep(1);
        if (out_ctx->file_error.load() == true) {
            exit(EXIT_FAILURE);
        }
    }
    out_ctx->record_countdown = out_ctx->max_records;
    /* This output thread uses a "tournament tree" algorithm
     * to perform a k-way merge of the lockless queues.
     *
     * https://en.wikipedia.org/wiki/Tournament_sort
     * https://www.geeksforgeeks.org/tournament-tree-and-binary-heap/
     * https://en.wikipedia.org/wiki/Priority_queue
     *
     * The actual algorithm is virtually identical to a priority queue
     * with the caveat that instead of swapping elements in an array
     * the priority queue just tracks a tree if of the "winning" queue
     * index.  In this algorithm "winning" is the oldest message.
     *
     * This algorithm is very efficient because it leaves messages in
     * the lockless queue until they are ready to be sent to output
     * intsead of making copies of messages and throwing them in a
     * priority queue.
     *
     * One "gotcha" about the usual k-way merge with a tournament tree
     * is that we're reading messages out of the lockless queues in
     * real-time as the queues are being filled.  This means not all
     * queues will always have a message in them which means we can't
     * really run the tournament properly because we don't know the
     * timestamp of the next message that queue will have when a
     * message finally arrives.
     *
     * To avoid things getting out-of-order the output thread won't
     * run a tournament until either 1) all queues have a message in
     * them, or 2) one of the queues has a message older than
     * LLQ_MAX_AGE (100ms by default).
     *
     * This means that as long as no queue pauses for more than
     * LLQ_MAX_AGE the k-way merge will be perfectly in-order.  If a
     * queue does pause for more than LLQ_MAX_AGE only messages older
     * than LLQ_MAX_AGE will be flushed.
     *
     * The other big assumption is that each lockless queue is in
     * perfect order.  Testing shows that rarely, packets can be
     * out-of-order by a few microseconds in an individual queue.  This
     * may be the fault of tiny clock abnormalities, could be machine
     * dependant, or ethernet card dependant.  The exact situations
     * where packets can be recieved out of cronological order aren't
     * known (to me anyways).
     */

    struct tourn_tree t_tree;
    t_tree.qnum = out_ctx->qs.qnum;
    t_tree.qp2 = 2; /* This is the smallest power of 2 >= the number of queues */
    while (t_tree.qp2 < t_tree.qnum) {
        t_tree.qp2 *= 2;
    }
    t_tree.tree = (int *)calloc(t_tree.qp2 - 1, sizeof(int)); /* The tournament needs qp2 - 1 nodes */
    if (t_tree.tree == NULL) {
        fprintf(stderr, "Failed to allocate enough memory for the tournament tree\n");
        exit(255);
    }
    for (int i = 0; i < (t_tree.qp2 - 1); i++) {
        t_tree.tree[i] = -1;
    }

    int all_output_flushed = 0;
    enum status status = status_ok;
    while (all_output_flushed == 0) {

        /* Bring the tree up-to-date */
        t_tree.stalled = 0;
        run_tourn_for_entire_tree(&t_tree, &out_ctx->qs);
        //for (int q = 0; q < t_tree.qp2; q += 2) {
        //run_tourn_for_queue(&t_tree, q, &out_ctx->qs);
        //}

        /* This loop runs the tournament as long as the tree
         * isn't "stalled".  A stalled tree means at least
         * one of the lockless queues is currenty empty.
         */

        int wq; /* winning queue */
        while (t_tree.stalled == 0) {
            wq = t_tree.tree[0]; /* the root node is always the winning queue */

            struct llq_msg *wmsg = &(out_ctx->qs.queue[wq].msgs[out_ctx->qs.queue[wq].ridx]);
            if (wmsg->used == 1) {
                fwrite(wmsg->buf, wmsg->len, 1, out_ctx->file_pri);

                /* A full memory barrier prevents the following flag (un)set from happening too soon */
                __sync_synchronize();
                wmsg->used = 0;

                /* Handle rotating file if needed */
                if (output_file_needs_rotation(out_ctx)) {
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

                out_ctx->qs.queue[wq].ridx = (out_ctx->qs.queue[wq].ridx + 1) % LLQ_DEPTH;

                run_tourn_for_queue(&t_tree, wq, &out_ctx->qs);
            }
            else {
                break;
            }

        }

        /* The tree is now stalled because a queue has been emptied
         * Now we must remove messages as long as they are "too old"
         */
        struct timespec old_ts;
        if (clock_gettime(CLOCK_REALTIME, &old_ts) != 0) {
            perror("Unable to get current time");
        }

        /* This is the time we compare against to flush */
        time_subtract_ns(&old_ts, LLQ_MAX_AGE);

        /* This loop runs the tournament even though the tree is stalled
         * but only pull messages out of queues that are older than
         * LLQ_MAX_AGE (currently set to 100ms).
         */

        int old_done = 0;
        while (old_done == 0) {
            wq = t_tree.tree[0];

            struct llq_msg *wmsg = &(out_ctx->qs.queue[wq].msgs[out_ctx->qs.queue[wq].ridx]);
            if (wmsg->used == 0) {
                /* Even the top queue has nothing so we can just stop now */
                old_done = 1;

                /* This is how we detect no more output is coming */
                if (out_ctx->sig_stop_output != 0) {
                    all_output_flushed = 1;
                }

                break;
            } else if (time_less(&(wmsg->ts), &old_ts) == 1) {
                //fprintf(stderr, "DEBUG: writing old message from queue %d\n", wq);
                fwrite(wmsg->buf, wmsg->len, 1, out_ctx->file_pri);

                /* A full memory barrier prevents the following flag (un)set from happening too soon */
                __sync_synchronize();
                wmsg->used = 0;

                /* Handle rotating file if needed */
                if (output_file_needs_rotation(out_ctx)) {
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

                out_ctx->qs.queue[wq].ridx = (out_ctx->qs.queue[wq].ridx + 1) % LLQ_DEPTH;

                run_tourn_for_queue(&t_tree, wq, &out_ctx->qs);
            } else {
                old_done = 1;
            }
        }

        /* This sleep slows us down so we don't spin the CPU.
         * We probably could afford to call fflush() here
         * the first time instead of sleeping and only sleep
         * if we really aren't recieving any messages on
         * any queues.
         */
        struct timespec sleep_ts;
        sleep_ts.tv_sec = 0;
        sleep_ts.tv_nsec = 1000000;
        nanosleep(&sleep_ts, NULL);
    } /* End all_output_flushed == 0 meaning we got a signal to stop */

    if (t_tree.tree) {
        free(t_tree.tree);
    }

    if (out_ctx->type != file_type_stdout) {
        close_outfiles(out_ctx);
    }

    return NULL;
}


int output_thread_init(pthread_t &output_thread, struct output_file &out_ctx, const struct mercury_config &cfg) {

    /* make the thread queues */
    thread_queues_init(&out_ctx.qs, cfg.num_threads);

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
    int err = pthread_create(&output_thread, NULL, output_thread_func, &out_ctx);
    if (err != 0) {
        perror("error creating output thread");
        return -1;
    }
    return 0;
}

void output_thread_finalize(pthread_t output_thread, struct output_file *out_file) {
    out_file->sig_stop_output = 1;
    pthread_join(output_thread, NULL);
    thread_queues_free(&out_file->qs);
}
