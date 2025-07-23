/*
 * pcap_reader.c
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <errno.h>
#include "pcap_reader.h"
#include "output.h"
#include "pkt_processing.h"
#include "libmerc/utils.h"

extern sig_atomic_t sig_close_flag;  // defined in signal_handling.c

#define BILLION 1000000000L

enum status pcap_reader_thread_context_init_from_config(struct pcap_reader_thread_context *tc,
                                                        struct mercury_config *cfg,
                                                        mercury_context mc,
                                                        int tnum,
                                                        struct ll_queue *llq) {
    char input_filename[FILENAME_MAX];
    tc->tnum = tnum;
	tc->loop_count = cfg->loop_count;
    enum status status;

    tc->pkt_processor = pkt_proc_new_from_config(cfg, mc, tnum, llq);
    if (tc->pkt_processor == NULL) {
        printf("error: could not initialize frame handler\n");
        return status_err;
    }

    // if cfg->use_test_packet is on, read_filename will be NULL
    if (cfg->read_filename != NULL) {
        status = filename_append(input_filename, cfg->read_filename, "/", NULL);
        if (status) {
            return status;
        }
        status = pcap_file_open(&tc->rf, input_filename, io_direction_reader, cfg->flags);
        if (status) {
            printf("error: could not open pcap input file %s\n", cfg->read_filename);
            return status;
        }
    }
    return status_ok;
}

void pcap_reader_thread_context_finalize(struct pcap_reader_thread_context *tc) {
    pcap_file_close(&(tc->rf));
    delete tc->pkt_processor;
}

void *pcap_file_processing_thread_func(void *userdata) {
    struct pcap_reader_thread_context *tc = (struct pcap_reader_thread_context *)userdata;
    enum status status;

    status = pcap_file_dispatch_pkt_processor(&tc->rf, tc->pkt_processor, tc->loop_count, sig_close_flag);
    if (status) {
        fprintf(stderr, "error in pcap file dispatch (code: %d)\n", (int)status);
        return NULL;
    }

    return NULL;
}

enum status open_and_dispatch(struct mercury_config *cfg, mercury_context mc, struct output_file *of) {
    enum status status;
    struct timer t;
	u_int64_t nano_seconds = 0;
	u_int64_t bytes_written = 0;
	u_int64_t packets_written = 0;

    timer_start(&t); // get timestamp before we start processing

    struct pcap_reader_thread_context tc;

    status = pcap_reader_thread_context_init_from_config(&tc, cfg, mc, 0, &of->qs.queue[0]);
    if (status != status_ok) {
        if (errno) {
            perror("could not initialize pcap reader thread context");
        }
        return status;
    }

    /* Wake up output thread so it's polling the queues waiting for data */
    of->t_output_p = 1;
    int err = pthread_cond_broadcast(&(of->t_output_c)); /* Wake up output */
    if (err != 0) {
        printf("%s: error broadcasting all clear on output start condition\n", strerror(err));
        exit(255);
    }

#ifdef DONT_USE_THREADS
    pcap_file_processing_thread_func(&tc);
#else

    // Set the stack size to a large value, since some platforms (like OS X) have stack sizes that are too small
    pthread_attr_t pt_stack_size;
    err = pthread_attr_init(&pt_stack_size);
    if (err != 0) {
        printf("Unable to init stack size attribute for pcap reader pthread: %s\n", strerror(err));
    }

    err = pthread_attr_setstacksize(&pt_stack_size, 16 * 1024 * 1024); // 16 MB is plenty big enough
    if (err != 0) {
        printf("Unable to set stack size attribute for pcap reader pthread: %s\n", strerror(err));
    }

    err = pthread_create(&(tc.tid), &pt_stack_size, pcap_file_processing_thread_func, &tc);
    if (err != 0) {
        printf("%s: error creating file reader thread\n", strerror(err));
        exit(255);
    }
    pthread_join(tc.tid, NULL);
#endif
    //    struct pkt_proc_stats pkt_stats = tc.pkt_processor->get_stats();
    bytes_written = tc.pkt_processor->bytes_written;
    packets_written = tc.pkt_processor->packets_written;
    pcap_reader_thread_context_finalize(&tc);

    nano_seconds = timer_stop(&t);
    double byte_rate = ((double)bytes_written * BILLION) / (double)nano_seconds;
    double packet_rate = ((double)packets_written * BILLION) / (double)nano_seconds;
    if (cfg->verbosity) {
        fprintf(stderr, "Packets processed: %" PRIu64 ", packets per second: %.4e, bytes processed: %" PRIu64 ", nano sec: %" PRIu64 ", bytes per second: %.4e\n",
                packets_written, packet_rate, bytes_written, nano_seconds, byte_rate);
    }

    return status_ok;
}
