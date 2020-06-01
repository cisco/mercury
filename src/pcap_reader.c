/*
 * pcap_reader.c
 */

#include <errno.h>
#include "pcap_reader.h"
#include "output.h"
#include "pkt_proc.h"
#include "utils.h"

#define BILLION 1000000000L

enum status pcap_reader_thread_context_init_from_config(struct pcap_reader_thread_context *tc,
                                                        struct mercury_config *cfg,
                                                        int tnum,
                                                        struct ll_queue *llq) {
    char input_filename[MAX_FILENAME];
    tc->tnum = tnum;
	tc->loop_count = cfg->loop_count;
    enum status status;

    tc->pkt_processor = pkt_proc_new_from_config(cfg, tnum, llq);
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
            printf("%s: could not open pcap input file %s\n", strerror(errno), cfg->read_filename);
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

    status = pcap_file_dispatch_pkt_processor(&tc->rf, tc->pkt_processor, tc->loop_count);
    if (status) {
        printf("error in pcap file dispatch (code: %d)\n", (int)status);
        return NULL;
    }

    return NULL;
}

enum status open_and_dispatch(struct mercury_config *cfg, struct output_file *of) {
    enum status status;
    struct timer t;
	u_int64_t nano_seconds = 0;
	u_int64_t bytes_written = 0;
	u_int64_t packets_written = 0;

    timer_start(&t); // get timestamp before we start processing

    struct pcap_reader_thread_context tc;

    status = pcap_reader_thread_context_init_from_config(&tc, cfg, 0, &of->qs.queue[0]);
    if (status != status_ok) {
        perror("could not initialize pcap reader thread context");
        return status;
    }

    /* Wake up output thread so it's polling the queues waiting for data */
    of->t_output_p = 1;
    int err = pthread_cond_broadcast(&(of->t_output_c)); /* Wake up output */
    if (err != 0) {
        printf("%s: error broadcasting all clear on output start condition\n", strerror(err));
        exit(255);
    }

#if 0
    pcap_file_processing_thread_func(&tc);
#else
    err = pthread_create(&(tc.tid), NULL, pcap_file_processing_thread_func, &tc);
    if (err) {
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

    if (cfg->write_filename && cfg->verbosity) {
        printf("For all files, packets written: %" PRIu64 ", bytes written: %" PRIu64 ", nano sec: %" PRIu64 ", bytes per second: %.4e\n",
               packets_written, bytes_written, nano_seconds, byte_rate);
    }

    return status_ok;
}

