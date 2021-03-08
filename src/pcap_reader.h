/*
 * pcap_reader.c
 *
 * Copyright (c) 2021 Cisco Systems, Inc.  All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <pthread.h>
#include "pcap_file_io.h"
#include "mercury.h"
#include "llq.h"

/*
 * struct pcap_reader_thread_context holds thread-specific information
 * for a pcap-file-reading thread; it is a sister to struct
 * thread_context, which has the equivalent role for network capture
 * threads
 */
struct pcap_reader_thread_context {
    struct pkt_proc *pkt_processor;
    int tnum;                 /* Thread Number */
    pthread_t tid;            /* Thread ID */
    struct pcap_file rf;
    int loop_count;           /* loop count */
};

enum status pcap_reader_thread_context_init_from_config(struct pcap_reader_thread_context *tc,
                                                        struct mercury_config *cfg,
                                                        int tnum,
                                                        struct ll_queue *llq);

void pcap_reader_thread_context_finalize(struct pcap_reader_thread_context *tc);


enum status open_and_dispatch(struct mercury_config *cfg, struct output_file *of);

#endif /* PCAP_READER_H */
