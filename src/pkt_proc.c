/*
 * pkt_proc.c
 * 
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at 
 * https://github.com/cisco/mercury/blob/master/LICENSE 
 */

#include <string.h>
#include "extractor.h"
#include "pcap_file_io.h"
#include "json_file_io.h"
#include "packet.h"
#include "rnd_pkt_drop.h"
#include "pkt_proc.h"
#include "mercury.h"

extern struct thread_queues t_queues;

/*
 * packet_filter_threshold is a (somewhat arbitrary) threshold used in
 * the packet metadata filter; it will probably get eliminated soon,
 * in favor of extractor::proto_state::state, but for now it remains
 */
unsigned int packet_filter_threshold = 7;

struct pkt_proc *pkt_proc_new_from_config(struct mercury_config *cfg,
                                          int tnum,
                                          char *fileset_id) {

    try {

        enum status status;
        char outfile[MAX_FILENAME];
        pid_t pid = tnum;

        uint64_t max_records = 0;
        if (cfg->rotate) {
            max_records = cfg->rotate;
        }

        if (cfg->write_filename) {

            status = filename_append(outfile, cfg->write_filename, "/", fileset_id);
            if (status) {
                throw "error in filename";
            }
            if (cfg->verbosity) {
                printf("initializing thread function %x with filename %s\n", pid, outfile);
            }

            if (cfg->filter) {
                /*
                 * write only packet metadata (TLS clientHellos, TCP SYNs, ...) to capture file
                 */
                return new pkt_proc_filter_pcap_writer(outfile, cfg->flags);

            } else {
                /*
                 * write all packets to capture file
                 */
                return new pkt_proc_pcap_writer(outfile, cfg->flags);

            }

        } else if (cfg->fingerprint_filename) {
            /*
             * write fingerprints into output file
             */
            /* status = filename_append(outfile, cfg->fingerprint_filename, "/", fileset_id); */
            /* if (status) { */
            /*     throw "error in filename"; */
            /* } */
            /* if (cfg->verbosity) { */
            /*     printf("initializing thread function %x with filename %s\n", pid, outfile); */
            /* } */

            /* return new pkt_proc_json_writer(outfile, cfg->mode, max_records);*/
            (void)max_records;
            /* This is a mess right now because we no longer deal with output file names
             * and instead are dealing with a queue.  We don't pass a file handle or file
             * name and instead must pass a pointer to a lockless queue
             */
            unsigned int qnum = 0;
            if (fileset_id != NULL) {
                int ret = sscanf(fileset_id, "%x", &qnum); /* /me dies a little inside */
                if (ret != 1) {
                    fprintf(stderr, "Parsing thread fileset_id string failed!\n");
                }
            }
            return new pkt_proc_json_writer_llq(&(t_queues.queue[qnum]));

        } else {
            /*
             * default: dump JSON-formatted packet info to stdout
             */
            return new pkt_proc_dumper();

        }

    }
    catch (const char *s) {
        fprintf(stdout, "error: %s\n", s);
    };

    return NULL;
}
