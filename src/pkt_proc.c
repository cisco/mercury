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
#include "utils.h"
#include "llq.h"

/*
 * packet_filter_threshold is a (somewhat arbitrary) threshold used in
 * the packet metadata filter; it will probably get eliminated soon,
 * in favor of extractor::proto_state::state, but for now it remains
 */
unsigned int packet_filter_threshold = 7;

struct pkt_proc *pkt_proc_new_from_config(struct mercury_config *cfg,
                                          int tnum,
                                          struct ll_queue *llq) {

    try {

        enum status status;
        char outfile[MAX_FILENAME];
        pid_t pid = tnum;

        if (cfg->write_filename) {

            status = filename_append(outfile, cfg->write_filename, "/", NULL);
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
                return new pkt_proc_filter_pcap_writer_llq(llq, cfg->packet_filter_cfg);

            } else {
                /*
                 * write all packets to capture file
                 */
                return new pkt_proc_pcap_writer_llq(llq);

            }

        } else if (cfg->fingerprint_filename) {
            /*
             * write fingerprints into output file
             */

            return new pkt_proc_json_writer_llq(llq, cfg->packet_filter_cfg);

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
