/*
 * pkt_processing.c
 * 
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at 
 * https://github.com/cisco/mercury/blob/master/LICENSE 
 */

#include <string.h>
#include "pcap_file_io.h"
#include "rnd_pkt_drop.h"
#include "pkt_processing.h"
#include "libmerc/utils.h"


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
                fprintf(stderr, "initializing thread function %x with filename %s\n", pid, outfile);
            }

            if (cfg->filter) {
                /*
                 * write only packet metadata (TLS clientHellos, TCP SYNs, ...) to capture file
                 */
                return new pkt_proc_filter_pcap_writer_llq(llq, cfg->packet_filter_cfg, cfg->output_block);

            } else {
                /*
                 * write all packets to capture file
                 */
                return new pkt_proc_pcap_writer_llq(llq, cfg->output_block);

            }

        } else {
            /*
             * write fingerprints into output file
             */

            return new pkt_proc_json_writer_llq(llq, cfg->packet_filter_cfg, cfg->output_block);

        }
        // note: we no longer have a 'packet dumper' option
        //    return new pkt_proc_dumper();

    }
    catch (const char *s) {
        fprintf(stdout, "error: %s\n", s);
    };

    return NULL;
}


