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

/*
 * packet_filter_threshold is a (somewhat arbitrary) threshold used in
 * the packet metadata filter; it will probably get eliminated soon,
 * in favor of extractor::proto_state::state, but for now it remains
 */
unsigned int packet_filter_threshold = 8;

void frame_handler_flush_pcap(void *userdata) {
    union frame_handler_context *fhc = (union frame_handler_context *)userdata;
    struct pcap_file *f = &fhc->pcap_file;
    FILE *file_ptr = f->file_ptr;
    if (file_ptr != NULL) {
        if (fflush(file_ptr) != 0) {
            perror("warning: could not flush the pcap file\n");
        }
    }
}

void frame_handler_filter_write_pcap(void *userdata,
				     struct packet_info *pi,
				     uint8_t *eth_hdr) {

    union frame_handler_context *fhc = (union frame_handler_context *)userdata;
    struct parser p;
    struct extractor x;
    unsigned char extractor_buffer[2048];
    size_t bytes_extracted;
    uint8_t *packet = eth_hdr;
    unsigned int length = pi->len;
    
    extractor_init(&x, extractor_buffer, 2048);
    parser_init(&p, (unsigned char *)packet, length);
    bytes_extracted = parser_extractor_process_packet(&p, &x);

    if (bytes_extracted > packet_filter_threshold) {
	pcap_file_write_packet_direct(&fhc->pcap_file, eth_hdr, pi->len, pi->ts.tv_sec, pi->ts.tv_nsec / 1000);
    }
}

enum status frame_handler_filter_write_pcap_init(struct frame_handler *handler,
					   const char *outfile,
					   int flags) {
    /*
     * setup output to fingerprint file or PCAP write file
     */
    handler->func = frame_handler_filter_write_pcap;
    handler->flush_func = frame_handler_flush_pcap;
    enum status status = pcap_file_open(&handler->context.pcap_file, outfile, io_direction_writer, flags);
    
    return status;
}

void frame_handler_write_pcap(void *userdata,
			      struct packet_info *pi,
			      uint8_t *eth) {
    union frame_handler_context *fhc = (union frame_handler_context *)userdata;

    extern int rnd_pkt_drop_percent_accept;  /* defined in rnd_pkt_drop.c */

    if (rnd_pkt_drop_percent_accept && drop_this_packet()) {
        return;  /* random packet drop configured, and this packet got selected to be discarded */
    }
    pcap_file_write_packet_direct(&fhc->pcap_file, eth, pi->len, pi->ts.tv_sec, pi->ts.tv_nsec / 1000);

}

enum status frame_handler_write_pcap_init(struct frame_handler *handler,
				    const char *outfile,
				    int flags) {

    /*
     * setup output to fingerprint file or PCAP write file
     */
    enum status status = pcap_file_open(&handler->context.pcap_file, outfile, io_direction_writer, flags);
    if (status) {
	printf("error: could not open pcap output file %s\n", outfile);
	return status_err;
    }
    handler->func = frame_handler_write_pcap;
    handler->flush_func = frame_handler_flush_pcap;

    return status_ok;
}

void frame_handler_flush_fingerprints(void *userdata) {
    union frame_handler_context *fhc = (union frame_handler_context *)userdata;
    FILE *file_ptr = fhc->json_file.file;
    if (file_ptr != NULL) {
        if (fflush(file_ptr) != 0) {
            perror("warning: could not flush the json file\n");
        }
    }
}

void frame_handler_write_fingerprints(void *userdata,
				      struct packet_info *pi,
				      uint8_t *eth) {
    union frame_handler_context *fhc = (union frame_handler_context *)userdata;
    
    json_file_write(&fhc->json_file, eth, pi->len, pi->ts.tv_sec, pi->ts.tv_nsec / 1000);
}

enum status frame_handler_write_fingerprints_init(struct frame_handler *handler,
						  const char *outfile_name,
						  const char *mode,
						  uint64_t max_records) {

    enum status status;

    status = json_file_init(&handler->context.json_file, outfile_name, mode, max_records);
    if (status) {
	return status;
    }
    handler->func = frame_handler_write_fingerprints;
    handler->flush_func = frame_handler_flush_fingerprints;

    return status_ok;
}

void frame_handler_dump(void *ignore,
			struct packet_info *pi,
			uint8_t *eth) {
    (void)ignore;

    packet_fprintf(stdout, eth, pi->len, pi->ts.tv_sec, pi->ts.tv_nsec / 1000);
    // printf_raw_as_hex(packet, tphdr->tp_len);

}

enum status frame_handler_dump_init(struct frame_handler *handler) {

    /* note: we leave handler->context uninitialized */
    handler->func = frame_handler_dump;
    handler->flush_func = NULL;

    return status_ok;
}

struct frame_handler_class *frame_handler_class_new_from_config(struct mercury_config *cfg,
                                                                int tnum,
                                                                char *fileset_id) {
    enum status status;
    char outfile[MAX_FILENAME];
    pid_t pid = tnum; // syscall(__NR_gettid);

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
             * write only TLS clientHellos and TCP SYNs to capture file
             */
            return new frame_handler_filter_pcap_writer(outfile, cfg->flags);
            if (status) {
                printf("error: could not open pcap output file %s\n", outfile);
                throw "error in pcap output file";
            }
        } else {
            /*
             * write all packets to capture file
             */
            return new frame_handler_pcap_writer(outfile, cfg->flags);

        }

    } else if (cfg->fingerprint_filename) {
        /*
         * write fingerprints into output file
         */
        status = filename_append(outfile, cfg->fingerprint_filename, "/", fileset_id);
        if (status) {
            throw "error in filename";
        }
        if (cfg->verbosity) {
            printf("initializing thread function %x with filename %s\n", pid, outfile);
        }

        return new frame_handler_json_writer(outfile, cfg->mode, max_records);
        if (status) {
            perror("error: could not open fingerprint output file");
            throw "error opening json file";
        }
    } else {
        /*
         * default: dump JSON-formatted packet info to stdout
         */
        return new frame_handler_dumper();

    }

    return NULL;
}
