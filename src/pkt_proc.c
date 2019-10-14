/*
 * pkt_proc.c
 * 
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at 
 * https://github.com/cisco/mercury/blob/master/LICENSE 
 */

#include <linux/if_packet.h>
#include <string.h>
#include "extractor.h"
#include "pcap_file_io.h"
#include "json_file_io.h"
#include "packet.h"

/*
 * packet_filter_threshold is a (somewhat arbitrary) threshold used in
 * the packet metadata filter; it will probably get eliminated soon, 
 * in favor of extractor::proto_state::state, but for now it remains
 */
unsigned int packet_filter_threshold = 8;

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
    enum status status = pcap_file_open(&handler->context.pcap_file, outfile, io_direction_writer, flags);
    
    return status;
}
				      

void frame_handler_write_pcap(void *userdata,
			      struct packet_info *pi,
			      uint8_t *eth) {
    union frame_handler_context *fhc = (union frame_handler_context *)userdata;

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

    return status_ok;
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

    return status_ok;
}
				    
