/*
 * pkt_proc.h
 * 
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at 
 * https://github.com/cisco/mercury/blob/master/LICENSE 
 */

#ifndef PKT_PROC_H
#define PKT_PROC_H

#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include "pcap_file_io.h"
#include "json_file_io.h"
#include "extractor.h"      /* for struct packet_filter */

/* Information about each packet on the wire */
struct packet_info {
  struct timespec ts;   /* timestamp */
  uint32_t caplen;     /* length of portion present */
  uint32_t len;        /* length this packet (off wire) */
};


struct filter_writer_context {
    struct pcap_file pcap_file;
    struct packet_filter pf; 
};

typedef void (*frame_handler_func)(void *userdata,
				   struct packet_info *pi,
				   uint8_t *eth);

typedef void (*frame_handler_flush_func)(void *userdata);

/*
 * struct frame_handler 'object' includes the function pointer func
 * and the context passed to that function, which may be either a
 * struct pcap_file or a FILE depending on the function to which
 * 'func' points
 *
 * to initialize a frame_handler, call one of the frame_handler_*_init
 * functions defined below (or define your own)
 */
union frame_handler_context {
    struct pcap_file pcap_file;
    struct json_file json_file;
    struct filter_writer_context filter_writer;
};
struct frame_handler {
    frame_handler_func func;
    frame_handler_flush_func flush_func;
    union frame_handler_context context;
};


/*
 * frame_handler_write_fingerprints_init(handler, outfile_name, mode)
 * initializes handler to write (TLS and TCP) fingerprints to the
 * output file with the path outfile_name and mode passed as
 * arguments; that file is opened by this invocation, with that mode.  
 * 
 * return values are status_ok (no error), status_err (unspecified error),
 * or other error values
 *
 */
enum status frame_handler_write_fingerprints_init(struct frame_handler *handler,
						  const char *outfile_name,
						  const char *mode,
						  uint64_t max_records);


/*
 * frame_handler_write_pcap_init(handler, outfile_name, mode)
 * initializes handler to filter packets and then write the remaining
 * packets into the pcap file with the path outfile and flags passed
 * as arguments; that file is opened by this invocation, with those
 * flags.
 * 
 * return values are status_ok (no error), status_err (unspecified error),
 * or other error values
 *
 */
enum status frame_handler_filter_write_pcap_init(struct frame_handler *handler,
						 const char *outfile,
						 int flags,
						 const char *packet_filter_config_string);


/*
 * frame_handler_write_pcap_init(handler, outfile_name, mode)
 * initializes handler to write packets into the pcap file with the
 * path outfile and flags passed as arguments; that file is opened by
 * this invocation, with those flags.
 * 
 * return values are status_ok (no error), status_err (unspecified error),
 * or other error values
 *
 */
enum status frame_handler_write_pcap_init(struct frame_handler *handler,
					  const char *outfile,
					  int flags);

/*
 * frame_handler_dump_init(handler) initializes handler to write a
 * JSON object summarizing each packet to stdout
 * 
 * return values are status_ok (no error), status_err (unspecified error),
 * or other error values
 *
 */
enum status frame_handler_dump_init(struct frame_handler *handler);


enum status frame_handler_init_from_config(struct frame_handler *handler,
					   struct mercury_config *ppt,
					   int tnum,
					   char *fileset_id);

enum status pcap_file_dispatch_frame_handler(struct pcap_file *f,
					     frame_handler_func func,
					     void *userdata,
						 int loop_count);

enum status pcap_file_dispatch_test_packet(frame_handler_func func,
                         void *userdata,
                         int loop_count);

#endif /* PKT_PROC_H */
