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
#include <errno.h>
#include <string.h>
#include "pcap_file_io.h"
#include "json_file_io.h"
#include "extractor.h"
#include "packet.h"

/* Information about each packet on the wire */
struct packet_info {
  struct timespec ts;   /* timestamp */
  uint32_t caplen;     /* length of portion present */
  uint32_t len;        /* length this packet (off wire) */
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
};
struct frame_handler {
    frame_handler_func func;
    frame_handler_flush_func flush_func;
    union frame_handler_context context;
};


// c++ classes for frame handling / packet processing
//
struct frame_handler_class {
    virtual void frame_handler_func(struct packet_info *pi, uint8_t *eth) = 0;
    virtual void frame_handler_flush_func() = 0;
    virtual ~frame_handler_class() {};
};

struct frame_handler_json_writer : public frame_handler_class {
    struct json_file json_file;

    frame_handler_json_writer(const char *outfile_name,
                              const char *mode,
                              uint64_t max_records) {

        enum status status = json_file_init(&json_file, outfile_name, mode, max_records);
        if (status) {
            throw "exception in frame_handler_json_writer()";
        }
    }

    void frame_handler_func(struct packet_info *pi, uint8_t *eth) {
        json_file_write(&json_file, eth, pi->len, pi->ts.tv_sec, pi->ts.tv_nsec / 1000);
    }

    void frame_handler_flush_func() {
        FILE *file_ptr = json_file.file;
        if (file_ptr != NULL) {
            if (fflush(file_ptr) != 0) {
                perror("warning: could not flush json file\n");
            }
        }
    }
};

struct frame_handler_pcap_writer : public frame_handler_class {
    struct pcap_file pcap_file;

    frame_handler_pcap_writer(const char *outfile, int flags) {
        enum status status = pcap_file_open(&pcap_file, outfile, io_direction_writer, flags);
        if (status) {
            printf("%s: could not open pcap output file %s\n", strerror(errno), outfile);
            throw "could not open pcap output file";
        }
    }

    void frame_handler_func(struct packet_info *pi, uint8_t *eth) {
        pcap_file_write_packet_direct(&pcap_file, eth, pi->len, pi->ts.tv_sec, pi->ts.tv_nsec / 1000);
    }

    void frame_handler_flush_func() {
        FILE *file_ptr = pcap_file.file_ptr;
        if (file_ptr != NULL) {
            if (fflush(file_ptr) != 0) {
                perror("warning: could not flush pcap file\n");
            }
        }
    }

};

struct frame_handler_filter_pcap_writer : public frame_handler_class {
    struct pcap_file pcap_file;

    /*
     * packet_filter_threshold is a (somewhat arbitrary) threshold used in
     * the packet metadata filter; it will probably get eliminated soon,
     * in favor of extractor::proto_state::state, but for now it remains
     */
    unsigned int packet_filter_threshold = 8;

    frame_handler_filter_pcap_writer(const char *outfile, int flags) {
        enum status status = pcap_file_open(&pcap_file, outfile, io_direction_writer, flags);
        if (status) {
            printf("error: could not open pcap output file %s\n", outfile);
            throw "could not open pcap output file";
        }
    }

    void frame_handler_func(struct packet_info *pi, uint8_t *eth) {
        struct parser p;
        struct extractor x;
        unsigned char extractor_buffer[2048];
        size_t bytes_extracted;
        uint8_t *packet = eth;
        unsigned int length = pi->len;

        extractor_init(&x, extractor_buffer, 2048);
        parser_init(&p, (unsigned char *)packet, length);
        bytes_extracted = parser_extractor_process_packet(&p, &x);

        if (bytes_extracted > packet_filter_threshold) {
            pcap_file_write_packet_direct(&pcap_file, eth, pi->len, pi->ts.tv_sec, pi->ts.tv_nsec / 1000);
        }
    }

    void frame_handler_flush_func() {
        FILE *file_ptr = pcap_file.file_ptr;
        if (file_ptr != NULL) {
            if (fflush(file_ptr) != 0) {
                perror("warning: could not flush pcap file\n");
            }
        }
    }

};

struct frame_handler_dumper : public frame_handler_class {

    frame_handler_dumper() {}

    void frame_handler_func(struct packet_info *pi, uint8_t *eth) {
        packet_fprintf(stdout, eth, pi->len, pi->ts.tv_sec, pi->ts.tv_nsec / 1000);
    }

    void frame_handler_flush_func() {
    }
};

struct frame_handler_class *frame_handler_class_new_from_config(struct mercury_config *cfg,
                                                                int tnum,
                                                                char *fileset_id);

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
						 int flags);


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
