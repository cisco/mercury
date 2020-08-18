/*
 * mercury.h
 *
 * main header file for mercury packet metadata capture and analysis
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef MERCURY_H
#define MERCURY_H

#include <inttypes.h>
#include <stdio.h>

#define MAX_FILENAME 256

#define MAX_HEX 16

#ifdef DEBUG
    #define debug_print_int(X)  printf("%s:\t%d:\t%s():\t%s:\t%ld\n", __FILE__, __LINE__, __func__, #X, (unsigned long)(X))
    #define debug_print_uint(X) printf("%s:\t%d:\t%s():\t%s:\t%lu\n", __FILE__, __LINE__, __func__, #X, (unsigned long)(X))
    #define debug_print_ptr(X)  printf("%s:\t%d:\t%s():\t%s:\t%p\n",  __FILE__, __LINE__, __func__, #X, (void *)(X))
    #define debug_print_u8_array(X)  printf("%s:\t%d:\t%s():\t%s:\t%02x%02x%02x%02x\n",  __FILE__, __LINE__, __func__, #X, ((unsigned char *)X)[0], ((unsigned char *)X)[1], ((unsigned char *)X)[2], ((unsigned char *)X)[3])
#else
    #define debug_print_int(X)
    #define debug_print_uint(X)
    #define debug_print_ptr(X)
    #define debug_print_u8_array(X)
#endif

enum status {
    status_ok = 0,
    status_err = 1,
    status_err_no_more_data = 2
};

/*
 * struct mercury_config holds the configuration information for a run
 * of the program
 */
struct mercury_config {
    char *read_filename;            /* base name of pcap file to read, if any         */
    char *write_filename;           /* base name of pcap file to write, if any        */
    char *fingerprint_filename;     /* base name of fingerprint file to write, if any */
    char *capture_interface;        /* base name of interface to capture from, if any */
    char *working_dir;              /* working directory                              */
    bool filter;                    /* indicates that packets should be filtered      */
    bool analysis;                  /* indicates that fingerprints should be analyzed */
    int flags;                      /* flags for open()                               */
    char *mode;                     /* mode for fopen()                               */
    int fanout_group;               /* identifies fanout group used by sockets        */
    float buffer_fraction;          /* fraction of phys mem used for RX_RING buffers  */
    int num_threads;                /* number of worker threads                       */
    uint64_t rotate;                /* number of records per file rotation, or 0      */
    char *user;                     /* username of account used for privilege drop    */
    int loop_count;                 /* loop count for repeat processing of read file  */
    int verbosity;                  /* 0=minimal output; 1=more detailed output       */
    char *packet_filter_cfg;        /* packet filter configuration string             */
    int use_test_packet;            /* use test packet to write output file           */
    int adaptive;                   /* adaptively accept/skip packets for PCAP output */
    bool output_block;              /* use blocking output                            */
};

#define mercury_config_init() { NULL, NULL, NULL, NULL, NULL, false, false, O_EXCL, (char *)"w", 0, 8, 1, 0, NULL, 1, 0, NULL, 0, 0, false }

/*
 * struct global_variables holds all of mercury's global variables.
 * This set is currently limited to booleans that control the
 * processing and output.  It would be nice avoid global state by
 * passing these values into the packet processor (struct pkt_proc),
 * but for now we are using this global struct to keep track of the
 * global state, and put them all on the same cache line.
 */
struct global_variables {
    global_variables() : dns_json_output{false}, certs_json_output{false}, metadata_output{false}, do_analysis{false} {}

    bool dns_json_output;   /* output DNS as JSON              */
    bool certs_json_output; /* output certificates as JSON     */
    bool metadata_output;   /* output lots of metadata         */
    bool do_analysis;       /* write analysys{} JSON object    */
};

#endif /* MERCURY_H */
