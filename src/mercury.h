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

#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>
#include <pthread.h>

#define MAX_FILENAME 256

#define MAX_HEX 16
#define BILLION 1000000000L

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
    int filter;                     /* indicates that packets should be filtered      */
    int analysis;                   /* indicates that fingerprints should be analyzed */
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
};

#define mercury_config_init() { NULL, NULL, NULL, NULL, NULL, 0, 0, O_EXCL, (char *)"w", 0, 8, 1, 0, NULL, 1, 0, NULL, 0, 0  }

#define LLQ_MSG_SIZE 16384   /* The number of bytes allowed for each message in the lockless queue */
#define LLQ_DEPTH    2048    /* The number of "buckets" (queue messages) allowed */
#define LLQ_MAX_AGE  5       /* Maximum age (in seconds) messages are allowed to sit in a queue */

enum file_type { unknown=0, json, pcap };

struct output_file {
    FILE *file;
    int64_t record_countdown;
    int64_t max_records;
    uint32_t file_num;
    char *outfile_name;
    const char *mode;
    enum file_type type;
    int t_output_p;
    pthread_cond_t t_output_c;
    pthread_mutex_t t_output_m;
};

extern int sig_stop_output;    /* Watched by the output thread to know when to terminate */
//extern struct output_file out_ctx;
//extern int t_output_p;
//extern pthread_cond_t t_output_c;


/* The message object suitable for the std::priority_queue */
struct llq_msg {
    volatile int used; /* The flag that says if this object is actually in use (if not, it's available) */
    char buf[LLQ_MSG_SIZE];
    ssize_t len;
    struct timespec ts;
};


/* a "lockless" queue */
struct ll_queue {
    int qnum;  /* This is the queue number and is only needed for debugging */
    int ridx;  /* The read index */
    int widx;  /* The write index */
    struct llq_msg msgs[LLQ_DEPTH];
};


struct thread_queues {
    int qnum;             /* The number of queues that have been allocated */
    int qidx;             /* The index of the first free queue */
    struct ll_queue *queue;      /* The actual queue datastructure */
};


struct tourn_tree {
    int qnum;
    int qp2;
    int *tree;
    int stalled;
};


enum create_subdir_mode {
    create_subdir_mode_do_not_overwrite = 0,
    create_subdir_mode_overwrite = 1
};

void create_subdirectory(const char *outdir, enum create_subdir_mode mode);

enum status filename_append(char dst[MAX_FILENAME],
			    const char *src,
			    const char *delim,
			    const char *tail);

void get_clocktime_before (struct timespec *before);
uint64_t get_clocktime_after (struct timespec *before, struct timespec *after);

mqd_t open_thread_queue(const char *qid);

#endif /* MERCURY_H */
