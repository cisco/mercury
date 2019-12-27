/*
 * af_packet_io.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */


#ifndef AF_PACKET_IO_H
#define AF_PACKET_IO_H

#include <stdlib.h>
#include <stdio.h>
#include <linux/if_packet.h>
#include "pcap_file_io.h"
#include "pkt_proc.h"

#ifdef TPACKET3_HDRLEN
#define USE_FANOUT 
#endif


/*
 * struct thread_context stores information about each thread
 * including its thread id and socket file handle
 */
struct thread_context {
    // packet_callback_t p_callback; /* The packet callback function */
    int tnum;                 /* Thread Number */
    pthread_t tid;            /* Thread ID */
    int sockfd;               /* Socket owned by this thread */
    char *if_name;            /* The name of the interface to bind the socket to */
    uint8_t *mapped_buffer;   /* The pointer to the mmap()'d region */
    struct tpacket_req tp_req;
    size_t frames_per_buffer;
    size_t rx_ring_size;
    //struct tpacket_block_desc **block_header; /* The pointer to each block in the mmap()'d region */
    //struct tpacket_req3 ring_params; /* The ring allocation params to setsockopt() */
};

enum status capture_init(struct thread_context *tc, int fanout_group, int buffer_fraction);

enum status capture_loop(struct thread_context *tc);

void get_readable_number_int(unsigned int power,
			     unsigned int input,
			     unsigned int *num_output,
			     char **str_output);

void get_readable_number_float(double power,
			       double input,
			       double *num_output,
			       char **str_output);

void frame_handler_write_pcap(void *userdata,
			      //struct tpacket_hdr *tphdr,
			      struct packet_info *pi,
			      uint8_t *eth);

void frame_handler_write_fingerprints(void *userdata,
				      //struct tpacket_hdr *tphdr,
				      struct packet_info *pi,
				      uint8_t *eth);

void frame_handler_filter_write_fingerprints(void *userdata,
					     //struct tpacket_hdr *tphdr,
					     struct packet_info *pi,
					     char *eth);

void frame_handler_filter_write_pcap(void *userdata,
				     // struct tpacket_hdr *tphdr,
				     struct packet_info *pi,
				     uint8_t *eth);

#endif /* AF_PACKET_IO_H */
