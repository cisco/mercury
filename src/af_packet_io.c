/*
 * af_packet.c
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/mman.h>

#include "mercury.h"
#include "extractor.h"
#include "pkt_proc.h"
#include "pcap_file_io.h"
#include "af_packet_io.h"
#include "af_packet_v3.h"
#include "utils.h"



#define MAX_READABLE_SUFFIX 9
char *readable_number_suffix[MAX_READABLE_SUFFIX] = {
    (char *)"B",
    (char *)"K",
    (char *)"M",
    (char *)"G",
    (char *)"T",
    (char *)"P",
    (char *)"E",
    (char *)"Z",
    (char *)"Y"
};

void get_readable_number(unsigned int input,
                         unsigned int *num_output,
                         char **str_output) {
    unsigned int index = 0;

    while (input > 1024 && index < MAX_READABLE_SUFFIX) {
        index++;
        input = input / 1024;
    }
    *num_output = input;
    *str_output = readable_number_suffix[index];

}

enum status capture_init(struct thread_context *ts, int fanout_group, int buffer_fraction) {
    size_t snaplen = 2048;

    /* open socket file descriptor for packet capture */
    ts->sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ts->sockfd == -1) {
        perror("error opening socket");
        return status_err;
    }

    /*
     * set frame size to hold aligned packet (snaplen bytes long) plus headers
     */
    ts->tp_req.tp_frame_size = TPACKET_ALIGN(TPACKET_HDRLEN + ETH_HLEN) + TPACKET_ALIGN(snaplen);
    /*
     * set block size to the smallest N such that 2^N*(system page size) > frame size
     */
    ts->tp_req.tp_block_size = sysconf(_SC_PAGESIZE);
    while (ts->tp_req.tp_block_size < ts->tp_req.tp_frame_size) {
        ts->tp_req.tp_block_size = ts->tp_req.tp_block_size << 1;
        if (ts->tp_req.tp_block_size > 0x80000000) {
            return status_err; /* error: could not find suitable block size */
        }
    }

    /*
     * request an RX_RING with (buffer_fraction * phs mem) bytes
     */
    ts->tp_req.tp_block_nr = sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE) / (buffer_fraction * ts->tp_req.tp_block_size);
    ts->frames_per_buffer = ts->tp_req.tp_block_size / ts->tp_req.tp_frame_size;
    ts->tp_req.tp_frame_nr = ts->tp_req.tp_block_nr * ts->frames_per_buffer;

    debug_print_uint(ts->tp_req.tp_block_size);
    debug_print_uint(ts->tp_req.tp_block_nr);
    debug_print_uint(ts->tp_req.tp_frame_size);
    debug_print_uint(ts->tp_req.tp_frame_nr);

    unsigned int readable_num;
    char *readable_str;
    get_readable_number(ts->tp_req.tp_block_nr * ts->tp_req.tp_block_size,
                        &readable_num,
                        &readable_str);
    printf("setting up RX_RING with %u%s bytes\n", readable_num, readable_str);

    /* create ring buffer */
    if (setsockopt(ts->sockfd, SOL_PACKET, PACKET_RX_RING, &ts->tp_req, sizeof(struct tpacket_req))==-1) {
        perror("setsockopt(SOL_PACKET, PACKET_RX_RING)");
        exit(1);
    }

    /*
     * set up mmap'ed buffer
     */
    ts->rx_ring_size = ts->tp_req.tp_block_nr * ts->tp_req.tp_block_size;
    ts->mapped_buffer = (uint8_t *)mmap(0, ts->rx_ring_size, PROT_READ|PROT_WRITE, MAP_SHARED, ts->sockfd, 0);
    debug_print_uint(ts->rx_ring_size);

#ifdef USE_FANOUT

    /*
     * set up fanout
     */
    /*
     * set up fanout (each thread gets some portion of packets)
     */
    if (fanout_group) {
        /*
         * PACKET_FANOUT_HASH sends packets from the same flow to the same socket
         * PACKET_FANOUT_LB implements a round-robin algorithm
         * PACKET_FANOUT_CPU selects the socket based on the CPU that the packet arrived on
         * PACKET_FANOUT_ROLLOVER processes all data on a single socket, moving to the next when one becomes backlogged
         * PACKET_FANOUT_RND selects the socket using a pseudo-random number generator
         * PACKET_FANOUT_QM selects the socket using the recorded queue_mapping of the received skb
         */
        int fanout_type = PACKET_FANOUT_HASH;

        int fanout_arg = (fanout_group | (fanout_type << 16));

        int err = setsockopt(ts->sockfd, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg));
        if (err) {
            perror("error: could not configure fanout\n");
            return status_err;
        }
    }
#endif /* USE_FANOUT */

    return status_ok;
}

enum status capture_loop(struct thread_context *ts) {
    struct pollfd fds[1] = {{0, 0, 0}};
    fds[0].fd = ts->sockfd;
    fds[0].events = POLLIN;
    size_t frame_idx = 0;
    uint8_t *frame_ptr = ts->mapped_buffer;
    frame_handler_func frame_handler = ts->handler.func;
    union frame_handler_context *frame_handler_context = (union frame_handler_context *)&ts->handler.context;

    while (1) {
        struct tpacket_hdr* tphdr = (struct tpacket_hdr*)frame_ptr;
        while (!(tphdr->tp_status & TP_STATUS_USER)) {
            if (poll(fds, 1, -1) == -1) {
                perror("error in poll");
                return status_err;
            }
        }

        struct packet_info pi;
        pi.ts.tv_sec = tphdr->tp_sec;
        pi.ts.tv_nsec = tphdr->tp_usec * 1000;
        pi.len = tphdr->tp_len;
        pi.caplen = tphdr->tp_snaplen;

        frame_handler(frame_handler_context, &pi, frame_ptr + tphdr->tp_mac);
        tphdr->tp_status = TP_STATUS_KERNEL;

        frame_idx = (frame_idx + 1) % ts->tp_req.tp_frame_nr;
        int buffer_idx = frame_idx / ts->frames_per_buffer;
        uint8_t *buffer_ptr = ts->mapped_buffer + buffer_idx * ts->tp_req.tp_block_size;
        int frame_idx_diff = frame_idx % ts->frames_per_buffer;
        frame_ptr = buffer_ptr + frame_idx_diff * ts->tp_req.tp_frame_size;
    }

}
