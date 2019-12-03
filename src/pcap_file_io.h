/*
 * pcap_file_io.h
 * 
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at 
 * https://github.com/cisco/mercury/blob/master/LICENSE 
 */

#ifndef PCAP_FILE_IO_H
#define PCAP_FILE_IO_H

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include "mercury.h"

/*
 * define a pcap_pkthdr, guarding against name collision with libpcap
 */
#ifndef lib_pcap_pcap_h

struct pcap_pkthdr {
    struct timeval ts;   /* timestamp                     */
    uint32_t caplen;     /* length of portion present     */
    uint32_t len;        /* length this packet (off wire) */
};

typedef void (*packet_handler_t)(uint8_t *user,
				 const struct pcap_pkthdr *h,
				 const uint8_t *bytes);

#endif /* lib_pcap_pcap_h */

enum io_direction {
    io_direction_none   = 0,
    io_direction_reader = 1,
    io_direction_writer = 2
};

struct pcap_file {
    FILE *file_ptr;
    int fd;                /* file descriptor that is returned by fileno() */
    int flags;
    unsigned int byteswap; /* boolean, indicates if swap needed after read */
    size_t buf_len;        /* number of bytes in buffer                    */
    unsigned char *buffer; /* buffer used for disk i/o                     */
    off_t  allocated_size; /* file size allocated using posix_fallocate    */
    uint64_t bytes_written; /* number of bytes written to this file       */
    uint64_t packets_written; /* number of packets written to this file   */
};

#define pcap_file_init() { NULL, 0, 0, 0, NULL, NULL, NULL }

enum status pcap_file_open(struct pcap_file *f,
			   const char *fname,
			   enum io_direction dir,
			   int flags);


enum status pcap_file_read_packet(struct pcap_file *f,
				  struct pcap_pkthdr *pkthdr, /* output */
				  void *packet_data           /* output */
				  );

enum status pcap_file_write_packet(struct pcap_file *f,
				   const void *packet,
				   size_t length);

enum status pcap_file_write_packet_direct(struct pcap_file *f,
					  const void *packet,
					  size_t length,
					  unsigned int sec,
					  unsigned int usec);

enum status pcap_file_close(struct pcap_file *f);

enum status pcap_file_dispatch_pkt_processor(struct pcap_file *f,
                                             struct pkt_proc *pkt_processor,
                                             int loop_count);
#endif /* PCAP_FILE_IO_H */
