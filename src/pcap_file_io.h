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
#include <sys/time.h>
#include <stdio.h>
#include <fcntl.h>
#include <utility>
#include <stdexcept>
#include "mercury.h"
#include "packet.h"

enum io_direction {
    io_direction_none   = 0,
    io_direction_reader = 1,
    io_direction_writer = 2
};

enum status pcap_file_open(struct pcap_file *f,
                           const char *fname,
                           enum io_direction dir,
                           int flags);

enum status pcap_file_read_packet(struct pcap_file *f,
				  struct pcap_pkthdr *pkthdr, /* output */
				  void *packet_data           /* output */
				  );

struct pcap_file {
    FILE *file_ptr = nullptr;
    int fd = 0;                      // file descriptor returned by fileno()
    int flags = 0;                   // flags passed to open()
    unsigned int byteswap = false;   // true if swap needed after read
    size_t buf_len = 0;              // number of bytes in buffer
    unsigned char *buffer = nullptr; // buffer used for disk i/o
    off_t  allocated_size = 0;       // file size allocated using posix_fallocate
    uint64_t bytes_written = 0;      // number of bytes written to this file
    uint64_t packets_written = 0;    // number of packets written to this file
    uint16_t linktype = LINKTYPE::NONE; // data link type

    pcap_file() { }

    pcap_file(const char *fname, enum io_direction dir, int flags=0) {
        if (pcap_file_open(this, fname, dir, flags) != status_ok) {
            throw std::runtime_error("could not open pcap file");
        }
    }

    enum status read_packet(struct pcap_pkthdr *pkthdr, /* output */
                            void *packet_data           /* output */
                            ) {
        return pcap_file_read_packet(this, pkthdr, packet_data);
    }

    enum LINKTYPE : uint16_t {
        NULL_    =   0,  // BSD loopback encapsulation
        ETHERNET =   1,  // Ethernet
        PPP      =   9,  // Point-to-Point Protocol (PPP)
        RAW      = 101,  // Raw IP; begins with IPv4 or IPv6 header
        NONE     = 65535 // reserved, used here as 'none'
    };

    const char *get_linktype() const {
        switch(linktype) {
        case LINKTYPE::NULL_:    return "NULL";
        case LINKTYPE::ETHERNET: return "ETHERNET";
        case LINKTYPE::PPP:      return "PPP";
        case LINKTYPE::RAW:      return "RAW";
        case LINKTYPE::NONE:     return "NONE";
        }
        return "unknown";
    }

};

#define pcap_file_init() { NULL, 0, 0, 0, NULL, NULL, NULL }


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
                                             int loop_count,
                                             int &sig_close_flag);


// pcap_queue_write() sends a packet to a lockless queue
//
void pcap_queue_write(struct ll_queue *llq,
                      uint8_t *packet,
                      size_t length,
                      unsigned int sec,
                      unsigned int nsec,
                      bool blocking);

enum status write_pcap_file_header(FILE *f);


#endif /* PCAP_FILE_IO_H */
