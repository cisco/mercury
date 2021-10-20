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
#include <stdexcept>
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

enum status pcap_file_open(struct pcap_file *f,
                           const char *fname,
                           enum io_direction dir,
                           int flags);

enum status pcap_file_read_packet(struct pcap_file *f,
				  struct pcap_pkthdr *pkthdr, /* output */
				  void *packet_data           /* output */
				  );

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
    uint16_t linktype;        /* data link type                           */

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

    enum linktype : uint16_t {
        LINKTYPE_NULL =       0,  // BSD loopback encapsulation
        LINKTYPE_ETHERNET =   1,  // Ethernet
        LINKTYPE_RAW      = 101   // Raw IP; begins with IPv4 or IPv6 header
    };

    const char *get_linktype() const {
        switch(linktype) {
        case LINKTYPE_NULL:     return "NULL";
        case LINKTYPE_ETHERNET: return "ETHERNET";
        case LINKTYPE_RAW:      return "RAW";
        }
        return "unknown";
    }

    pcap_file() { } // TODO: eliminate vacuous constructor
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
                                             int loop_count);


// pcap_queue_write() sends a packet to a lockless queue
//
void pcap_queue_write(struct ll_queue *llq,
                      uint8_t *packet,
                      size_t length,
                      unsigned int sec,
                      unsigned int nsec,
                      bool blocking);

enum status write_pcap_file_header(FILE *f);


// class packet holds a network data packet (in buffer[]) and an
// associated pcap_pkthdr structure, and can load packets from a pcap
// file successively (using get_next())
//
template <size_t N>
class packet {
    uint8_t buffer[N];
    struct pcap_pkthdr pkthdr;
public:

    // packet() initializes an empty (zero-length) packet
    //
    packet() : pkthdr{{0,0},0,0} {}

    // get_next(file) sets this packet to the next one read from the
    // packet capture file provided as an argument, and returns a pair
    // of pointers to the first and last bytes of the packet data
    // (including link layer headers, if present)
    //
    //    struct datum get_next(struct pcap_file &pcap) {
    std::pair<const uint8_t *, const uint8_t *> get_next(struct pcap_file &pcap) {
        enum status s = pcap.read_packet(&pkthdr, buffer);
        if (s != status_ok) {
            return {nullptr, nullptr};
        }
        return {buffer, buffer + pkthdr.caplen};
    }

    // ts() returns the struct timeval associated with this packet
    //
    struct timeval ts() const { return pkthdr.ts; }

    // caplen() returns the capture length associated with this packet
    // (that is, the number of bytes of the packet that are actually
    // available)
    //
    uint32_t caplen() const { return pkthdr.caplen; }

    // len() returns the length of this packet (that is, the length
    // that the packet claims to have)
    //
    uint32_t len() const { return pkthdr.len; }

};


#endif /* PCAP_FILE_IO_H */
