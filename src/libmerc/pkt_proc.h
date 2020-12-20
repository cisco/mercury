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
#include "extractor.h"
#include "packet.h"

extern class libmerc_config global_vars;    // defined in libmerc.cc

extern bool select_tcp_syn;                 // defined in extractor.cc

/* Information about each packet on the wire */
struct packet_info {
  struct timespec ts;   /* timestamp */
  uint32_t caplen;     /* length of portion present */
  uint32_t len;        /* length this packet (off wire) */
};

struct pkt_proc_stats {
    size_t bytes_written;
    size_t packets_written;
};

struct stateful_pkt_proc {
    struct packet_filter pf;
    struct flow_table ip_flow_table;
    struct flow_table_tcp tcp_flow_table;
    struct tcp_reassembler reassembler;
    struct tcp_reassembler *reassembler_ptr;

    explicit stateful_pkt_proc() :
        pf{},
        ip_flow_table{65536},
        tcp_flow_table{65536},
        reassembler{65536},
        reassembler_ptr{&reassembler}
    {
        if (packet_filter_init(&pf) == status_err) {
            throw "could not initialize packet filter";
        }
#ifndef USE_TCP_REASSEMBLY
// #pragma message "omitting tcp reassembly; 'make clean' and recompile with OPTFLAGS=-DUSE_TCP_REASSEMBLY to use that option"
        reassembler_ptr = nullptr;
#else
// #pragma message "using tcp reassembly; 'make clean' and recompile to omit that option"
#endif

    }

    void finalize() {
        reassembler.count_all();
        tcp_flow_table.count_all();
    }

    size_t write_json(void *buffer,
                      size_t buffer_size,
                      uint8_t *packet,
                      size_t length,
                      struct timespec *ts) {
        return write_json(buffer, buffer_size, packet, length, ts, reassembler_ptr);
    }

    size_t write_json(void *buffer,
                              size_t buffer_size,
                              uint8_t *packet,
                              size_t length,
                              struct timespec *ts,
                              struct tcp_reassembler *reassembler);

    void tcp_data_write_json(struct buffer_stream &buf,
                             struct datum &pkt,
                             const struct key &k,
                             struct tcp_packet &tcp_pkt,
                             struct timespec *ts,
                             struct tcp_reassembler *reassembler);

};

#endif /* PKT_PROC_H */
