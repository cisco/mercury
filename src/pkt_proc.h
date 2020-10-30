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
#include "extractor.h"
#include "packet.h"
#include "rnd_pkt_drop.h"

/* Information about each packet on the wire */
struct packet_info {
  struct timespec ts;   /* timestamp */
  uint32_t caplen;     /* length of portion present */
  uint32_t len;        /* length this packet (off wire) */
};

extern unsigned int packet_filter_threshold;

struct pkt_proc_stats {
    size_t bytes_written;
    size_t packets_written;
};

/*
 * struct pkt_proc is a packet processor; this abstract class defines
 * the interface to packet processing that can be used by packet
 * capture or packet file readers.
 */

struct pkt_proc {
    virtual void apply(struct packet_info *pi, uint8_t *eth) = 0;
    virtual void flush() = 0;
    virtual void finalize() = 0;
    virtual ~pkt_proc() {};
    size_t bytes_written = 0;
    size_t packets_written = 0;
};

/*
 * struct pkt_proc_json_writer_llq represents a packet processing object
 * that writes out a JSON representation of fingerprints, metadata,
 * flow keys, and event time to a queue that is then written to a file
 * by a dedicated output thread.
 */
struct pkt_proc_json_writer_llq : public pkt_proc {
    struct ll_queue *llq;
    bool block;
    struct packet_filter pf;
    struct tcp_reassembler reassembler;

    /*
     * pkt_proc_json_writer(outfile_name, mode, max_records)
     * initializes object to write a single JSON line containing the
     * flow key, time, fingerprints, and metadata to the output file
     * with the path outfile_name and mode passed as arguments; that
     * file is opened by this invocation, with that mode.  If
     * max_records is nonzero, then it defines the maximum number of
     * records (lines) per file; after that limit is reached, file
     * rotation will take place.
     */
    explicit pkt_proc_json_writer_llq(struct ll_queue *llq_ptr, const char *filter, bool blocking) : block{blocking}, reassembler{65536} {
        llq = llq_ptr;
        if (packet_filter_init(&pf, filter) == status_err) {
            throw "could not initialize packet filter";
        }
    }

    void apply(struct packet_info *pi, uint8_t *eth) override {
#ifdef OMIT_TCP_REASSEMBLY

#warning "omitting tcp reassembly; 'make clean' and recompile to use that option"

        json_queue_write(llq, eth, pi->len, pi->ts.tv_sec, pi->ts.tv_nsec, nullptr, block);
#else

#warning "using tcp reassembly; 'make clean' and recompile with OPTFLAGS=-DOMIT_TCP_REASSEMBLY to omit that option"

        json_queue_write(llq, eth, pi->len, pi->ts.tv_sec, pi->ts.tv_nsec, &reassembler, block);
#endif
    }

    void finalize() override {
        reassembler.count_all();
    }

    void flush() override {

    }
};

/*
 * struct pkt_proc_pcap_writer represents a packet processing object
 * that writes out packets in PCAP file format.
 */
struct pkt_proc_pcap_writer_llq : public pkt_proc {
    struct ll_queue *llq;
    bool block;

    explicit pkt_proc_pcap_writer_llq(struct ll_queue *llq_ptr, bool blocking) : block{blocking} {
        llq = llq_ptr;
    }

    void apply(struct packet_info *pi, uint8_t *eth) override {
        extern int rnd_pkt_drop_percent_accept;  /* defined in rnd_pkt_drop.c */

        if (rnd_pkt_drop_percent_accept && drop_this_packet()) {
            return;  /* random packet drop configured, and this packet got selected to be discarded */
        }
        pcap_queue_write(llq, eth, pi->len, pi->ts.tv_sec, pi->ts.tv_nsec / 1000, block);
    }

    void finalize() override { }

    void flush() override {
    }

};


/*
 * struct pkt_proc_pcap_writer represents a packet processing object
 * that writes out packets in PCAP file format.
 */
struct pkt_proc_pcap_writer : public pkt_proc {
    struct pcap_file pcap_file;

    /*
     * pkt_proc_pcap_writer(outfile_name, mode) initializes an object
     * to write packets into the pcap file with the path outfile_name
     * and flags passed as arguments; that file is opened by this
     * invocation, with those flags.
     */
    pkt_proc_pcap_writer(const char *outfile, int flags) {
        enum status status = pcap_file_open(&pcap_file, outfile, io_direction_writer, flags);
        if (status) {
            throw "could not open PCAP output file";
        }
    }

    void apply(struct packet_info *pi, uint8_t *eth) override {
        extern int rnd_pkt_drop_percent_accept;  /* defined in rnd_pkt_drop.c */

        if (rnd_pkt_drop_percent_accept && drop_this_packet()) {
            return;  /* random packet drop configured, and this packet got selected to be discarded */
        }
        pcap_file_write_packet_direct(&pcap_file, eth, pi->len, pi->ts.tv_sec, pi->ts.tv_nsec / 1000);
    }

    void finalize() override { }

    void flush() override {
        FILE *file_ptr = pcap_file.file_ptr;
        if (file_ptr != NULL) {
            if (fflush(file_ptr) != 0) {
                perror("warning: could not flush pcap file\n");
            }
        }
    }

};

/*
 * struct pkt_proc_filter_pcap_writer represents a packet processing
 * object that first filters packets, then writes tem out in PCAP file
 * format.
 */
struct pkt_proc_filter_pcap_writer : public pkt_proc {
    struct pcap_file pcap_file;

    /*
     * packet_filter_threshold is a (somewhat arbitrary) threshold used in
     * the packet metadata filter; it will probably get eliminated soon,
     * in favor of extractor::proto_state::state, but for now it remains
     */
    unsigned int packet_filter_threshold = 8;

    pkt_proc_filter_pcap_writer(const char *outfile, int flags) {
        enum status status = pcap_file_open(&pcap_file, outfile, io_direction_writer, flags);
        if (status) {
            throw "could not open PCAP output file";
        }
    }

    void apply(struct packet_info *pi, uint8_t *eth) override {
        uint8_t *packet = eth;
        unsigned int length = pi->len;

        extern int rnd_pkt_drop_percent_accept;  /* defined in rnd_pkt_drop.c */

        if (rnd_pkt_drop_percent_accept && drop_this_packet()) {
            return;  /* random packet drop configured, and this packet got selected to be discarded */
        }

        struct packet_filter pf;
        if (packet_filter_apply(&pf, packet, length)) {
            pcap_file_write_packet_direct(&pcap_file, eth, pi->len, pi->ts.tv_sec, pi->ts.tv_nsec / 1000);
        }
    }

    void finalize() override { }

    void flush() override {
        FILE *file_ptr = pcap_file.file_ptr;
        if (file_ptr != NULL) {
            if (fflush(file_ptr) != 0) {
                perror("warning: could not flush pcap file\n");
            }
        }
    }

};

/*
 * struct pkt_proc_filter_pcap_writer represents a packet processing
 * object that first filters packets, then writes tem out in PCAP file
 * format.
 */
struct pkt_proc_filter_pcap_writer_llq : public pkt_proc {
    struct ll_queue *llq;
    struct packet_filter pf;
    bool block;
    
    /*
     * packet_filter_threshold is a (somewhat arbitrary) threshold used in
     * the packet metadata filter; it will probably get eliminated soon,
     * in favor of extractor::proto_state::state, but for now it remains
     */
    unsigned int packet_filter_threshold = 8;

    explicit pkt_proc_filter_pcap_writer_llq(struct ll_queue *llq_ptr, const char *filter, bool blocking) : block{blocking} {
        llq = llq_ptr;
        if (packet_filter_init(&pf, filter) == status_err) {
            throw "could not initialize packet filter";
        }
    }

    void apply(struct packet_info *pi, uint8_t *eth) override {
        uint8_t *packet = eth;
        unsigned int length = pi->len;

        extern int rnd_pkt_drop_percent_accept;  /* defined in rnd_pkt_drop.c */

        if (rnd_pkt_drop_percent_accept && drop_this_packet()) {
            return;  /* random packet drop configured, and this packet got selected to be discarded */
        }

        if (packet_filter_apply(&pf, packet, length)) {
            pcap_queue_write(llq, eth, pi->len, pi->ts.tv_sec, pi->ts.tv_nsec / 1000, block);
        }
    }

    void finalize() override { }

    void flush() override {
    }

};

/*
 * pkt_proc_dumper writes a JSON object summarizing each packet to
 * stdout
 */
struct pkt_proc_dumper : public pkt_proc {

    pkt_proc_dumper() {}

    void apply(struct packet_info *pi, uint8_t *eth) override {
        packet_fprintf(stdout, eth, pi->len, pi->ts.tv_sec, pi->ts.tv_nsec / 1000);
    }

    void finalize() override { }

    void flush() override {
    }
};

/*
 * the function pkt_proc_new_from_config() takes as input a
 * configuration structure, a thread number, and a pointer to a
 * fileset identifier, and returns a pointer to a new packet processor
 * object.  This is a factory function that chooses what type of class
 * to return based on the details of the configuration.
 */
struct pkt_proc *pkt_proc_new_from_config(struct mercury_config *cfg,
                                          int tnum,
                                          struct ll_queue *llq);

#endif /* PKT_PROC_H */
