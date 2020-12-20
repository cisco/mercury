/*
 * pkt_processing.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef PKT_PROCESSING_H
#define PKT_PROCESSING_H

#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include "pcap_file_io.h"
#include "rnd_pkt_drop.h"
#include "llq.h"
#include "libmerc/pkt_proc.h"

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
 * object that first filters packets, then writes them out in PCAP file
 * format.
 */
struct pkt_proc_filter_pcap_writer : public pkt_proc {
    struct pcap_file pcap_file;
    struct stateful_pkt_proc processor;

    pkt_proc_filter_pcap_writer(const char *outfile, int flags) : processor{} {
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

        uint8_t buf[LLQ_MSG_SIZE];
        if (processor.write_json(buf, LLQ_MSG_SIZE, packet, length, &pi->ts) != 0) {
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
 * struct pkt_proc_json_writer_llq represents a packet processing object
 * that writes out a JSON representation of fingerprints, metadata,
 * flow keys, and event time to a queue that is then written to a file
 * by a dedicated output thread.
 */
struct pkt_proc_json_writer_llq : public pkt_proc {
    struct ll_queue *llq;
    bool block;
    struct stateful_pkt_proc processor;

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
    explicit pkt_proc_json_writer_llq(struct ll_queue *llq_ptr, bool blocking) :
        block{blocking},
        processor{}
    {
        llq = llq_ptr;
    }

    void apply(struct packet_info *pi, uint8_t *eth) override {
        struct llq_msg *msg = llq->init_msg(block, pi->ts.tv_sec, pi->ts.tv_nsec);
        if (msg) {
            size_t write_len = processor.write_json(msg->buf, LLQ_MSG_SIZE, eth, pi->len, &(msg->ts));
            if (write_len > 0) {
                msg->send(write_len);
                llq->increment_widx();
            }
        }
    }

    void finalize() override {
        processor.finalize();
    }

    void flush() override {

    }

};


/*
 * struct pkt_proc_filter_pcap_writer represents a packet processing
 * object that first filters packets, then writes them out in PCAP file
 * format.
 */
struct pkt_proc_filter_pcap_writer_llq : public pkt_proc {
    struct ll_queue *llq;
    bool block;
    struct stateful_pkt_proc processor;

    explicit pkt_proc_filter_pcap_writer_llq(struct ll_queue *llq_ptr, bool blocking) : block{blocking}, processor{} {
        llq = llq_ptr;
    }

    void apply(struct packet_info *pi, uint8_t *eth) override {
        uint8_t *packet = eth;
        unsigned int length = pi->len;

        extern int rnd_pkt_drop_percent_accept;  /* defined in rnd_pkt_drop.c */

        if (rnd_pkt_drop_percent_accept && drop_this_packet()) {
            return;  /* random packet drop configured, and this packet got selected to be discarded */
        }

        uint8_t buf[LLQ_MSG_SIZE];
        if (processor.write_json(buf, LLQ_MSG_SIZE, packet, length, &pi->ts) != 0) {
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

#endif /* PKT_PROCESSING_H */
