// \file pkt_proc.hpp
//
// packet processing base class and helpers


#ifndef PKT_PROC_HPP
#define PKT_PROC_HPP

#include "linktype.hpp"

// struct packet_info contains timestamp and length information about
// a packet
//
struct packet_info {
    struct timespec ts;   // timestamp
    uint32_t caplen;      // length of portion present
    uint32_t len;         // length this packet (off wire)
    uint16_t linktype = LINKTYPE::ETHERNET;    // linktype of packet from pcap
};


// struct pkt_proc is a packet processor; this abstract class defines
// the interface to packet processing that can be used by packet
// capture or packet file readers.
//
struct pkt_proc {
    virtual void apply(struct packet_info *pi, uint8_t *eth) = 0;
    virtual void flush() = 0;
    virtual void finalize() = 0;
    virtual ~pkt_proc() {};
    size_t bytes_written = 0;
    size_t packets_written = 0;
};

// the function pkt_proc_new_from_config() takes as input a
// configuration structure, a thread number, and a pointer to a
// fileset identifier, and returns a pointer to a new packet processor
// object.  This is a factory function that chooses what type of class
// to return based on the details of the configuration.
//
struct pkt_proc *pkt_proc_new_from_config(struct mercury_config *cfg,
                                          mercury_context mc,
                                          int tnum,
                                          struct ll_queue *llq);

#endif // PKT_PROC_HPP
