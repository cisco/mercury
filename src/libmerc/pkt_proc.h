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
#include <stdexcept>
#include <memory>
#include "tcp.h"
#include "flow_key.h"
#include "analysis.h"
#include "libmerc.h"
#include "stats.h"
#include "proto_identify.h"
#include "global_config.h"
#include "quic.h"
#include "perfect_hash.h"
#include "crypto_assess.h"
#include "pkt_proc_util.h"

/**
 * enum linktype is a 16-bit enumeration that identifies a protocol
 * type; it is defined by the PCAP internet draft
 * [draft-gharris-opsawg-pcap-02], and is used here to indicate how a
 * particular packet/frame should be parsed.  This enumeration defines
 * all of the linktypes supported by the stateful_pkt_proc class.
 */
enum linktype : uint16_t {
    LINKTYPE_NULL =       0,  // BSD loopback encapsulation
    LINKTYPE_ETHERNET =   1,  // Ethernet
    LINKTYPE_PPP      =   9,  // PPP
    LINKTYPE_RAW      = 101   // Raw IP; begins with IPv4 or IPv6 header
};


/**
 * struct mercury holds state that is used by one or more
 * mercury_packet_processor
 *
 */
struct mercury {
    struct global_config global_vars;
    std::unique_ptr<data_aggregator> aggregator{nullptr};
    classifier *c;
    class traffic_selector selector;

    mercury(const struct libmerc_config *vars, int verbosity) : global_vars{*vars}, aggregator{ global_vars.do_stats? (std::make_unique<data_aggregator>(global_vars.max_stats_entries)) : nullptr}, c{nullptr}, selector{global_vars.protocols} {
        if (global_vars.do_analysis) {
            c = analysis_init_from_archive(verbosity, global_vars.get_resource_file(),
                                           vars->enc_key, vars->key_type,
                                           global_vars.fp_proc_threshold,
                                           global_vars.proc_dst_threshold,
                                           global_vars.report_os);
            if (c == nullptr) {
                throw std::runtime_error("error: analysis_init_from_archive() failed"); // failure
            }

            // set fingerprint formats to match those in the resource file
            //
            size_t resources_tls_format = c->get_tls_fingerprint_format();
            global_vars.set_tls_fingerprint_format(resources_tls_format);
            printf_err(log_info, "setting tls fingerprint format to match resource file (format: %zu)\n", resources_tls_format);
        }
    }

    ~mercury() {
        analysis_finalize(c);
    }
};

struct stateful_pkt_proc {
    struct flow_table ip_flow_table;
    struct flow_table_tcp tcp_flow_table;
    struct tcp_reassembler reassembler;
    struct tcp_reassembler *reassembler_ptr;
    struct tcp_initial_message_filter tcp_init_msg_filter;
    struct analysis_context analysis;
    class message_queue *mq;
    mercury_context m;
    classifier *c;        // TODO: change to reference
    data_aggregator *ag;
    global_config global_vars;
    class traffic_selector &selector;
    quic_crypto_engine quic_crypto;
    crypto_policy::assessor *crypto_policy = nullptr;

    explicit stateful_pkt_proc(mercury_context mc, size_t prealloc_size=0) :
        ip_flow_table{prealloc_size},
        tcp_flow_table{prealloc_size},
        reassembler{prealloc_size},
        reassembler_ptr{&reassembler},
        tcp_init_msg_filter{},
        analysis{},
        mq{nullptr},
        m{mc},
        c{nullptr},
        ag{nullptr},
        global_vars{mc->global_vars},
        selector{mc->selector},
        quic_crypto{}
    {

        constexpr bool DO_CRYPTO_ASSESSMENT = false;
        if (DO_CRYPTO_ASSESSMENT) {
            // set crypto assessment policy
            crypto_policy = new crypto_policy::quantum_safe;
        }

        // set config and classifier to (refer to) context m
        //
        if (m->c == nullptr && m->global_vars.do_analysis) {
            throw std::runtime_error("error: classifier pointer is null");
        }
        this->c = m->c;
        this->global_vars = m->global_vars;

        //fprintf(stderr, "note: setting classifier to %p, setting global_vars to %p\n", (void *)m->c, (void *)&m->global_vars));
        // }

        if (global_vars.do_stats) {
            ag = m->aggregator.get();
            mq = ag->add_producer();
            if (mq == nullptr) {
                throw std::runtime_error("error: could not initialize event queue");
            }
        }

        if (!global_vars.tcp_reassembly) {
            reassembler_ptr = nullptr;
        }

//#ifndef USE_TCP_REASSEMBLY
// #pragma message "omitting tcp reassembly; 'make clean' and recompile with OPTFLAGS=-DUSE_TCP_REASSEMBLY to use that option"
//        reassembler_ptr = nullptr;
//#else
      // #pragma message "using tcp reassembly; 'make clean' and recompile to omit that option"
//#endif

    }

    ~stateful_pkt_proc() {
        delete crypto_policy;
        // we could call ag->remote_procuder(mq), but for now we do not
    }

    // TODO: the count_all() functions should probably be removed
    //
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

    //    LIBMERC_DLL_EXPORTED  // TODO: check that we need this
    size_t write_json(void *buffer,
                      size_t buffer_size,
                      uint8_t *packet,
                      size_t length,
                      struct timespec *ts,
                      struct tcp_reassembler *reassembler);

    size_t write_json(void *buffer,
                      size_t buffer_size,
                      uint8_t *packet,
                      size_t length,
                      struct timespec *ts,
                      struct tcp_reassembler *reassembler,
                      uint16_t linktype);

    void tcp_data_write_json(struct buffer_stream &buf,
                             struct datum &pkt,
                             const struct key &k,
                             struct tcp_packet &tcp_pkt,
                             struct timespec *ts,
                             struct tcp_reassembler *reassembler);

    size_t ip_write_json(void *buffer,
                         size_t buffer_size,
                         const uint8_t *ip_packet,
                         size_t length,
                         struct timespec *ts,
                         struct tcp_reassembler *reassembler);

    bool analyze_packet(const uint8_t *eth_packet,
                            size_t length,
                            struct timespec *ts,
                            struct tcp_reassembler *reassembler,
                            uint16_t linktype);

    bool analyze_eth_packet(const uint8_t *eth_packet,
                            size_t length,
                            struct timespec *ts,
                            struct tcp_reassembler *reassembler);

    bool analyze_ppp_packet(const uint8_t *ppp_packet,
                            size_t length,
                            struct timespec *ts,
                            struct tcp_reassembler *reassembler);

    bool analyze_raw_packet(const uint8_t *ppp_packet,
                            size_t length,
                            struct timespec *ts,
                            struct tcp_reassembler *reassembler);

    bool analyze_ip_packet(const uint8_t *ip_packet,
                           size_t length,
                           struct timespec *ts,
                           struct tcp_reassembler *reassembler);

    bool tcp_data_set_analysis_result(struct analysis_result *r,
                                      struct datum &pkt,
                                      const struct key &k,
                                      struct tcp_packet &tcp_pkt,
                                      struct timespec *ts,
                                      struct tcp_reassembler *reassembler);

    bool process_tcp_data (protocol &x,
                          struct datum &pkt,
                          struct tcp_packet &tcp_pkt,
                          struct key &k,
                          struct timespec *ts, 
                          struct tcp_reassembler *reassembler);
    
    void set_tcp_protocol(protocol &x,
                          struct datum &pkt,
                          bool is_new,
                          struct tcp_packet *tcp_pkt);

    void set_udp_protocol(protocol &x,
                          struct datum &pkt,
                          enum udp_msg_type msg_type,
                          bool is_new,
                          const struct key& k);

    bool dump_pkt ();
};

#endif /* PKT_PROC_H */
