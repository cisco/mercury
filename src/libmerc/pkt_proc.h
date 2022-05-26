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
#include "tcp.h"
#include "packet.h"
#include "analysis.h"
#include "libmerc.h"
#include "stats.h"
#include "proto_identify.h"
#include "global_config.h"
#include "quic.h"
#include "perfect_hash.h"

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
    data_aggregator aggregator;
    classifier *c;
    class traffic_selector selector;

    mercury(const struct libmerc_config *vars, int verbosity) : global_vars{*vars}, aggregator{global_vars.max_stats_entries}, c{nullptr}, selector{global_vars.protocols} {
        if (global_vars.do_analysis) {
            c = analysis_init_from_archive(verbosity, global_vars.get_resource_file(),
                                           vars->enc_key, vars->key_type,
                                           global_vars.fp_proc_threshold,
                                           global_vars.proc_dst_threshold,
                                           global_vars.report_os);
            if (c == nullptr) {
                throw std::runtime_error("error: analysis_init_from_archive() failed"); // failure
            }
        }
    }

    ~mercury() {
        analysis_finalize(c);
    }
};

// protocol is an alias for a std::variant that can hold any protocol
// data element.  The default value of std::monostate indicates that
// the protocol matcher did not recognize the packet.
//
// The classes unknown_initial_packet and unknown_udp_initial_packet
// represents the TCP and UDP data fields, respectively, of an
// unrecognized packet that is the first data packet in a flow.
//
//protocol structs forward declarations
struct http_request;                      // start of tcp protocols
struct http_response;
struct tls_client_hello;
class tls_server_hello_and_certificate;
struct ssh_init_packet;
struct ssh_kex_init;
class smtp_client;
class smtp_server;
class unknown_initial_packet;
class quic_init;                         // start of udp protocols
struct wireguard_handshake_init;
struct dns_packet;
class dtls_client_hello;
class
dtls_server_hello;
struct dhcp_discover;
class unknown_udp_initial_packet;
class icmp_packet;                        // start of ip protocols
class ospf;
struct tcp_packet;

using protocol = std::variant<std::monostate,
                              http_request,                      // start of tcp protocols
                              http_response,
                              tls_client_hello,
                              tls_server_hello_and_certificate,
                              ssh_init_packet,
                              ssh_kex_init,
                              smtp_client,
                              smtp_server,
                              unknown_initial_packet,
                              quic_init,                         // start of udp protocols
                              wireguard_handshake_init,
                              dns_packet,
                              dtls_client_hello,
                              dtls_server_hello,
                              dhcp_discover,
                              unknown_udp_initial_packet,
                              icmp_packet,                        // start of ip protocols
                              ospf,
                              tcp_packet
                              >;

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
    perfect_hash_visitor& ph_visitor;

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
        global_vars{},
        selector{mc->selector},
        quic_crypto{},
        ph_visitor{perfect_hash_visitor::get_default_perfect_hash_visitor()}
    {

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
            ag = &m->aggregator;
            mq = ag->add_producer();
            if (mq == nullptr) {
                throw std::runtime_error("error: could not initialize event queue");
            }
        }

#ifndef USE_TCP_REASSEMBLY
// #pragma message "omitting tcp reassembly; 'make clean' and recompile with OPTFLAGS=-DUSE_TCP_REASSEMBLY to use that option"
        reassembler_ptr = nullptr;
#else
      // #pragma message "using tcp reassembly; 'make clean' and recompile to omit that option"
#endif

    }

    ~stateful_pkt_proc() {
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

    void set_tcp_protocol(protocol &x,
                          struct datum &pkt,
                          bool is_new,
                          struct tcp_packet *tcp_pkt);

    void set_udp_protocol(protocol &x,
                          struct datum &pkt,
                          enum udp_msg_type msg_type,
                          bool is_new);
};

#endif /* PKT_PROC_H */
