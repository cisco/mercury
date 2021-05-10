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
#include "analysis.h"
#include "libmerc.h"

extern struct mercury *global_context; // defined in libmerc.cc

extern bool select_tcp_syn;                 // defined in extractor.cc

/**
 * struct mercury holds state that is used by one or more
 * mercury_packet_processor
 *
 */
struct mercury {
    struct libmerc_config global_vars;
    data_aggregator aggregator;
    classifier *c;

    mercury(const struct libmerc_config *vars, int verbosity) : c{nullptr} {
        global_vars = *vars;
        global_vars.resources = vars->resources;
        global_vars.packet_filter_cfg = vars->packet_filter_cfg;
        enum status status = proto_ident_config(vars->packet_filter_cfg);
        if (status) {
            throw (const char *)"error: proto_ident_config() failed"; // failure
        }
        if (global_vars.do_analysis) {
            c = analysis_init_from_archive(verbosity, global_vars.resources,
                                           vars->enc_key, vars->key_type,
                                           global_vars.fp_proc_threshold,
                                           global_vars.proc_dst_threshold,
                                           global_vars.report_os);
            if (c == nullptr) {
                throw (const char *)"error: analysis_init_from_archive() failed"; // failure
            }
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
    struct message_queue *mq;
    mercury_context m;
    classifier *c;
    libmerc_config global_vars;

    explicit stateful_pkt_proc(size_t prealloc_size=0,
                               mercury_context mc=nullptr) :
        ip_flow_table{prealloc_size},
        tcp_flow_table{prealloc_size},
        reassembler{prealloc_size},
        reassembler_ptr{&reassembler},
        tcp_init_msg_filter{},
        analysis{},
        mq{nullptr},
        m{mc},
        c{nullptr},
        global_vars{}
    {

        if (m == nullptr) { // TODO: eliminate or document

            if (global_context == nullptr) {
                throw "error: global_context uninitialized in stateful_pkt_processor()";
            }
            // set config and classifier to (refer to) global context
            //
            //extern classifier *c;
            this->c = global_context->c;
            this->global_vars = global_context->global_vars;

        } else {

            // set config and classifier to (refer to) context m
            //
            this->c = m->c;
            this->global_vars = m->global_vars;

            //fprintf(stderr, "note: setting classifier to %p, setting global_vars to %p\n", (void *)m->c, (void *)&m->global_vars));
        }

        extern data_aggregator aggregator;  // pkt_proc.cc

        //        mq = aggregator.add_producer();  // TODO: restore aggregator

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

    LIBMERC_DLL_EXPORTED
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

    void tcp_data_write_json_OBSOLETE(struct buffer_stream &buf,
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

    bool ip_set_analysis_result(struct analysis_result *r,
                                const uint8_t *ip_packet,
                                size_t length,
                                struct timespec *ts,
                                struct tcp_reassembler *reassembler);

    bool tcp_data_set_analysis_result(struct analysis_result *r,
                                      struct datum &pkt,
                                      const struct key &k,
                                      struct tcp_packet &tcp_pkt,
                                      struct timespec *ts,
                                      struct tcp_reassembler *reassembler);
};

#endif /* PKT_PROC_H */
