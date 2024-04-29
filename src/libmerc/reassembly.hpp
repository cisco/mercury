/*
 * tcp.h
 *
 * Copyright (c) 2024 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef REASSEMBLY_HPP
#define REASSEMBLY_HPP

#include <unordered_map>
#include "datum.h"
#include "json_object.h"

// tcp_segment_init contains initial info about the tcp session that
// requires reassembly - initial data seq no., additional bytes 
// needed and current data pkt len
//
struct tcp_segment_init {
    uint32_t data_length;
    uint32_t seq;
    uint32_t additional_bytes_needed;

    tcp_segment_init(uint32_t len, uint32_t seq_no, uint32_t additional_bytes) : data_length{len}, seq{seq_no}, additional_bytes_needed{additional_bytes} {}
};

// tcp_reassembly_flow_context contains all the state associated with a particular
// tcp flow under reassembly, including reassembly buffer, flags etc.
//
struct tcp_reassembly_flow_context {

};

// tcp_reassembler holds all tcp flows under reassembly
//
struct tcp_reassembler {

};







#endif /* MERC_TCP_H */