/*
 * tcp.h
 *
 * Copyright (c) 2024 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef REASSEMBLY_HPP
#define REASSEMBLY_HPP

#include "datum.h"
#include "json_object.h"
#include "util_obj.h"

#include <bitset>
#include <vector>
#include <unordered_map>

// tcp_segment contains initial info about the tcp segment 
// associated with reassembly - seq no, data len, timestamp
// if init_seg == true, also holds additional_byte_needed for reassembly
//
struct tcp_segment {
    bool init_seg;
    uint32_t data_length;
    uint32_t seq;
    uint32_t additional_bytes_needed;
    unsigned int seg_time;

    tcp_segment(bool init, uint32_t len, uint32_t seq_no, uint32_t additional_bytes, unsigned int seg_time_) : init_seg{init}, data_length{len}, seq{seq_no}, additional_bytes_needed{additional_bytes}, seg_time{seg_time_} {}
};

// reassembly_flags denotes special conditions that occur during reassembly
// terminal conditions results in immediate reassembly closure
enum class reassembly_flags : uint8_t {
    missing_syn = 0,
    missing_mid_segment = 1,
    timeout = 2,        // terminal condition
    ooo = 3,
    out_of_buffer = 4,  // terminal condition
    max_seg_exceed = 5, // terminal condition
    segment_overlap = 6,
};

// reassembly_state tracks the current state of the flow
//
enum class reassembly_state : uint8_t {
    reassembly_none = 0,        // no reassembly {requried/in progress}
    reassembly_progress = 1,    // reassembly in progress 
    reassembly_success = 2,     // reassembly success
    reassembly_truncated = 3,   // reassembly failed, output truncated
    reassembly_consumed = 4,    // reassembly data consumed, either success or truncated
};

static constexpr unsigned int reassembly_timeout = 15; 

// tcp_reassembly_flow_context contains all the state associated with a particular
// tcp flow under reassembly, including reassembly buffer, flags etc.
//
struct tcp_reassembly_flow_context {

    std::bitset<7> reassembly_flag_val;
    reassembly_state state;
    unsigned int  init_time;
    uint32_t init_seq;
    uint32_t init_seg_len;
    uint32_t total_bytes_needed;

    // reassembly buffer and contiguous data
    static constexpr size_t max_data_size = 8192;
    size_t curr_contiguous_data;   // reassembly succeeds when this equals total_bytes_needed
    size_t total_set_data;         // size of data buffer already filed, excluding overlaps/duplicates
    uint8_t buffer[max_data_size];

    // segments
    static constexpr size_t max_segments = 20;
    size_t curr_seg_count;
    std::vector<std::pair<uint32_t,uint32_t> > seg_list;  // pair of start and end seq for segment


    // ctor to be called only on inital tcp data segment required for reassembly, for the first time
    //
    tcp_reassembly_flow_context(const tcp_segment &seg, const datum &tcp_pkt) : reassembly_flag_val{}, state{reassembly_state::reassembly_progress}, init_time{seg.seg_time}, init_seq{seg.seq},
                    init_seg_len{seg.data_length}, total_bytes_needed{(seg.data_length) + (seg.additional_bytes_needed)}, curr_contiguous_data{seg.data_length}, total_set_data{seg.data_length},
                    buffer{}, curr_seg_count{0}, seg_list{} {
    
        seg_list.reserve(20);
        seg_list.push_back({seg.init_seg,seg.data_length});
        curr_seg_count = 1;

        // process the pkt
        memcpy(buffer,tcp_pkt.data,seg.data_length);
    }

    void process_tcp_segment(const tcp_segment &seg, const datum &tcp_pkt);

    void write_json(struct json_object record);

    datum get_reassembled_data();

    void update_contiguous_data();

    bool is_expired( unsigned int curr_time);
};

// return a datum associated with the maximum reassmbled data of contiguous segments
// for a successful reassembly curr_contiguous_data == total_bytes_needed
//
struct datum tcp_reassembly_flow_context::get_reassembled_data() { return datum{buffer, buffer+curr_contiguous_data}; }

// reassembly timeout of 15 s
bool tcp_reassembly_flow_context::is_expired(unsigned int curr_time) { return (curr_time - init_time) >= reassembly_timeout; }


// tcp_reassembler holds all tcp flows under reassembly
// order of processing segments:
// 1. check for flow in table
// 2. if present, continue_reassembly
// 3. else init_reassembly
//
typedef std::unordered_map<struct key, tcp_reassembly_flow_context>::iterator reassembly_map_iterator;
struct tcp_reassembler {

    static constexpr size_t max_reassembly_entries = 10000;
    std::unordered_map<struct key, tcp_reassembly_flow_context> table;
    reassembly_map_iterator reap_it;  // iterator used for cleaning the table
    reassembly_map_iterator curr_flow; // iterator pointing to the current flow in reassembly

    tcp_reassembler() : table{} {
        table.reserve(max_reassembly_entries);
        reap_it = table.end();
        curr_flow = table.end();
    } 

    reassembly_state check_flow(const struct key &k, unsigned int sec);
    reassembly_map_iterator init_reassembly(const struct key &k, unsigned int sec, const tcp_segment &seg, const datum &d);
    reassembly_map_iterator continue_reassembly(const struct key &k, unsigned int sec, const tcp_segment &seg, const datum &d);
    void passive_reap(unsigned int sec);
    void active_reap();
    void increment_reap_iterator();

};


void tcp_reassembler::increment_reap_iterator() {
    if (reap_it != table.end()) {
        ++reap_it;
    }
    else {
        reap_it = table.begin();
    }
}

// passively look for expired entires and clear them
// best case - 2 entries, worst case - 0 entries cleared
//
void tcp_reassembler::passive_reap(unsigned int sec) {
    // check for expired flows
    increment_reap_iterator();
    if (reap_it != table.end() && reap_it->second.is_expired(sec)) {
        reap_it = table.erase(reap_it);
    }
    increment_reap_iterator();
    if (reap_it != table.end() && reap_it->second.is_expired(sec)) {
        reap_it = table.erase(reap_it);
    }
}

// actively clear up the table
// always clears 2 entries, may/may not be expired
//
void tcp_reassembler::active_reap() {
    // aggressive : try to remove two entries
    increment_reap_iterator();
    if (reap_it != table.end()) {
        reap_it = table.erase(reap_it);
    }
    increment_reap_iterator();
    if (reap_it != table.end()) {
        reap_it = table.erase(reap_it);
    }
}

// perform housekeeping for table and then
// check if flow_key corresponds to a table entry
// if present return reassembly state or else return reassembly_none
//
reassembly_state tcp_reassembler::check_flow(const struct key &k, unsigned int sec) {
    // housekeeping before find/emplace for maintain iterator validity
    //
    if (table.size() >= max_reassembly_entries) {
        active_reap();  // forcefully remove entries
    }
    else {
        passive_reap(sec);  // passive: try to clean expired entries
    }
    
    curr_flow = table.find(k);
    if (curr_flow != table.end()) {
        return curr_flow->second.state;
    }
    else
        return reassembly_state::reassembly_none;
}

// Initiate reassembly on a flow
// To be called only once, when the initial segment seen for the first time
// Post this, the flow will be in reassembly and continue_reassembly should be called
//
reassembly_map_iterator tcp_reassembler::init_reassembly(const struct key &k, unsigned int sec, const tcp_segment &seg, const datum &d) {
    curr_flow = table.emplace(k,seg,d).first;
    return curr_flow;
}





#endif /* MERC_TCP_H */