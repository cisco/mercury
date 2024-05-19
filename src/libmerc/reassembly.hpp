/*
 * reassembly.hpp
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
    missing_mid_segment = 0,    // reason of truncation
    timeout = 1,        // terminal condition, reason of truncation
    ooo = 2,
    out_of_buffer = 3,  // terminal condition, reason of trncation
    max_seg_exceed = 4, // terminal condition, reason of truncation
    segment_overlap = 5,
    truncated = 6
};

static const char* reassembly_flag_str[] = {
    "missing_segment",
    "timeout",
    "out_of_order",
    "out_of_buffer",
    "max_segments_exceed",
    "segment_overlaps",
    "truncated"
};

// types of segment overlaps
enum class reassembly_overlaps : uint8_t {
    back_partial_overlap = 0,
    back_subset_overlap = 1,
    front_partial_overlap = 2,
    front_superset_overlap = 3
};

static const char* reassembly_overlaps_str[] = {
    "back_partial_overlap",
    "back_subset_overlap",
    "front_partial_overlap",
    "front_superset_overlap"
};

// reassembly_state tracks the current state of the flow
//
enum class reassembly_state : uint8_t {
    reassembly_none = 0,        // no reassembly {requried/in progress}
    reassembly_progress = 1,    // reassembly in progress 
    reassembly_success = 2,     // reassembly success
    reassembly_truncated = 3,   // reassembly failed, output truncated, either max segments or timeout
    reassembly_consumed = 4,    // reassembly data already consumed, either success or truncated
};

static constexpr unsigned int reassembly_timeout = 15; 

// tcp_reassembly_flow_context contains all the state associated with a particular
// tcp flow under reassembly, including reassembly buffer, flags etc.
//
struct tcp_reassembly_flow_context {

    std::bitset<7> reassembly_flag_val;
    std::bitset<4> reassembly_overlap_flags;
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
    tcp_reassembly_flow_context(const tcp_segment &seg, const datum &tcp_pkt) : reassembly_flag_val{}, reassembly_overlap_flags{}, state{reassembly_state::reassembly_progress}, init_time{seg.seg_time}, init_seq{seg.seq},
                    init_seg_len{seg.data_length}, total_bytes_needed{(seg.data_length) + (seg.additional_bytes_needed)}, curr_contiguous_data{seg.data_length}, total_set_data{seg.data_length},
                    buffer{}, curr_seg_count{0}, seg_list{} {
    
        seg_list.reserve(20);
        seg_list.push_back({seg.seq - init_seq, seg.seq - init_seq + seg.data_length - 1});
        curr_seg_count = 1;

        // process the pkt
        memcpy(buffer,tcp_pkt.data,seg.data_length);
    }

    void process_tcp_segment(const tcp_segment &seg, const datum &tcp_pkt);

    void simplify_seglist (size_t idx);

    void write_json(struct json_object &record);

    datum get_reassembled_data();

    void update_contiguous_data();

    bool is_expired( unsigned int curr_time);

    void set_reassembly_flag(size_t idx);

    void set_expired();
};

// return a datum associated with the maximum reassmbled data of contiguous segments
// for a successful reassembly curr_contiguous_data == total_bytes_needed
// this can be called after reassmebly reaches any terminal state
//
inline struct datum tcp_reassembly_flow_context::get_reassembled_data() { return datum{buffer, buffer+curr_contiguous_data}; }

// reassembly timeout of 15 s
inline bool tcp_reassembly_flow_context::is_expired(unsigned int curr_time) { return (curr_time - init_time) >= reassembly_timeout; }

inline void tcp_reassembly_flow_context::set_reassembly_flag(size_t idx) { reassembly_flag_val[idx] = true; }

inline void tcp_reassembly_flow_context::set_expired() {
    state = reassembly_state::reassembly_truncated;
    set_reassembly_flag((size_t)reassembly_flags::timeout);
}


    // process the seglist and simplify so that none of the segments overlap with each other
    // Forward partial overlap :  Update the seg end
    //      seg(a,b) has forward partial overlap with immediate next element seg(x,y) if a < x && x <= b <= y
    //      eg. {(40,60)} with (50,100)
    // Forward superset overlap : Remove all subset segments
    //      seg(a,b) has forward superset overlap with one or more next elements seg(x,y) if a < x && x <= y <= b
    //      e.g. {(40,100)} with (50,60), (70,80)
    // One segment can have multiple forward superset overlaps and at max one forward partial overlap
    //      e.g. {(40,100)} with (50,60), (70,80), (90,120)
    //
    //
    // Backward partial overlap: update seg start
    // seg(a,b) has backward partial overlap with immediate previous element seg(x,y) if b > y && x <= a <= y
    //      e.g. {(45,60)} with (40,50)
    // Backward subset overlap : Ignore this seg
    // seg(a,b) has backward subset overlap with immediate previous element seg(x,y) if x <= a <= b <= y
    //      e.g. {(45,48)} with (40,50)
    // One segment can either one backward partial overlap or one backward subset overlap
    //
    // Both backward and forward partial overlaps can occur together, along with multiple forward superset overlaps
    // Backward subset overlap is an exclusive case

inline void tcp_reassembly_flow_context::simplify_seglist (size_t idx) {
    size_t back_overlap = 0;
    size_t front_overlap = 0;
    size_t dlen = seg_list[idx].second - seg_list[idx].first + 1;

    if (idx) {
        // check for backward subset overlap or duplicate segment
        if ( ((seg_list[idx].first == seg_list[idx-1].first) && (seg_list[idx].second == seg_list[idx-1].second)) ||
                ((seg_list[idx].first <= seg_list[idx-1].second) && (seg_list[idx].second <= seg_list[idx-1].second)) ) {
            // remove and ignore this segment
            seg_list.erase(seg_list.begin()+idx);
            reassembly_flag_val[(size_t)reassembly_flags::segment_overlap] = true;
            reassembly_overlap_flags[(size_t)reassembly_overlaps::back_subset_overlap] = true;
            return;
        }
        // check for backward partial overlap
        if ((seg_list[idx].first <= seg_list[idx-1].second) && (seg_list[idx].second > seg_list[idx-1].second)) {
            back_overlap = seg_list[idx-1].second - seg_list[idx].first + 1;
            // update seg start
            seg_list[idx].first = seg_list[idx-1].second + 1;
            reassembly_flag_val[(size_t)reassembly_flags::segment_overlap] = true;
            reassembly_overlap_flags[(size_t)reassembly_overlaps::back_partial_overlap] = true;
        }
    }

    if (idx != (seg_list.size()-1)) {
        // check for multiple superset overlaps
        size_t i = idx + 1; 
        for (; i < seg_list.size()-1; i++) {
            if ( (seg_list[i].first <= seg_list[idx].second) && (seg_list[i].second <= seg_list[idx].second) ) {
                front_overlap = seg_list[i].second - seg_list[i].first + 1;
                reassembly_flag_val[(size_t)reassembly_flags::segment_overlap] = true;
                reassembly_overlap_flags[(size_t)reassembly_overlaps::front_superset_overlap] = true;
            }
            else
                break;
        }
        if (i != idx + 1){
            // delete all entries till index i - 1
            seg_list.erase(seg_list.begin()+idx+1,seg_list.begin()+i);
        }
    }

    // check again for forward partial overlap
    if (idx != (seg_list.size()-1)) {
        if ( (seg_list[idx].second >= seg_list[idx+1].first) && (seg_list[idx].second <= seg_list[idx+1].second) ) {
            front_overlap = seg_list[idx].second - seg_list[idx+1].first + 1;
            // update seg end
            seg_list[idx].second = seg_list[idx+1].first - 1;
            reassembly_flag_val[(size_t)reassembly_flags::segment_overlap] = true;
            reassembly_overlap_flags[(size_t)reassembly_overlaps::front_partial_overlap] = true;
        }
    }

    size_t total_overlap = front_overlap + back_overlap;
    total_set_data = total_set_data + dlen - total_overlap;

}

// update maximum bytes that the reassembly buffer has
// without any holes
// seg(a,b) and seg(x,y) are contiguous if x == b+1
// first segment is always part of contiguous data
//
inline void tcp_reassembly_flow_context::update_contiguous_data() {
    curr_contiguous_data = init_seg_len;
    for (auto it = seg_list.begin()+1; it != seg_list.end(); it++) {
        if (it->first == ((it-1)->second+1)) {
            curr_contiguous_data = curr_contiguous_data + it->second - it->first + 1;
        }
    }
}

// segments can arrive ooo or have overlapping parts
// handle appropriately
inline void tcp_reassembly_flow_context::process_tcp_segment(const tcp_segment &seg, const datum &tcp_pkt) {
    uint32_t rel_seq_st = seg.seq - init_seq;       // start index
    uint32_t dlen = seg.data_length;
    uint32_t rel_seq_en = ( (rel_seq_st + dlen - 1) >= (max_data_size-1) ? (max_data_size-1) : (rel_seq_st + dlen - 1) );     // end index
    
    curr_seg_count++;
    if (curr_seg_count > max_segments) {
        // use existing max contiguous bytes and exit
        reassembly_flag_val[(size_t)reassembly_flags::max_seg_exceed] = true;
        reassembly_flag_val[(size_t)reassembly_flags::truncated] = true;
        state = reassembly_state::reassembly_truncated;
        return;
    }

    // check for bounds
    if (rel_seq_st > (max_data_size -1)) {
        return;
    }

    // memcpy data into buffer
    memcpy(buffer+rel_seq_st,tcp_pkt.data,rel_seq_en-rel_seq_st+1);

    // start from last segment and find the right place
    // as most likely case is the best case scenario of in order pkts
    // seg (a,b) represent the starting and ending byte index in the buffer
    // find the last segment (x,y) so that a > x
    // empalce on reverse iterator base() adds the new segment after the element
    //
    size_t idx = seg_list.size();   // index at which the new element is inserted
    for (auto it = seg_list.rbegin(); it != seg_list.rend(); it++){
        if (it->first <= rel_seq_st) {
            seg_list.emplace(it.base(),rel_seq_st,rel_seq_en);
            break;
        }
        idx--;
    }

    // simplify the seglist to avoid overlaps
    // this operation guarantees overlap free seglist
    //
    simplify_seglist(idx);

    // update max contiguous bytes
    update_contiguous_data();

    // check for success
    if (curr_contiguous_data >= total_bytes_needed) {
        state = reassembly_state::reassembly_success;
    }
}

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
    bool dump_pkt;  // used by pkt_filter to dump pkts involved in reassembly

    tcp_reassembler() : table{}, dump_pkt{false} {
        table.reserve(max_reassembly_entries);
        reap_it = table.end();
        curr_flow = table.end();
    } 

    reassembly_state check_flow(const struct key &k, unsigned int sec);
    void init_reassembly(const struct key &k, unsigned int sec, const tcp_segment &seg, const datum &d);
    void continue_reassembly(const struct key &k, unsigned int sec, const tcp_segment &seg, const datum &d);
    reassembly_map_iterator process_tcp_data_pkt(const struct key &k, unsigned int sec, const tcp_segment &seg, const datum &d);
    void passive_reap(unsigned int sec);
    void active_reap();
    void increment_reap_iterator();
    reassembly_map_iterator get_current_flow();
    bool is_ready(reassembly_map_iterator it);
    bool in_progress(reassembly_map_iterator it);
    bool is_done(reassembly_map_iterator it);
    datum get_reassembled_data(reassembly_map_iterator it);
    void set_completed(reassembly_map_iterator it);
    void write_json(json_object &record);
    void clean_curr_flow();
    void count_all();

};


inline void tcp_reassembler::increment_reap_iterator() {
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
inline void tcp_reassembler::passive_reap(unsigned int sec) {
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

// Returns the current flow under processing, either init_reassembly or continue_reassembly
// This pointer may get invalidated after any kind of delete or insert operation, so reqiures carefull usage
//
inline reassembly_map_iterator tcp_reassembler::get_current_flow() { return curr_flow; }

// actively clear up the table
// always clears 2 entries, may/may not be expired
//
inline void tcp_reassembler::active_reap() {
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
// sets curr_flow to the flow if found or table.end() otherwise
//
inline reassembly_state tcp_reassembler::check_flow(const struct key &k, unsigned int sec) {
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
    else {
        curr_flow = table.end();
        return reassembly_state::reassembly_none;
    }
}

// Initiate reassembly on a flow
// To be called only once, when the initial segment seen for the first time
// Post this, the flow will be in reassembly and continue_reassembly should be called
//
inline void tcp_reassembler::init_reassembly(const struct key &k, unsigned int sec, const tcp_segment &seg, const datum &d) {
    curr_flow = table.emplace(std::piecewise_construct,std::forward_as_tuple(k),std::forward_as_tuple(seg,d)).first;
}

// Continue reassembly on existing flow
//
inline void tcp_reassembler::continue_reassembly(const struct key &k, unsigned int sec, const tcp_segment &seg, const datum &d) {
    if (curr_flow->second.is_expired(sec)) {
        curr_flow->second.set_expired();
    }
    else
        curr_flow->second.process_tcp_segment(seg, d);
}

// Entry function for reassmbly
//
inline reassembly_map_iterator tcp_reassembler::process_tcp_data_pkt(const struct key &k, unsigned int sec, const tcp_segment &seg, const datum &d){
    reassembly_state flow_state = check_flow(k,sec);

    switch (flow_state)
    {
    case reassembly_state::reassembly_none :
        // not in reassembly, init
        init_reassembly(k,sec,seg,d);
        return curr_flow;

    case reassembly_state::reassembly_progress :
        // in reassembly, continue
        // no break statement, so code can fall through to next cases
        // if any terminal state is reached after processing the current pkt
        //
        continue_reassembly(k,sec,seg,d);
        [[fallthrough]];

    case reassembly_state::reassembly_success :
    case reassembly_state::reassembly_truncated :
        return curr_flow;

    case reassembly_state::reassembly_consumed :
        // stale flow, clean it
        // TODO: cleanup
        return table.end();
    default:
        return table.end();
    }
}

inline bool tcp_reassembler::is_ready(reassembly_map_iterator it) {
    if (it != table.end())
        return ((it->second.state == reassembly_state::reassembly_success) || (it->second.state == reassembly_state::reassembly_truncated));
    else
        return false;
}

inline bool tcp_reassembler::in_progress(reassembly_map_iterator it) {
    if (it != table.end())
        return ((it->second.state == reassembly_state::reassembly_progress));
    else
        return false;
}

inline bool tcp_reassembler::is_done(reassembly_map_iterator it)  {
    if (it != table.end())
        return ((it->second.state == reassembly_state::reassembly_consumed));
    else
        return false;
}

inline datum tcp_reassembler::get_reassembled_data(reassembly_map_iterator it) {
    if (it != table.end())
        return it->second.get_reassembled_data();
    else
        return datum{nullptr,nullptr};
}

inline void tcp_reassembler::set_completed(reassembly_map_iterator it) {
    if (it != table.end())
        it->second.state = reassembly_state::reassembly_consumed;
}

inline void tcp_reassembler::clean_curr_flow() {
    if ((curr_flow!=table.end()) && is_done(curr_flow)) {
        reap_it = table.erase(curr_flow);   
    }
    curr_flow = table.end();
}

inline void tcp_reassembler::write_json(json_object &record) {
    if (curr_flow == table.end())
        return;
    json_object flags{record, "reassembly_properties"};
    flags.print_key_bool("reassembled",true);
    for (size_t i = 0; i < 7; i++) {
        if (curr_flow->second.reassembly_flag_val[i]) {
            flags.print_key_bool(reassembly_flag_str[i],true);
        }
    }
    flags.close();
}

inline void tcp_reassembler::count_all() {
    table.clear();
}

#endif /* REASSEMBLY_HPP */