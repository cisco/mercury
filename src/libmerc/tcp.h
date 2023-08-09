/*
 * tcp.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef MERC_TCP_H
#define MERC_TCP_H

#include <stdint.h>
#include <string.h>
#include <unordered_map>
#include "datum.h"
#include "analysis.h"
#include "util_obj.h"

struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  offrsv;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} __attribute__ ((__packed__));

/*
 * modular arithmetic comparisons, for tcp Seq and Ack processing
 */

#define LT(X, Y)  ((int32_t)((X)-(Y)) <  0)
#define LEQ(X, Y) ((int32_t)((X)-(Y)) <= 0)
#define GT(X, Y)  ((int32_t)((X)-(Y)) >  0)
#define GEQ(X, Y) ((int32_t)((X)-(Y)) >= 0)

enum disposition { talking, listening };

struct tcp_state {
    uint32_t seq;
    uint32_t ack;
    uint32_t msg_num;
    uint32_t init_seq;
    uint32_t init_ack;
    enum disposition disposition;
};

#define tcp_state_init = { 0, 0, 0, 0, 0, talking };

namespace std {

    template <>  struct hash<struct key>  {
        std::size_t operator()(const struct key& k) const    {

            size_t multiplier = 2862933555777941757;  // source: https://nuclear.llnl.gov/CNP/rng/rngman/node3.html

            /* assume sizeof(size_t) == 8 for now */
            // size_t x = (size_t) k.src_port | ((size_t) k.dst_port << 16) | ((size_t) k.ip_vers) << 32 | ((size_t) k.protocol) << 40;
            // x ^= (size_t) k.addr.ipv6.src.a;
            // x ^= (size_t) k.addr.ipv6.src.b;
            // x ^= (size_t) k.addr.ipv6.src.c;
            // x ^= (size_t) k.addr.ipv6.src.d;
            // x ^= (size_t) k.addr.ipv6.dst.a;
            // x ^= (size_t) k.addr.ipv6.dst.b;
            // x ^= (size_t) k.addr.ipv6.dst.c;
            // x ^= (size_t) k.addr.ipv6.dst.d;
            // return x;

            size_t x;
            if (k.ip_vers == 4) {
                uint32_t sa = k.addr.ipv4.src;
                uint32_t da = k.addr.ipv4.dst;
                uint16_t sp = k.src_port;
                uint16_t dp = k.dst_port;
                uint8_t  pr = k.protocol;
                x = ((uint64_t) sp * da) + ((uint64_t) dp * sa);
                x *= multiplier;
                x += sa + da + sp + dp + pr;
                x *= multiplier;
            } else {
                uint64_t *sa = (uint64_t *)&k.addr.ipv6.src;
                uint64_t *da = (uint64_t *)&k.addr.ipv6.dst;
                uint16_t sp = k.src_port;
                uint16_t dp = k.dst_port;
                uint8_t  pr = k.protocol;
                x = ((uint64_t) sp * da[0] * da[1]) + ((uint64_t) dp * sa[0] * sa[1]);
                x *= multiplier;
                x += sa[0] + sa[1] + da[0] + da[1] + sp + dp + pr;
                x *= multiplier;
            }

            return x;

        }
    };
}


#define BYTE_BINARY_FORMAT "%c%c%c%c%c%c%c%c"
#define UINT8_BINARY(x)                         \
    (x & 0x80 ? '1' : '0'),                     \
        (x & 0x40 ? '1' : '0'),                 \
        (x & 0x20 ? '1' : '0'),                 \
        (x & 0x10 ? '1' : '0'),                 \
        (x & 0x08 ? '1' : '0'),                 \
        (x & 0x04 ? '1' : '0'),                 \
        (x & 0x02 ? '1' : '0'),                 \
        (x & 0x01 ? '1' : '0')

#define TCP_FLAGS_FORMAT "%c%c%c%c "
#define TCP_FLAGS_PRINT(x) ((x & 0x02) ? 'S' : ' '), ((x & 0x10) ? 'A' : ' '), ((x & 0x01) ? 'F' : ' '), ((x & 0x04) ? 'R' : ' ')
 
#define TCP_IS_ACK(flags) ((flags) & 0x10)
#define TCP_IS_PSH(flags) ((flags) & 0x08)
#define TCP_IS_RST(flags) ((flags) & 0x04)
#define TCP_IS_SYN(flags) ((flags) & 0x02)
#define TCP_IS_FIN(flags) ((flags) & 0x01)

#define tcp_offrsv_get_header_length(offrsv) ((offrsv >> 4) * 4)

#ifndef DEBUG_TCP
#define fprintf_tcp_hdr_info(f, k, tcp, state, length, retval)
#else
void fprintf_tcp_hdr_info(FILE *f, const struct key *k, const struct tcp_header *tcp, const struct tcp_state *state, size_t length, size_t retval) {
    size_t data_length = length - tcp_offrsv_get_header_length(tcp->offrsv);
    uint32_t rel_seq = ntoh(tcp->seq) - ntoh(state->init_seq);
    uint32_t rel_ack = ntoh(tcp->ack) - ntoh(state->init_ack);

    if (k->ip_vers == 4) {
        uint8_t *s = (uint8_t *)&k->addr.ipv4.src;
        uint8_t *d = (uint8_t *)&k->addr.ipv4.dst;
        fprintf(f, "%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\t",
                s[0], s[1], s[2], s[3], ntohs(tcp->src_port),
                d[0], d[1], d[2], d[3], ntohs(tcp->dst_port));
    } else if (k->ip_vers == 6) {
        uint8_t *s = (uint8_t *)&k->addr.ipv6.src;
        uint8_t *d = (uint8_t *)&k->addr.ipv6.dst;
        fprintf(f,
                "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%u -> "
                "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%u\t",
                s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15], ntohs(tcp->src_port),
                d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15], ntohs(tcp->dst_port));
    }
    //    fprintf(f, "flags: " BYTE_BINARY_FORMAT "\t", UINT8_BINARY(tcp->flags));
    fprintf(f, TCP_FLAGS_FORMAT, TCP_FLAGS_PRINT(tcp->flags));
    fprintf(f, "seq: %10u ack: %10u ", rel_seq, rel_ack);
    fprintf(f, "len: %5zu ", data_length);
    // fprintf(f, "len: %5d\tpkt: %5zu\n", tcp_offrsv_get_length(tcp->offrsv), length);
    if (state->disposition == talking) {
        fprintf(f, "talking [%u] ", state->msg_num);
    } else {
        fprintf(f, "listening   ");
    }
    if (retval != 0) {
        fprintf(f, "ACCEPT\n");
    } else {
        fprintf(f, "\n");
    }
}
#endif /* DEBUG */

#define ACCEPT_PACKET 100
#define DROP_PACKET     0

struct tcp_initial_message_filter {
    std::unordered_map<struct key, struct tcp_state> tcp_flow_table;

    tcp_initial_message_filter(void) : tcp_flow_table{} {}

    // A TCP message is defined as the set of TCP/IP packets for which
    // the ACK flag is set, the Ack value is constant, and the Seq is
    // increasing.  In the TCP initial message, the relative Ack of
    // the first packet in the message is equal to 1, or the relative
    // Seq of the first packet in the message is equal to 1, or both.
    // In a typical session, the first packet of the client’s initial
    // message has both the relative Seq and Ack equal to one, and the
    // first packet of the server’s initial message has only the Seq
    // equal to 1
    //
    //                  p.seq > s.seq      p.seq == s.seq      p.seq < s.seq
    // p.ack > s.ack      crosstalk          listening               *
    // p.ack = s.ack       talking           listening               *
    // p.ack < s.ack          *                  *                   *

    size_t apply(struct key &k, const struct tcp_header *tcp, size_t length) {

        size_t retval = DROP_PACKET;

        k.src_port = tcp->src_port;
        k.dst_port = tcp->dst_port;
        size_t data_length = length - tcp_offrsv_get_header_length(tcp->offrsv);

        auto it = tcp_flow_table.find(k);
        if (it == tcp_flow_table.end()) {

            uint32_t tmp_seq = tcp->seq;
            if (TCP_IS_SYN(tcp->flags)) {
                tmp_seq = hton(ntoh(tcp->seq) + 1);
            }
            struct tcp_state state = { tmp_seq,  // .seq
                                       tcp->ack, // .ack
                                       0,        // .msg_num
                                       tmp_seq,  // .init_seq
                                       tcp->ack, // .init_ack
                                       listening // .disposition
            };
            tcp_flow_table[k] = state;
            retval = ACCEPT_PACKET;

            fprintf_tcp_hdr_info(stderr, &k, tcp, &state, length, retval);

        } else {

            struct tcp_state state = it->second;

            // initialize acknowledgement number, if it has not yet been set
            if (state.ack == 0) {
                state.ack = tcp->ack;
                state.init_ack = tcp->ack;
            }

            // update disposition and message number if appropriate
            if (data_length > 0) {
                if (ntoh(tcp->ack) > ntoh(state.ack) || state.disposition == listening) {
                    state.msg_num++;
                }
                state.disposition = talking;
            } else {
                if (ntoh(tcp->ack) > ntoh(state.ack)) {
                    state.disposition = listening;
                }
            }
            if (state.disposition == talking && state.msg_num < 2) {
                retval = ACCEPT_PACKET;
            }

            // update state
            if (ntoh(tcp->seq) > ntoh(state.seq)) {
                state.seq = tcp->seq;
            }
            if (ntoh(tcp->ack) > ntoh(state.ack)) {
                state.ack = tcp->ack;
            }
            tcp_flow_table[k] = state;

            fprintf_tcp_hdr_info(stderr, &k, tcp, &state, length, retval);

            if (TCP_IS_FIN(tcp->flags) || TCP_IS_RST(tcp->flags)) {
                tcp_flow_table.erase(it);
            }
        }

        return retval;
    }

};

/*
 * partial tcp reassembly
 *
 * strategy:
 *
 *    - pre-allocated storage to hold reassembled packets
 *
 *    - flow key maps to tcp_segment
 *
 *    - to request reassembly, call copy_packet() and pass it the
 *      initial bytes of the packet being reassembled, along with the
 *      number of additional bytes needed
 *
 *    - to check a tcp packet to see if it contributes to, or
 *      completes, a requested segment, invoke check_packet().  If it
 *      returns a non-null value, that value points to the reassembled
 *      tcp_segment.
 */

struct tcp_seg_context {
    uint32_t data_length;
    uint32_t seq;
    uint32_t additional_bytes_needed;

    tcp_seg_context(uint32_t len, uint32_t seq_no, uint32_t additional_bytes) : data_length{len}, seq{seq_no}, additional_bytes_needed{additional_bytes} {}
};

struct tcp_segment {
    uint32_t seq_init;
    uint32_t curr_seq;
    uint32_t index;
    uint32_t end_index;
    uint32_t seg_len;
    uint32_t max_index;
    uint32_t total_bytes_needed;
    uint32_t current_bytes;
    uint32_t seg_count;
    uint16_t prune_index;  // index of prune node in pruning table
    unsigned int init_time;
    bool done;
    bool seg_overlap;  // current pkt overlaps with a previous segment
    bool max_seg_exceed;

    static const unsigned int timeout = 30;    // seconds before flow timeout

    static const size_t buffer_len = 8192;
    uint8_t data[buffer_len];

    static const uint32_t max_seg_count = 20;
    std::pair<uint32_t, uint32_t> seg[max_seg_count];
    //std::vector< std::pair<uint32_t,uint32_t> > seg;

    tcp_segment() : seq_init{0}, curr_seq{0}, index{0}, end_index{0}, seg_len{0}, max_index{8192}, total_bytes_needed{8192},
                        current_bytes{0}, seg_count{0}, prune_index{0}, init_time{0}, done{false}, seg_overlap{false}, max_seg_exceed{false} {}

    bool init_from_pkt (unsigned int sec, struct tcp_seg_context &tcp_pkt, uint32_t syn_seq, datum &p) {
        seq_init = syn_seq;
        init_time = sec;
        seg_len = tcp_pkt.data_length;
        curr_seq = tcp_pkt.seq;
        seg_count++;
        bool is_initial = (seq_init == curr_seq);

        if (is_initial) {
            total_bytes_needed = seg_len + tcp_pkt.additional_bytes_needed;
            max_index = total_bytes_needed;
        }

        index = curr_seq - seq_init;
        end_index = index + seg_len;
        seg[0].first = index;
        seg[0].second = end_index;
        if (max_index > buffer_len) {
            return false;   // cannot accommodate reassembled data
        }
        if (index >= buffer_len) {
            return true;    // ignore this seg
        }

        // TODO: check for datum len
        uint32_t len = end_index > buffer_len ? (buffer_len-index):seg_len;
        memcpy(data+index, p.data, len);
        current_bytes += seg_len;
        return true;
    }

    bool check_overlap (uint32_t start, uint32_t end, std::pair<uint32_t,uint32_t> *segment) {

        // right overlap
        bool right = (start > segment->first && start < segment->second);
        bool left = (end > segment->first && end < segment->second);

        return (right || left);
    }

    bool check_seg_overlaps (uint32_t start, uint32_t end) {
        uint32_t index = seg_count - 2;

        for (size_t i = 0; i <= index; i++) {
            if (check_overlap(start, end, seg+i)) {
                return true;
            }
        }

        seg[index + 1].first = start;
        seg[index + 1].second = end;
    
        return false;
    }

    struct tcp_segment *check_packet (struct tcp_seg_context &tcp_pkt, datum &p) {
        seg_len = tcp_pkt.data_length;
        curr_seq = tcp_pkt.seq;
        bool is_initial = (seq_init == curr_seq);

        if (is_initial) {
            total_bytes_needed = seg_len + tcp_pkt.additional_bytes_needed;
            max_index = total_bytes_needed;
        }

        index = curr_seq - seq_init;
        end_index = index + seg_len;

        seg_count++;
        if (seg_count > max_seg_count) {
            // force flush
            done = true;
            max_seg_exceed = true;
            return this;
        }

        if (check_seg_overlaps(index, end_index)) {
            seg_overlap = true;
        }

        if (max_index > buffer_len) {
            return nullptr;   // cannot accommodate reassembled data
        }
        if (index >= buffer_len) {
            return this;    // ignore this seg
        }

        // TODO: check for datum len
        uint32_t len = end_index > buffer_len ? (buffer_len-index):seg_len;
        memcpy(data+index, p.data, len);
        current_bytes += seg_len;

        if (current_bytes >= total_bytes_needed) {
            done = true;
        }

        return this;
    }

    struct datum get_reassembled_segment() {
        struct datum reassembled_tcp_data{data, data + total_bytes_needed};
        return reassembled_tcp_data;
    }

    bool expired(unsigned int sec) {
        if (sec - init_time > timeout) {
            return true;
        }
        return false;
    }

};

struct prune_node {
    unsigned int init_timestamp;
    struct key seg_key;
    bool is_in_map;  // segment already removed from map post reassembly

    static const unsigned int timeout = 30;

    prune_node() : init_timestamp{0}, seg_key{}, is_in_map{true}{}

    void update(unsigned int ts, struct key k) {
        init_timestamp = ts;
        seg_key = k;
    }

    bool is_expired(unsigned int ts) {
        return (ts - init_timestamp > timeout);
    }
};

struct prune_table {
    unsigned int last_prune_ts;     // timestamp of last time pruning
    uint16_t index_start;           // start of ciruclar buffer, prune from this side
    uint16_t index_end;             // end of circular buffer, add from this side
    uint16_t node_count;            // entries count

    static const unsigned int prune_time = 30;          // prune every 30 sec
    static const uint16_t max_prune_entries = 8000;     // max entries in prune table
    static const uint16_t prune_limit = 6000;           // force prune after entries reach this value

    struct prune_node nodes[max_prune_entries];

    prune_table() : last_prune_ts{0}, index_start{0}, index_end{0}, node_count{0}, nodes{} {}

    bool remove_node(struct key k, std::unordered_map<struct key, struct tcp_segment> &table) {
        auto it = table.find(k);
        if (it != table.end()) {
            table.erase(it);
            return true;
        }
        return false;
    }

    void do_pruning (unsigned int ts, std::unordered_map<struct key, struct tcp_segment> &table) {
        uint16_t prune_count = 0;
        uint16_t curr_index = 0;
        uint16_t temp_start = index_start;
        //uint16_t temp_end = index_end;
        uint16_t temp_node_count = node_count;

        for (uint16_t i = 0; i < temp_node_count; i++) {
            curr_index = (i+temp_start < max_prune_entries) ? (i+temp_start) : (i+temp_start) - max_prune_entries;
            if (nodes[curr_index].is_expired(ts)) {
                if (nodes[curr_index].is_in_map && remove_node(nodes[curr_index].seg_key, table)) {
                    prune_count++;
                }
                index_start++;
                node_count--;
            }
            else {
                // last expired entry, break
                break;
            }
        }
        if (index_start >= max_prune_entries) {
            index_start -= max_prune_entries;
        }
    }

    //  this tries to free up exactly one entry in the segment map forcefully
    void do_force_pruning (std::unordered_map<struct key, struct tcp_segment> &table) {
        uint16_t curr_index = 0;
        uint16_t temp_start = index_start;
        //uint16_t temp_end = index_end;
        uint16_t temp_node_count = node_count;

        for (uint16_t i = 0; i < temp_node_count; i++) {
            curr_index = (i+temp_start < max_prune_entries) ? (i+temp_start) : (i+temp_start) - max_prune_entries;
            index_start++;
            node_count--;
            if (index_start >= max_prune_entries) {
                index_start -= max_prune_entries;
            }
            if (nodes[curr_index].is_in_map && remove_node(nodes[curr_index].seg_key, table)) {
                return;
            }
        }
    }

    void check_time_pruning (unsigned int ts, std::unordered_map<struct key, struct tcp_segment> &table) {
        if ((ts - last_prune_ts) > prune_time) {
            last_prune_ts = ts;     // update prune time
            do_pruning(ts, table);
        }
    }

    bool add_node(unsigned int ts, struct key k, std::unordered_map<struct key, struct tcp_segment> &table, uint16_t &index) {
        bool force_pruned = false;
        if (node_count >= prune_limit) {
            do_pruning(ts, table);
            if (node_count == max_prune_entries) {
                // force remove oldest entry
                if (remove_node(nodes[index_start].seg_key, table)) {
                    force_pruned = true;
                }
                index_start++;
                if (index_start >= max_prune_entries) {
                    index_start -= max_prune_entries;
                }
                node_count--;
            }
        }

        index_end++;
        if (index_end >= max_prune_entries) {
            index_end -= max_prune_entries;
        }

        nodes[index_end].update(ts, k);
        index = index_end;
        node_count++;

        return force_pruned;
    }
};

void fprintf_json_string_escaped(FILE *f, const char *key, const uint8_t *data, unsigned int len);

enum reassembly_status {
    reassembly_none = 0,
    reassembly_in_progress = 1,
    reassembly_done = 2
};

struct tcp_reassembler {
    bool dump_pkt;          // current pkt involved in reassembly, dump pkt regardless of json
    struct prune_table pruner;
    uint64_t force_prunes;
    bool curr_reassembly_consumed;
    enum reassembly_status curr_reassembly_state;

    static const uint32_t max_map_entries = 5000;
    static const uint32_t force_prune_count = 4000;

    std::unordered_map<struct key, struct tcp_segment> segment_table;
    std::unordered_map<struct key, struct tcp_segment>::iterator reap_it;

    tcp_reassembler(unsigned int size) : dump_pkt{false}, pruner{}, force_prunes{0}, curr_reassembly_consumed{false}, curr_reassembly_state{reassembly_none}, segment_table{}, reap_it{segment_table.end()} {
        segment_table.reserve(size);
        reap_it = segment_table.end();
    }

    bool init_segment(const struct key &k, unsigned int sec, struct tcp_seg_context &tcp_pkt, uint32_t syn_seq, datum &p) {
        active_prune(sec);     // try pruning before inserting
        tcp_segment segment;
        if (segment.init_from_pkt(sec, tcp_pkt, syn_seq, p)) {
            reap_it = segment_table.emplace(k, segment).first;
            uint16_t index;
            if (pruner.add_node(sec,k,segment_table,index)) {
                force_prunes++;
            }
            reap_it->second.prune_index = index;
            //++reap_it;
            return true;
        }
        return false;
    }

    bool is_init_seg (const struct key&k, uint32_t seq) {
        auto it = segment_table.find(k);
        if (it != segment_table.end()) {
            return (it->second.seq_init == seq);
        }
        return false;
    }

    struct tcp_segment *check_packet(const struct key &k, unsigned int sec, struct tcp_seg_context &tcp_pkt, datum &p, bool &reassembly_consumed) {

        auto it = segment_table.find(k);
        if (it != segment_table.end()) {
            if (it->second.expired(sec)) {
                pruner.nodes[it->second.prune_index].is_in_map = false;
                remove_segment(it);
                return nullptr;
            }
            // Before adding more data, check if reassembly already done
            if (it->second.done) {
                reassembly_consumed = true;
                return &it->second;
            }
            reap_it = it;
            return it->second.check_packet(tcp_pkt, p);
        }
        return nullptr;
    }

    void remove_segment(key &k) {
        auto it = segment_table.find(k);
        if (it != segment_table.end()) {
            reap_it = segment_table.erase(it);
        }
    }

    void remove_segment(std::unordered_map<struct key, struct tcp_segment>::iterator it) {
        if (it != segment_table.end()) {
            reap_it = segment_table.erase(it);
        }
    }

    void active_prune(unsigned int ts) {
        if (segment_table.size() >= force_prune_count) {
            pruner.do_pruning(ts, segment_table);
        }
        if (segment_table.size() == max_map_entries) {
            pruner.do_force_pruning(segment_table);
        }
        pruner.check_time_pruning(ts, segment_table);
    }

    void count_all() {
        auto it = segment_table.begin();
        while (it != segment_table.end()) {
            it = segment_table.erase(it);
        }
    }

    void write_flags(struct json_object &record, const char *key) {
        if (reap_it == segment_table.end()) {
            return;
        }
        if (reap_it->second.done) {
            struct json_object flags{record, key};
            flags.print_key_bool("reassembled", true);
            if (reap_it->second.seg_overlap) {
                flags.print_key_bool("segment_overlap", reap_it->second.seg_overlap);
            }
            if (reap_it->second.max_seg_exceed) {
                flags.print_key_bool("segment_count_exceed", reap_it->second.max_seg_exceed);
            }
            flags.close();
        }
        reap_it = segment_table.end();
        return;
    }

};

struct flow_table {
    std::unordered_map<struct key, unsigned int> table;
    std::unordered_map<struct key, unsigned int>::iterator reap_it;

    flow_table(unsigned int size) : table{}, reap_it{table.end()} {
        table.reserve(size);
        reap_it = table.end();
    }

    bool flow_is_new(const struct key &k, unsigned int sec) {

        auto it = table.find(k);
        if (it != table.end() && (sec - it->second < flow_table::timeout)) {
            it->second = sec;
            reap(sec);
            //printf_err(log_debug, "FLOW OLD\n");
            return false;
        }
        auto tmp = table.insert({k, sec}).first;
        update_reap_iterator(tmp);
        //printf_err(log_debug, "FLOW NEW\n");
        return true;
    }

    void reap(unsigned int sec) {

        // check for expired flows
        if (reap_it != table.end() && (sec - reap_it->second > flow_table::timeout)) {
            reap_it = table.erase(reap_it);
        }
    }

    void update_reap_iterator(std::unordered_map<struct key, unsigned int>::iterator x) {
        if (x != table.end()) {
            reap_it = x++;
        }
    }

    static const unsigned int timeout = 60 * 60; // seconds before flow timeout

};


// struct flow_table_tcp
//
// goal: identify the first data packet in each TCP flow, with zero
// false positives.
//
// approach: create a tcp_context when a SYN packet is observed, and
// when the first data packet is observed, delete the context;
// randomly traverse the table of tcp_contexts and check for expired
// elements.


struct tcp_context {
public:
    tcp_context(unsigned int seconds, uint32_t sequence_number) : sec{seconds}, seq{sequence_number+1} {}

    ~tcp_context() {}

    bool is_expired(unsigned int current_time) {
        return (current_time - sec) >= timeout;
    }
    bool seq_is_equal_to(uint32_t s) {
        return seq == s;
    }
    bool seq_is_greater(uint32_t s) {
        return s > seq;
    }
    uint32_t get_seq() {
        return seq;
    }

private:
    unsigned int sec;
    uint32_t seq;

    static const unsigned int timeout = 30; // seconds before flow timeout
};

struct flow_table_tcp {
    std::unordered_map<struct key, struct tcp_context> table;
    std::unordered_map<struct key, struct tcp_context>::iterator reap_it;

    flow_table_tcp(unsigned int size) : table{}, reap_it{table.end()} {
        table.reserve(size);
        reap_it = table.end();
    }

    void syn_packet(const struct key &k, unsigned int sec, uint32_t seq) {
        auto it = table.find(k);
        if (it == table.end()) {
            table.insert({k, {sec, seq}});
            // printf_err(log_debug, "tcp_flow_table size: %zu\n", table.size());
        }
    }

    bool is_first_data_packet(const struct key &k, unsigned int sec, uint32_t seq) {
        auto it = table.find(k);
        if (it != table.end()) {
            if (it->second.is_expired(sec)) {
                reap_it = table.erase(it);
                return true;
            }
            if (it->second.seq_is_equal_to(seq)) {
                reap_it = table.erase(it);
                return true;
            }
        }
        reap(sec);
        return false;
    }

    // Returns the syn seq no, whether the received data pkt is first segment and whether the flow expired
    //
    uint32_t check_flow(const struct key &k, unsigned int sec, uint32_t seq, bool &initial_seq, bool &expired) {
        uint32_t syn_seq;
        auto it = table.find(k);
        if (it != table.end()) {
            if (it->second.is_expired(sec)) {
                syn_seq = it->second.get_seq();
                reap_it = table.erase(it);
                expired = true;
                return syn_seq;
            }
            if (it->second.seq_is_equal_to(seq)) {
                reap_it = table.erase(it);
                initial_seq = true;
                return seq;
            }
            else if (it->second.seq_is_greater(seq)) {
                syn_seq = it->second.get_seq();
                reap_it = table.erase(it);
                return syn_seq;       
            }
        }
        reap(sec);
        return 0;    
    }

    void reap(unsigned int sec) {

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

    void increment_reap_iterator() {
        if (reap_it != table.end()) {
            ++reap_it;
        } else {
            reap_it = table.begin();
        }
    }

    void count_all() {
        auto it = table.begin();
        while (it != table.end()) {
            it = table.erase(it);
        }
    }

    static const unsigned int timeout = 1; // seconds before flow timeout

};

#endif /* MERC_TCP_H */
