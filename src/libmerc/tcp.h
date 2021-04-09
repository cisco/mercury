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
#include <arpa/inet.h>
#include <unordered_map>
#include "datum.h"

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

struct ipv6_address {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;

    bool operator==(const ipv6_address &rhs) const {
        return a == rhs.a && b == rhs.b && c == rhs.c && d == rhs.d;
    }
};

struct ip_address {
    enum ip_version { v4, v6 };
    enum ip_version version;
    union address {
        address(uint32_t a)     : ipv4{a} {}
        address(ipv6_address a) : ipv6{a} {}
        uint32_t ipv4;
        ipv6_address ipv6;
    } value;

    ip_address(uint32_t v4_addr)     : version{ip_version::v4}, value{v4_addr} {}
    ip_address(ipv6_address v6_addr) : version{ip_version::v6}, value{v6_addr} {}
};

struct key {
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t ip_vers;
    union {
        struct {
            uint32_t src;
            uint32_t dst;
        } ipv4;
        struct {
            ipv6_address src;
            ipv6_address dst;
        } ipv6;
    } addr;

    key(uint16_t sp, uint16_t dp, uint32_t sa, uint32_t da, uint8_t proto) {
        src_port = sp;
        dst_port = dp;
        protocol = proto;
        ip_vers = 4;
        addr.ipv6.src = { 0, 0, 0, 0 };   /* zeroize v6 src addr */
        addr.ipv6.dst = { 0, 0, 0, 0 };   /* zeroize v6 dst addr */
        addr.ipv4.src = sa;
        addr.ipv4.dst = da;
    }
    key(uint16_t sp, uint16_t dp, ipv6_address sa, ipv6_address da, uint8_t proto) {
        src_port = sp;
        dst_port = dp;
        protocol = proto;
        ip_vers = 6;
        addr.ipv6.src = sa;
        addr.ipv6.dst = da;
    }
    key() {
        src_port = 0;
        dst_port = 0;
        protocol = 0;
        ip_vers = 0;       // null key can be distinguished by ip_vers field
        addr.ipv6.src = { 0, 0, 0, 0 };
        addr.ipv6.dst = { 0, 0, 0, 0 };
    }
    void zeroize() {
        ip_vers = 0;
    }
    bool is_zero() const {
        return ip_vers == 0;
    }
    bool operator==(const key &k) const {
        switch (ip_vers) {
        case 4:
            return src_port == k.src_port
                && dst_port == k.dst_port
                && protocol == k.protocol
                && k.ip_vers == 4
                && addr.ipv4.src == k.addr.ipv4.src
                && addr.ipv4.dst == k.addr.ipv4.dst;
            break;
        case 6:
            return src_port == k.src_port
                && dst_port == k.dst_port
                && protocol == k.protocol
                && k.ip_vers == 6
                && addr.ipv6.src == k.addr.ipv6.src
                && addr.ipv6.dst == k.addr.ipv6.dst;
        default:
            return 0;
        }
    }

#define MAX_ADDR_STR_LEN 48

    void sprint_src_addr(char src_addr[MAX_ADDR_STR_LEN]) const {
        if (ip_vers == 4) {
            uint8_t *sa = (uint8_t *)&addr.ipv4.src;
            snprintf(src_addr, MAX_ADDR_STR_LEN, "%u.%u.%u.%u", sa[0], sa[1], sa[2], sa[3]);
        } else {
            uint8_t *sa = (uint8_t *)&addr.ipv6.src;
            snprintf(src_addr, MAX_ADDR_STR_LEN, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                    sa[0], sa[1], sa[2], sa[3], sa[4], sa[5], sa[6], sa[7], sa[8], sa[9], sa[10], sa[11], sa[12], sa[13], sa[14], sa[15]);
        }
    }
};


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
    uint32_t rel_seq = ntohl(tcp->seq) - ntohl(state->init_seq);
    uint32_t rel_ack = ntohl(tcp->ack) - ntohl(state->init_ack);

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
                tmp_seq = htonl(ntohl(tcp->seq) + 1);
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
                if (ntohl(tcp->ack) > ntohl(state.ack) || state.disposition == listening) {
                    state.msg_num++;
                }
                state.disposition = talking;
            } else {
                if (ntohl(tcp->ack) > ntohl(state.ack)) {
                    state.disposition = listening;
                }
            }
            if (state.disposition == talking && state.msg_num < 2) {
                retval = ACCEPT_PACKET;
            }

            // update state
            if (ntohl(tcp->seq) > ntohl(state.seq)) {
                state.seq = tcp->seq;
            }
            if (ntohl(tcp->ack) > ntohl(state.ack)) {
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

struct tcp_segment {
    uint32_t seq_init;
    uint32_t seq_end;
    uint32_t index;
    uint32_t last_byte_needed;
    unsigned int timestamp;

    static const size_t array_length = 8192;
    static const size_t header_length = sizeof(seq_init) + sizeof(seq_end) + sizeof(index) + sizeof(last_byte_needed) + sizeof(timestamp);
    static const size_t buffer_length = array_length - header_length;
    uint8_t data[buffer_length];

    static const bool debug = false;

    tcp_segment() : seq_init{0}, seq_end{0}, index{0}, last_byte_needed{0}, timestamp{0} {
        // fprintf(stderr, "creating tcp_segment ()\n");
    };

    tcp_segment(const struct tcp_segment &r) : seq_init{r.seq_init}, seq_end{r.seq_end}, index{r.index}, last_byte_needed{r.last_byte_needed}, timestamp{r.timestamp} {
        memcpy(data, r.data, r.index);
        // fprintf(stderr, "creating tcp_segment (*)\n");
    };

    tcp_segment(const struct tcp_header *tcp, size_t length, size_t bytes_needed, unsigned int sec) : seq_init{0}, seq_end{0}, index{0}, last_byte_needed{0}, timestamp{0} {
        // fprintf(stderr, "creating tcp_segment (**)\n");
        init_from_packet(tcp, length, bytes_needed, sec);
    };

    ~tcp_segment() {
        //fprintf(stderr, "destroying tcp_segment\n");
    };

    bool init_from_packet(const struct tcp_header *tcp, size_t length, size_t bytes_needed, unsigned int sec) {
        if (length + bytes_needed > tcp_segment::buffer_length) {
            //            fprintf(stderr, "warning: tcp segment length %zu exceeds buffer length %zu (length: %zu, bytes_needed: %zu)\n", length + bytes_needed, tcp_segment::buffer_length, length, bytes_needed);

            if (length < tcp_segment::buffer_length) {
                bytes_needed = tcp_segment::buffer_length - length;
            } else {
                // packet is longer than buffer; it should be processed immediately
                fprintf(stderr, "processing immediately as packet is longer than buffer\n");
                return false;
            }
        }
        // fprintf(stderr, "requesting reassembly\n");
        //        fprintf(stderr, "requesting reassembly (length: %zu)[%zu, %zu]\n", length + bytes_needed, length, bytes_needed);

        index = length;
        seq_init = ntohl(tcp->seq);
        seq_end = ntohl(tcp->seq) + length + bytes_needed;
        last_byte_needed = length + bytes_needed;
        timestamp = sec;
        if (debug) {
            fprintf(stderr, "inserted flow key with seq %u and packet length %zu\n", ntohl(tcp->seq), length);
            fprintf(stderr, "%s (src: %u, dst: %u)\tpacket: [%u,%zu]\tsegment: [%u,%u]",
                    __func__, ntohs(tcp->src_port), ntohs(tcp->dst_port), ntohl(tcp->seq)-seq_init, ntohl(tcp->seq)-seq_init+length, 0, index);
        }

        const uint8_t *src_start = (const uint8_t*)tcp;
        src_start += tcp_offrsv_get_header_length(tcp->offrsv);
        uint8_t *dst_start = data;
        uint32_t copy_len = length;
        memcpy(dst_start, src_start, copy_len);
        if (debug) {
            fprintf(stderr, "\tcopying %u bytes", copy_len);
            fprintf(stderr, "\tsegment: [%u,%u]\n", 0, index);
            //fprintf_json_string_escaped(stderr, "segment", dst_start, copy_len); fprintf(stderr, "\n");
        }
        return true;
    }

    struct tcp_segment *check_packet(const struct tcp_header *tcp, size_t length, unsigned int sec) {
        (void)sec;

        if (debug) {
            fprintf(stderr, "%s (src: %u, dst: %u)\tpacket: [%u,%zu]\tsegment: [%u,%u]",
                    __func__, ntohs(tcp->src_port), ntohs(tcp->dst_port), ntohl(tcp->seq)-seq_init, ntohl(tcp->seq)-seq_init+length, 0, index);
        }

        const uint8_t *src_start = (const uint8_t*)tcp;
        src_start += tcp_offrsv_get_header_length(tcp->offrsv);

        uint32_t pkt_start = ntohl(tcp->seq) - seq_init;
        uint32_t pkt_end   = pkt_start + length;
        if (pkt_start == index) {
            if (debug) {
                fprintf(stderr, "==");
            }

            if (pkt_end >= last_byte_needed) {
                uint8_t *dst_start = data + index;
                uint32_t copy_len = last_byte_needed - index;
                memcpy(dst_start, src_start, copy_len);
                index += copy_len;
                if (debug) {
                    fprintf(stderr, "\tcopying %u bytes", copy_len);
                    fprintf(stderr, "\tsegment: [%u,%u]", 0, index);
                    fprintf(stderr, "\tDONE\n");
                    //fprintf_json_string_escaped(stderr, "segment", data, last_byte_needed);  fprintf(stderr, "\n");
                }
                // fprintf(stderr, "reassembled packet\n");
                // fprintf(stderr, "reassembled packet age: %u\n", sec - timestamp);
                return this;

            } else {
                uint8_t *dst_start = data + index;
                uint32_t copy_len = pkt_end - index;
                memcpy(dst_start, src_start, copy_len);
                index += copy_len;
                if (debug) {
                    fprintf(stderr, "\tcopying %u bytes", copy_len);
                    fprintf(stderr, "\tsegment: [%u,%u]\n", 0, index);
                }
                return nullptr;
            }
        } else if (pkt_start < index) {

            if (pkt_end >= last_byte_needed) {
                pkt_start += (index - pkt_start);
                uint8_t *dst_start = data + index;
                uint32_t copy_len = last_byte_needed - index;
                memcpy(dst_start, src_start, copy_len);
                index += copy_len;
                if (debug) {
                    fprintf(stderr, "\tcopying %u bytes", copy_len);
                    fprintf(stderr, "\tsegment: [%u,%u]", 0, index);
                    fprintf(stderr, "\tDONE\n");
                    //fprintf_json_string_escaped(stderr, "segment", data, last_byte_needed);  fprintf(stderr, "\n");
                }
                fprintf(stderr, "reassembled packet\n");
                // fprintf(stderr, "reassembled packet age: %u\n", sec - timestamp);
                return this;
            } else {
                fprintf(stderr, "pkt_end < last_byte_needed\n");
            }
            if (debug) {
                fprintf(stderr, ">\n");
            }

        } else if (pkt_start > index) { // pkt_start > index
            //            fprintf(stderr, "pkt_start > index (difference: %u, pkt_start: %u, index: %u)\n", pkt_start - index, pkt_start, index);
        } else {
            fprintf(stderr, "wtf?\n");
        }
        if (debug) {
            fprintf(stderr, "\n");
        }
        return nullptr;
    }

    bool is_too_old(unsigned int sec) {
        unsigned int max_sec_in_table = 30;

        return (sec > timestamp + max_sec_in_table);
    }

    struct datum reassembled_segment() const {
        struct datum reassembled_tcp_data{data, data + index};
        return reassembled_tcp_data;
    }

};

void fprintf_json_string_escaped(FILE *f, const char *key, const uint8_t *data, unsigned int len);

struct tcp_reassembler {
    std::unordered_map<struct key, struct tcp_segment> segment_table;
    std::unordered_map<struct key, struct tcp_segment>::iterator reap_it;

    tcp_reassembler(unsigned int size) : segment_table{}, reap_it{segment_table.end()} {
        segment_table.reserve(size);
        reap_it = segment_table.end();
        // fprintf(stderr, "tcp_reassembler segment_table size: %zu bytes\n", size * sizeof(tcp_segment));
    }

    bool copy_packet(const struct key &k, unsigned int sec, const struct tcp_header *tcp, size_t length, size_t bytes_needed) {

        if (length == 0) {
            fprintf(stderr, "warning: got length=0 in copy_packet()\n");
            //            return;
        }

        tcp_segment segment;
        if (segment.init_from_packet(tcp, length, bytes_needed, sec)) {
            reap_it = segment_table.emplace(k, segment).first;
            ++reap_it;
            return true;
        }
        return false;
    }

    struct tcp_segment *check_packet(struct key &k, unsigned int sec, const struct tcp_header *tcp, size_t length) {

        auto it = segment_table.find(k);
        if (it != segment_table.end()) {
            return it->second.check_packet(tcp, length, sec);
        }
        return nullptr;
    }

    std::unordered_map<struct key, struct tcp_segment>::iterator reap(unsigned int sec) {

        // check for expired elements

        if (reap_it != segment_table.end() && reap_it->second.is_too_old(sec)) {
            // fprintf(stderr, "processing expired segment\n");
            // fprintf(stderr, "processing expired segment (age: %u seconds)\n", sec - reap_it->second.timestamp);
            return reap_it;  // not fully reassembled, but expired
        }
        return segment_table.end();
    }

    void remove_segment(key &k) {
        auto it = segment_table.find(k);
        if (it != segment_table.end()) {
            reap_it = segment_table.erase(it);
        }
        //    segment_table.erase(k);
    }

    void remove_segment(std::unordered_map<struct key, struct tcp_segment>::iterator it) {
        if (it != segment_table.end()) {
            reap_it = segment_table.erase(it);
        }
    }

    void count_all() {
        auto it = segment_table.begin();
        while (it != segment_table.end()) {
            fprintf(stderr, "counting segment\n");
            it = segment_table.erase(it);
        }
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
            //fprintf(stderr, "FLOW OLD\n");
            return false;
        }
        auto tmp = table.insert({k, sec}).first;
        update_reap_iterator(tmp);
        //fprintf(stderr, "FLOW NEW\n");
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

private:
    unsigned int sec;
    uint32_t seq;

    static const unsigned int timeout = 1; // seconds before flow timeout
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
            // fprintf(stderr, "tcp_flow_table size: %zu\n", table.size());
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
