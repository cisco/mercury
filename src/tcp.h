/*
 * tcp.h
 *
 *
 */

#ifndef MERC_TCP_H
#define MERC_TCP_H

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <unordered_map>
#include "mercury.h"

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

struct ipv6_addr {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    bool operator==(const ipv6_addr &rhs) const {
        return a == rhs.a && b == rhs.b && c == rhs.c && d == rhs.d;
    }
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
            ipv6_addr src;
            ipv6_addr dst;
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
    key(uint16_t sp, uint16_t dp, ipv6_addr sa, ipv6_addr da, uint8_t proto) {
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
    bool is_zero() {
        return ip_vers == 0;
    }
    bool operator==(const key &k) const {
        switch (ip_vers) {
        case 4:
            return src_port == k.src_port && dst_port == k.dst_port && protocol == k.protocol && k.ip_vers == 4 && addr.ipv4.src == k.addr.ipv4.src && addr.ipv4.dst == k.addr.ipv4.dst;
            break;
        case 6:
            return src_port == k.src_port && dst_port == k.dst_port && protocol == k.protocol && k.ip_vers == 6 && addr.ipv6.src == k.addr.ipv6.src && addr.ipv6.dst == k.addr.ipv6.dst;
        default:
            return 0;
        }
    }
};


namespace std {

    template <>  struct hash<struct key>  {
        std::size_t operator()(const struct key& k) const    {

            /* assume sizeof(size_t) == 8 for now */
            size_t x = (size_t) k.src_port | ((size_t) k.dst_port << 16) | ((size_t) k.ip_vers) << 32 | ((size_t) k.protocol) << 40;
            x ^= (size_t) k.addr.ipv6.src.a;
            x ^= (size_t) k.addr.ipv6.src.b;
            x ^= (size_t) k.addr.ipv6.src.c;
            x ^= (size_t) k.addr.ipv6.src.d;
            x ^= (size_t) k.addr.ipv6.dst.a;
            x ^= (size_t) k.addr.ipv6.dst.b;
            x ^= (size_t) k.addr.ipv6.dst.c;
            x ^= (size_t) k.addr.ipv6.dst.d;

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

    void tcp_initial_message_filter_init(void) {
        tcp_flow_table = {};
    }

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
 *    - pre-allocated storage array to hold reassembled packets
 *    - maximum length 8192 bytes
 *    - flow key maps to array entry
 *
 *    - copy_packet(packet, packet_length, additional_bytes_needed)
 *    - check_packet(packet, packet_length)
 */

struct tcp_segment {
    struct key k;
    uint32_t seq_init;
    uint32_t seq_end;
    uint32_t index;
    uint32_t last_byte_needed;
    static const size_t array_length = 8192;
    uint8_t data[array_length - sizeof(struct key) - sizeof(seq_end)];

    static const bool debug = false;

    tcp_segment() : k{}, seq_init{0}, seq_end{0}, index{0}, last_byte_needed{0}, data{} { };

    void init_from_packet(const struct key &k_in, const struct tcp_header *tcp, size_t length, size_t bytes_needed) {
        k = k_in;
        index = length;
        seq_init = ntohl(tcp->seq);
        seq_end = ntohl(tcp->seq) + length + bytes_needed;
        last_byte_needed = length + bytes_needed;
        if (debug) {
            fprintf(stderr, "inserted flow key (src: %u, dst: %u) with seq %u and packet length %zu\n", k.src_port, k.dst_port, ntohl(tcp->seq), length);
            fprintf(stderr, "%s (src: %u, dst: %u)\tpacket: [%u,%zu]\tsegment: [%u,%u]",
                    __func__, k.src_port, k.dst_port, ntohl(tcp->seq)-seq_init, ntohl(tcp->seq)-seq_init+length, 0, index);
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
    }

    struct tcp_segment *check_packet(const struct key &k_in, const struct tcp_header *tcp, size_t length) {
        if (k_in == k) {

            if (debug) {
                fprintf(stderr, "%s (src: %u, dst: %u)\tpacket: [%u,%zu]\tsegment: [%u,%u]",
                        __func__, k.src_port, k.dst_port, ntohl(tcp->seq)-seq_init, ntohl(tcp->seq)-seq_init+length, 0, index);
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
                    k.zeroize();
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
                fprintf(stderr, "<\n");

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
                    k.zeroize();
                    return this;
                }
                if (debug) {
                    fprintf(stderr, ">\n");
                }

            }
            if (debug) {
                fprintf(stderr, "\n");
            }
        }
        return nullptr;
    }

    bool operator==(const struct tcp_segment &s) const {
        return k == s.k && seq_init == s.seq_init && seq_end == s.seq_end && index == s.index && last_byte_needed == s.last_byte_needed ;
    }
};

void fprintf_json_string_escaped(FILE *f, const char *key, const uint8_t *data, unsigned int len);

struct tcp_reassembler {
    static const size_t array_size = 8192;
    struct tcp_segment segment[tcp_reassembler::array_size];
    struct tcp_segment *current_segment;

    tcp_reassembler() : segment{}, current_segment{segment} {
        for(auto &b : segment) {
            b.k.zeroize();
        }
    }

    void copy_packet(const struct key &k, const struct tcp_header *tcp, size_t length, size_t bytes_needed) {

        if (length + bytes_needed > tcp_segment::array_length) {
            fprintf(stderr, "warning: tcp segment length %zu exceeds buffer length %zu\n", length + bytes_needed, tcp_segment::array_length);
        }
        //fprintf(stderr, "requesting reassembly (length: %zu)[%zu, %zu]\n", length + bytes_needed, length, bytes_needed);

        std::hash<struct key> hasher;
        size_t h = hasher(k) % tcp_reassembler::array_size;
        struct tcp_segment &b = segment[h];

        if (b.k.is_zero() == false) {
            fprintf(stderr, "clobber: key is not zero\n");
        }
        b.init_from_packet(k, tcp, length, bytes_needed);
    }

    struct tcp_segment *check_packet(struct key &k, const struct tcp_header *tcp, size_t length) {

        // reap();
        const uint8_t *src_start = (const uint8_t*)tcp;
        src_start += tcp_offrsv_get_header_length(tcp->offrsv);

        std::hash<struct key> hasher;
        size_t h = hasher(k) % tcp_reassembler::array_size;
        struct tcp_segment &b = segment[h];
        return b.check_packet(k, tcp, length);
    }

    void reap() {
        if (current_segment->k.is_zero() == false) {
            fprintf(stderr, "reaper found nonzero key\n");
        }

        // advance pointer, and wrap around to start when needed
        if (current_segment++ == (segment + tcp_reassembler::array_size)) {
            current_segment = segment;
        }
    }

};

#endif /* MERC_TCP_H */
