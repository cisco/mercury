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
};

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

typedef unsigned __int128 uint128_t;

#pragma pack (1)
struct key {
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t ip_vers;
    union {
	struct {
	    uint32_t src;
	    uint32_t dst;
	} ipv4;
	struct {
	    uint128_t src;
	    uint128_t dst;
	} ipv6;	
    } addr;
    
    key(uint16_t sp, uint16_t dp, uint32_t sa, uint32_t da) {
	src_port = sp;
	dst_port = dp;
	ip_vers = 4;
	addr.ipv6.src = 0;   /* zeroize v6 src addr */
	addr.ipv6.dst = 0;   /* zeroize v6 dst addr */
	addr.ipv4.src = sa;
	addr.ipv4.dst = da;
    }
    key(uint16_t sp, uint16_t dp, uint128_t sa, uint128_t da) {
	src_port = sp;
	dst_port = dp;
	ip_vers = 6;
	addr.ipv6.src = sa;
	addr.ipv6.dst = da;
    }
    
    bool operator==(const key &k) const {
	switch (ip_vers) {
	case 4:
	return src_port == k.src_port && dst_port == k.dst_port && k.ip_vers == 4 && addr.ipv4.src == k.addr.ipv4.src && addr.ipv4.dst == k.addr.ipv4.dst;
	break;
	case 6:
	return src_port == k.src_port && dst_port == k.dst_port && k.ip_vers == 6 && addr.ipv6.src == k.addr.ipv6.src && addr.ipv6.dst == k.addr.ipv6.dst;
	default:
	return 0;
	}
    }
};

// class key could use this comparison strategy: 
//	return memcmp(this, k, sizeof(class key));

namespace std {

    template <>  struct hash<struct key>  {
	std::size_t operator()(const struct key& k) const    {
	    
	    /* assume sizeof(size_t) == 8 for now */
	    size_t x = (size_t) k.src_port | ((size_t) k.dst_port << 16) | ((size_t) k.ip_vers << 32);
	    x ^= (size_t) k.addr.ipv6.src;
	    x ^= (size_t) (k.addr.ipv6.src >> 64);
	    x ^= (size_t) k.addr.ipv6.dst;
	    x ^= (size_t) (k.addr.ipv6.dst >> 64);

	    return x;
	}
    };
}

#define BYTE_BINARY_FORMAT "%c%c%c%c%c%c%c%c"
#define UINT8_BINARY(x)  \
  (x & 0x80 ? '1' : '0'), \
  (x & 0x40 ? '1' : '0'), \
  (x & 0x20 ? '1' : '0'), \
  (x & 0x10 ? '1' : '0'), \
  (x & 0x08 ? '1' : '0'), \
  (x & 0x04 ? '1' : '0'), \
  (x & 0x02 ? '1' : '0'), \
  (x & 0x01 ? '1' : '0') 

#define tcp_offrsv_get_header_length(offrsv) ((offrsv >> 4) * 4)
//#define tcp_offrsv_get_header_length(offrsv) ((offrsv >> 2) & 0x3C)

#define ACCEPT_PACKET 100
#define DROP_PACKET     0

struct tcp_initial_message_filter {
    std::unordered_map<struct key, struct tcp_state> tcp_flow_table;

    tcp_initial_message_filter() {
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
	
    size_t apply(struct key &k, const struct tcp_header *tcp, size_t length) {
	(void)k;

	size_t retval = DROP_PACKET; 
	
	struct key kk(tcp->src_port, tcp->dst_port, (uint32_t)0, (uint32_t)0);
	size_t data_length = length - tcp_offrsv_get_header_length(tcp->offrsv);
	
	auto it = tcp_flow_table.find(kk);
	if (it == tcp_flow_table.end()) {
	    
	    fprintf(stderr, "src: %5u\tdst: %5u\t", ntohs(tcp->src_port), ntohs(tcp->dst_port));
	    fprintf(stderr, "seq: %10u\tack: %10u\t", ntohl(tcp->seq), ntohl(tcp->ack));
	    fprintf(stderr, "len: %5zu\t", length - tcp_offrsv_get_header_length(tcp->offrsv));
	    fprintf(stderr, "flags: " BYTE_BINARY_FORMAT "\t", UINT8_BINARY(tcp->flags));
	    fprintf(stderr, "hdrlen: %5d\tpkt: %5zu\t", tcp_offrsv_get_header_length(tcp->offrsv), length);
	    fprintf(stderr, "NEW\n");

	    struct tcp_state state = { tcp->seq, tcp->ack, 0, tcp->seq, tcp->ack, listening };
	    tcp_flow_table[kk] = state;
	    retval = ACCEPT_PACKET;

	} else {
	    
	    struct tcp_state state = it->second;

	    if (state.ack == 0) { 
		state.ack = tcp->ack;
		state.init_ack = tcp->ack;
	    }

	    uint32_t rel_ack = ntohl(tcp->ack) - ntohl(state.init_ack);
	    uint32_t rel_seq = ntohl(tcp->seq) - ntohl(state.init_seq);

	    if (data_length > 0) {
		if (ntohl(tcp->seq) >= ntohl(state.seq)) {
		    if (ntohl(tcp->ack) <= ntohl(state.ack)) {
			if (state.disposition == listening) { 
			    state.disposition = talking;
			    state.msg_num++;
			}
		    } else {
			state.disposition = listening;
		    }
		}
	    } else {
		if (ntohl(tcp->ack) > ntohl(state.ack)) {
		    state.disposition = listening;
		}
	    }
	    if (state.disposition == talking && state.msg_num < 2) {
		retval = ACCEPT_PACKET;
	    }
	    if (ntohl(tcp->seq) > ntohl(state.seq)) {
		state.seq = tcp->seq;
	    }
	    if (ntohl(tcp->ack) > ntohl(state.ack)) {
		state.ack = tcp->ack;
	    }
	    tcp_flow_table[kk] = state;		
	    
	    fprintf(stderr, "src: %5u\tdst: %5u\t", ntohs(tcp->src_port), ntohs(tcp->dst_port));
	    fprintf(stderr, "seq: %10u\tack: %10u\t", rel_seq, rel_ack);
	    fprintf(stderr, "len: %5zu\t", data_length);
	    fprintf(stderr, "flags: " BYTE_BINARY_FORMAT "\t", UINT8_BINARY(tcp->flags));
	    // fprintf(stderr, "len: %5d\tpkt: %5zu\n", tcp_offrsv_get_length(tcp->offrsv), length);
	    fprintf(stderr, "msg: %u\t", state.msg_num);
	    fprintf(stderr, state.disposition == listening ? "listening\t" : "talking  \t" );
	    if (retval) { fprintf(stderr, "ACCEPT\n"); } else { fprintf(stderr, "\n"); }
	}
	
	return retval;
    }
};

//  example use of tcp_init_msg_filter.apply():
//
//    struct tcp_initial_message_filter tcp_init_msg_filter;
//
//    struct key k(0,0,(uint32_t)0,(uint32_t)0);
//    const struct tcp_header *tcp = (const struct tcp_header *)data;
//    tcp_init_msg_filter.apply(k, tcp, init_len);


/*
 * modular arithmetic comparisons, for tcp Seq and Ack processing
 */

#define LT(X, Y)  ((int32_t)((X)-(Y)) <  0)
#define LEQ(X, Y) ((int32_t)((X)-(Y)) <= 0)
#define GT(X, Y)  ((int32_t)((X)-(Y)) >  0)
#define GEQ(X, Y) ((int32_t)((X)-(Y)) >= 0)


#endif /* MERC_TCP_H */
