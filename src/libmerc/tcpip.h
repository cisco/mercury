/*
 * tcpip.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef TCPIP_H
#define TCPIP_H

#include "tcp.h"
#include "ip.h"
#include "datum.h"
#include "protocol.h"
#include "json_object.h"
#include "fingerprint.h"
#include "flow_key.h"

/*
 * TCP fingerprinting
 *
 * The following data are extracted from the SYN packet: the ordered
 * list of all TCP option kinds, with repeated values allowed in the
 * list.  The length and data for the MSS and WS TCP options are
 * included, but are not for other option kinds.
 */

static constexpr bool report_IP = false;  // compile-time option

/*
 * TCP header as per RFC 793
 *
 *    0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Source Port          |       Destination Port        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                        Sequence Number                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Acknowledgment Number                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Data |       |C|E|U|A|P|R|S|F|                               |
 *  | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
 *  |       |       |R|E|G|K|H|T|N|N|                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           Checksum            |         Urgent Pointer        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Options                    |    Padding    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                             data                              |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/*
 * TCP macros
 *
 * The following macros indicate the lengths of each field in the TCP
 * header, in the same order of appearance as on the wire.  The needed
 * option kinds (EOL, NOP, MSS, and WS) are defined, as is the value
 * of the Flag field for a SYN pakcet (TCP_SYN).
 */

#define L_src_port      2
#define L_dst_port      2
#define L_tcp_seq       4
#define L_tcp_ack       4
#define L_tcp_offrsv    1
#define L_tcp_flags     1
#define L_tcp_win       2
#define L_tcp_csm       2
#define L_tcp_urp       2
#define L_option_kind   1
#define L_option_length 1

#define TCP_OPT_EOL     0
#define TCP_OPT_NOP     1
#define TCP_OPT_MSS     2
#define TCP_OPT_WS      3
#define TCP_OPT_TS      8

#define TCP_FIN      0x01
#define TCP_SYN      0x02
#define TCP_RST      0x04
#define TCP_PSH      0x08
#define TCP_ACK      0x10
#define TCP_URG      0x20
#define TCP_ECE      0x40
#define TCP_CWR      0x80

#define TCP_FIXED_HDR_LEN 20

#define tcp_offrsv_get_length(offrsv) ((offrsv >> 4) * 4)


/*
 * From RFC 793 (TCP):
 *
 *   Options may occupy space at the end of the TCP header and are a
 *   multiple of 8 bits in length.  All options are included in the
 *   checksum.  An option may begin on any octet boundary.  There are two
 *   cases for the format of an option:
 *
 *     Case 1:  A single octet of option-kind.
 *
 *     Case 2:  An octet of option-kind, an octet of option-length, and
 *              the actual option-data octets.
 *
 *   The option-length counts the two octets of option-kind and
 *   option-length as well as the option-data octets.
 *
 */

struct tcp_option : public datum {
    uint8_t kind;
    uint8_t len;

    tcp_option() : datum{NULL, NULL}, kind{0}, len{0} {};

    void parse(struct datum &p) {
        p.read_uint8(&kind);
        if (kind == 0 || kind == 1) {
            return;
        }
        p.read_uint8(&len);
        if (len < 2) {
            return;
        }
        datum::parse(p, len - 2);
    }

};

struct tcp_packet : public base_protocol {
    const struct tcp_header *header = nullptr;
    struct datum tcp_options;
    ip *ip_pkt = nullptr;          // TODO: make this const?
    uint32_t data_length = 0;
    uint32_t additional_bytes_needed = 0;
    uint8_t indefinite_reassembly = 0;
    // supplementary_reassembly refers to case where the specific tcp pkt may have a
    // complete protocol msg, but may also be used by another protocol in reassembly
    bool supplementary_reassembly = false;

    tcp_packet(datum &p, ip *outer=nullptr) : ip_pkt{outer} {
        parse(p);
    };

    void parse(struct datum &p) {
        header = p.get_pointer<tcp_header>();
        if (header == nullptr) {
            return;  // too short
        }

        tcp_options.parse(p, tcp_offrsv_get_length(header->offrsv) - TCP_FIXED_HDR_LEN);
        data_length = p.length();
        //        fprintf(stderr, "tcp.data_length: %u\n", data_length);
    }

    bool is_valid()     const { return header != nullptr && ip_pkt != nullptr; }
    bool is_not_empty() const { return header != nullptr && ip_pkt != nullptr; }

    void reassembly_needed(uint32_t num_bytes_needed, uint8_t indef_reassembly = 0) {
        additional_bytes_needed = num_bytes_needed;
        indefinite_reassembly = indef_reassembly;
    }

    void set_supplementary_reassembly() { supplementary_reassembly = true; }

    bool is_SYN() {
        return header && TCP_IS_SYN(header->flags) && !TCP_IS_ACK(header->flags);
    }

    bool is_SYN_ACK() {
        return header && TCP_IS_SYN(header->flags) && TCP_IS_ACK(header->flags);
    }

    bool is_FIN() {
        return header && TCP_IS_FIN(header->flags);
    }

    bool is_RST() {
        return header && TCP_IS_RST(header->flags);
    }

    uint32_t seq() const { return hton(header->seq); }

    void set_key(struct key &k) {
        if (header) {
            k.src_port = ntoh(header->src_port);
            k.dst_port = ntoh(header->dst_port);
        }
    }
    void fingerprint (struct buffer_stream &buf) {
        if (header == NULL) {
            return;
        }
        buf.write_char('(');
        buf.raw_as_hex((const uint8_t *)&header->window, sizeof(header->window));
        buf.write_char(')');

        // process sequence of TCP options
        //
        buf.write_char('(');
        struct datum tmp = tcp_options;
        while (tmp.length() > 0) {
            struct tcp_option opt;
            opt.parse(tmp);
            buf.write_char('(');
            buf.raw_as_hex(&opt.kind, sizeof(opt.kind));
            if (opt.kind == TCP_OPT_MSS || opt.kind == TCP_OPT_WS) {
                buf.raw_as_hex(&opt.len, sizeof(opt.len));
                buf.raw_as_hex(opt.data, opt.length());
            }
            buf.write_char(')');
        }
        buf.write_char(')');
    }

    void compute_fingerprint(class fingerprint &fp) {

        // note: we assume that this function is invoked only on a syn or syn/ack packet
        //
        fp.set_type(is_SYN_ACK() ? fingerprint_type_tcp_server : fingerprint_type_tcp);
        fp.add(*ip_pkt);
        fp.add(*this);
        fp.final();
    }

    void write_timestamp(struct json_object &json_tcp) {
        struct datum tmp = tcp_options;
        while (tmp.length() > 0) {
            struct tcp_option opt;
            opt.parse(tmp);
            if (opt.kind == TCP_OPT_TS) {
                struct json_object json_ts{json_tcp, "timestamp"};
                uint64_t ts = 0;
                if (opt.read_uint(&ts, 4)) {
                    json_ts.print_key_uint("ts_val", ts);
                }
                if (opt.read_uint(&ts, 4) && ts != 0) {
                    json_ts.print_key_uint("ts_ecr", ts);
                }
                json_ts.close();
            }
        }
    }
    void write_json(struct json_object &o, bool metadata=false) {

        if (metadata) {
            if (is_SYN()) {
                if (report_IP) {
                    ip_pkt->write_json(o);
                }
                struct json_object json_tcp{o, "tcp"};
                json_tcp.print_key_uint("seq", hton(header->seq));
                write_timestamp(json_tcp);
                json_tcp.close();

            } else if (is_SYN_ACK()) {
                if (report_IP) {
                    ip_pkt->write_json(o);
                }
                struct json_object json_tcp{o, "tcp_server"};
                json_tcp.print_key_uint("seq", hton(header->seq));
                write_timestamp(json_tcp);
                json_tcp.close();
            }
        }
    }
};

namespace {

    [[maybe_unused]] inline int tcp_packet_fuzz_test(const uint8_t *data, size_t size) {
        return json_output_fuzzer<tcp_packet>(data, size);
    }

};

#endif /* TCPIP_H */
