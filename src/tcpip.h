/*
 * tcpip.h
 */

#ifndef TCPIP_H
#define TCPIP_H

#include "tcp.h"
#include "parser.h"
#include "json_object.h"

/*
 * TCP fingerprinting
 *
 * The following data are extracted from the SYN packet: the ordered
 * list of all TCP option kinds, with repeated values allowed in the
 * list.  The length and data for the MSS and WS TCP options are
 * included, but are not for other option kinds.
 */

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

struct tcp_option : public parser {
    uint8_t kind;
    uint8_t len;

    tcp_option() : parser{NULL, NULL}, kind{0}, len{0} {};

    void parse(struct parser &p) {
        p.read_uint8(&kind);
        if (kind == 0 || kind == 1) {
            return;
        }
        p.read_uint8(&len);
        if (len < 2) {
            return;
        }
        parser::parse(p, len - 2);
    }

};

struct tcp_packet {
    const struct tcp_header *header;
    struct parser tcp_options;

    tcp_packet() : header{NULL}, tcp_options{NULL, NULL} {};

    void parse(struct parser &p) {
        if (p.length() < (int)sizeof(struct tcp_header)) {
            return;
        }
        header = (const struct tcp_header *)p.data;
        p.skip(sizeof(struct tcp_header));

        tcp_options.parse(p, tcp_offrsv_get_length(header->offrsv) - TCP_FIXED_HDR_LEN);

    }

    bool is_SYN() {
        return header && TCP_IS_SYN(header->flags);
    }

    void set_key(struct key &k) {
        if (header) {
            k.src_port = ntohs(header->src_port);
            k.dst_port = ntohs(header->dst_port);
        }
    }
    void operator() (struct buffer_stream &buf) {
        buf.write_char('\"');
        //buf.raw_as_hex(tcp_options.data, tcp_options.length());

        buf.write_char('(');
        buf.raw_as_hex((const uint8_t *)&header->window, sizeof(header->window));
        buf.write_char(')');
        struct parser tmp = tcp_options;
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
        buf.write_char('\"');
    }

    void write_json(struct json_object &o) {
        struct json_object json_tcp{o, "tcp"};
        json_tcp.print_key_value("fingerprint", *this);
        json_tcp.close();
    }
};

#endif /* TCPIP_H */
