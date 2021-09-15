// ip.h
//
// internet protocol (ip) packet processing
//

#ifndef MERC_IP_H
#define MERC_IP_H

#include "datum.h"
#include "json_object.h"

// IP (v4 and v6) parsing
//

#define TTL_MASK 0xe0

// IPv6 header length
#define IPV6_HDR_LENGTH    40
#define IPV6_EXT_HDR_LEN    8

// IPv4 header (following RFC 791)
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |Version|  IHL  |Type of Service|          Total Length         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Identification        |Flags|      Fragment Offset    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Time to Live |    Protocol   |         Header Checksum       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Source Address                          |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Destination Address                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Options                    |    Padding    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//
struct ipv4_header {
    unsigned char  vhl;    /* version and hdr length */
    unsigned char  tos;    /* type of service        */
    unsigned short len;    /* packet length          */
    unsigned short id;     /* identification         */
    unsigned short flgoff; /* flags, frag off field  */
    unsigned char  ttl;    /* time to live           */
    unsigned char  prot;   /* protocol               */
    unsigned short cksum;  /* checksum               */
    uint32_t       src_addr;  /* source address         */
    uint32_t       dst_addr;  /* destination address    */
} __attribute__((packed));

class ipv4_packet {
    const struct ipv4_header *header;

 public:

    ipv4_packet() : header{NULL} {
        // defer parsing until later; TODO: clean this up
    }

    ipv4_packet(struct datum *p, struct key *k) : header{NULL} {
        parse(*p, *k);
    }

    uint8_t get_transport_protocol() const {
        if (header) {
            return header->prot;
        }
        return 255; // indicate error by returning reserved value
    }

    void parse(struct datum &p, struct key &k) {
        if (p.length() < (int)sizeof(struct ipv4_header)) {
            return;
        }
        header = (const struct ipv4_header *)p.data;
        k.addr.ipv4.src = header->src_addr;
        k.addr.ipv4.dst = header->dst_addr;
        k.protocol = header->prot;
        k.ip_vers = 4;  // ipv4

        // check Total Length field, and trim data from parser if appropriate
        //
        datum_set_data_length(&p, ntohs(header->len));
        p.skip(sizeof(struct ipv4_header));

        // TODO: parse options
    }

    void debug_output() {
        if (header) {
            fprintf(stderr, "ipv4.ttl: %x (%x)\n", header->ttl, header->ttl & 0xe0);   // TODO: deleteme
            //fprintf(stderr, "ipv4.id: %zu\n", id);   // TODO: deleteme
        }
    }

    // fingerprinting
    //
    void write_fingerprint(json_object &o) {
        if (header) {
            o.print_key_value("ip", *this);
        }
    }
    void operator() (struct buffer_stream &buf) {
        if (header) {
            // version
            //
            buf.puts("(40)");

            // identification field, if zero
            //
            buf.write_char('(');
            if (header->id == 0) {
                buf.raw_as_hex((const uint8_t *)&header->id, sizeof(header->id));
            }
            buf.write_char(')');

            // ttl (time to live, or hop count)
            //
            buf.write_char('(');
            uint8_t tmp = header->ttl & TTL_MASK;
            buf.raw_as_hex((const uint8_t *)&tmp, sizeof(tmp));
            buf.write_char(')');
        }
    }

    void write_json(struct json_object &o) {
        if (header) {
            struct json_object json_ip{o, "ip"};
            json_ip.print_key_uint("ttl", header->ttl);
            json_ip.print_key_uint("id", ntohs(header->id));
            json_ip.close();
        }
    }

};

// IPv6 header (following RFC 2460)
//
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |Version| Traffic Class |           Flow Label                  |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Payload Length        |  Next Header  |   Hop Limit   |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +                         Source Address                        +
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +                      Destination Address                      +
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//
// ipv6 extension header format (from RFC 6564)
//
//      0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |  Next Header  |  Hdr Ext Len  |                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
//  |                                                               |
//  .                                                               .
//  .                  Header Specific Data                         .
//  .                                                               .
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//  Next Header          8-bit selector.  Identifies the type of header
//                       immediately following the extension header.
//                       Uses the same values as the IPv4 Protocol field
//                       [IANA_IP_PARAM].
//
//  Hdr Ext Len          8-bit unsigned integer.  Length of the extension
//                       header in 8-octet units, not including the first
//                       8 octets.
//
//  Header Specific      Variable length.  Fields specific to the
//  Data                 extension header.
//
//

#define L_ipv6_version_tc_hi         1
#define L_ipv6_tc_lo_flow_label_hi   1
#define L_ipv6_flow_label_lo         2
#define L_ipv6_payload_length        2
#define L_ipv6_next_header           1
#define L_ipv6_hop_limit             1
#define L_ipv6_source_address       16
#define L_ipv6_destination_address  16
#define L_ipv6_hdr_ext_len           1
#define L_ipv6_ext_hdr_base          8

class ipv6_extension_header : public datum {
    uint8_t next_header;
    uint8_t length;

public:

    // following https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#extension-header
    //
    enum type : uint8_t  {
        hop_by_hop = 0,   // IPv6 Hop-by-Hop Option [RFC8200]
        routing    = 43,  // Routing Header for IPv6 [RFC8200][RFC5095]
        fragment   = 44,  // Fragment Header for IPv6 [RFC8200]
        esp        = 50,  // Encapsulating Security Payload [RFC4303]
        ah         = 51,  // Authentication Header	[RFC4302]
        none       = 59,  // No next header [RFC8200]
        dest_opt   = 60,  // Destination Options for IPv6 [RFC8200]
        mobility   = 135, // Mobility Header [RFC6275]
        hip        = 139, // Host Identity Protocol [RFC7401]
        shim6      = 140, // Shim6 Protocol [RFC5533]
        reserved   = 255
    };
    // 253 = Use for experimentation and testing [RFC3692][RFC4727]
    // 254 = Use for experimentation and testing [RFC3692][RFC4727]

    ipv6_extension_header() { }

    void parse(struct datum &p) {

        p.read_uint8(&next_header);

        switch(next_header) {
        case hop_by_hop:
        case routing:
        case fragment:
        case esp:
        case ah:
        case dest_opt:
        case mobility:
        case hip:
        case shim6:
            p.read_uint8(&length);
            datum::parse(p, length*8 - 6); // header-specific data field
            break;
        case none: // ????
            break;
        case reserved:
        default:
            break;
        }
    }

    uint8_t get_next_header() const { return next_header; }

    static bool is_extension(uint8_t type) {
        switch (type) {
        case hop_by_hop:
        case routing:
        case fragment:
        case esp:
        case ah:
        case dest_opt:
        case mobility:
        case hip:
        case shim6:
            return true;
            break;
        case none: // ????
        case reserved:
        default:
            break;
        }
        return false;
    }

};

struct ipv6_header {
    uint8_t bytes[4];
    unsigned short  len;      /* payload length         */
    unsigned char   nxh;      /* next header            */
    unsigned char   ttl;      /* hop limit (time to live) */
    ipv6_address    src_addr; /* source address         */
    ipv6_address    dst_addr; /* destination address    */

    uint8_t version() const {
        return bytes[0] & 0xf0;
    }

    uint8_t traffic_class() const {
        return (bytes[0] << 4) | (bytes[1] >> 4);
    }

    uint32_t flow_label() const {
        return (uint32_t)bytes[1] << 16 | (uint32_t)bytes[2] << 8 | bytes[3];
    }

} __attribute__((packed));


class ipv6_packet {
    const struct ipv6_header *header;
    uint8_t transport_protocol;

public:

    ipv6_packet() : header{NULL}, transport_protocol{255} {
        // defer parsing until later; TODO: clean this up
    }

    ipv6_packet(struct datum *p, struct key *k) : header{NULL}, transport_protocol{255} {
        parse(*p, *k);
    }

    uint8_t get_transport_protocol() const {
        if (header) {
            return header->nxh;
        }
        return ipv6_extension_header::type::reserved; // indicate error by returning reserved value
    }

    void parse(struct datum &p, struct key &k) {
        if (p.length() < (int)sizeof(struct ipv6_header)) {
            return;
        }
        header = (const struct ipv6_header *)p.data;
        k.addr.ipv6.src = header->src_addr;
        k.addr.ipv6.dst = header->dst_addr;
        k.ip_vers = 6;  // ipv4
        p.skip(sizeof(struct ipv6_header));

        // check payload length field, and trim data from parser if appropriate
        //
        datum_set_data_length(&p, ntohs(header->len));

        //        fprintf(stderr, "nh: ");

        // loop over extensions headers until we find an upper layer protocol
        //
        uint8_t next_header = header->nxh;
        while (p.length() > 0) {
            //fprintf(stderr, "%u:", next_header);
            if (!ipv6_extension_header::is_extension(next_header)) {
                break;
            }
            class ipv6_extension_header ext_hdr;
            ext_hdr.parse(p);
            next_header = ext_hdr.get_next_header();
        }
        k.protocol = transport_protocol = next_header;

        // fprintf(stderr, "\n");
        //        fprintf(stderr, "ipv6.transport_protcol: %u\n", transport_protocol);
    }

    void debug_output() {
        if (header) {
            fprintf(stderr, "ipv6.ttl: %x (%x)\n", header->ttl, header->ttl & 0xe0);   // TODO: deleteme
        }
    }

    // fingerprinting
    //
    void write_fingerprint(json_object &o) {
        if (header) {
            o.print_key_value("ip", *this);
        }
    }
    void operator() (struct buffer_stream &buf) {
        if (header) {

            // version
            //
            buf.puts("(60)");

            // identification field, if zero
            //
            buf.write_char('(');
            uint32_t flow_label = header->flow_label();
            if (flow_label == 0) {
                buf.raw_as_hex((const uint8_t *)&flow_label, sizeof(flow_label));  // TODO: we ought to print this as a 24-bit value
            }
            buf.write_char(')');

            // ttl (time to live, or hop count)
            //
            buf.write_char('(');
            uint8_t tmp = header->ttl & TTL_MASK;
            buf.raw_as_hex((const uint8_t *)&tmp, sizeof(tmp));
            buf.write_char(')');

        }
    }

    void write_json(struct json_object &o) {
        if (header) {
            struct json_object json_ip{o, "ip"};
            json_ip.print_key_uint("version", header->version() >> 4);
            json_ip.print_key_uint("ttl", header->ttl);
            json_ip.print_key_uint("id", header->flow_label());
            json_ip.close();
        }
    }

};


#include <variant>

using ip = std::variant<std::monostate, ipv4_packet, ipv6_packet>;

void set_ip_packet(ip &packet, datum &d, key &k) {
    uint8_t version;
    d.lookahead_uint8(&version);  // peek at first half-byte for version field
    switch(version & 0xf0) {
    case 0x40:
        {
            packet.emplace<ipv4_packet>();
            auto &p = std::get<ipv4_packet>(packet);
            p.parse(d, k);
            break;
        }
    case 0x60:
        {
            packet.emplace<ipv6_packet>();
            auto &p = std::get<ipv6_packet>(packet);
            p.parse(d, k);
            break;
        }
    default:
        packet.emplace<std::monostate>();
        break;
    }
}

struct get_transport_protocol {

    template <typename T>
    uint8_t operator()(T &r) {
        return r.get_transport_protocol();
    }

    uint8_t operator()(std::monostate &) {
        return 255;  // reserved, meaning 'none'
    }
};

struct ip_pkt_write_json {
    struct json_object &json_record;

    ip_pkt_write_json(struct json_object &record) : json_record{record} {}

    template <typename T>
    void operator()(T &r) {
        r.write_json(json_record);
    }

    void operator()(std::monostate &) {
    }
};

struct ip_pkt_write_fingerprint {
    struct json_object &json_record;

    ip_pkt_write_fingerprint(json_object &record) : json_record{record} {}

    // fingerprinting
    //
    template <typename T>
    void operator()(T &r) {
        r.write_fingerprint(json_record);
    }

    void operator()(std::monostate &) {
    }
};

#endif // MERC_IP_H
