// ip.h
//
// internet protocol (ip) packet processing
//

#ifndef MERC_IP_H
#define MERC_IP_H

#include "datum.h"
#include "tcp.h"
#include "json_object.h"
#include "flow_key.h"
#include <variant>
#include <utility>


// IP (v4 and v6) packet parsing, fingerprinting, and metadata reporting
//


// TTL mask is used to zeroize the low-order bits of the TTL (v4) and
// Hop Count (v6) field, while creating IP fingerprints
//
#define TTL_MASK 0xe0


// IPv4 header (following RFC 791)
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |Version|  IHL  |Type of Service|          Total Length         |
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
    struct ipv4_header *header;

 public:

    void set_src_ip(uint32_t new_addr) {
        if (header) {
            header->src_addr = new_addr;
        }
    }

    ipv4_address get_src_addr() const {
        if (header) {
            return ipv4_address{header->src_addr};
        }
        return 0; // error
    }

    void set_dst_addr(uint32_t new_addr) {
        if (header) {
            header->dst_addr = new_addr;
        }
    }

    ipv4_address get_dst_addr() const {
        if (header) {
            return ipv4_address{header->dst_addr};
        }
        return 0; // error
    }

    ipv4_packet() : header{NULL} { }

    ipv4_packet(struct datum &p, struct key &k) : header{NULL} {
        parse(p, k);
    }

    uint8_t get_transport_protocol() const {
        if (header) {
            return header->prot;
        }
        return 255; // indicate error by returning reserved value
    }

    void parse(struct datum &p, struct key &k) {
        header = p.get_pointer<ipv4_header>();
        if (header == nullptr) {
            return;  // too short
        }
        p.trim_to_length(ntoh(header->len) - sizeof(ipv4_header));

        k.addr.ipv4.src = header->src_addr;
        k.addr.ipv4.dst = header->dst_addr;
        k.protocol = header->prot;
        k.ip_vers = 4;  // ipv4

        // TODO: parse options
    }

    // fingerprinting
    //
    void fingerprint (struct buffer_stream &buf) {
        if (header) {
            // version
            //
            buf.puts("(40)");

            // identification field, if zero
            //
            buf.write_char('(');
            if (header->id == 0) {
                buf.write_char('0');
                buf.write_char('0');
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
            json_ip.print_key_uint("version", header->vhl >> 4);
            json_ip.print_key_uint("ttl", header->ttl);
            json_ip.print_key_uint_hex("id", ntoh(header->id));
            json_ip.close();
        }
    }

    bool is_not_empty() const { return header != nullptr; }
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


// IPv6 extension header format (from RFC 6564)
//
// This format is used for these extensions:
//
//   Hop-by-Hop          (https://www.rfc-editor.org/rfc/rfc8200.html#section-4.3)
//   Routing             (https://www.rfc-editor.org/rfc/rfc8200.html#section-4.4)
//   Destination Options (https://www.rfc-editor.org/rfc/rfc8200.html#section-4.6)
//   Mobility            (https://www.rfc-editor.org/rfc/rfc6275.html#section-6.1.1)
//   HIP (?)             (https://www.rfc-editor.org/rfc/rfc8200.html#section-4.6)
//   Shim6               (https://www.rfc-editor.org/rfc/rfc5533.html#section-5.2)
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

//  Fragment Header (from RFC 2460)
//
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                         Identification                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//   Reserved field is set to zero.
//

// Authentication Header (from RFC 4302)
//
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | Next Header   |  Payload Len  |          RESERVED             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                 Security Parameters Index (SPI)               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Sequence Number Field                      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                Integrity Check Value-ICV (variable)           |
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//   The Payload Len field specifies the length of AH in 4-octet
//   units, minus "2".  For IPv6, this value must be a multiple of
//   eight octets.

class ipv6_extension_header {
    uint8_t next_header;
    uint8_t hdr_ext_len;
    datum data;

public:

    // The IPv6 next_header field can hold either an IP protocol
    // number or an extension header type.  To correctly parse an IPv6
    // packet, extension headers must be identified so that they can
    // be processed.  The IANA lists the extension types at
    // https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#extension-header.
    // We use that list here, after removing ESP, which is more like a
    // protocol than an extension.
    //
    // Different extension types have different formats
    //
    enum type : uint8_t  {
        hop_by_hop = 0,   // IPv6 Hop-by-Hop Option [RFC8200]
        routing    = 43,  // Routing Header for IPv6 [RFC8200][RFC5095]
        fragment   = 44,  // Fragment Header for IPv6 [RFC8200]
        ah         = 51,  // Authentication Header	[RFC4302]
        dest_opt   = 60,  // Destination Options for IPv6 [RFC8200]
        mobility   = 135, // Mobility Header [RFC6275]
        hip        = 139, // Host Identity Protocol [RFC7401]
        shim6      = 140, // Shim6 Protocol [RFC5533]
        reserved   = 255
    };
    // The type codes that we exclude because they don't really act as
    // extensions (ESP) or there is no published format (253, 254)
    // are:
    //
    // esp  = 50  Encapsulating Security Payload [RFC4303]
    // none = 59  No next header [RFC8200]
    // 253        Use for experimentation and testing [RFC3692][RFC4727]
    // 254        Use for experimentation and testing [RFC3692][RFC4727]

    static bool is_extension(uint8_t type) {
        switch (type) {
        case hop_by_hop:
        case routing:
        case fragment:
        case ah:
        case dest_opt:
        case mobility:
        case hip:
        case shim6:
            return true;
            break;
        case reserved:
        default:
            break;
        }
        return false;
    }

    ipv6_extension_header(struct datum &p, uint8_t header) : next_header{type::reserved}, hdr_ext_len{0}, data{} { parse(p, header); }

    void parse(struct datum &p, uint8_t header) {

        p.read_uint8(&next_header);

        switch(header) {
        case hop_by_hop:
        case routing:
        case dest_opt:
        case mobility:
        case hip:
        case shim6:
            p.read_uint8(&hdr_ext_len);
            data.parse(p, hdr_ext_len*8 + 6);
            break;
        case fragment:
            data.parse(p, 7);
            break;
        case ah:
            p.read_uint8(&hdr_ext_len);
            data.parse(p, hdr_ext_len*4 + 6);
            break;
        case reserved:
        default:
            break;
        }
    }

    uint8_t get_next_header() const { return next_header; }

    void debug_output(FILE *f) {
        fprintf(f, "(nh: %u, l: %u, d.length(): %zd)", next_header, hdr_ext_len, data.length());
    }
};

struct ipv6_header {
    uint8_t bytes[4];
    unsigned short  len;      // payload length
    unsigned char   nxh;      // next header
    unsigned char   ttl;      // hop limit (time to live)
    ipv6_address    src_addr; // source address
    ipv6_address    dst_addr; // destination address

    uint8_t version() const {
        return bytes[0] & 0xf0;
    }

    uint8_t traffic_class() const {
        return (bytes[0] << 4) | (bytes[1] >> 4);
    }

    uint20_t flow_label() const {
        return uint20_t{(uint32_t)bytes[1] << 16 | (uint32_t)bytes[2] << 8 | bytes[3]};
    }

} __attribute__((packed));


class ipv6_packet {
    const struct ipv6_header *header;
    datum extension_headers;
    uint8_t transport_protocol;

public:

    ipv6_packet() : header{NULL}, transport_protocol{ipv6_extension_header::type::reserved} { }

    ipv6_packet(struct datum &p, struct key &k) : header{NULL}, extension_headers{}, transport_protocol{ipv6_extension_header::type::reserved} {
        parse(p, k);
    }

    uint8_t get_transport_protocol() const {
        return transport_protocol;
    }

    void parse(struct datum &p, struct key &k) {
        header = p.get_pointer<ipv6_header>();
        if (header == nullptr) {
            return;  // too short
        }
        p.trim_to_length(ntoh(header->len));

        k.addr.ipv6.src = header->src_addr;
        k.addr.ipv6.dst = header->dst_addr;
        k.ip_vers = 6;  // ipv6

        extension_headers.data = p.data; // remember start of extension headers

        // loop over extensions headers until we find an upper layer protocol
        //
        uint8_t next_header = header->nxh;
        while (p.length() > 0) {
            if (!ipv6_extension_header::is_extension(next_header)) {
                break;
            }
            class ipv6_extension_header ext_hdr{p, next_header};
            next_header = ext_hdr.get_next_header();
        }
        k.protocol = transport_protocol = next_header;

        extension_headers.data_end = p.data; // set end of extension headers
    }

    // fingerprinting
    //
    void fingerprint (struct buffer_stream &buf) {
        if (header) {

            // version
            //
            buf.puts("(60)");

            // identification field, if zero
            //
            buf.write_char('(');
            uint32_t flow_label = header->flow_label();
            if (flow_label == 0) {
                buf.write_char('0');
                buf.write_char('0');
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
            json_ip.print_key_uint_hex("id", header->flow_label());
            if (extension_headers.length() > 0) {
                json_ip.print_key_hex("extensions", extension_headers);
            }
            json_ip.close();
        }
    }

    bool is_not_empty() const { return header != nullptr; }

};


//using ip = std::variant<std::monostate, ipv4_packet, ipv6_packet>;

struct get_transport_protocol {

    template <typename T>
    uint8_t operator()(T &r) {
        return r.get_transport_protocol();
    }

    uint8_t operator()(std::monostate &) {
        return ipv6_extension_header::type::reserved;  // no transport protocol
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

struct ip_pkt_fingerprint {
    buffer_stream &buf;

    ip_pkt_fingerprint(buffer_stream &b) : buf{b} {}

    // fingerprinting
    //
    template <typename T>
    void operator()(T &r) {
        r.fingerprint(buf);
    }

    void operator()(std::monostate &) { }
};

class ip {
    std::variant<std::monostate, ipv4_packet, ipv6_packet> packet;

public:

    enum protocol : uint8_t {
        hopopt     = 0,     // IPv6 Hop-by-Hop Option                 [RFC8200]
        icmp       = 1,     // Internet Control Message               [RFC792]
        igmp       = 2,     // Internet Group Management              [RFC1112]
        ggp        = 3,     // Gateway-to-Gateway                     [RFC823]
        ipv4       = 4,     // IPv4 encapsulation                     [RFC2003]
        st         = 5,     // Stream                                 [RFC1190][RFC1819]
        tcp        = 6,     // Transmission Control Protocol          [RFC793]
        egp        = 8,     // Exterior Gateway Protocol              [RFC888]
        igp        = 9,     // any private interior gateway protocol
        udp        = 17,    // User Datagram Protocol                 [RFC768]
        dccp       = 33,    // Datagram Congestion Control Protocol   [RFC4340]
        ipv6       = 41,    // IPv6 encapsulation                     [RFC2473]
        ipv6_route = 43,    // Routing Header for IPv6
        ipv6_frag  = 44,    // Fragment Header for IPv6
        idrp       = 45,    // Inter-Domain Routing Protocol
        rsvp       = 46,    // Reservation Protocol                   [RFC2205][RFC3209]
        gre        = 47,    // Generic Routing Encapsulation          [RFC2784]
        esp        = 50,    // Encap Security Payload                 [RFC4303]
        ah         = 51,    // Authentication Header                  [RFC4302]
        mobile     = 55,    // IP Mobility
        ipv6_icmp  = 58,    // ICMP for IPv6                          [RFC8200]
        ipv6_nonxt = 59,    // No Next Header for IPv6                [RFC8200]
        ipv6_opts  = 60,    // Destination Options for IPv6           [RFC8200]
        eigrp      = 88,    // EIGRP                                  [RFC7868]
        ospfigp    = 89,    // OSPFIGP                                [RFC1583][RFC2328][RFC5340]
        etherip    = 97,    // Ethernet-within-IP Encapsulation       [RFC3378]
        pim        = 103,   // Protocol Independent Multicast         [RFC7761]
        ipcomp     = 108,   // IP Payload Compression Protocol        [RFC2393]
        l2tp       = 115,   // Layer Two Tunneling Protocol           [RFC3931]
        sctp       = 132,   // Stream Control Transmission Protocol
        fc         = 133,   // Fibre Channel                          [RFC6172]
        mobility   = 135,   // Mobility Header                        [RFC6275]
        udplite    = 136,   // [RFC3828]
        mpls_in_ip = 137,   // [RFC4023]
        manet      = 138,   // MANET Protocols                        [RFC5498]
        hip        = 139,   // /Host Identity Protocol                [RFC7401]
        shim6      = 140,   // Shim6 Protocol                         [RFC5533]
        wesp       = 141,   // Wrapped Encapsulating Security Payload [RFC5840]
        rohc       = 142,   // Robust Header Compression              [RFC5858]
        ethernet   = 143,   // Ethernet                               [RFC8986]
        reserved   = 255
    };

    ip(datum &d, key &k) {
        parse(d, k);
    }

    void parse(datum &d, key &k) {
        uint8_t version;
        d.lookahead_uint8(&version);  // peek at first half-byte for version field
        switch(version & 0xf0) {
        case 0x40:
            packet.emplace<ipv4_packet>(d, k);
            break;
        case 0x60:
            packet.emplace<ipv6_packet>(d, k);
            break;
        default:
            packet.emplace<std::monostate>();
        }
    }

    size_t version() const {
        switch(packet.index()) {
        case 1:
            return 4;
        case 2:
            return 6;
        default:
            ;
        }
        return 0;
    }

    void write_json(json_object &o) {
        std::visit(ip_pkt_write_json{o}, packet);
    }

    void fingerprint(buffer_stream &buf) {
        std::visit(ip_pkt_fingerprint{buf}, packet);
    }

    ip::protocol transport_protocol() {  // TODO: should be const
        return static_cast<ip::protocol>(std::visit(get_transport_protocol{}, packet));
    }

    bool src_is_private() const {
        if (std::get<1>(packet).get_src_addr().get_addr_type() == ipv4_address::addr_type::private_use) {
            return true;
        }
        return false;
    }

    bool dst_is_private() const {
        if (std::get<1>(packet).get_dst_addr().get_addr_type() == ipv4_address::addr_type::private_use) {
            return true;
        }
        return false;
    }

    // static std::pair<bool,bool> is_service(ip &ip_pkt, datum &transport_headers) {
    //     key k;
    //     ip::protocol protocol = ip_pkt.transport_protocol();
    //     //fprintf(stdout, "packet.ip.protocol: %u\n", protocol);
    //     if (protocol == ip::protocol::tcp) {
    //         tcp_packet tcp_pkt{transport_headers};
    //         tcp_pkt.set_key(k);
    //         // fprintf(stdout, "packet.ip.tcp.data.length: %zd\n", pkt_data.length());
    //         // fprintf(stdout, "packet.ip.tcp.data:");
    //         // pkt_data.fprint_hex(stdout);
    //         // fputc('\n', stdout);
    //     } else if (protocol == ip::protocol::udp) {
    //         class udp udp_pkt{transport_headers};
    //         udp_pkt.set_key(k);
    //     }
    //     bool src_is_service = k.src_port == 53;
    //     bool dst_is_service  = k.dst_port == 53;
    //     return { src_is_service, dst_is_service };
    // }

    std::pair<bool, bool> remap_private_addrs(std::unordered_map<ipv4_address, ipv4_address> &addr_map,
                             ipv4_address &src,
                             ipv4_address &dst) {

        // TODO: revise to accept both ipv4 and ipv6

        bool update_src = false;
        bool update_dst = false;

        if (src_is_private()) {

            ipv4_packet &pkt = std::get<1>(packet);
            ipv4_address src_addr = pkt.get_src_addr();
            auto result = addr_map.find(src_addr);
            if (result == addr_map.end()) {
                addr_map.insert({src_addr, src});
                // uint32_t a = pkt.get_src_addr().get_value();
                // fprintf(stderr, "private: %u.%u.%u.%u\n",
                //     a >> 0  & 0xff,
                //     a >> 8  & 0xff,
                //     a >> 16 & 0xff,
                //     a >> 24 & 0xff);
                // uint32_t t = src.get_value();
                // fprintf(stderr, "top: %u.%u.%u.%u\n",
                //     t >> 0  & 0xff,
                //     t >> 8  & 0xff,
                //     t >> 16 & 0xff,
                //     t >> 24 & 0xff);
                pkt.set_src_ip(src.get_value());
                src.next_addr_in_subnet();
                update_src = true;

            } else {
                uint32_t r = result->second.get_value();
                // fprintf(stderr, "result: %u.%u.%u.%u\n",
                //     r >> 0  & 0xff,
                //     r >> 8  & 0xff,
                //     r >> 16 & 0xff,
                //     r >> 24 & 0xff);
                pkt.set_src_ip(r);
            }
        }

        if (dst_is_private()) {

            ipv4_packet &pkt = std::get<1>(packet);
            ipv4_address dst_addr = pkt.get_dst_addr();
            auto result = addr_map.find(dst_addr);
            if (result == addr_map.end()) {
                addr_map.insert({dst_addr, dst});
                // uint32_t a = pkt.get_dst_addr().get_value();
                // fprintf(stderr, "private: %u.%u.%u.%u\n",
                //     a >> 0  & 0xff,
                //     a >> 8  & 0xff,
                //     a >> 16 & 0xff,
                //     a >> 24 & 0xff);
                // uint32_t t = a.get_value();
                // fprintf(stderr, "top: %u.%u.%u.%u\n",
                //     t >> 0  & 0xff,
                //     t >> 8  & 0xff,
                //     t >> 16 & 0xff,
                //     t >> 24 & 0xff);
                pkt.set_dst_addr(dst.get_value());
                dst.next_addr_in_subnet();
                update_dst = true;

            } else {
                uint32_t r = result->second.get_value();
                // fprintf(stderr, "result: %u.%u.%u.%u\n",
                //     r >> 0  & 0xff,
                //     r >> 8  & 0xff,
                //     r >> 16 & 0xff,
                //     r >> 24 & 0xff);
                pkt.set_dst_addr(r);
            }
        }

        return { update_src, update_dst };
    }

};

class ip_encapsulation {
    struct key k;

public:
    ip_encapsulation(struct key &_k) : k{_k} { }

    bool is_next_header() const { return true; }

    void write_json(json_array &a) const {
        struct json_object rec{a};
        rec.print_key_string("type", "ip encapsulation");
        k.write_ip_address(rec);
        rec.close();
    }
};

[[maybe_unused]] inline int ipv4_packet_fuzz_test(const uint8_t *data, size_t size) {
    key k;
    struct datum packet_data{data, data+size};
    ipv4_packet pkt{packet_data, k};
    if (pkt.is_not_empty()) {
        char buffer[8192];
        struct buffer_stream buf_json(buffer, sizeof(buffer));
        struct json_object record(&buf_json);
        pkt.write_json(record);
    }
    return 0;
}

[[maybe_unused]] inline int ipv6_packet_fuzz_test(const uint8_t *data, size_t size) {
    key k;
    struct datum packet_data{data, data+size};
    ipv6_packet pkt{packet_data, k};
    if (pkt.is_not_empty()) {
        char buffer[8192];
        struct buffer_stream buf_json(buffer, sizeof(buffer));
        struct json_object record(&buf_json);
        pkt.write_json(record);
    }
    return 0;
}

#endif // MERC_IP_H
