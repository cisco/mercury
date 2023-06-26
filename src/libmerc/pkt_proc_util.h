/*
 * pkt_proc_util.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

/**
 * \file pkt_proc_util.h
 *
 * \brief visitor functions for protocol specific processing like metadata, compute_fingerprint
 */

#ifndef PKT_PROC_UTIL_HPP
#define PKT_PROC_UTIL_HPP

#include "protocol.h"
#include "dns.h"
#include "mdns.h"
#include "tls.h"
#include "http.h"
#include "tcpip.h"
#include "udp.h"
#include "quic.h"
#include "analysis.h"
#include "buffer_stream.h"

// protocol is an alias for a std::variant that can hold any protocol
// data element.  The default value of std::monostate indicates that
// the protocol matcher did not recognize the packet.
//
// The classes unknown_initial_packet and unknown_udp_initial_packet
// represents the TCP and UDP data fields, respectively, of an
// unrecognized packet that is the first data packet in a flow.
//
//protocol structs forward declarations
struct http_request;                      // start of tcp protocols
struct http_response;
struct tls_client_hello;
class tls_server_hello_and_certificate;
struct ssh_init_packet;
struct ssh_kex_init;
class smtp_client;
class smtp_server;
class dnp3;
class tofsee_initial_message;
class unknown_initial_packet;
class quic_init;                         // start of udp protocols
struct wireguard_handshake_init;
struct dns_packet;
struct mdns_packet;
class dtls_client_hello;
class
dtls_server_hello;
struct dhcp_discover;
class ssdp;
//class stun::message;
class unknown_udp_initial_packet;
class icmp_packet;                        // start of ip protocols
class ospf;
class sctp_init;
struct tcp_packet;
class iec60870_5_104;
class openvpn_tcp;
class mysql_server_greet;

using protocol = std::variant<std::monostate,
                              http_request,                      // start of tcp protocols
                              http_response,
                              tls_client_hello,
                              tls_server_hello_and_certificate,
                              ssh_init_packet,
                              ssh_kex_init,
                              smtp_client,
                              smtp_server,
                              iec60870_5_104,
                              dnp3,
                              nbss_packet,
                              bittorrent_handshake,
                              tofsee_initial_message,
                              unknown_initial_packet,
                              quic_init,                         // start of udp protocols
                              wireguard_handshake_init,
                              dns_packet,
                              mdns_packet,
                              dtls_client_hello,
                              dtls_server_hello,
                              dhcp_discover,
                              ssdp,
                              stun::message,
                              nbds_packet,
                              bittorrent_dht,
                              bittorrent_lsd,
                              unknown_udp_initial_packet,
                              icmp_packet,                        // start of ip protocols
                              ospf,
                              sctp_init,
                              tcp_packet,
                              smb1_packet,
                              smb2_packet,
                              openvpn_tcp,
                              mysql_server_greet
                              >;

// class unknown_initial_packet represents the initial data field of a
// tcp or udp packet from an unknown protocol
//
class unknown_initial_packet : public base_protocol {
    datum tcp_data_field;

public:

    unknown_initial_packet(datum &pkt) : tcp_data_field{} { parse(pkt); }

    void parse(struct datum &pkt) {
        // if this packet is a TLS record, ignore it
        if (tls_record::is_valid(tcp_data_field)) {
            tcp_data_field.set_empty();
        } else {
            tcp_data_field = pkt;
        }
    }

    void operator()(buffer_stream &) { }

    void write_json(json_object &record, bool) {
        struct json_object tcp{record, "tcp"};     // TODO: tcp or udp
        tcp.print_key_hex("data", tcp_data_field);
        tcp.close();
    }

    bool is_not_empty() { return tcp_data_field.is_not_empty(); }

};

// class unknown_udp_initial_packet represents the initial data field of a
// udp packet from an unknown protocol
//
class unknown_udp_initial_packet : public base_protocol {
    datum udp_data_field;

public:

    unknown_udp_initial_packet(struct datum &pkt) : udp_data_field{pkt} { }

    void operator()(buffer_stream &) { }

    void write_json(json_object &record, bool) {
        struct json_object udp{record, "udp"};
        udp.print_key_hex("data", udp_data_field);
        udp.close();
    }

    bool is_not_empty() { return udp_data_field.is_not_empty(); }

};

// function objects that are applied to the protocol std::variant (and
// any other variant that can hold a subset of its protocol data
// element types)
//
struct is_not_empty {
    template <typename T>
    bool operator()(T &r) {
        return r.is_not_empty();
    }

    bool operator()(std::monostate &r) {
        (void)r;
        return false;
    }
};

struct write_metadata {
    struct json_object &record;
    bool metadata_output_;
    bool certs_json_output_;
    bool dns_json_output_;

    write_metadata(struct json_object &object,
                   bool metadata_output,
                   bool certs_json_output,
                   bool dns_json_output=false) : record{object},
                                             metadata_output_{metadata_output},
                                             certs_json_output_{certs_json_output},
                                             dns_json_output_{dns_json_output}
    {}

    template <typename T>
    void operator()(T &r) {
        r.write_json(record, metadata_output_);
    }

    void operator()(dns_packet &r) {
        std::string name{"dns"};
        if (r.netbios()) {
            name = "nbns";
        }

        if (dns_json_output_) {
            struct json_object json_dns{record, name.c_str()};
            r.write_json(json_dns);
            json_dns.close();
        } else {
            struct json_object json_dns{record, name.c_str()};
            struct datum pkt = r.get_datum();  // get complete packet
            json_dns.print_key_base64("base64", pkt);
            json_dns.close();
        }
    }

    void operator()(mdns_packet &r) {
        if (dns_json_output_) {
            struct json_object json_mdns{record, "mdns"};
            r.write_json(json_mdns);
            json_mdns.close();
        } else {
            struct json_object json_mdns{record, "mdns"};
            struct datum pkt = r.get_datum();  // get complete packet
            json_mdns.print_key_base64("base64", pkt);
            json_mdns.close();
        }
    }

    void operator()(dtls_server_hello &r) {
        struct json_object dtls{record, "dtls"};
        struct json_object dtls_server{dtls, "server"};
        r.write_json(dtls_server, metadata_output_);
        dtls_server.close();
        dtls.close();
    }

    void operator()(tls_server_hello_and_certificate &r) {
        r.write_json(record, metadata_output_, certs_json_output_);
    }

    void operator()(std::monostate &) { }

};

struct compute_fingerprint {
    fingerprint &fp_;
    size_t format_version;

    compute_fingerprint(fingerprint &fp, size_t format=0) : fp_{fp}, format_version{format} {
        fp.init();
    }

    template <typename T>
    void operator()(T &msg) {
        msg.compute_fingerprint(fp_);
    }

    void operator()(tls_client_hello &msg) {
        msg.compute_fingerprint(fp_, format_version);
    }

    void operator()(std::monostate &) { }

};

struct do_analysis {
    const struct key &k_;
    struct analysis_context &analysis_;
    classifier *c_;

    do_analysis(const struct key &k,
                struct analysis_context &analysis,
                classifier *c) :
        k_{k},
        analysis_{analysis},
        c_{c}
    {}

    template <typename T>
    bool operator()(T &msg) {
        return msg.do_analysis(k_, analysis_, c_);
    }

    bool operator()(std::monostate &) { return false; }

};

#endif  /* PKT_PROC_UTIL_HPP */
