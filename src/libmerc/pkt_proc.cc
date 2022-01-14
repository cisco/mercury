/*
 * pkt_proc.c
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <string.h>
#include <variant>
#include <set>

#include "libmerc.h"
#include "pkt_proc.h"
#include "utils.h"

// include files needed by stateful_pkt_proc; they provide the
// interface to mercury's packet parsing and handling routines
//
#include "proto_identify.h"
#include "arp.h"
#include "ip.h"
#include "tcp.h"
#include "dns.h"
#include "tls.h"
#include "http.h"
#include "wireguard.h"
#include "ssh.h"
#include "dhcp.h"
#include "tcpip.h"
#include "eth.h"
#include "gre.h"
#include "icmp.h"
#include "udp.h"
#include "quic.h"
#include "smtp.h"
#include "cdp.h"
#include "lldp.h"
#include "ospf.h"
#include "analysis.h"
#include "buffer_stream.h"
#include "stats.h"

// class unknown_initial_packet represents the initial data field of a
// tcp or udp packet from an unknown protocol
//
class unknown_initial_packet : public tcp_base_protocol {
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
class unknown_udp_initial_packet {
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

// protocol is an alias for a std::variant that can hold any protocol
// data element.  The default value of std::monostate indicates that
// the protocol matcher did not recognize the packet.
//
// The classes unknown_initial_packet and unknown_udp_initial_packet
// represents the TCP and UDP data fields, respectively, of an
// unrecognized packet that is the first data packet in a flow.
//
using protocol = std::variant<std::monostate,
                              http_request,                      // start of tcp protocols
                              http_response,
                              tls_client_hello,
                              tls_server_hello_and_certificate,
                              ssh_init_packet,
                              ssh_kex_init,
                              smtp_client,
                              smtp_server,
                              unknown_initial_packet,
                              quic_init,                         // start of udp protocols
                              wireguard_handshake_init,
                              dns_packet,
                              tls_client_hello,                  // dtls
                              tls_server_hello,                  // dtls
                              dhcp_discover,
                              unknown_udp_initial_packet,
                              icmp_packet,                        // start of ip protocols
                              ospf,
                              tcp_packet
                              >;

// set_tcp_protocol() sets the protocol variant record to the data
// structure resulting from the parsing of the TCP data field, which
// will be one of the TCP protocols in that variant.  The default
// value of std::monostate indicates that the protocol matcher did not
// recognize, or could not parse, the packet.  The class
// unknown_initial_packet represents the TCP data field of an
// unrecognized packet that is the first data packet in a flow.
//
void set_tcp_protocol(protocol &x,
                      struct datum &pkt,
                      traffic_selector &sel,
                      bool is_new,
                      struct tcp_packet *tcp_pkt,
                      struct perfect_hash_visitor& ph_visitor) {

    // note: std::get<T>() throws exceptions; it might be better to
    // use get_if<T>(), which does not

    enum tcp_msg_type msg_type = (tcp_msg_type) sel.get_tcp_msg_type(pkt.data, pkt.length());
    switch(msg_type) {
    case tcp_msg_type_http_request:
        x.emplace<http_request>(pkt, ph_visitor);
        break;
    case tcp_msg_type_http_response:
        x.emplace<http_response>(pkt, ph_visitor);
        break;
    case tcp_msg_type_tls_client_hello:
        {
            struct tls_record rec{pkt};
            struct tls_handshake handshake{rec.fragment};
            if (tcp_pkt && handshake.additional_bytes_needed) {
                tcp_pkt->reassembly_needed(handshake.additional_bytes_needed);
                return;
            }
            x.emplace<3>(handshake.body);
            // x.emplace<tls_client_hello>(handshake.body);
            break;
        }
    case tcp_msg_type_tls_server_hello:
    case tcp_msg_type_tls_certificate:
        x.emplace<4>(pkt, tcp_pkt);
        // x.emplace<tls_server_hello_and_certificate>(pkt, tcp_pkt);
        break;
    case tcp_msg_type_ssh:
        x.emplace<ssh_init_packet>(pkt);
        break;
    case tcp_msg_type_ssh_kex:
        {
            struct ssh_binary_packet ssh_pkt{pkt};
            if (tcp_pkt && ssh_pkt.additional_bytes_needed) {
                tcp_pkt->reassembly_needed(ssh_pkt.additional_bytes_needed);
                return;
            }
            x.emplace<ssh_kex_init>(ssh_pkt.payload);
            break;
        }
    case tcp_msg_type_smtp_client:
        x.emplace<smtp_client>(pkt);
        break;
    case tcp_msg_type_smtp_server:
        x.emplace<smtp_server>(pkt);
        break;
    default:
        if (is_new) {
            x.emplace<unknown_initial_packet>(pkt);
        } else {
            x.emplace<std::monostate>();
        }
        break;
    }
}


// double malware_prob_threshold = -1.0; // TODO: document hidden option

void write_flow_key(struct json_object &o, const struct key &k) {
    if (k.ip_vers == 6) {
        const uint8_t *s = (const uint8_t *)&k.addr.ipv6.src;
        o.print_key_ipv6_addr("src_ip", s);

        const uint8_t *d = (const uint8_t *)&k.addr.ipv6.dst;
        o.print_key_ipv6_addr("dst_ip", d);

    } else {

        const uint8_t *s = (const uint8_t *)&k.addr.ipv4.src;
        o.print_key_ipv4_addr("src_ip", s);

        const uint8_t *d = (const uint8_t *)&k.addr.ipv4.dst;
        o.print_key_ipv4_addr("dst_ip", d);

    }

    o.print_key_uint8("protocol", k.protocol);
    o.print_key_uint16("src_port", k.src_port);
    o.print_key_uint16("dst_port", k.dst_port);

    // o.b->snprintf(",\"flowhash\":\"%016lx\"", std::hash<struct key>{}(k));
}

// set_udp_protocol() sets the protocol variant record to the data
// structure resulting from the parsing of the UDP data field, which
// will be one of the UDP protcols in that variant.  The default value
// of std::monostate indicates that the protocol matcher did not
// recognize, or could not parse, the packet.  The class
// unknown_udp_initial_packet represents the UDP data field of an
// unrecognized packet that is the first data packet in a flow.
//
void set_udp_protocol(protocol &x,
                      struct datum &pkt,
                      enum udp_msg_type msg_type,
                      bool is_new,
                      quic_crypto_engine &quic_crypto) {

    // note: std::get<T>() throws exceptions; it might be better to
    // use get_if<T>(), which does not

    // enum msg_type msg_type = udp_get_message_type(pkt.data, pkt.length());
    // if (msg_type == msg_type_unknown) {
    //     msg_type = udp_pkt.estimate_msg_type_from_ports();
    // }
    switch(msg_type) {
    case udp_msg_type_dns:
        x.emplace<dns_packet>(pkt);
        break;
    case udp_msg_type_dhcp:
        x.emplace<dhcp_discover>(pkt);
        break;
    case udp_msg_type_quic:
        x.emplace<quic_init>(pkt, quic_crypto);
        break;
    case udp_msg_type_dtls_client_hello:
        {
            struct dtls_record dtls_rec{pkt};
            struct dtls_handshake handshake{dtls_rec.fragment};
            if (handshake.msg_type == handshake_type::client_hello) {
                // x.emplace<tls_client_hello>(handshake.body);
                x.emplace<13>(handshake.body);
            }
        }
        break;
    case udp_msg_type_dtls_server_hello:
        {
            struct dtls_record dtls_rec{pkt};
            struct dtls_handshake handshake{dtls_rec.fragment};
            if (handshake.msg_type == handshake_type::server_hello) {
                // x.emplace<tls_server_hello>(handshake.body);
                x.emplace<14>(handshake.body);
            }
        }
        break;
    case udp_msg_type_wireguard:
        x.emplace<wireguard_handshake_init>(pkt);
        break;
    default:
        if (is_new) {
            x.emplace<unknown_udp_initial_packet>(pkt);
        } else {
            x.emplace<std::monostate>();
        }
        break;
    }
}

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

    void operator()(http_response &r) {
        if (metadata_output_) {
            r.write_json(record);
        }
    }

    void operator()(dhcp_discover &r) {
        if (metadata_output_) {
            r.write_json(record);
        }
    }

    void operator()(dns_packet &r) {
        if (dns_json_output_) {
            struct json_object json_dns{record, "dns"};
            r.write_json(json_dns);
            json_dns.close();
        } else {
            struct json_object json_dns{record, "dns"};
            struct datum pkt = r.get_datum();  // get complete packet
            json_dns.print_key_base64("base64", pkt);
            json_dns.close();
        }
    }

    void operator()(tls_server_hello &r) {
        const char *label = "tls";
        if (r.dtls) {
            label = "dtls";
        }
        struct json_object tls{record, label};
        struct json_object tls_server{tls, "server"};
        r.write_json(tls_server, metadata_output_);
        tls_server.close();
        tls.close();
    }

    void operator()(tls_server_hello_and_certificate &r) {
        r.write_json(record, metadata_output_, certs_json_output_);
    }
    void operator()(std::monostate &r) {
        (void) r;
    }
};

struct compute_fingerprint {
    struct fingerprint &fp_;

    compute_fingerprint(struct fingerprint &fp) : fp_{fp} {
        fp.init();
    }

    template <typename T>
    void operator()(T &msg) {
        msg.compute_fingerprint(fp_);
    }

    // these protocols are not fingerprinted
    //
    void operator()(ospf &) { }
    void operator()(icmp_packet &) { }
    void operator()(wireguard_handshake_init &) { }
    void operator()(unknown_initial_packet &) { }
    void operator()(unknown_udp_initial_packet &) { }
    void operator()(dns_packet &) { }
    void operator()(std::monostate &) { }

};


struct write_fingerprint {
    struct json_object &record;

    write_fingerprint(struct json_object &object) : record{object} {}

    template <typename T>
    void operator()(T &r) {
        r.write_fingerprint(record);
    }

    void operator()(http_request &r) {
        struct json_object fps{record, "fingerprints"};
        fps.print_key_value("http", r);
        fps.close();
        //record.print_key_string("complete", r.headers.complete ? "yes" : "no"); // TBD: (re)move?
    }

    void operator()(http_response &r) {
        struct json_object fps{record, "fingerprints"};
        fps.print_key_value("http_server", r);
        fps.close();
        //record.print_key_string("complete", r.headers.complete ? "yes" : "no"); // TBD: (re)move?
    }

    void operator()(ssh_init_packet &r) {
        struct json_object fps{record, "fingerprints"};
        fps.print_key_value("ssh", r);
        fps.close();
    }

    void operator()(ssh_kex_init &r) {
        struct json_object fps{record, "fingerprints"};
        fps.print_key_value("ssh_kex", r);
        fps.close();
    }

    // these protocols are not fingerprinted
    //
    void operator()(wireguard_handshake_init &) { }
    void operator()(unknown_initial_packet &) { }
    void operator()(dns_packet &) { }
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

    bool operator()(tls_client_hello &msg) {
        return msg.do_analysis(k_, analysis_, c_);
    }
    bool operator()(http_request &msg) {
        return msg.do_analysis(k_, analysis_, c_);
    }
    bool operator()(quic_init &msg) {
        return msg.do_analysis(k_, analysis_, c_);
    }

    template <typename T>
    bool operator()(T &) {
        return false;   // don't perform analysis for other types
    }

    bool operator()(std::monostate &) { return false; }

};

struct do_observation {
    const struct key &k_;
    struct analysis_context &analysis_;
    class message_queue *mq_;

    do_observation(const struct key &k,
                   struct analysis_context &analysis,
                   class message_queue *mq) :
        k_{k},
        analysis_{analysis},
        mq_{mq}
    {}

    void operator()(tls_client_hello &) {
        // create event and send it to the data/stats aggregator
        //
        char src_ip_str[MAX_ADDR_STR_LEN];
        k_.sprint_src_addr(src_ip_str);
        char dst_port_str[MAX_PORT_STR_LEN];
        k_.sprint_dst_port(dst_port_str);
        std::string event_string;
        event_string.append("(");
        event_string.append(src_ip_str).append(")#");
        event_string.append(analysis_.fp.string()).append("#(");
        event_string.append(analysis_.destination.sn_str).append(")(");
        event_string.append(analysis_.destination.dst_ip_str).append(")(");
        event_string.append(dst_port_str).append(")");
        //fprintf(stderr, "note: observed event_string '%s'\n", event_string.c_str());
        mq_->push((uint8_t *)event_string.c_str(), event_string.length()+1);
    }

    template <typename T>
    void operator()(T &) { }

};

// constant expression variables that control JSON output; these
// variables can be used as compile-time options.  In the future, they
// will probably become run-time options.
//
static constexpr bool report_IP       = false;
static constexpr bool report_GRE      = false;
static constexpr bool report_ICMP     = false;
static constexpr bool report_OSPF     = false;
static constexpr bool report_SYN_ACK  = false;

size_t stateful_pkt_proc::ip_write_json(void *buffer,
                                        size_t buffer_size,
                                        const uint8_t *ip_packet,
                                        size_t length,
                                        struct timespec *ts,
                                        struct tcp_reassembler *reassembler) {

    struct buffer_stream buf{(char *)buffer, buffer_size};
    struct key k;
    struct datum pkt{ip_packet, ip_packet+length};
    ip ip_pkt{pkt, k};
    uint8_t transport_proto = ip_pkt.transport_protocol();

    // process encapsulations
    //
    if (report_GRE && transport_proto == ip::protocol::gre) {
        gre_header gre{pkt};
        switch(gre.get_protocol_type()) {
        case ETH_TYPE_IP:
        case ETH_TYPE_IPV6:
            ip_pkt.parse(pkt, k);    // note: overwriting outer ip header in key
            transport_proto = ip_pkt.transport_protocol();
            break;
        default:
            ;
        }
    }

    // process transport/application protocols
    //
    protocol x;
    if (report_ICMP && (transport_proto == ip::protocol::icmp || transport_proto == ip::protocol::ipv6_icmp)) {
        x.emplace<icmp_packet>(pkt);

    } else if (report_OSPF && transport_proto == ip::protocol::ospfigp) {
        x.emplace<ospf>(pkt);

    } else if (transport_proto == ip::protocol::tcp) {
        tcp_packet tcp_pkt{pkt};
        if (!tcp_pkt.is_valid()) {
            return 0;  // incomplete tcp header; can't process packet
        }
        tcp_pkt.set_key(k);
        if (tcp_pkt.is_SYN()) {

            if (global_vars.output_tcp_initial_data) {
                tcp_flow_table.syn_packet(k, ts->tv_sec, ntohl(tcp_pkt.header->seq));
            }
            if (selector.tcp_syn()) {
                if (report_IP && global_vars.metadata_output) {
                    // ip_pkt.write_json(record);  // TODO: move to end of function
                }
                x = tcp_pkt; // process tcp syn
            }
            // note: we could check for non-empty data field

         } else if (tcp_pkt.is_SYN_ACK()) {
            if (global_vars.output_tcp_initial_data) {
                tcp_flow_table.syn_packet(k, ts->tv_sec, ntohl(tcp_pkt.header->seq));
            }
            if (report_SYN_ACK && selector.tcp_syn()) {
                x = tcp_pkt;
            }
            // note: we could check for non-empty data field

        } else {

            bool is_new = false;
            if (global_vars.output_tcp_initial_data) {
                is_new = tcp_flow_table.is_first_data_packet(k, ts->tv_sec, ntohl(tcp_pkt.header->seq));
            }
            set_tcp_protocol(x, pkt, selector, is_new, reassembler == nullptr ? nullptr : &tcp_pkt, ph_visitor);
        }

    } else if (transport_proto == ip::protocol::udp) {
        class udp udp_pkt{pkt};
        udp_pkt.set_key(k);
        enum udp_msg_type msg_type = (udp_msg_type) selector.get_udp_msg_type(pkt.data, pkt.length());

        if (msg_type == udp_msg_type_unknown) {  // TODO: wrap this up in a traffic_selector member function
            udp::ports ports = udp_pkt.get_ports();
            // if (ports.src == htons(53) || ports.dst == htons(53)) {
            //     msg_type = udp_msg_type_dns;
            // }
            // if (selector.mdns() && (ports.src == htons(5353) || ports.dst == htons(5353))) {
            //     msg_type = udp_msg_type_dns;
            // }
            if (ports.dst == htons(4789)) {
                msg_type = udp_msg_type_vxlan;
            }
        }

        bool is_new = false;
        if (global_vars.output_udp_initial_data && pkt.is_not_empty()) {
            is_new = ip_flow_table.flow_is_new(k, ts->tv_sec);
        }
        set_udp_protocol(x, pkt, msg_type, is_new, quic_crypto);
    }

    // process transport/application protocol
    //
    if (std::visit(is_not_empty{}, x)) {
        std::visit(compute_fingerprint{analysis.fp}, x);
        bool output_analysis = false;
        if (global_vars.do_analysis) {
            output_analysis = std::visit(do_analysis{k, analysis, c}, x);

            // note: we only perform observations when analysis is
            // configured, because we rely on do_analysis to set the

            // analysis_.destination
            //
            if (mq) {
                std::visit(do_observation{k, analysis, mq}, x);
            }
        }

        // if (malware_prob_threshold > -1.0 && (!output_analysis || analysis.result.malware_prob < malware_prob_threshold)) { return 0; } // TODO - expose hidden command

        struct json_object record{&buf};
        if (analysis.fp.get_type() != fingerprint_type_unknown) {
            analysis.fp.write(record);
        }
        std::visit(write_metadata{record, global_vars.metadata_output, global_vars.certs_json_output, global_vars.dns_json_output}, x);

        if (output_analysis) {
            analysis.result.write_json(record, "analysis");
        }
        write_flow_key(record, k);
        record.print_key_timestamp("event_start", ts);
        record.close();
    }

    // if buffer has JSON data, add newline and return buffer length
    //
    if (buf.length() != 0 && buf.trunc == 0) {
        buf.strncpy("\n");
        return buf.length();
    }
    return 0;
}

constexpr bool report_ARP  = false;
constexpr bool report_CDP  = false;
constexpr bool report_LLDP = false;

using link_layer_protocol = std::variant<std::monostate, arp_packet, cdp, lldp>;

size_t stateful_pkt_proc::write_json(void *buffer,
                                     size_t buffer_size,
                                     uint8_t *packet,
                                     size_t length,
                                     struct timespec *ts,
                                     struct tcp_reassembler *reassembler) {

    struct datum pkt{packet, packet+length};
    eth ethernet_frame{pkt};
    uint16_t ethertype = ethernet_frame.get_ethertype();

    link_layer_protocol x;
    switch(ethertype) {
    case ETH_TYPE_IP:
    case ETH_TYPE_IPV6:
        return ip_write_json(buffer,
                             buffer_size,
                             pkt.data,
                             pkt.length(),
                             ts,
                             reassembler);
    case ETH_TYPE_ARP:
        if (report_ARP) {
            x.emplace<arp_packet>(pkt);
        }
        break;
    case ETH_TYPE_CDP:
        if (report_CDP) {
            x.emplace<cdp>(pkt);
        }
        break;
    case ETH_TYPE_LLDP:
        if (report_LLDP) {
            x.emplace<lldp>(pkt);
        }
        break;
    default:
        ;  // unsupported ethertype
    }

    // write out link layer protocol metadata, if there is any
    //
    if (std::visit(is_not_empty{}, x)) {
        struct buffer_stream buf{(char *)buffer, buffer_size};
        struct json_object record{&buf};
        std::visit(write_metadata{record, false, false, false}, x);
        record.close();
        if (buf.length() != 0 && buf.trunc == 0) {
            buf.strncpy("\n");
            return buf.length();
        }
    }

    return 0;
}

// the function enumerate_protocol_types() prints out the types in
// the protocol variant
//
template <size_t I = 0>
static void enumerate_protocol_types(FILE *f) {
    if constexpr (I < std::variant_size_v<protocol>) {
        std::variant_alternative_t<I, protocol> tmp;
        fprintf(f, "I=%zu\n", I);
        enumerate_protocol_types<I + 1>();
    }
}

// set_config(config_map, config_string) updates the std::map provided
// as input, based on the configuration represented by config_string,
// and returns false if that string could not be parsed correctly
//
// the format of config_string is a comma-separated list of keywords,
// possibly including whitespace, such as like "tcp,ssh, tls"
//
bool set_config(std::map<std::string, bool> &config_map, const char *config_string) {
    if (config_string == NULL) {
        return true; // no updates needed
    }

    std::string s{config_string};
    std::string delim{","};
    size_t pos = 0;
    std::string token;
    while ((pos = s.find(delim)) != std::string::npos) {
        token = s.substr(0, pos);
        token.erase(std::remove_if(token.begin(), token.end(), isspace), token.end());
        s.erase(0, pos + delim.length());

        auto pair = config_map.find(token);
        if (pair != config_map.end()) {
            pair->second = true;
        } else {
            printf_err(log_err, "unrecognized filter command \"%s\"\n", token.c_str());
            return false;
        }
    }
    token = s.substr(0, pos);
    s.erase(std::remove_if(s.begin(), s.end(), isspace), s.end());
    auto pair = config_map.find(token);
    if (pair != config_map.end()) {
        pair->second = true;
    } else {
        printf_err(log_err, "unrecognized filter command \"%s\"\n", token.c_str());
        return false;
    }
    return true;
}

bool stateful_pkt_proc::analyze_ip_packet(const uint8_t *packet,
                                          size_t length,
                                          struct timespec *,
                                          struct tcp_reassembler *reassembler) {


    struct datum pkt{packet, packet+length};
    struct key k;
    ip ip_pkt{pkt, k};
    protocol x;
    uint8_t transport_proto = ip_pkt.transport_protocol();
    if (transport_proto == ip::protocol::tcp) {
        tcp_packet tcp_pkt{pkt};
        if (!tcp_pkt.is_valid()) {
            return 0;  // incomplete tcp header; can't process packet
         }
        tcp_pkt.set_key(k);
        set_tcp_protocol(x, pkt, selector, false, reassembler == nullptr ? nullptr : &tcp_pkt, ph_visitor);

    } else if (transport_proto == ip::protocol::udp) {
        class udp udp_pkt{pkt};
        udp_pkt.set_key(k);
        enum udp_msg_type msg_type = (udp_msg_type) selector.get_udp_msg_type(pkt.data, pkt.length());

        if (msg_type == udp_msg_type_unknown) {  // TODO: wrap this up in a traffic_selector member function
            udp::ports ports = udp_pkt.get_ports();
            if (ports.dst == htons(4789)) {
                msg_type = udp_msg_type_vxlan; // could parse VXLAN header here
            }
        }

        set_udp_protocol(x, pkt, msg_type, false, quic_crypto);
    }

    // process protocol data element
    //
    if (std::visit(is_not_empty{}, x)) {
        std::visit(compute_fingerprint{analysis.fp}, x);
        if (global_vars.do_analysis) {

            // re-initialize the structure that holds analysis results
            //
            analysis.result.reinit();
            bool output_analysis = std::visit(do_analysis{k, analysis, c}, x);

            // note: we only perform observations when analysis is
            // configured, because we rely on do_analysis to set the
            // analysis_.destination
            //
            if (mq) {
                std::visit(do_observation{k, analysis, mq}, x);
            }

            return output_analysis;
        }
    }

    return false;  // indicate no analysis results were returned
}

bool stateful_pkt_proc::analyze_eth_packet(const uint8_t *packet,
                                           size_t length,
                                           struct timespec *ts,
                                           struct tcp_reassembler *reassembler) {

    struct datum pkt{packet, packet+length};
    if (!eth::get_ip(pkt)) {
        return false;   // not an IP packet
    }

    return analyze_ip_packet(pkt.data, pkt.length(), ts, reassembler);
}
