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
#include "analysis.h"
#include "buffer_stream.h"
#include "stats.h"

double malware_prob_threshold = -1.0; // TODO: document hidden option

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


// class unknown_initial_packet represents the initial data field of a
// tcp or udp packet from an unknown protocol
//
class unknown_initial_packet : public tcp_base_protocol {
    datum tcp_data_field;

public:

    unknown_initial_packet() : tcp_data_field{} { }

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
        struct json_object tcp{record, "tcp"};
        tcp.print_key_hex("data", tcp_data_field);
        tcp.close();
    }

    bool is_not_empty() { return tcp_data_field.is_not_empty(); }

};

// udp_protocol is an alias for a variant record that holds the data
// structure resulting from the parsing of the UDP data field.  The
// default value of std::monostate indicates that the protocol matcher
// did not recognize the packet.  The class unknown_initial_packet
// represents the UDP data field of an unrecognized packet that is the
// first data packet in a flow.
//
using udp_protocol = std::variant<std::monostate,
                                  quic_init,
                                  wireguard_handshake_init,
                                  dns_packet,
                                  tls_client_hello, // dtls
                                  tls_server_hello, // dtls
                                  dhcp_discover,
                                  unknown_initial_packet
                                  >;

void set_udp_protocol(udp_protocol &x,
                      struct datum &pkt,
                      enum udp_msg_type msg_type,
                      bool is_new) {

    // note: std::get<T>() throws exceptions; it might be better to
    // use get_if<T>(), which does not

    // enum msg_type msg_type = udp_get_message_type(pkt.data, pkt.length());
    // if (msg_type == msg_type_unknown) {
    //     msg_type = udp_pkt.estimate_msg_type_from_ports();
    // }
    switch(msg_type) {
    case udp_msg_type_dns:
        {
            x.emplace<dns_packet>();
            auto &y = std::get<dns_packet>(x);
            y.parse(pkt);
        }
        break;
    case udp_msg_type_dhcp:
        {
            x.emplace<dhcp_discover>();
            auto &y = std::get<dhcp_discover>(x);
            y.parse(pkt);
        }
        break;
    case udp_msg_type_quic:
        x.emplace<quic_init>(pkt);
        break;
    case udp_msg_type_dtls_client_hello:
        {
            //x.emplace<dtls_client_hello>(pkt);

            struct dtls_record dtls_rec;
            dtls_rec.parse(pkt);
            struct dtls_handshake handshake;
            handshake.parse(dtls_rec.fragment);
            if (handshake.msg_type == handshake_type::client_hello) {
                x.emplace<tls_client_hello>();
                auto &message = std::get<tls_client_hello>(x);
                message.parse(handshake.body);
            }
        }
        break;
    case udp_msg_type_dtls_server_hello:
        {
            struct dtls_record dtls_rec;
            dtls_rec.parse(pkt);
            struct dtls_handshake handshake;
            handshake.parse(dtls_rec.fragment);
            if (handshake.msg_type == handshake_type::server_hello) {
                x.emplace<tls_server_hello>();
                auto &message = std::get<tls_server_hello>(x);
                message.parse(handshake.body);
            }
        }
        break;
    case udp_msg_type_wireguard:
        {
            x.emplace<wireguard_handshake_init>();
            auto &y = std::get<wireguard_handshake_init>(x);
            y.parse(pkt);
        }
        break;
    default:
        if (is_new) {
            x.emplace<unknown_initial_packet>();
            auto &msg = std::get<unknown_initial_packet>(x);
            msg.parse(pkt);
        } else {
            x.emplace<std::monostate>();
        }
        break;
    }
}

// function objects that are applied to tcp_protocol and udp_protocol
// std::variants
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
        fp_.type = fingerprint_type_unknown;
        fp.fp_str[0] = '\0';  // initialize fingerprint to 'emtpy'
    }

    template <typename T>
    void operator()(T &msg) {
        msg.compute_fingerprint(fp_);
    }

    // these protocols are not fingerprinted
    //
    void operator()(wireguard_handshake_init &) { }
    void operator()(unknown_initial_packet &) { }
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
        event_string.append(analysis_.fp.fp_str).append("#(");
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
    ip ip_pkt;
    set_ip_packet(ip_pkt, pkt, k);
    size_t transport_proto = std::visit(get_transport_protocol{}, ip_pkt);

    // process encapsulations
    //
    if (report_GRE && transport_proto == 47) {
        gre_header gre{pkt};
        switch(gre.get_protocol_type()) {
        case ETH_TYPE_IP:
        case ETH_TYPE_IPV6:
            set_ip_packet(ip_pkt, pkt, k);  // note: overwriting outer ip header
            transport_proto = std::visit(get_transport_protocol{}, ip_pkt);
            break;
        default:
            ;
        }
    }

    // process transport/application protocols
    //
    if (report_ICMP && (transport_proto == 1 || transport_proto == 58)) {

        icmp_packet icmp;
        icmp.parse(pkt);

        struct json_object record{&buf};

        std::visit(ip_pkt_write_json{record}, ip_pkt);
        icmp.write_json(record);

        write_flow_key(record, k);
        record.print_key_timestamp("event_start", ts);
        record.close();

    } else if (transport_proto == 6) { // TCP
        struct tcp_packet tcp_pkt;
        tcp_pkt.parse(pkt);
        if (tcp_pkt.header == nullptr) {
            return 0;  // incomplete tcp header; can't process packet
        }
        tcp_pkt.set_key(k);
        if (tcp_pkt.is_SYN()) {

            if (global_vars.output_tcp_initial_data) {
                tcp_flow_table.syn_packet(k, ts->tv_sec, ntohl(tcp_pkt.header->seq));
            }
            if (selector.tcp_syn()) {
                struct json_object record{&buf};

                if (report_IP && global_vars.metadata_output) {
                    std::visit(ip_pkt_write_json{record}, ip_pkt);
                }

                struct json_object fps{record, "fingerprints"};
                if (report_IP) {
                    std::visit(ip_pkt_write_fingerprint{fps}, ip_pkt);
                }
                fps.print_key_value("tcp", tcp_pkt);
                fps.close();
                if (global_vars.metadata_output) {
                    tcp_pkt.write_json(fps);
                }
                // note: we could check for non-empty data field
                write_flow_key(record, k);
                record.print_key_timestamp("event_start", ts);
                record.close();
            }

        } else if (tcp_pkt.is_SYN_ACK()) {
            if (global_vars.output_tcp_initial_data) {
                tcp_flow_table.syn_packet(k, ts->tv_sec, ntohl(tcp_pkt.header->seq));
            }

            if (report_SYN_ACK && selector.tcp_syn()) {
                struct json_object record{&buf};
                struct json_object fps{record, "fingerprints"};
                fps.print_key_value("tcp_server", tcp_pkt);
                fps.close();
                if (global_vars.metadata_output) {
                    tcp_pkt.write_json(fps);
                }
                write_flow_key(record, k);
                record.print_key_timestamp("event_start", ts);
                record.close();

                // note: we could check for non-empty data field
            }

        } else {

            // fprintf(stderr, "ip_flow_table.table.size(): %zu\n", ip_flow_table.table.size());
            // fprintf(stderr, "reassembler->segment_table.size(): %zu\n", reassembler->segment_table.size());

            if (reassembler) {
                const struct tcp_segment *data_buf = reassembler->check_packet(k, ts->tv_sec, tcp_pkt.header, pkt.length());
                if (data_buf) {
                    //fprintf(stderr, "REASSEMBLED TCP PACKET (length: %u)\n", data_buf->index);
                    struct datum reassembled_tcp_data = data_buf->reassembled_segment();
                    tcp_data_write_json(buf, reassembled_tcp_data, k, tcp_pkt, ts, reassembler);
                    reassembler->remove_segment(k);
                } else {
                    const uint8_t *tmp = pkt.data;
                    tcp_data_write_json(buf, pkt, k, tcp_pkt, ts, reassembler);
                    if (pkt.data == tmp) {
                        auto segment = reassembler->reap(ts->tv_sec);
                        if (segment != reassembler->segment_table.end()) {
                            //fprintf(stderr, "EXPIRED PARTIAL TCP PACKET (length: %u)\n", segment->second.index);
                            struct datum reassembled_tcp_data = segment->second.reassembled_segment();
                            tcp_data_write_json(buf, reassembled_tcp_data, segment->first, tcp_pkt, ts, nullptr);
                            reassembler->remove_segment(segment);
                        }
                    }
                }
            } else {
                tcp_data_write_json(buf, pkt, k, tcp_pkt, ts, nullptr);  // process packet without tcp reassembly
            }
        }

    } else if (transport_proto == 17) { // UDP
        struct udp udp_pkt{pkt};
        udp_pkt.set_key(k);
        enum udp_msg_type msg_type = (udp_msg_type) selector.get_udp_msg_type(pkt.data, pkt.length());

        if (msg_type == udp_msg_type_unknown) {  // TODO: wrap this up in a traffic_selector member function
            udp::ports ports = udp_pkt.get_ports();
            // if (ports.src == htons(53) || ports.dst == htons(53)) {
            //     msg_type = udp_msg_type_dns;
            // }
            if (selector.mdns() && (ports.src == htons(5353) || ports.dst == htons(5353))) {
                msg_type = udp_msg_type_dns;
            }
            if (ports.dst == htons(4789)) {
                msg_type = udp_msg_type_vxlan;
            }
        }

        //enum udp_msg_type msg_type = udp_pkt.get_msg_type();
        bool is_new = false;
        if (global_vars.output_udp_initial_data && pkt.is_not_empty()) {
            is_new = ip_flow_table.flow_is_new(k, ts->tv_sec);
        }
        udp_protocol x;
        set_udp_protocol(x, pkt, msg_type, is_new);
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

            if (malware_prob_threshold > -1.0 && (!output_analysis || analysis.result.malware_prob < malware_prob_threshold)) { return 0; } // TODO - expose hidden command

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

    } else if (report_OSPF && transport_proto == 89) { // OSPF
        struct json_object record{&buf};
        std::visit(ip_pkt_write_json{record}, ip_pkt);
        struct json_object ospf_record{record, "ospf"};
        ospf_record.print_key_hex("data", pkt);
        ospf_record.close();
        write_flow_key(record, k);
        record.print_key_timestamp("event_start", ts);
        record.close();
    }

    if (buf.length() != 0 && buf.trunc == 0) {
        buf.strncpy("\n");
        return buf.length();
    }
    return 0;
}

bool stateful_pkt_proc::ip_set_analysis_result(struct analysis_result *r,
                                               const uint8_t *ip_packet,
                                               size_t length,
                                               struct timespec *ts,
                                               struct tcp_reassembler *reassembler) {

    // TODO: rewrite this function based on ip_write_json()
    //
    (void)r;
    (void)ip_packet;
    (void)length;
    (void)ts;
    (void)reassembler;

    return false;
}

size_t stateful_pkt_proc::write_json(void *buffer,
                                     size_t buffer_size,
                                     uint8_t *packet,
                                     size_t length,
                                     struct timespec *ts,
                                     struct tcp_reassembler *reassembler) {

    struct datum pkt{packet, packet+length};
    eth ethernet_frame{pkt};
    uint16_t ethertype = ethernet_frame.get_ethertype();

    switch(ethertype) {
    case ETH_TYPE_IP:
    case ETH_TYPE_IPV6:
        return ip_write_json(buffer,
                             buffer_size,
                             pkt.data,
                             pkt.length(),
                             ts,
                             reassembler);
    default:
        ;  // unsupported ethertype
    }
    return 0;
}

//////////////////////////////////////////////////////////


// tcp_protocol is an alias for a variant record that holds the data
// structure resulting from the parsing of the TCP data field.  The
// default value of std::monostate indicates that the protocol matcher
// did not recognize the packet.  The class unknown_initial_packet
// represents the TCP data field of an unrecognized packet that is
// the first data packet in a flow.
//
using tcp_protocol = std::variant<std::monostate,
                                  http_request,
                                  http_response,
                                  tls_client_hello,
                                  tls_server_hello_and_certificate,
                                  ssh_init_packet,
                                  ssh_kex_init,
                                  smtp_client,
                                  smtp_server,
                                  unknown_initial_packet
                                  >;

// the function enumerate_tcp_protocol_types() prints out the types in
// the tcp_protocol variant
//
template <size_t I = 0>
void enumerate_tcp_protocol_types(FILE *f) {
    if constexpr (I < std::variant_size_v<tcp_protocol>) {
        std::variant_alternative_t<I, tcp_protocol> tmp;
        fprintf(f, "I=%zu\n", I);
        enumerate_tcp_protocol_types<I + 1>();
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


void set_tcp_protocol(tcp_protocol &x,
                      struct datum &pkt,
                      traffic_selector &sel,
                      bool is_new,
                      struct tcp_packet *tcp_pkt) {

    // note: std::get<T>() throws exceptions; it might be better to
    // use get_if<T>(), which does not

    enum tcp_msg_type msg_type = (tcp_msg_type) sel.get_tcp_msg_type(pkt.data, pkt.length());
    switch(msg_type) {
    case tcp_msg_type_http_request:
        {
            x.emplace<http_request>();
            auto &request = std::get<http_request>(x);
            request.parse(pkt);
            break;
        }
    case tcp_msg_type_http_response:
        {
            x.emplace<http_response>();
            auto &response = std::get<http_response>(x);
            response.parse(pkt);
            break;
        }
    case tcp_msg_type_tls_client_hello:
        {
            struct tls_record rec;
            rec.parse(pkt);
            struct tls_handshake handshake;
            handshake.parse(rec.fragment);
            if (tcp_pkt && handshake.additional_bytes_needed) {
                tcp_pkt->reassembly_needed(handshake.additional_bytes_needed);
                return;
            }
            x.emplace<tls_client_hello>();
            auto &message = std::get<tls_client_hello>(x);
            message.parse(handshake.body);
            break;
        }
    case tcp_msg_type_tls_server_hello:
    case tcp_msg_type_tls_certificate:
        {
            x.emplace<tls_server_hello_and_certificate>();
            auto &msg = std::get<tls_server_hello_and_certificate>(x);
            msg.parse(pkt, tcp_pkt);
            break;
        }
    case tcp_msg_type_ssh:
        {
            x.emplace<ssh_init_packet>();
            auto &request = std::get<ssh_init_packet>(x);
            request.parse(pkt);
            break;
        }
    case tcp_msg_type_ssh_kex:
        {
            struct ssh_binary_packet ssh_pkt;
            ssh_pkt.parse(pkt);
            if (tcp_pkt && ssh_pkt.additional_bytes_needed) {
                tcp_pkt->reassembly_needed(ssh_pkt.additional_bytes_needed);
                return;
            }
            x.emplace<ssh_kex_init>();
            auto &kex_init = std::get<ssh_kex_init>(x);
            kex_init.parse(ssh_pkt.payload);
            break;
        }
    case tcp_msg_type_smtp_client:
        {
            x.emplace<smtp_client>();
            auto &response = std::get<smtp_client>(x);
            response.parse(pkt);
            break;
        }
    case tcp_msg_type_smtp_server:
        {
            x.emplace<smtp_server>();
            auto &response = std::get<smtp_server>(x);
            response.parse(pkt);
            break;
        }
    default:
        if (is_new) {
            x.emplace<unknown_initial_packet>();
            auto &msg = std::get<unknown_initial_packet>(x);
            msg.parse(pkt);
        } else {
            x.emplace<std::monostate>();
        }
        break;
    }
}

// tcp_data_write_json() parses TCP data and writes metadata into
// a buffer stream, if any is found
//
void stateful_pkt_proc::tcp_data_write_json(struct buffer_stream &buf,
                                            struct datum &pkt,
                                            const struct key &k,
                                            struct tcp_packet &tcp_pkt,
                                            struct timespec *ts,
                                            struct tcp_reassembler *reassembler) {

    if (pkt.is_not_empty() == false) {
        return;
    }
    bool is_new = false;
    if (global_vars.output_tcp_initial_data) {
        is_new = tcp_flow_table.is_first_data_packet(k, ts->tv_sec, ntohl(tcp_pkt.header->seq));
    }
    tcp_protocol x;
    set_tcp_protocol(x, pkt, selector, is_new, reassembler == nullptr ? nullptr : &tcp_pkt);

    if (tcp_pkt.additional_bytes_needed) {
        if (reassembler->copy_packet(k, ts->tv_sec, tcp_pkt.header, tcp_pkt.data_length, tcp_pkt.additional_bytes_needed)) {
            return;
        }
    }
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

        if (malware_prob_threshold > -1.0 && (!output_analysis || analysis.result.malware_prob < malware_prob_threshold)) { return; } // TODO - expose hidden command

        struct json_object record{&buf};
        if (analysis.fp.get_type() != fingerprint_type_unknown) {
            analysis.fp.write(record);
        }

        std::visit(write_metadata{record, global_vars.metadata_output, global_vars.certs_json_output}, x);

        if (output_analysis) {
            analysis.result.write_json(record, "analysis");
        }
        write_flow_key(record, k);
        record.print_key_timestamp("event_start", ts);
        record.close();
    }

}

bool stateful_pkt_proc::tcp_data_set_analysis_result(struct analysis_result *r,
                                                     struct datum &pkt,
                                                     const struct key &k,
                                                     struct tcp_packet &,
                                                     struct timespec *,
                                                     struct tcp_reassembler *) {

    if (pkt.is_not_empty() == false) {
        return false;
    }
    tcp_protocol x;
    set_tcp_protocol(x, pkt, selector, false, nullptr);

    if (std::visit(is_not_empty{}, x)) {

        std::visit(compute_fingerprint{analysis.fp}, x);
        if (std::visit(do_analysis{k, analysis, c}, x)) {
            *r = analysis.result;
            return true;
        }
    }

    return false;
}

