/*
 * pkt_proc.c
 * 
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at 
 * https://github.com/cisco/mercury/blob/master/LICENSE 
 */

#include <string.h>
#include <variant>

#include "libmerc.h"
#include "pkt_proc.h"
#include "utils.h"

// include files needed by stateful_pkt_proc; they provide the
// interface to mercury's packet parsing and handling routines
//
#include "proto_identify.h"
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
#include "udp.h"
#include "quic.h"
#include "analysis.h"
#include "buffer_stream.h"
#include "stats.h"

extern struct libmerc_config global_vars;  // defined in libmerc.h

stats_aggregator fp_stats;  // global just for experimentation

double malware_prob_threshold = -1.0; // HACK for demo

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

static constexpr bool report_GRE = false;

size_t stateful_pkt_proc::ip_write_json(void *buffer,
                                        size_t buffer_size,
                                        const uint8_t *ip_packet,
                                        size_t length,
                                        struct timespec *ts,
                                        struct tcp_reassembler *reassembler) {

    struct buffer_stream buf{(char *)buffer, buffer_size};
    struct key k;
    struct datum pkt{ip_packet, ip_packet+length};
    size_t transport_proto = 0;

    size_t ip_version;
    if (datum_read_uint(&pkt, 1, &ip_version) == status_err) {
        return 0;
    }
    ip_version &= 0xf0;
    switch(ip_version) {
    case 0x40:
        datum_process_ipv4(&pkt, &transport_proto, &k);
        break;
    case 0x60:
        datum_process_ipv6(&pkt, &transport_proto, &k);
        break;
    default:
        return 0;  // unsupported IP version
    }

    if (report_GRE && transport_proto == 47) {
        gre_header gre{pkt};
        switch(gre.get_protocol_type()) {
        case ETH_TYPE_IP:
            datum_process_ipv4(&pkt, &transport_proto, &k);
            break;
        case ETH_TYPE_IPV6:
            datum_process_ipv6(&pkt, &transport_proto, &k);
            break;
        default:
            ;
        }

    }
    if (transport_proto == 6) {
        struct tcp_packet tcp_pkt;
        tcp_pkt.parse(pkt);
        if (tcp_pkt.header == nullptr) {
            return 0;  // incomplete tcp header; can't process packet
        }
        tcp_pkt.set_key(k);
        if (tcp_pkt.is_SYN()) {
            tcp_flow_table.syn_packet(k, ts->tv_sec, ntohl(tcp_pkt.header->seq));
            if (select_tcp_syn) {
                struct json_object record{&buf};
                struct json_object fps{record, "fingerprints"};
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
            tcp_flow_table.syn_packet(k, ts->tv_sec, ntohl(tcp_pkt.header->seq));

#ifdef REPORT_SYN_ACK
            if (select_tcp_syn) {
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
#endif

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

    } else if (transport_proto == 17) {
        struct udp_packet udp_pkt;
        udp_pkt.parse(pkt);
        udp_pkt.set_key(k);
        bool is_new = false;
        if (global_vars.output_udp_initial_data && pkt.is_not_empty()) {
            is_new = ip_flow_table.flow_is_new(k, ts->tv_sec);
        }
        enum udp_msg_type msg_type = udp_get_message_type(pkt.data, pkt.length());
        if (msg_type == udp_msg_type_unknown) {
            msg_type = udp_pkt.estimate_msg_type_from_ports();
        }
        switch(msg_type) {
        case udp_msg_type_quic:
            {
                struct quic_initial_packet quic_pkt{pkt};
                if (quic_pkt.is_not_empty()) {
                    struct json_object json_record{&buf};
                    struct quic_initial_packet_crypto quic_pkt_crypto{quic_pkt};
                    quic_pkt_crypto.decrypt(quic_pkt.data.data, quic_pkt.data.length());
                    if (quic_pkt_crypto.is_not_empty()) {
                        struct tls_client_hello hello;
                        struct datum quic_plaintext(quic_pkt_crypto.plaintext+8, quic_pkt_crypto.plaintext+quic_pkt_crypto.plaintext_len);
                        hello.parse(quic_plaintext);
                        if (hello.is_not_empty()) {
                            struct json_object fps{json_record, "fingerprints"};
                            fps.print_key_value("quic", hello);
                            fps.close();
                            hello.write_json(json_record, global_vars.metadata_output);
                        }
                    }
                    struct json_object json_quic{json_record, "quic"};
                    quic_pkt.write_json(json_quic);
                    json_quic.close();
                    write_flow_key(json_record, k);
                    json_record.print_key_timestamp("event_start", ts);
                    json_record.close();
                }
            }
            break;
        case udp_msg_type_wireguard:
            {
                wireguard_handshake_init wg;
                wg.parse(pkt);
                if (wg.is_valid()) {
                    struct json_object record{&buf};
                    wg.write_json(record);
                    write_flow_key(record, k);
                    record.print_key_timestamp("event_start", ts);
                    record.close();
                }
            }
            break;
        case udp_msg_type_dns:
            {
                if (global_vars.dns_json_output) {
                    struct dns_packet dns_pkt{pkt};
                    if (dns_pkt.is_not_empty()) {
                        struct json_object json_record{&buf};
                        struct json_object json_dns{json_record, "dns"};
                        dns_pkt.write_json(json_dns);
                        json_dns.close();
                        write_flow_key(json_record, k);
                        json_record.print_key_timestamp("event_start", ts);
                        json_record.close();
                    }
                } else {
                    struct json_object json_record{&buf};
                    struct json_object json_dns{json_record, "dns"};
                    json_dns.print_key_base64("base64", pkt);
                    json_dns.close();
                    write_flow_key(json_record, k);
                    json_record.print_key_timestamp("event_start", ts);
                    json_record.close();
                }
            }
            break;
        case udp_msg_type_dtls_client_hello:
            {
                struct dtls_record dtls_rec;
                dtls_rec.parse(pkt);
                struct dtls_handshake handshake;
                handshake.parse(dtls_rec.fragment);
                if (handshake.msg_type == handshake_type::client_hello) {
                    struct tls_client_hello hello;
                    hello.parse(handshake.body);
                    if (hello.is_not_empty()) {
                        struct json_object record{&buf};
                        struct json_object fps{record, "fingerprints"};
                        fps.print_key_value("dtls", hello);
                        fps.close();
                        hello.write_json(record, global_vars.metadata_output);
                        write_flow_key(record, k);
                        record.print_key_timestamp("event_start", ts);
                        record.close();
                    }
                }
            }
            break;
        case udp_msg_type_dhcp:
            {
                struct dhcp_discover dhcp_disco;
                dhcp_disco.parse(pkt);
                if (dhcp_disco.is_not_empty()) {
                    struct json_object record{&buf};
                    struct json_object fps{record, "fingerprints"};
                    fps.print_key_value("dhcp", dhcp_disco);
                    fps.close();
                    if (global_vars.metadata_output) {
                        dhcp_disco.write_json(record);
                    }
                    write_flow_key(record, k);
                    record.print_key_timestamp("event_start", ts);
                    record.close();
                }
            }
            break;
        case udp_msg_type_dtls_server_hello:
        case udp_msg_type_dtls_certificate:
            // cases that fall through here are not yet supported
        case udp_msg_type_unknown:
            if (is_new) {
                struct json_object record{&buf};
                struct json_object udp{record, "udp"};
                udp.print_key_hex("data", pkt);
                // udp.print_key_json_string("data_string", pkt);
                udp.close();
                write_flow_key(record, k);
                record.print_key_timestamp("event_start", ts);
                record.close();
            }
            break;
        }
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

    struct buffer_stream buf{NULL, 0};
    struct key k;
    struct datum pkt{ip_packet, ip_packet+length};
    size_t transport_proto = 0;

    size_t ip_version;
    if (datum_read_uint(&pkt, 1, &ip_version) == status_err) {
        return 0;
    }
    ip_version &= 0xf0;
    switch(ip_version) {
    case 0x40:
        datum_process_ipv4(&pkt, &transport_proto, &k);
        break;
    case 0x60:
        datum_process_ipv6(&pkt, &transport_proto, &k);
        break;
    default:
        return 0;  // unsupported IP version
    }

    if (report_GRE && transport_proto == 47) {
        gre_header gre{pkt};
        switch(gre.get_protocol_type()) {
        case ETH_TYPE_IP:
            datum_process_ipv4(&pkt, &transport_proto, &k);
            break;
        case ETH_TYPE_IPV6:
            datum_process_ipv6(&pkt, &transport_proto, &k);
            break;
        default:
            ;
        }

    }
    if (transport_proto == 6) {
        struct tcp_packet tcp_pkt;
        tcp_pkt.parse(pkt);
        if (tcp_pkt.header == nullptr) {
            return 0;  // incomplete tcp header; can't process packet
        }
        tcp_pkt.set_key(k);
        if (tcp_pkt.is_SYN()) {

        } else if (tcp_pkt.is_SYN_ACK()) {

        } else {

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
                return tcp_data_set_analysis_result(r, pkt, k, tcp_pkt, ts, nullptr);  // process packet without tcp reassembly
            }
        }
    }

    return false;
}

size_t stateful_pkt_proc::write_json(void *buffer,
                                     size_t buffer_size,
                                     uint8_t *packet,
                                     size_t length,
                                     struct timespec *ts,
                                     struct tcp_reassembler *reassembler) {

    struct datum pkt{packet, packet+length};
    size_t ethertype = 0;
    datum_process_eth(&pkt, &ethertype);

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

class tls_server_hello_and_certificate {
    struct tls_server_hello hello;
    struct tls_server_certificate certificate;

public:
    tls_server_hello_and_certificate() : hello{}, certificate{} {}

    void parse(struct datum &pkt, struct tcp_packet *tcp_pkt) {
        struct tls_record rec;
        struct tls_handshake handshake;

        // parse server_hello and/or certificate
        //
        rec.parse(pkt);
        handshake.parse(rec.fragment);
        if (handshake.msg_type == handshake_type::server_hello) {
            hello.parse(handshake.body);
            if (rec.is_not_empty()) {
                struct tls_handshake h;
                h.parse(rec.fragment);
                certificate.parse(h.body);
            }

        } else if (handshake.msg_type == handshake_type::certificate) {
            certificate.parse(handshake.body);
        }
        struct tls_record rec2;
        rec2.parse(pkt);
        struct tls_handshake handshake2;
        handshake2.parse(rec2.fragment);
        if (handshake2.msg_type == handshake_type::certificate) {
            certificate.parse(handshake2.body);
        }
        if (tcp_pkt && certificate.additional_bytes_needed) {
            tcp_pkt->reassembly_needed(certificate.additional_bytes_needed);
        }
    }

    bool is_not_empty() {
        return hello.is_not_empty() || certificate.is_not_empty();
    }

    void write_json(struct json_object &record) {

        bool have_hello = hello.is_not_empty();
        bool have_certificate = certificate.is_not_empty();
        if (have_hello || have_certificate) {

            // output certificate (always) and server_hello (if configured to)
            //
            if ((global_vars.metadata_output && have_hello) || have_certificate) {
                struct json_object tls{record, "tls"};
                struct json_object tls_server{tls, "server"};
                if (have_certificate) {
                    struct json_array server_certs{tls_server, "certs"};
                    certificate.write_json(server_certs, global_vars.certs_json_output);
                    server_certs.close();
                }
                if (global_vars.metadata_output && have_hello) {
                    hello.write_json(tls_server);
                }
                tls_server.close();
                tls.close();
            }
        }
    }

    void write_fingerprint(struct json_object &object) {
        if (hello.is_not_empty()) {
            struct json_object fps{object, "fingerprints"};
            fps.print_key_value("tls_server", hello);
            fps.close();
        }
    }

    void compute_fingerprint(struct fingerprint &fp) const {
        if (hello.is_not_empty()) {
            fp.set(hello, fingerprint_type_tls_server);
        }
    }

    const char *get_name() {
        if (hello.is_not_empty()) {
            return "tls_server";
        }
        return nullptr;
    }

    void operator()(buffer_stream &b) {
        if (hello.is_not_empty()) {
            hello(b);
        }
    }
};

class unknown_initial_packet {
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
                                  unknown_initial_packet
                                  >;


template <size_t I = 0>
void enumerate_tcp_protocol_types() {
    if constexpr (I < std::variant_size_v<tcp_protocol>) {
        std::variant_alternative_t<I, tcp_protocol> tmp;
        fprintf(stderr, "I=%zu\n", I);
        enumerate_tcp_protocol_types<I + 1>();
    }
}

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

    write_metadata(struct json_object &object) : record{object} {}

    template <typename T>
    void operator()(T &r) {
        r.write_json(record, global_vars.metadata_output);
    }

    void operator()(http_response &r) {
        if (global_vars.metadata_output) {
            r.write_json(record);
        }
    }

    void operator()(tls_server_hello_and_certificate &r) {
        r.write_json(record);
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

    void operator()(std::monostate &) { }

    void operator()(unknown_initial_packet &) { }

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

    void operator()(tls_client_hello &r) {
        struct json_object fps{record, "fingerprints"};
        fps.print_key_value("tls", r);
        fps.close();
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

    void operator()(std::monostate &) { }
};

struct do_analysis {
    const struct key &k_;
    struct analysis_context &analysis_;

    do_analysis(const struct key &k,
                struct analysis_context &analysis) :
        k_{k},
        analysis_{analysis}
    {}

    bool operator()(tls_client_hello &r) {
        if (global_vars.do_analysis) {
            extern classifier *c;
            //  r.set_fingerprint(analysis_.fp);
            //  analysis_.fp.init(r);
            analysis_.destination.init(r, k_);
            return c->analyze_fingerprint_and_destination_context(analysis_.fp, analysis_.destination, analysis_.result);
        }
        return false;
    }

    template <typename T>
    bool operator()(T &) { return false; }

};

void set_tcp_protocol(tcp_protocol &x,
                      struct datum &pkt,
                      bool is_new,
                      struct tcp_packet *tcp_pkt) {

    // note: std::get<T>() throws exceptions; it might be better to
    // use get_if<T>(), which does not

    enum tcp_msg_type msg_type = get_message_type(pkt.data, pkt.length());
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
    set_tcp_protocol(x, pkt, is_new, reassembler == nullptr ? nullptr : &tcp_pkt);

    if (tcp_pkt.additional_bytes_needed) {
        if (reassembler->copy_packet(k, ts->tv_sec, tcp_pkt.header, tcp_pkt.data_length, tcp_pkt.additional_bytes_needed)) {
            return;
        }
    }
    if (std::visit(is_not_empty{}, x)) {

        std::visit(compute_fingerprint{analysis.fp}, x);
        bool output_analysis = std::visit(do_analysis{k, analysis}, x);

        if (malware_prob_threshold > -1.0 && (!output_analysis || analysis.result.malware_prob < malware_prob_threshold)) { return; } // TODO - expose hidden command

        struct json_object record{&buf};
        if (analysis.fp.get_type() != fingerprint_type_unknown) {
            analysis.fp.write(record);
        }

        if (analysis.fp.get_type() == fingerprint_type_tls) {
            //
            // TODO: observe_event() should only be invoked if
            // analysis.destination has been set by a previous call to
            // do_analysis
            //
            char src_ip_str[MAX_ADDR_STR_LEN];
            k.sprint_src_addr(src_ip_str);
            char dst_port_str[MAX_PORT_STR_LEN];
            k.sprint_dst_port(dst_port_str);
            //fp_stats.observe(src_ip_str, analysis.fp.fp_str, analysis.destination.sn_str, analysis.destination.dst_ip_str, analysis.destination.dst_port);
            std::string event_string;
            event_string.append("(");
            event_string.append(src_ip_str).append(")#(");
            event_string.append(analysis.fp.fp_str).append(")#(");
            event_string.append(analysis.destination.sn_str).append(")(");
            event_string.append(analysis.destination.dst_ip_str).append(")(");
            event_string.append(dst_port_str).append(")");
            mq->push((uint8_t *)event_string.c_str(), event_string.length()+1);
        }

        std::visit(write_metadata{record}, x);
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
    set_tcp_protocol(x, pkt, false, nullptr);

    if (std::visit(is_not_empty{}, x)) {

        std::visit(compute_fingerprint{analysis.fp}, x);
        if (std::visit(do_analysis{k, analysis}, x)) {
            *r = analysis.result;
            return true;
        }
    }

    return false;
}

// aggregator is a global data structure holding all of the statistics
// on traffic observations, as well as the message queues needed to
// send data to the aggregator.

struct data_aggregator aggregator;

