/*
 * pkt_proc.c
 * 
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at 
 * https://github.com/cisco/mercury/blob/master/LICENSE 
 */

#include <string.h>
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

extern struct libmerc_config global_vars;  // defined in libmerc.h

double malware_prob_threshold = 0.0; // HACK for demo

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
    enum tcp_msg_type msg_type = get_message_type(pkt.data, pkt.length());

    bool is_new = false;
    if (global_vars.output_tcp_initial_data) {
        is_new = tcp_flow_table.is_first_data_packet(k, ts->tv_sec, ntohl(tcp_pkt.header->seq));
    }

    switch(msg_type) {
    case tcp_msg_type_http_request:
        {
            struct http_request request;
            request.parse(pkt);
            if (request.is_not_empty()) {
                struct json_object record{&buf};
                struct json_object fps{record, "fingerprints"};
                fps.print_key_value("http", request);
                fps.close();
                // record.print_key_string("complete", request.headers.complete ? "yes" : "no");  // TBD: (re)move
                request.write_json(record, global_vars.metadata_output);
                write_flow_key(record, k);
                record.print_key_timestamp("event_start", ts);
                record.close();
            }
        }
        break;
    case tcp_msg_type_tls_client_hello:
        {
            struct tls_record rec;
            rec.parse(pkt);
            struct tls_handshake handshake;
            handshake.parse(rec.fragment);
            if (handshake.additional_bytes_needed && reassembler) {
                // fprintf(stderr, "tls.handshake.client_hello (%zu)\n", handshake.additional_bytes_needed);
                if (reassembler->copy_packet(k, ts->tv_sec, tcp_pkt.header, tcp_pkt.data_length, handshake.additional_bytes_needed)) {
                    return;
                }
            }
            struct tls_client_hello hello;
            hello.parse(handshake.body);
            if (hello.is_not_empty()) {
                struct json_object record{&buf};
                struct json_object fps{record, "fingerprints"};
                fps.print_key_value("tls", hello);
                fps.close();
                hello.write_json(record, global_vars.metadata_output);
                /*
                 * output analysis (if it's configured)
                 */
                if (global_vars.do_analysis) {
                    extern classifier *c;
                    analysis.fp.init(hello);
                    analysis.destination.init(hello, k);
                    if (c->analyze_fingerprint_and_destination_context(analysis.fp, analysis.destination, analysis.result)) {
                        analysis.result.write_json(record, "analysis");
                    }
                }
                write_flow_key(record, k);
                record.print_key_timestamp("event_start", ts); // HACK: _as_string
                record.close();
            }
            // if (analysis.result.max_mal || (analysis.result.malware_prob >= malware_prob_threshold)) { return; } // HACK
        }
        break;
    case tcp_msg_type_tls_server_hello:
    case tcp_msg_type_tls_certificate:
        {
            struct tls_record rec;
            struct tls_handshake handshake;
            struct tls_server_hello hello;
            struct tls_server_certificate certificate;

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

            if (certificate.additional_bytes_needed && reassembler) {
                // fprintf(stderr, "tls.handshake.certificate (%zu)\n", certificate.additional_bytes_needed);
                if (reassembler->copy_packet(k, ts->tv_sec, tcp_pkt.header, tcp_pkt.data_length, certificate.additional_bytes_needed)) {
                    return;
                }
            }

            bool have_hello = hello.is_not_empty();
            bool have_certificate = certificate.is_not_empty();
            if (have_hello || have_certificate) {
                struct json_object record{&buf};

                // output fingerprint
                if (have_hello) {
                    struct json_object fps{record, "fingerprints"};
                    fps.print_key_value("tls_server", hello);
                    fps.close();
                }

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
                write_flow_key(record, k);
                record.print_key_timestamp("event_start", ts);
                record.close();
            }
        }
        break;
    case tcp_msg_type_http_response:
        {
            struct http_response response;
            response.parse(pkt);
            if (response.is_not_empty()) {
                struct json_object record{&buf};
                struct json_object fps{record, "fingerprints"};
                fps.print_key_value("http_server", response);
                fps.close();
                // record.print_key_string("complete", response.headers.complete ? "yes" : "no");  // TBD: (re)move?
                if (global_vars.metadata_output) {
                    response.write_json(record);
                }
                write_flow_key(record, k);
                record.print_key_timestamp("event_start", ts);
                record.close();
            }
        }
        break;
    case tcp_msg_type_ssh:
        {
            struct ssh_init_packet init_packet;
            init_packet.parse(pkt);
            struct json_object record{&buf};
            struct json_object fps{record, "fingerprints"};
            fps.print_key_value("ssh", init_packet);
            fps.close();
            init_packet.write_json(record, global_vars.metadata_output);
#ifdef SSHM
            if (pkt.is_not_empty()) {
                pkt.accept('\n');
                record.print_key_json_string("ssh_residual_data", pkt.data, pkt.length());
                struct ssh_binary_packet bin_pkt;
                bin_pkt.parse(pkt);
                struct ssh_kex_init kex_init;
                kex_init.parse(bin_pkt.payload);
                kex_init.write_json(record, global_vars.metadata_output);
            }
#endif
            write_flow_key(record, k);
            record.print_key_timestamp("event_start", ts);
            record.close();
        }
        break;
    case tcp_msg_type_ssh_kex:
        {
            struct ssh_binary_packet ssh_pkt;
            ssh_pkt.parse(pkt);
            if (ssh_pkt.additional_bytes_needed && reassembler) {
                // fprintf(stderr, "ssh.binary_packet (%zu)\n", ssh_pkt.additional_bytes_needed);
                if (reassembler->copy_packet(k, ts->tv_sec, tcp_pkt.header, tcp_pkt.data_length, ssh_pkt.additional_bytes_needed)) {
                    return;
                }
            }
            struct ssh_kex_init kex_init;
            kex_init.parse(ssh_pkt.payload);
            if (kex_init.is_not_empty()) {
                struct json_object record{&buf};
                struct json_object fps{record, "fingerprints"};
                fps.print_key_value("ssh_kex", kex_init);
                fps.close();
                kex_init.write_json(record, global_vars.metadata_output);
                write_flow_key(record, k);
                record.print_key_timestamp("event_start", ts);
                record.close();
            }
        }
        break;
    case tcp_msg_type_unknown:

        if (is_new) {
            // if this packet is a TLS record, ignore it
            if (tls_record::is_valid(pkt)) {
                return;
            }

            // output the data field
            struct json_object record{&buf};
            struct json_object tcp{record, "tcp"};
            tcp.print_key_hex("data", pkt);
            tcp.close();
            write_flow_key(record, k);
            record.print_key_timestamp("event_start", ts);
            record.close();
        }
        break;
    }

    //buf.doff = 0; // HACK: squelch printing
}

// tcp_data_write_json() parses TCP data and writes metadata into
// a buffer stream, if any is found
//
bool stateful_pkt_proc::tcp_data_set_analysis_result(struct analysis_result *r,
                                                     struct datum &pkt,
                                                     const struct key &k,
                                                     struct tcp_packet &tcp_pkt,
                                                     struct timespec *ts,
                                                     struct tcp_reassembler *reassembler) {

    if (pkt.is_not_empty() == false) {
        return false;
    }
    enum tcp_msg_type msg_type = get_message_type(pkt.data, pkt.length());

    // DEAD CODE
    //
    // bool is_new = false;
    // if (global_vars.output_tcp_initial_data) {
    //     is_new = tcp_flow_table.is_first_data_packet(k, ts->tv_sec, ntohl(tcp_pkt.header->seq));
    // }

    switch(msg_type) {
    case tcp_msg_type_http_request:
        break;
    case tcp_msg_type_tls_client_hello:
        {
            struct tls_record rec;
            rec.parse(pkt);
            struct tls_handshake handshake;
            handshake.parse(rec.fragment);
            if (handshake.additional_bytes_needed && reassembler) {
                // fprintf(stderr, "tls.handshake.client_hello (%zu)\n", handshake.additional_bytes_needed);
                if (reassembler->copy_packet(k, ts->tv_sec, tcp_pkt.header, tcp_pkt.data_length, handshake.additional_bytes_needed)) {
                    return false;
                }
            }
            struct tls_client_hello hello;
            hello.parse(handshake.body);
            if (hello.is_not_empty()) {
                if (global_vars.do_analysis) {
                    extern classifier *c;

                    analysis.fp.init(hello);
                    analysis.destination.init(hello, k);
                    if (c->analyze_fingerprint_and_destination_context(analysis.fp, analysis.destination, analysis.result)) {
                        *r = analysis.result;
                        return true;
                    }
                }
            }
        }
        break;
    case tcp_msg_type_tls_server_hello:
    case tcp_msg_type_tls_certificate:
        break;
    case tcp_msg_type_http_response:
        break;
    case tcp_msg_type_ssh:
        break;
    case tcp_msg_type_ssh_kex:
        break;
    case tcp_msg_type_unknown:
        break;
    }
    return false;
}

//////////////////////////////////////////////////////////


class tls_server_hello_and_certificate {
    struct tls_server_hello hello;
    struct tls_server_certificate certificate;

public:
    tls_server_hello_and_certificate() : hello{}, certificate{} {}

    void parse(struct datum &pkt) {
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
#ifdef TBD
        if (certificate.additional_bytes_needed && reassembler) {
            // fprintf(stderr, "tls.handshake.certificate (%zu)\n", certificate.additional_bytes_needed);
            if (reassembler->copy_packet(k, ts->tv_sec, tcp_pkt.header, tcp_pkt.data_length, certificate.additional_bytes_needed)) {
                return;
            }
        }
#endif
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

};

//#define NEWCODE 1  // using std::variant
#ifdef NEWCODE

#include <variant>

using tcp_protocol = std::variant<http_request,
                                  http_response,
                                  tls_client_hello,
                                  tls_server_hello_and_certificate,
                                  ssh_init_packet,
                                  ssh_kex_init,
                                  std::monostate>;

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
        r.write_json(record);
    }
    void operator()(tls_server_hello_and_certificate &r) {
        r.write_json(record);
    }
    void operator()(std::monostate &r) {
        (void) r;
    }
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

    void operator()(std::monostate &r) {
        (void) r;
    }
};

struct write_analysis {
    struct json_object &record;
    const struct key &k_;
    struct analysis_context &analysis_;

    write_analysis(struct json_object &object,
                   const struct key &k,
                   struct analysis_context &analysis) :
        record{object},
        k_{k},
        analysis_{analysis}
    {}

    void operator()(tls_client_hello &r) {
        if (global_vars.do_analysis) {
            extern classifier *c;
            analysis_.fp.init(r);
            analysis_.destination.init(r, k_);
            if (c->analyze_fingerprint_and_destination_context(analysis_.fp, analysis_.destination, analysis_.result)) {
                analysis_.result.write_json(record, "analysis");
            }
        }
    }

    template <typename T>
    void operator()(T &r) {
        (void) r;
    }
    void operator()(std::monostate &r) {
        (void) r;
    }
};



tcp_protocol get_tcp_protocol(struct datum &pkt) {

    enum tcp_msg_type msg_type = get_message_type(pkt.data, pkt.length());
    switch(msg_type) {
    case tcp_msg_type_http_request:
        {
            tcp_protocol tmp{std::in_place_type<http_request>};
            auto &request = std::get<http_request>(tmp);
            request.parse(pkt);
            return tmp;
        }
    case tcp_msg_type_http_response:
        {
            tcp_protocol tmp{std::in_place_type<http_response>};
            auto &response = std::get<http_response>(tmp);
            response.parse(pkt);
            return tmp;
        }
    case tcp_msg_type_tls_client_hello:
        {
            struct tls_record rec;
            rec.parse(pkt);
            struct tls_handshake handshake;
            handshake.parse(rec.fragment);
#ifdef TBD
            if (handshake.additional_bytes_needed && reassembler) {
                // fprintf(stderr, "tls.handshake.client_hello (%zu)\n", handshake.additional_bytes_needed);
                if (reassembler->copy_packet(k, ts->tv_sec, tcp_pkt.header, tcp_pkt.data_length, handshake.additional_bytes_needed)) {
                    return;
                }
            }
#endif
            tcp_protocol tmp{std::in_place_type<tls_client_hello>};
            auto &message = std::get<tls_client_hello>(tmp);
            message.parse(handshake.body);
            return tmp;
        }
    case tcp_msg_type_tls_server_hello:
    case tcp_msg_type_tls_certificate:
        {
            //            class tls_server_hello_and_certificate hello_and_cert{};
            tcp_protocol tmp{std::in_place_type<tls_server_hello_and_certificate>};
            auto &response = std::get<tls_server_hello_and_certificate>(tmp);
            response.parse(pkt);
            return tmp;
        }
    default:
        ;
    }
    tcp_protocol tmp{std::in_place_type<std::monostate>};
    return tmp;
}

void set_tcp_protocol(tcp_protocol &x, struct datum &pkt) {

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
#ifdef TBD
            if (handshake.additional_bytes_needed && reassembler) {
                // fprintf(stderr, "tls.handshake.client_hello (%zu)\n", handshake.additional_bytes_needed);
                if (reassembler->copy_packet(k, ts->tv_sec, tcp_pkt.header, tcp_pkt.data_length, handshake.additional_bytes_needed)) {
                    return;
                }
            }
#endif
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
            msg.parse(pkt);
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
#if TBD
            if (ssh_pkt.additional_bytes_needed && reassembler) {
                // fprintf(stderr, "ssh.binary_packet (%zu)\n", ssh_pkt.additional_bytes_needed);
                if (reassembler->copy_packet(k, ts->tv_sec, tcp_pkt.header, tcp_pkt.data_length, ssh_pkt.additional_bytes_needed)) {
                    return;
                }
            }
#endif // TBD
            x.emplace<ssh_kex_init>();
            auto &kex_init = std::get<ssh_kex_init>(x);
            kex_init.parse(ssh_pkt.payload);
            break;
        }
    default:
        x.emplace<std::monostate>();
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

    (void) tcp_pkt;
    (void) reassembler;

    if (pkt.is_not_empty() == false) {
        return;
    }
    tcp_protocol x;
    set_tcp_protocol(x, pkt);
    if (std::visit(is_not_empty{}, x)) {
        struct json_object record{&buf};
        std::visit(write_fingerprint{record}, x);
        std::visit(write_metadata{record}, x);
        std::visit(write_analysis{record, k, analysis}, x);
        write_flow_key(record, k);
        record.print_key_timestamp("event_start", ts);
        record.close();
    }

    // TBD: add first data packet processing

}

#endif // NEWCODE
