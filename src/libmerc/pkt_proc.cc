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
#include "bittorrent.h"
#include "ip.h"
#include "tcp.h"
#include "dns.h"
#include "mdns.h"
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
#include "ssdp.h"
#include "stun.h"
#include "smtp.h"
#include "tofsee.hpp"
#include "cdp.h"
#include "lldp.h"
#include "ospf.h"
#include "sctp.h"
#include "analysis.h"
#include "buffer_stream.h"
#include "stats.h"
#include "ppp.h"
#include "smb1.h"
#include "smb2.h"
#include "netbios.h"
#include "openvpn.h"
#include "mysql.hpp"

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

struct do_crypto_assessment {
    const crypto_policy::assessor *ca;
    json_object &record;

    do_crypto_assessment(const crypto_policy::assessor *assessor, json_object &o) : ca{assessor}, record{o} { }

    bool operator()(const tls_client_hello &msg) {
        ca->assess(msg, record);
        return false;
    }

    bool operator()(const quic_init &msg) {
        if (msg.has_tls()) {
            ca->assess(msg.get_tls_client_hello(), record);
        }
        return false;
    }

    template <typename T>
    bool operator()(const T &) {
        return false;   // no assessment performed for all other types
    }

    bool operator()(std::monostate &) { return false; }

};

class event_string
{
    const struct key &k;
    const struct analysis_context &analysis;
    std::string dest_context;
    event_msg event;

public:
    event_string(const struct key &k, const struct analysis_context &analysis) :
        k{k}, analysis{analysis} {  }

    event_msg construct_event_string() {
        char src_ip_str[MAX_ADDR_STR_LEN];
        k.sprint_src_addr(src_ip_str);
        char dst_port_str[MAX_PORT_STR_LEN];
        k.sprint_dst_port(dst_port_str);

        dest_context.append("(");
        dest_context.append(analysis.destination.sn_str).append(")(");
        dest_context.append(analysis.destination.dst_ip_str).append(")(");
        dest_context.append(dst_port_str).append(")");

        event = std::make_tuple(src_ip_str, analysis.fp.string(), analysis.destination.ua_str, dest_context);
        return event;
    }
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
        event_string ev_str{k_, analysis_};
        mq_->push(ev_str.construct_event_string());
    }

    void operator()(quic_init &) {
        // create event and send it to the data/stats aggregator
        event_string ev_str{k_, analysis_};
        mq_->push(ev_str.construct_event_string());
    }

    void operator()(http_request &) {
        // create event and send it to the data/stats aggregator
        event_string ev_str{k_, analysis_};
        mq_->push(ev_str.construct_event_string());
        analysis_.reset_user_agent();
    }

    template <typename T>
    void operator()(T &) { }

};

// set_tcp_protocol() sets the protocol variant record to the data
// structure resulting from the parsing of the TCP data field, which
// will be one of the TCP protocols in that variant.  The default
// value of std::monostate indicates that the protocol matcher did not
// recognize, or could not parse, the packet.  The class
// unknown_initial_packet represents the TCP data field of an
// unrecognized packet that is the first data packet in a flow.
//
void stateful_pkt_proc::set_tcp_protocol(protocol &x,
                      struct datum &pkt,
                      bool is_new,
                      struct tcp_packet *tcp_pkt) {

    // note: std::get<T>() throws exceptions; it might be better to
    // use get_if<T>(), which does not

    enum tcp_msg_type msg_type = (tcp_msg_type) selector.get_tcp_msg_type(pkt);
    if (msg_type == tcp_msg_type_unknown) {
        msg_type = (tcp_msg_type) selector.get_tcp_msg_type_from_ports(tcp_pkt);
    }

    switch(msg_type) {
    case tcp_msg_type_http_request:
        x.emplace<http_request>(pkt);
        break;
    case tcp_msg_type_http_response:
        x.emplace<http_response>(pkt);
        break;
    case tcp_msg_type_tls_client_hello:
        {
            struct tls_record rec{pkt};
            struct tls_handshake handshake{rec.fragment};
            if (reassembler_ptr && tcp_pkt && handshake.additional_bytes_needed) {
                tcp_pkt->reassembly_needed(handshake.additional_bytes_needed);
                //  set pkt type as tls CH, so that initial segments can be fingerprinted as best effort for reassembly failed cases
            }
            x.emplace<tls_client_hello>(handshake.body);
            break;
        }
    case tcp_msg_type_tls_server_hello:
    case tcp_msg_type_tls_certificate:
        x.emplace<tls_server_hello_and_certificate>(pkt, tcp_pkt);
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
    case tcp_msg_type_dns:
    {
        /* Trim the 2 byte length field in case of
         * dns over tcp.
         */
        uint16_t len = 0;
        pkt.read_uint16(&len);
        pkt.trim_to_length(len);
        x.emplace<dns_packet>(pkt);
        break;
    }
    case tcp_msg_type_smb1:
        x.emplace<smb1_packet>(pkt);
        break;
    case tcp_msg_type_smb2:
        x.emplace<smb2_packet>(pkt);
        break;
    case tcp_msg_type_iec:
        x.emplace<iec60870_5_104>(pkt);
        break;
    case tcp_msg_type_dnp3:
        x.emplace<dnp3>(pkt);
        break;
    case tcp_msg_type_nbss:
        x.emplace<nbss_packet>(pkt);
        break;
    case tcp_msg_type_openvpn:
        x.emplace<openvpn_tcp>(pkt);
        break;
    case tcp_msg_type_bittorrent:
        x.emplace<bittorrent_handshake>(pkt);
        break;
    case tcp_msg_type_mysql_server:
        x.emplace<mysql_server_greet>(pkt);
        break;
    default:
        if (is_new && global_vars.output_tcp_initial_data) {
            if (pkt.length() == 200) {
                x.emplace<tofsee_initial_message>(pkt);
                break;
            }
            x.emplace<unknown_initial_packet>(pkt);
        } else {
            x.emplace<std::monostate>();
        }
        break;
    }
}

// set_udp_protocol() sets the protocol variant record to the data
// structure resulting from the parsing of the UDP data field, which
// will be one of the UDP protcols in that variant.  The default value
// of std::monostate indicates that the protocol matcher did not
// recognize, or could not parse, the packet.  The class
// unknown_udp_initial_packet represents the UDP data field of an
// unrecognized packet that is the first data packet in a flow.
//
void stateful_pkt_proc::set_udp_protocol(protocol &x,
                      struct datum &pkt,
                      enum udp_msg_type msg_type,
                      bool is_new,
                      const struct key& k) {

    // note: std::get<T>() throws exceptions; it might be better to
    // use get_if<T>(), which does not

    // enum msg_type msg_type = udp_get_message_type(pkt.data, pkt.length());
    // if (msg_type == msg_type_unknown) {
    //     msg_type = udp_pkt.estimate_msg_type_from_ports();
    // }
    switch(msg_type) {
    case udp_msg_type_dns:
        if (mdns_packet::check_if_mdns(k)) {
            if (!selector.mdns()) {
                return;
            }
            x.emplace<mdns_packet>(pkt);
        } else {
            dns_packet packet{pkt};
            if ((packet.netbios() and !selector.nbns()) or
                (!packet.netbios() and !selector.dns())) {
                return;
            }
            x = std::move(packet);
        }
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
                x.emplace<dtls_client_hello>(handshake.body);
            }
        }
        break;
    case udp_msg_type_dtls_server_hello:
        {
            struct dtls_record dtls_rec{pkt};
            struct dtls_handshake handshake{dtls_rec.fragment};
            if (handshake.msg_type == handshake_type::server_hello) {
                x.emplace<dtls_server_hello>(handshake.body);
            }
        }
        break;
    case udp_msg_type_wireguard:
        x.emplace<wireguard_handshake_init>(pkt);
        break;
    case udp_msg_type_ssdp:
        x.emplace<ssdp>(pkt);
        break;
    case udp_msg_type_stun:
        x.emplace<stun::message>(pkt);
        break;
    case udp_msg_type_nbds:
        x.emplace<nbds_packet>(pkt);
        break;
    case udp_msg_type_dht:
        x.emplace<bittorrent_dht>(pkt);
        break;
    case udp_msg_type_lsd:
        x.emplace<bittorrent_lsd>(pkt);
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

// returns boolean whether to fingerprrint/analyze current tcp pkt
bool stateful_pkt_proc::process_tcp_data (protocol &x,
                          struct datum &pkt,
                          struct tcp_packet &tcp_pkt,
                          struct key &k,
                          struct timespec *ts,
                          struct tcp_reassembler *reassembler) {

    // No reassembler : call set_tcp_protocol on every data pkt
    if (!reassembler) {
        bool is_new = false;
        if (global_vars.output_tcp_initial_data) {
            is_new = tcp_flow_table.is_first_data_packet(k, ts->tv_sec, ntoh(tcp_pkt.header->seq));
        }
        set_tcp_protocol(x, pkt, is_new, &tcp_pkt);
        //reassembler->dump_pkt = false;
        return true;
    }

    reassembler->curr_reassembly_consumed = false;
    reassembler->curr_reassembly_state = reassembly_none;
    uint32_t syn_seq;
    bool initial_seg = false;
    bool expired = false;
    bool in_reassembly = false;
    struct tcp_seg_context seg_context(tcp_pkt.data_length, ntoh(tcp_pkt.header->seq), tcp_pkt.additional_bytes_needed);

    if (!tcp_pkt.data_length) {
        reassembler->dump_pkt = false;
        return false;
    }

    // try to fetch the syn seq (seq for first data seg) for this flow
    syn_seq = tcp_flow_table.check_flow(k, ts->tv_sec, ntoh(tcp_pkt.header->seq), initial_seg, expired);

    if (syn_seq) {
        // In flow table, can't be in reassembly_table
        if (initial_seg) {
            // initial seg, try parsing
            datum pkt_copy{pkt};
            set_tcp_protocol(x, pkt, true, &tcp_pkt);
            if(!tcp_pkt.additional_bytes_needed) {
                reassembler->dump_pkt = false;
                reassembler->curr_reassembly_state = reassembly_none;
                return true;
            }
            
            //reassembly required, add to reassembly table
            seg_context.additional_bytes_needed = tcp_pkt.additional_bytes_needed;
            reassembler->init_segment(k, ts->tv_sec, seg_context, syn_seq, pkt_copy);
            //write_pkt = true;
            reassembler->dump_pkt = true;
            reassembler->curr_reassembly_state = reassembly_in_progress;
            return true;
        }
        else {
            // non initial seg, directly put in reassembler
            reassembler->init_segment(k, ts->tv_sec, seg_context, syn_seq, pkt);
            // write_pkt = false; for out of order pkts, write to pcap file only after initial seg is known
            reassembler->dump_pkt = false;
            reassembler->curr_reassembly_state = reassembly_in_progress;
            // call set_tcp_protocol in case there is something worth fingerpriting
            set_tcp_protocol(x, pkt, false, &tcp_pkt);
            return true;
        }
    }
    else {
        // check in reassembly_table
        //if initial segment, update additional bytes needed
        //
        bool is_init_seg = false;
        datum pkt_copy{pkt};
        is_init_seg = reassembler->is_init_seg(k, seg_context.seq);
        if (is_init_seg) {
            set_tcp_protocol(x, pkt, true, &tcp_pkt);
            seg_context.additional_bytes_needed = tcp_pkt.additional_bytes_needed;
        }
        else {
            set_tcp_protocol(x, pkt, false, &tcp_pkt);
        }

        bool reassembly_consumed = false;
        struct tcp_segment *seg = reassembler->check_packet(k, ts->tv_sec, seg_context, pkt_copy, reassembly_consumed);
        if (reassembly_consumed) {
            // reassmebled data already consumed for this flow
            reassembler->pruner.nodes[seg->prune_index].is_in_map = false;
            reassembler->remove_segment(k);
            reassembler->dump_pkt = false;
            reassembler->curr_reassembly_state = reassembly_done;
            return false;
        }
        if (seg) {
            in_reassembly = true;
            
            if (seg->total_bytes_needed) {
                reassembler->dump_pkt = true;
            }
            
            if(seg->done) {
                reassembler->pruner.nodes[seg->prune_index].is_in_map = false;
                struct datum reassembled_data = seg->get_reassembled_segment();
                set_tcp_protocol(x, reassembled_data, true, &tcp_pkt);
                reassembler->dump_pkt = false;
                reassembler->curr_reassembly_consumed = true;
                reassembler->curr_reassembly_state = reassembly_done;
                return true;
            }

            reassembler->curr_reassembly_state = reassembly_in_progress;
        }
        return true;
    }

    if (!syn_seq && !in_reassembly) {
        // data pkt without syn, try to process as new data pkt
        // TODO: add to table to prevent processing again
        set_tcp_protocol(x, pkt, false, &tcp_pkt);
        reassembler->dump_pkt = false;
        reassembler->curr_reassembly_state = reassembly_none;
        return true;
    }

    return false;

}

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
    if (selector.gre() && transport_proto == ip::protocol::gre) {
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
    if (selector.icmp() && (transport_proto == ip::protocol::icmp || transport_proto == ip::protocol::ipv6_icmp)) {
        x.emplace<icmp_packet>(pkt);

    } else if (selector.ospf() && transport_proto == ip::protocol::ospfigp) {
        x.emplace<ospf>(pkt);

    } else if (selector.sctp() && transport_proto == ip::protocol::sctp) {
        x.emplace<sctp_init>(pkt);

    } else if (transport_proto == ip::protocol::tcp) {
        tcp_packet tcp_pkt{pkt, &ip_pkt};
        if (!tcp_pkt.is_valid()) {
            return 0;  // incomplete tcp header; can't process packet
        }
        tcp_pkt.set_key(k);
        if (tcp_pkt.is_SYN()) {

            tcp_flow_table.syn_packet(k, ts->tv_sec, ntoh(tcp_pkt.header->seq));
            if (selector.tcp_syn()) {
                x = tcp_pkt; // process tcp syn
            }
            // note: we could check for non-empty data field

        } else if (tcp_pkt.is_SYN_ACK()) {
            tcp_flow_table.syn_packet(k, ts->tv_sec, ntoh(tcp_pkt.header->seq));
            if (selector.tcp_syn() and selector.tcp_syn_ack()) {
                x = tcp_pkt;  // process tcp syn/ack
            }
            // note: we could check for non-empty data field

        } else {
            //bool write_pkt = false;
            if (!process_tcp_data(x, pkt, tcp_pkt, k, ts, reassembler)) {
                return 0;
            }
        }

    } else if (transport_proto == ip::protocol::udp) {
        class udp udp_pkt{pkt};
        udp_pkt.set_key(k);
        enum udp_msg_type msg_type = (udp_msg_type) selector.get_udp_msg_type(pkt);

        if (msg_type == udp_msg_type_unknown) {  // TODO: wrap this up in a traffic_selector member function
            udp::ports ports = udp_pkt.get_ports();
            msg_type = (udp_msg_type) selector.get_udp_msg_type_from_ports(ports);
            // if (ports.src == htons(53) || ports.dst == htons(53)) {
            //     msg_type = udp_msg_type_dns;
            // }
            // if (selector.mdns() && (ports.src == htons(5353) || ports.dst == htons(5353))) {
            //     msg_type = udp_msg_type_dns;
            // }
        /*    if (ports.dst == htons(4789)) {
                msg_type = udp_msg_type_vxlan;
            }
        */
        }

        bool is_new = false;
        if (global_vars.output_udp_initial_data && pkt.is_not_empty()) {
            is_new = ip_flow_table.flow_is_new(k, ts->tv_sec);
        }
        set_udp_protocol(x, pkt, msg_type, is_new, k);
    }

    // process transport/application protocol
    //
    if (std::visit(is_not_empty{}, x)) {
        std::visit(compute_fingerprint{analysis.fp, global_vars.tls_fingerprint_format}, x);
        bool output_analysis = false;
        if (global_vars.do_analysis && analysis.fp.get_type() != fingerprint_type_unknown) {
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
        if (crypto_policy) { std::visit(do_crypto_assessment{crypto_policy, record}, x); }

        if (reassembler) {
            reassembler->write_flags(record, "reassembly_properties");
            if (reassembler->curr_reassembly_consumed == true) {
                reassembler->remove_segment(reassembler->reap_it);
                reassembler->curr_reassembly_consumed = false;
            }
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
        if (selector.arp()) {
            x.emplace<arp_packet>(pkt);
        }
        break;
    case ETH_TYPE_CDP:
        if (selector.cdp()) {
            x.emplace<cdp>(pkt);
        }
        break;
    case ETH_TYPE_LLDP:
        if (selector.lldp()) {
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

size_t stateful_pkt_proc::write_json(void *buffer,
                                     size_t buffer_size,
                                     uint8_t *packet,
                                     size_t length,
                                     struct timespec *ts,
                                     struct tcp_reassembler *reassembler,
                                     uint16_t linktype) {

    struct datum pkt{packet, packet+length};

    switch (linktype)
    {
    case LINKTYPE_ETHERNET:
        return write_json(buffer, buffer_size, packet, length, ts, reassembler);
        break;
    case LINKTYPE_PPP:
       if(!ppp::is_ip(pkt))
            return 0;
        break;
    case LINKTYPE_RAW:
        break; 
    default:
        break;
    }

    return ip_write_json(buffer,
                         buffer_size,
                         pkt.data,
                         pkt.length(),
                         ts,
                         reassembler);
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

bool stateful_pkt_proc::analyze_ip_packet(const uint8_t *packet,
                                          size_t length,
                                              struct timespec *ts,
                                          struct tcp_reassembler *reassembler) {


    struct datum pkt{packet, packet+length};
    struct key k;
    ip ip_pkt{pkt, k};
    protocol x;
    uint8_t transport_proto = ip_pkt.transport_protocol();
    if (transport_proto == ip::protocol::tcp) {
        tcp_packet tcp_pkt{pkt, &ip_pkt};
        if (!tcp_pkt.is_valid()) {
            return 0;  // incomplete tcp header; can't process packet
         }
        tcp_pkt.set_key(k);
        if (reassembler) {
            analysis.flow_state_pkts_needed = false;
            if (tcp_pkt.is_SYN()) {
                tcp_flow_table.syn_packet(k, ts->tv_sec, ntoh(tcp_pkt.header->seq));
            } else if (tcp_pkt.is_SYN_ACK()) {
                tcp_flow_table.syn_packet(k, ts->tv_sec, ntoh(tcp_pkt.header->seq));
            } else {
                bool ret = process_tcp_data(x, pkt, tcp_pkt, k, ts, reassembler);
                if (reassembler->curr_reassembly_state == reassembly_in_progress) {
                        analysis.flow_state_pkts_needed = true;
                }
                if (!ret) {
                    return 0;
                }
            }
        }
        else {
            set_tcp_protocol(x, pkt, false, &tcp_pkt);
        }

    } else if (transport_proto == ip::protocol::udp) {
        class udp udp_pkt{pkt};
        udp_pkt.set_key(k);
        enum udp_msg_type msg_type = (udp_msg_type) selector.get_udp_msg_type(pkt);

        if (msg_type == udp_msg_type_unknown) {  // TODO: wrap this up in a traffic_selector member function
            udp::ports ports = udp_pkt.get_ports();
            msg_type = (udp_msg_type) selector.get_udp_msg_type_from_ports(ports);
           /* if (ports.dst == htons(4789)) {
                msg_type = udp_msg_type_vxlan; // could parse VXLAN header here
            }
        */
        }

        set_udp_protocol(x, pkt, msg_type, false, k);
    }

    // process protocol data element
    //
    if (std::visit(is_not_empty{}, x)) {
        std::visit(compute_fingerprint{analysis.fp, global_vars.tls_fingerprint_format}, x);
        if (global_vars.do_analysis && analysis.fp.get_type() != fingerprint_type_unknown) {

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

            if (reassembler) {
                if (reassembler->curr_reassembly_consumed == true) {
                    reassembler->remove_segment(reassembler->reap_it);
                    reassembler->curr_reassembly_consumed = false;
                    analysis.flow_state_pkts_needed = false;
                }
            }

            return output_analysis;
        }
    }

    if (reassembler) {
        if (reassembler->curr_reassembly_consumed == true) {
            reassembler->remove_segment(reassembler->reap_it);
            reassembler->curr_reassembly_consumed = false;
            analysis.flow_state_pkts_needed = false;
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

bool stateful_pkt_proc::analyze_ppp_packet(const uint8_t *packet,
                                           size_t length,
                                           struct timespec *ts,
                                           struct tcp_reassembler *reassembler) {

    struct datum pkt{packet, packet+length};
    if (!ppp::is_ip(pkt)) {
        return false;   // not an IP packet
    }

    return analyze_ip_packet(pkt.data, pkt.length(), ts, reassembler);
}

bool stateful_pkt_proc::analyze_raw_packet(const uint8_t *packet,
                                           size_t length,
                                           struct timespec *ts,
                                           struct tcp_reassembler *reassembler) {

    struct datum pkt{packet, packet+length};
    return analyze_ip_packet(pkt.data, pkt.length(), ts, reassembler);
}

bool stateful_pkt_proc::analyze_packet(const uint8_t *eth_packet,
                            size_t length,
                            struct timespec *ts,
                            struct tcp_reassembler *reassembler,
                            uint16_t linktype) {
    switch (linktype)
    {
    case LINKTYPE_ETHERNET:
        return analyze_eth_packet(eth_packet, length, ts, reassembler);
        break;
    case LINKTYPE_PPP:
        return analyze_ppp_packet(eth_packet, length, ts, reassembler);
        break;
    case LINKTYPE_RAW:
        return analyze_raw_packet(eth_packet, length, ts, reassembler);
        break;
    default:
        break;
    }
    return false;
}

bool stateful_pkt_proc::dump_pkt() {
    if (reassembler_ptr) {
        return reassembler_ptr->dump_pkt;
    }
    return false;
}
