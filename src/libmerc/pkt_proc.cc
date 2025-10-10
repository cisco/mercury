/*
 * pkt_proc.c
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <string.h>
#include <variant>
#include <set>
#include <tuple>
#ifndef _WIN32
#include <netinet/in.h>
#endif

#include "libmerc.h"
#include "pkt_proc.h"
#include "flow_key.h"
#include "utils.h"
#include "loopback.hpp"
#include "linux_sll.hpp"

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
#include "tacacs.hpp"
#include "tofsee.hpp"
#include "cdp.h"
#include "krb5.hpp"
#include "ldap.hpp"
#include "lldp.h"
#include "ospf.h"
#include "esp.hpp"
#include "ike.hpp"
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
#include "rfb.hpp"
#include "geneve.hpp"
#include "tsc_clock.hpp"
#include "ftp.hpp"
#include "rdp.hpp"
#include "tftp.hpp"
#include "ppoe.hpp"
#include "vxlan.hpp"
#include "fdc.hpp"
#include "l7m.hpp"

// double malware_prob_threshold = -1.0; // TODO: document hidden option

void write_flow_key(struct json_object &o, const struct key &k) {
    k.write_ip_address(o);

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

    bool operator()(const tls_server_hello &msg) {
        ca->assess(msg, record);
        return false;
    }

    bool operator()(const tls_server_hello_and_certificate &msg) {
        ca->assess(msg, record);
        return false;
    }

    bool operator()(const dtls_client_hello &msg) {
        ca->assess(msg, record);
        return false;
    }

    bool operator()(const dtls_server_hello &msg) {
        ca->assess(msg, record);
        return false;
    }


    bool operator()(const quic_init &msg) {
        if (msg.has_tls()) {
            ca->assess(msg.get_tls_client_hello(), record);
        }
        return false;
    }

    bool operator()(const ssh_init_packet &msg) {
        if (msg.kex_pkt.is_not_empty()) {
            ca->assess(msg.kex_pkt,record);
        }
        return false;
    }

    bool operator()(const ssh_kex_init &msg) {
        if (msg.is_not_empty()) {
            ca->assess(msg,record);
        }
        return false;
    }

    template <typename T>
    bool operator()(const T &) {
        return false;   // no assessment performed for all other types
    }

    bool operator()(std::monostate &) { return false; }

};

template <typename T_M>
class event_string
{
    const struct key &k;
    const struct analysis_context &analysis;
    std::string dest_context;
    event_msg event;
    T_M &message_pkt;

public:
    event_string(const struct key &k, const struct analysis_context &analysis, T_M &proto) :
        k{k}, analysis{analysis}, message_pkt{proto} {  }

    event_msg construct_event_string_proto( [[maybe_unused]] tofsee_initial_message &msg) {
        // For tofsee initial pkt, src ip, src port and bot ip are important
        // replace dst ip and port with src ip and port
        // add bot ip as user agent string
        //
        char src_ip_str[MAX_ADDR_STR_LEN];
        k.sprintf_dst_addr(src_ip_str);
        char dst_ip_str[MAX_ADDR_STR_LEN];
        k.sprint_src_addr(dst_ip_str);
        char dst_port_str[MAX_PORT_STR_LEN];
        k.sprint_src_port(dst_port_str);

        dest_context.append("(");
        dest_context.append(analysis.destination.sn_str).append(")(");
        dest_context.append(dst_ip_str).append(")(");
        dest_context.append(dst_port_str).append(")");

        event = std::make_tuple(src_ip_str, analysis.fp.string(), analysis.destination.ua_str, dest_context);
        return event;
    }

    template <typename T>
    event_msg construct_event_string_proto([[maybe_unused]] T &msg) {
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

    event_msg construct_event_string() {
        return construct_event_string_proto(message_pkt);
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

    void operator()(tls_client_hello &m) {
        event_string ev_str{k_, analysis_, m};
        mq_->push(ev_str.construct_event_string());
    }

    void operator()(quic_init &m) {
        // create event and send it to the data/stats aggregator
        event_string ev_str{k_, analysis_, m};
        mq_->push(ev_str.construct_event_string());
    }

    void operator()(tofsee_initial_message &tofsee_pkt) {
        // create event and send it to the data/stats aggregator
        event_string ev_str{k_, analysis_, tofsee_pkt};
        mq_->push(ev_str.construct_event_string());
        analysis_.reset_user_agent();
    }

    void operator()(http_request &m) {
        // create event and send it to the data/stats aggregator
        event_string ev_str{k_, analysis_, m};
        mq_->push(ev_str.construct_event_string());
        analysis_.reset_user_agent();
    }

    void operator()(stun::message &m) {
        // create event and send it to the data/stats aggregator
        event_string ev_str{k_, analysis_, m};
        mq_->push(ev_str.construct_event_string());
        analysis_.reset_user_agent();
    }

    void operator()(ssh_init_packet &m) {
        // create event and send it to the data/stats aggregator
        event_string ev_str{k_, analysis_, m};
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
            if (tcp_pkt && handshake.additional_bytes_needed) {
                tcp_pkt->reassembly_needed(handshake.additional_bytes_needed);
                //  set pkt type as tls CH, so that initial segments can be fingerprinted as best effort for reassembly failed cases
            }
            x.emplace<tls_client_hello>(handshake.body);
            break;
        }
    case tcp_msg_type_tls_server_hello:
        x.emplace<tls_server_hello_and_certificate>(pkt, tcp_pkt);
        break;
    case tcp_msg_type_tls_certificate:
        x.emplace<tls_certificate>(pkt, tcp_pkt);
        break;
    case tcp_msg_type_ssh:
        x.emplace<ssh_init_packet>(pkt);
        {
            uint32_t more_bytes = std::get<ssh_init_packet>(x).more_bytes_needed();
            if (tcp_pkt && more_bytes) {
                tcp_pkt->reassembly_needed(more_bytes,(uint8_t)indefinite_reassembly_type::ssh);
                return;
            }
        }
        break;
    case tcp_msg_type_ssh_kex:
        {
            struct ssh_binary_packet ssh_pkt{pkt};
            if (tcp_pkt && ssh_pkt.additional_bytes_needed) {
                tcp_pkt->reassembly_needed((uint32_t)ssh_pkt.additional_bytes_needed);
            }
            else {
                tcp_pkt->set_supplementary_reassembly();
            }
            x.emplace<ssh_kex_init>(ssh_pkt);
            break;
        }
    case tcp_msg_type_smtp_client:
        x.emplace<smtp_client>(pkt);
        break;
    case tcp_msg_type_smtp_server:
        x.emplace<smtp_server>(pkt);
        break;
    case tcp_msg_type_tacacs:
        x.emplace<tacacs::packet>(pkt);
        break;
    case tcp_msg_type_rdp:
        x.emplace<rdp::connection_request_pdu>(pkt);
        break;
    case tcp_msg_type_rfb:
        x.emplace<rfb::protocol_version_handshake>(pkt);
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
    case tcp_msg_type_mysql_login_request:
        x.emplace<mysql_login_request>(pkt);
        break;
    case tcp_msg_type_tofsee_initial_message:
        x.emplace<tofsee_initial_message>(pkt);
        break;
    case tcp_msg_type_socks4:
        x.emplace<socks4_req>(pkt);
        break;
    case tcp_msg_type_socks5_hello:
        x.emplace<socks5_hello>(pkt);
        break;
    case tcp_msg_type_socks5_req_resp:
        x.emplace<socks5_req_resp>(pkt);
        break;
    case tcp_msg_type_ldap:
        x.emplace<ldap::message>(pkt);
        break;
    case tcp_msg_type_ftp_response:
        x.emplace<ftp::response>(pkt);
        break;
    case tcp_msg_type_ftp_request:
        x.emplace<ftp::request>(pkt);
        break;
    default:
        if (is_new && global_vars.output_tcp_initial_data) {
            x.emplace<unknown_initial_packet>(pkt);
        } else {
            x.emplace<std::monostate>();
        }
        break;
    }
    //fprintf(stderr, "2nd got tcp_msg_type: %d\n", msg_type);
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
                      udp::ports ports,
                      bool is_new,
                      const struct key& k,
                      udp &udp_pkt) {

    // note: std::get<T>() throws exceptions; it might be better to
    // use get_if<T>(), which does not

    // enum msg_type msg_type = udp_get_message_type(pkt.data, pkt.length());
    // if (msg_type == msg_type_unknown) {
    //     msg_type = udp_pkt.estimate_msg_type_from_ports();
    // }
    enum udp_msg_type msg_type = (udp_msg_type) selector.get_udp_msg_type(pkt, ports);

    uint32_t more_bytes = 0;

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
        x.emplace<dhcp_message>(pkt);
        break;
    case udp_msg_type_quic:
        x.emplace<quic_init>(pkt, quic_crypto);
        more_bytes = std::get<quic_init>(x).additional_bytes_needed();
        if (more_bytes) {
            udp_pkt.reassembly_needed(more_bytes);
        }
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
    case udp_msg_type_esp:
        x.emplace<esp>(pkt);
        break;
    case udp_msg_type_ike:
        x.emplace<ike::packet>(pkt);
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
    case udp_msg_type_krb5:
        x.emplace<krb5::packet>(pkt);
        break;
    case udp_msg_type_tftp:
        x.emplace<tftp::packet>(pkt);
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

    if (!tcp_pkt.data_length) {
        // ignore acks and empty fin
        return false;
    }

    // No reassembler : call set_tcp_protocol on every data pkt
    if (!reassembler || !global_vars.reassembly) {
        bool is_new = false;
        if (global_vars.output_tcp_initial_data) {
            is_new = tcp_flow_table.is_first_data_packet(k, ts->tv_sec, ntoh(tcp_pkt.header->seq));
        }
        set_tcp_protocol(x, pkt, is_new, &tcp_pkt);
        return true;
    }

    bool is_new = false;
    if (global_vars.output_tcp_initial_data) {
        is_new = tcp_flow_table.is_first_data_packet(k, ts->tv_sec, ntoh(tcp_pkt.header->seq));
    }
    datum pkt_copy{pkt};

    // do not bother with syn seq no.
    // treat any tcp pkt that needs reassembly as initial pkt

    // check if more tcp data is required
    set_tcp_protocol(x,pkt,is_new,&tcp_pkt);
        if ((!tcp_pkt.additional_bytes_needed && !(std::holds_alternative<std::monostate>(x))) && (!tcp_pkt.supplementary_reassembly)) {
        // no need for reassembly
        // complete initial msg
        return true;
    }
    else if ((tcp_pkt.additional_bytes_needed > reassembly_flow_context::max_data_size) || (tcp_pkt.data_length > reassembly_flow_context::max_data_size)) {
        // cant do reassembly
        // TODO: add indication for truncation
        return true;
    }

    // reassembly may be needed
    // pkts that reach here are inital msg with additional_bytes_needed or
    // non initial pkts that dont match any protocol, so could be part of a reassembly flow
    // check if in reassembly table to continue
    // init otherwise
    //
    reassembly_state r_state = reassembler->check_flow(k,ts->tv_sec);

    // specical handling for supplementary reassembly
    if ((r_state == reassembly_state::reassembly_none) && tcp_pkt.supplementary_reassembly) {
        // since flow is not in reassembly, assume it as completed
        return true;
    }

    if ((r_state == reassembly_state::reassembly_none) && tcp_pkt.additional_bytes_needed){
        // init reassembly
        tcp_segment seg{true,tcp_pkt.data_length,tcp_pkt.seq(),tcp_pkt.additional_bytes_needed,(uint64_t)ts->tv_sec, (indefinite_reassembly_type)tcp_pkt.indefinite_reassembly};
        reassembler->process_tcp_data_pkt(k,ts->tv_sec,seg,pkt_copy);
        reassembler->dump_pkt = true;
    }
    else if (r_state == reassembly_state::reassembly_progress){
        // continue reassembly
        if (!tcp_pkt.seq()) {
            // 0 seq number, inorder reassembly, seq = existing_data
            reassembly_map_iterator curr_flow = reassembler->get_current_flow();
            uint32_t tmp_seq = curr_flow->second.curr_contiguous_data;
            tcp_segment seg{false,tcp_pkt.data_length,tmp_seq,0,(uint64_t)ts->tv_sec, (indefinite_reassembly_type)tcp_pkt.indefinite_reassembly};
            reassembler->process_tcp_data_pkt(k,ts->tv_sec,seg,pkt_copy);
            reassembler->dump_pkt = true;
        } else {
            tcp_segment seg{false,tcp_pkt.data_length,tcp_pkt.seq(),0,(uint64_t)ts->tv_sec, (indefinite_reassembly_type)tcp_pkt.indefinite_reassembly};
            reassembler->process_tcp_data_pkt(k,ts->tv_sec,seg,pkt_copy);
            reassembler->dump_pkt = true;
        }
    }
    else if (r_state == reassembly_state::reassembly_consumed) {
        // this will never happen
        return false;
    }
    else {
        // this will never happen
        return false;
    }

    // after processing this pkt, check for states again
    reassembly_map_iterator it = reassembler->get_current_flow();
    if (reassembler->is_ready(it)) {
        // reassmbly done
        // process reassembled data
        //
        struct datum reassembled_data = reassembler->get_reassembled_data(it);
        set_tcp_protocol(x, reassembled_data, true, &tcp_pkt);

        // mark flow as completed
        reassembler->set_completed(it);
        return true;
    }

    return false;
}

// returns boolean whether to fingerprrint/analyze current udp pkt
bool stateful_pkt_proc::process_udp_data (protocol &x,
                          struct datum &pkt,
                          udp &udp_pkt,
                          struct key &k,
                          struct timespec *ts,
                          struct tcp_reassembler *reassembler) {

    // No reassembler : call set_udp_protocol on every data pkt
    if (!reassembler || !global_vars.reassembly) {
        bool is_new = false;
        if (global_vars.output_udp_initial_data && pkt.is_not_empty()) {
            is_new = ip_flow_table.flow_is_new(k, ts->tv_sec);
        }
        set_udp_protocol(x, pkt, udp_pkt.get_ports(), is_new, k, udp_pkt);
        return true;
    }

    bool is_new = false;
    if (global_vars.output_udp_initial_data && pkt.is_not_empty()) {
        is_new = ip_flow_table.flow_is_new(k, ts->tv_sec);
    }
    //datum pkt_copy{pkt};

    // For UDP reassembly, all the reassembly will always happen at the encapsulated application or transport protocol layer, like QUIC
    // currently this code is tailored for QUIC only
    // A QUIC pkt/ UDP pkt can be checked if it is involved in reassembly if either the CH initial part is seen with additional bytes needed,
    // or a QUIC pkt with crypto frames and the flow exists in reassembly table

    set_udp_protocol(x, pkt, udp_pkt.get_ports(), is_new, k, udp_pkt);
    //if ( (!udp_pkt.additional_bytes_needed() && (std::holds_alternative<quic_init>(x)))  || (!(std::holds_alternative<quic_init>(x))) ) {
    if (!(std::holds_alternative<quic_init>(x))) {
        // no need for reassembly
        return true;
    }
    else if ((udp_pkt.additional_bytes_needed() > reassembly_flow_context::max_data_size)){ //|| (tcp_pkt.data_length > reassembly_flow_context::max_data_size)) {
        // cant do reassembly
        // TODO: add indication for truncation
        return true;
    }

    // reassembly may be needed
    // pkts that reach here are inital msg with/without additional_bytes_needed, missing crypto frames or
    // non initial pkts that dont match any protocol, so could be part of a reassembly flow
    // check if in reassembly table to continue
    // init otherwise
    //
    const datum &cid = std::get<quic_init>(x).get_cid();
    uint32_t crypto_len = 0;
    const uint8_t *crypto_data = std::get<quic_init>(x).get_crypto_buf(&crypto_len);
    uint32_t crypto_offset = std::get<quic_init>(x).get_min_crypto_offset();
    bool missing_crypto_frames = std::get<quic_init>(x).missing_crypto_frames();
    bool min_crypto_data = std::get<quic_init>(x).min_crypto_data();
    if (crypto_len > reassembly_flow_context::max_data_size) {
        // can't fit this crypto frame in buffer
        return true;
    }

    // skip checking in reassembly table for the following cases:
    // 1. no crypto data in quic pkt
    // 2. min offset is 0 and additional bytes needed is 0 : a complete initial quic pkt
    if (!crypto_len || (!crypto_offset && !udp_pkt.additional_bytes_needed())) {
        return true;
    }

    reassembly_state r_state = reassembler->check_flow(k,ts->tv_sec, cid);

    if ((r_state == reassembly_state::reassembly_none) && !udp_pkt.additional_bytes_needed()) {
        // pkt not involved in reassembly
        return true;
    }
    else if ((r_state == reassembly_state::reassembly_none) && udp_pkt.additional_bytes_needed()){
        if (!missing_crypto_frames) {
            // init reassembly
            quic_segment seg{true,crypto_len,crypto_offset,udp_pkt.additional_bytes_needed(),(uint64_t)ts->tv_sec, cid};
            reassembler->process_quic_data_pkt(k,ts->tv_sec,seg,datum{crypto_data+crypto_offset,crypto_data+crypto_offset+crypto_len});
            reassembler->dump_pkt = true;
        }
        // special case for missing / reordered crypto frames
        // fetch and process frames one by one
        else {
            uint16_t frame_count = 0;
            uint16_t first_frame_idx = 0;
            const crypto* frames = std::get<quic_init>(x).get_crypto_frames(frame_count,first_frame_idx);

            // init
            if (min_crypto_data) {
                quic_segment seg{true,cryptographic_buffer::min_crypto_data_len,(uint32_t)(frames[first_frame_idx].offset()),udp_pkt.additional_bytes_needed(),(uint64_t)ts->tv_sec, cid};
                reassembler->process_quic_data_pkt(k,ts->tv_sec,seg,datum{crypto_data+frames[first_frame_idx].offset(),
                                crypto_data+frames[first_frame_idx].offset()+cryptographic_buffer::min_crypto_data_len});
            }
            else {
                quic_segment seg{true,(uint32_t)(frames[first_frame_idx].length()),(uint32_t)(frames[first_frame_idx].offset()),udp_pkt.additional_bytes_needed(),(uint64_t)ts->tv_sec, cid};
                reassembler->process_quic_data_pkt(k,ts->tv_sec,seg,datum{crypto_data+frames[first_frame_idx].offset(),
                                crypto_data+frames[first_frame_idx].offset()+frames[first_frame_idx].length()});

            }

            for (uint16_t i = 0; i < frame_count; i++) {
                if (i != first_frame_idx) { // skip already processed first frame
                    quic_segment seg{false,(uint32_t)(frames[i].length()),(uint32_t)(frames[i].offset()),0,(uint64_t)ts->tv_sec, cid};
                    reassembler->process_quic_data_pkt(k,ts->tv_sec,seg,datum{crypto_data+frames[i].offset(),crypto_data+frames[i].offset()+frames[i].length()});
                }
            }
            reassembler->dump_pkt = true;
        }
    }
    else if (r_state == reassembly_state::reassembly_progress){
        if (!missing_crypto_frames) {
            // continue reassembly
            quic_segment seg{false,crypto_len,crypto_offset,0,(uint64_t)ts->tv_sec, cid};
            reassembler->process_quic_data_pkt(k,ts->tv_sec,seg,datum{crypto_data+crypto_offset,crypto_data+crypto_offset+crypto_len});
            reassembler->dump_pkt = true;
        }
        else {
            uint16_t frame_count = 0;
            uint16_t first_frame_idx = 0;
            const crypto* frames = std::get<quic_init>(x).get_crypto_frames(frame_count,first_frame_idx);

            for (uint16_t i = 0; i < frame_count; i++) {
                quic_segment seg{false,(uint32_t)(frames[i].length()),(uint32_t)(frames[i].offset()),0,(uint64_t)ts->tv_sec, cid};
                reassembler->process_quic_data_pkt(k,ts->tv_sec,seg,datum{crypto_data+frames[i].offset(),crypto_data+frames[i].offset()+frames[i].length()});

            }
            reassembler->dump_pkt = true;
        }
    }
    else if (r_state == reassembly_state::reassembly_consumed) {
        // this will never happen
        return false;
    }
    else if (r_state == reassembly_state::reassembly_quic_discard) {
        // some non matching quic flow on known 5 tuple
        return true;
    }
    else {
        // this will never happen
        return false;
    }

    // after processing this pkt, check for states again
    reassembly_map_iterator it = reassembler->get_current_flow();
    if (reassembler->is_ready(it)) {
        // reassmbly done
        // process reassembled data
        //
        struct datum reassembled_data = reassembler->get_reassembled_data(it);
        //set_tcp_protocol(x, reassembled_data, true, &tcp_pkt);
        // update quic crpto buffer and reparse client hello
        std::get<quic_init>(x).reparse_crypto_buf(reassembled_data);

        // mark flow as completed
        reassembler->set_completed(it);
        return true;
    }

    return false;
}

struct process_next_header {
    process_next_header() { }

    template <typename T>
    bool operator()(T &r) {
        return r.is_next_header();
    }

    bool operator()(std::monostate &) { return false;}

};

class encapsulations {
public:
    static constexpr uint8_t MAX_ENCAPSULATIONS = 5;
    std::array<encapsulation, encapsulations::MAX_ENCAPSULATIONS> encaps;
    uint8_t total_encap = 0;

    encapsulations(struct datum &pkt,
                   ip &ip_pkt,
                   struct key &k,
                   const traffic_selector &selector) {
        process_encapsulations(pkt, ip_pkt, k, selector);
    }

    void process_encapsulations(struct datum &pkt,
                                ip &ip_pkt,
                                struct key &k,
                                const traffic_selector &selector) {

        if (total_encap >= MAX_ENCAPSULATIONS - 1) {
            return;   // too many encapsulations to report
        }

        switch(ip_pkt.transport_protocol()) {
        case ip::protocol::gre: {
            if(!selector.gre()) {
                return;
            }
            encaps[total_encap].emplace<gre_header>(pkt, k);
            break;
        }
        case ip::protocol::ipv4:
        case ip::protocol::ipv6: {
            encaps[total_encap].emplace<ip_encapsulation>(k);
            break;
        }
        case ip::protocol::udp: {
            datum pkt_copy{pkt};
            udp udp_pkt{pkt_copy};
            udp_pkt.set_key(k);
            udp::ports ports = udp_pkt.get_ports();
            enum udp_msg_type msg_type = selector.get_udp_msg_type_from_ports(ports);
            switch(msg_type) {
            case udp_msg_type_vxlan: {
                pkt.data = pkt_copy.data;
                encaps[total_encap].emplace<vxlan>(pkt, k);
                break;
            }
            case udp_msg_type_geneve: {
                pkt.data = pkt_copy.data;
                encaps[total_encap].emplace<geneve>(pkt, k);
                break;
            }
            case udp_msg_type_gre: {
                pkt.data = pkt_copy.data;
                encaps[total_encap].emplace<gre_header>(pkt, k);
                break;
            }
            default:
                ;
            }
        }
        default:
            ;
        }
        if (std::visit(process_next_header{}, encaps[total_encap])) {
            total_encap++;
            ip_pkt.parse(pkt, k);
            process_encapsulations(pkt, ip_pkt, k, selector);
        }
    }

    bool is_empty() const {
        if (total_encap) {
            return false;
        }

        return true;
    }

    void write_json(struct json_object &record) {
        if (is_empty()) {
            return;
        }

        struct json_array encap(record, "encapsulations");
        for (uint8_t i = 0; i < total_encap; i++) {
            std::visit(write_encapsulation{encap}, encaps[i]);
        }
        encap.close();
    }
};

size_t stateful_pkt_proc::ip_write_json(void *buffer,
                                        size_t buffer_size,
                                        const uint8_t *ip_packet,
                                        size_t length,
                                        struct timespec *ts,
                                        struct tcp_reassembler *reassembler) {

    struct buffer_stream buf{(char *)buffer, (int)buffer_size};
    struct key k;
    struct datum pkt{ip_packet, ip_packet+length};
    ip ip_pkt{pkt, k};
    bool truncated_tcp = false;
    bool truncated_quic = false;

    analysis.reinit();
    if (reassembler) {
        reassembler->dump_pkt = false;
        reassembler_ptr->clean_curr_flow();
    }

    class encapsulations encaps{pkt, ip_pkt, k, selector};
    uint8_t transport_proto = ip_pkt.transport_protocol();

    if (ts->tv_sec == 0) {
        tsc_clock time_now;
        ts->tv_sec = time_now.time_in_seconds();
    }

    // process transport/application protocols
    //
    protocol x;
    if (selector.icmp() && (transport_proto == ip::protocol::icmp || transport_proto == ip::protocol::ipv6_icmp)) {
        x.emplace<icmp_packet>(pkt);

    } else if (selector.ospf() && transport_proto == ip::protocol::ospfigp) {
        x.emplace<ospf>(pkt);

    } else if (selector.ipsec() && transport_proto == ip::protocol::esp) {
        x.emplace<esp>(pkt);

    } else if (selector.sctp() && transport_proto == ip::protocol::sctp) {
        x.emplace<sctp_init>(pkt);

    } else if (transport_proto == ip::protocol::tcp) {
        tcp_packet tcp_pkt{pkt, &ip_pkt};
        if (!tcp_pkt.is_valid()) {
            return 0;  // incomplete tcp header; can't process packet
        }
        tcp_pkt.set_key(k);
        if (tcp_pkt.is_SYN()) {

            if (global_vars.output_tcp_initial_data) {
                tcp_flow_table.syn_packet(k, ts->tv_sec, ntoh(tcp_pkt.header->seq));
            }
            if (selector.tcp_syn()) {
                x = tcp_pkt; // process tcp syn
            }
            // note: we could check for non-empty data field

        } else if (tcp_pkt.is_SYN_ACK()) {
            if (global_vars.output_tcp_initial_data) {
                tcp_flow_table.syn_packet(k, ts->tv_sec, ntoh(tcp_pkt.header->seq));
            }
            if (selector.tcp_syn() and selector.tcp_syn_ack()) {
                x = tcp_pkt;  // process tcp syn/ack
            }
            // note: we could check for non-empty data field

        } else if (global_vars.output_tcp_initial_data && (tcp_pkt.is_FIN() || tcp_pkt.is_RST()) ) {
                tcp_flow_table.find_and_erase(k);
        }
        else {
            //bool write_pkt = false;
            if (!process_tcp_data(x, pkt, tcp_pkt, k, ts, reassembler)) {
                return 0;
            }
            else if (tcp_pkt.additional_bytes_needed) {
                truncated_tcp = true;
            }
        }

    } else if (transport_proto == ip::protocol::udp) {
        class udp udp_pkt{pkt};
        udp_pkt.set_key(k);

        if (!process_udp_data(x, pkt, udp_pkt, k, ts, reassembler)) {
            return 0;
        }
        else if (udp_pkt.additional_bytes_needed()) {
            truncated_quic = true;
        }
    }

    // process transport/application protocol
    //
    if (std::visit(is_not_empty{}, x)) {
        std::visit(compute_fingerprint{analysis.fp, global_vars.fp_format}, x);
        bool output_analysis = false;
        if (global_vars.do_analysis && analysis.fp.get_type() != fingerprint_type_unknown) {

            output_analysis = std::visit(do_analysis{k, analysis, c}, x);

            // note: we only perform observations when analysis is
            // configured, because we rely on do_analysis to set the

            // check for additional classifier agnostic attributes like encrypted dns and domain-faking
            //
            if (!analysis.result.attr.is_initialized() && c) {
                analysis.result.attr.initialize(&(c->get_common_data().attr_name.value()),c->get_common_data().attr_name.get_names_char());
            }
            c->check_additional_attributes(analysis);

            // analysis_.destination
            //
            if (mq) {
                std::visit(do_observation{k, analysis, mq}, x);
            }
        }

        bool output_nbd = false;
        if (global_vars.network_behavioral_detections) {
            if (!analysis.result.attr.is_initialized()) {
                nbd_common_data.initialize_behavioral_detections();
                analysis.result.attr.initialize(&(nbd_common_data.attr_name.value()),nbd_common_data.attr_name.get_names_char());
            }

            output_nbd = std::visit(do_network_behavioral_detections{k, analysis, c, nbd_common_data}, x);
        }


        // if (malware_prob_threshold > -1.0 && (!output_analysis || analysis.result.malware_prob < malware_prob_threshold)) { return 0; } // TODO - expose hidden command

        struct json_object record{&buf};
        if (analysis.fp.get_type() != fingerprint_type_unknown) {
            analysis.fp.write(record);
        }
        std::visit(write_metadata{record, global_vars.metadata_output, global_vars.certs_json_output, global_vars.dns_json_output}, x);

        if (output_analysis || output_nbd) {
            analysis.result.write_json(record, "analysis");
        }

//        if (output_nbd) {
//            nbd_analysis.write_json(record, "network_behavioral_detections");
//        }

        if (crypto_policy) { std::visit(do_crypto_assessment{crypto_policy, record}, x); }

        // write indication of truncation or reassembly
        //
        if ((!reassembler && (truncated_tcp || truncated_quic))
                || (!global_vars.reassembly && (truncated_tcp || truncated_quic)) ) {
            struct json_object flags{record, "reassembly_properties"};
            flags.print_key_bool("truncated", true);
            flags.close();
        }
        else if (reassembler && reassembler->is_done(reassembler->curr_flow)) {
            reassembler->write_json(record);
        }

        if (global_vars.metadata_output) {
            ip_pkt.write_json(record);      // write out ip{version,ttl,id}
        }

        if (!encaps.is_empty()) {
            encaps.write_json(record);
        }

        write_flow_key(record, k);

        record.print_key_timestamp("event_start", ts);
        record.close();
    }

    // reassembly clean and reset
    //
    if (reassembler) {
        reassembler->clean_curr_flow();
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
    case ETH_TYPE_PPOE: {
        ppoe ppoe_pkt(pkt);
        if(!ppp::is_ip(pkt)) {
            break;
        } else {
            return ip_write_json(buffer,
                         buffer_size,
                         pkt.data,
                         pkt.length(),
                         ts,
                         reassembler);
        }
    }
    default:
        ;  // unsupported ethertype
    }

    // write out link layer protocol metadata, if there is any
    //
    if (std::visit(is_not_empty{}, x)) {
        struct buffer_stream buf{(char *)buffer, (int)buffer_size};
        struct json_object record{&buf};
        std::visit(write_metadata{record, false, false, false}, x);
        record.print_key_timestamp("event_start", ts);
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
    case LINKTYPE_LINUX_SLL:
        linux_sll::skip_to_ip(pkt);
        break;
    case LINKTYPE_NULL:  // BSD loopback encapsulation
        {
            loopback_header loopback{pkt};
            if (pkt.is_not_null()) {
                switch(loopback.get_protocol_type()) {
                case ETH_TYPE_IP:
                case ETH_TYPE_IPV6:
                    break;
                default:
                    return 0;  // unsupported protocol in loopback header
                }
            }
        }
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

inline bool is_fdc_writable(fingerprint_type fp_type) {
    switch(fp_type) {
    case fingerprint_type_tls:
    case fingerprint_type_http:
    case fingerprint_type_quic:
    case fingerprint_type_tofsee:
    case fingerprint_type_stun:
    case fingerprint_type_ssh:
            return true;
        default:
            return false;
    }
}

int stateful_pkt_proc::analyze_payload_fdc(const struct flow_key_ext *k,
                                           const uint8_t *payload,
                                           const size_t length,
                                           uint8_t *buffer,
                                           size_t *buffer_size,
                                           [[maybe_unused]]const struct analysis_context** context) {

    if (k == nullptr or payload == nullptr or buffer == nullptr) {
        return fdc_return::INVALID_INPUT;
    }

    bool perform_reassembly = true;
    protocol x;
    key k_{*k};
    struct datum pkt{payload, payload+length};

    // add timestamp
    timespec ts;
    tsc_clock time_now;
    ts.tv_sec = time_now.time_in_seconds();

    if (reassembler_ptr) {
        reassembler_ptr->clean_curr_flow();
        reassembler_ptr->dump_pkt = false;
    }

    if (!length) {
        if (!reassembler_ptr)
            return fdc_return::FDC_NO_DATA;
        reassembly_state state = reassembler_ptr->check_flow(k_,(uint64_t)ts.tv_sec);
        if (state != reassembly_state::reassembly_progress) {
            return fdc_return::FDC_NO_DATA;
        }
        datum curr_data = reassembler_ptr->get_reassembled_data(reassembler_ptr->get_current_flow());
        pkt.data = curr_data.data;
        pkt.data_end = curr_data.data_end;
        reassembler_ptr->set_completed(reassembler_ptr->get_current_flow());
        perform_reassembly = false; // already reassembled some data, cant do further
    }

    bool truncated_tcp = false;
    bool truncated_udp = false;

    if (k->protocol == ip::protocol::tcp) {
        tcp_header tcp_hdr;
        tcp_hdr.src_port = k_.src_port;
        tcp_hdr.dst_port = k_.dst_port;
        // setup a seq no of 0 to denote in-order reassembly
        tcp_hdr.seq = 0;
        tcp_packet tcp_pkt{pkt, &tcp_hdr};

        if (reassembler_ptr && global_vars.reassembly && perform_reassembly) {
            analysis.flow_state_pkts_needed = false;
            bool ret = process_tcp_data(x, pkt, tcp_pkt, k_, &ts, reassembler_ptr);
            if (reassembler_ptr->in_progress(reassembler_ptr->curr_flow)) {
                analysis.flow_state_pkts_needed = true;
                return fdc_return::MORE_PACKETS_NEEDED;
            }
            if (!ret) {
                return fdc_return::FDC_NO_DATA;
            }
        }
        else {
            bool ret = process_tcp_data(x, pkt, tcp_pkt, k_, &ts, nullptr);
            if (!ret) {
                return fdc_return::FDC_NO_DATA;
            }
            if (tcp_pkt.additional_bytes_needed) {
                truncated_tcp = true;
            }
        }

    } else if (k->protocol == ip::protocol::udp) {
        udp udp_pseudoheader{k_};

        if (reassembler_ptr && global_vars.reassembly && perform_reassembly) {
            bool ret = process_udp_data(x, pkt, udp_pseudoheader, k_, &ts, reassembler_ptr);
            if (reassembler_ptr->in_progress(reassembler_ptr->curr_flow)) {
                analysis.flow_state_pkts_needed = true;
                return fdc_return::MORE_PACKETS_NEEDED;
            }
            if (!ret) {
                return fdc_return::FDC_NO_DATA;
            }
        }
        else {

            bool ret = process_udp_data(x, pkt, udp_pseudoheader, k_, &ts, nullptr);
            if (!ret) {
                return fdc_return::FDC_NO_DATA;
            }
            if (udp_pseudoheader.additional_bytes_needed()) {
                truncated_udp = true;
            }
        }
    }

    analysis.result.reinit();
    analysis.destination.reset();
    analysis.fp.init();

    if (std::visit(is_not_empty{}, x)) {
        std::visit(compute_fingerprint{analysis.fp, global_vars.fp_format}, x);
    }

    if (analysis.fp.get_type() == fingerprint_type_unknown && std::get_if<std::monostate>(&x) != nullptr) {
        return fdc_return::FDC_NO_DATA;
    }

    std::visit(do_analysis{k_, analysis, c}, x);

    if (context != nullptr and analysis.result.is_valid()) {
        *context = &analysis;
    }

    truncation_status status = truncation_status::none;

    if (reassembler_ptr) {
        if (reassembler_ptr->is_done(reassembler_ptr->curr_flow)) {
            if (truncated_tcp || truncated_udp) {
                status = truncation_status::reassembled_truncated;
            }
            else {
                status = truncation_status::reassembled;
            }
        }
    }
    else if (truncated_tcp || truncated_udp) {
        status = truncation_status::truncated;
    }

    size_t internal_buffer_size = *buffer_size;
    writeable output{buffer, buffer + internal_buffer_size};

    uint64_t fdc_version = 2;
    if (fdc_version == 1) {
        if (is_fdc_writable(analysis.fp.get_type())) {

            fdc fdc_object{
                datum{analysis.fp.string()},
                analysis.destination.ua_str,
                analysis.destination.sn_str,
                analysis.destination.dst_ip_str,
                analysis.destination.dst_port,
                status
            };
            bool encoding_ok = fdc_object.encode(output);
            if (encoding_ok == false) {
                *buffer_size = 2 * internal_buffer_size;
                return -1;
            }

        }
    } else if (fdc_version == 2) {
        //
        // write out data in FDC version two format
        //
        cbor_object outer_map{output};
        outer_map.print_key_uint("version", fdc_version);

        if (is_fdc_writable(analysis.fp.get_type())) {
            //
            // write fingerprint array
            //
            cbor_array fingerprint_array{outer_map, "fingerprints"};
            datum fp_string{analysis.fp.string()};
            cbor::tag{tag_npf_fingerprint}.write(fingerprint_array.get_writeable());
            cbor_fingerprint::encode_cbor_fingerprint(fp_string, fingerprint_array.get_writeable());
            fingerprint_array.close();
        }

        // write the metadata for the protocol message x into outer_map,
        // and return immediately if no metadata was written
        //
        ssize_t previous = output.writeable_length();
        std::visit(write_l7_metadata{outer_map}, x);
        if (output.writeable_length() == previous) {
            return fdc_return::FDC_NO_DATA;     // empty message; nothing to report
        }

        // write out the truncation status of the record
        //
        outer_map.print_key_uint("truncation", (uint64_t)status);

        outer_map.close();

        if (output.is_null()) {
            *buffer_size = 2 * internal_buffer_size;
            return fdc_return::FDC_WRITE_INSUFFICIENT_SPACE;
        }

    } else {
        return fdc_return::UNKNOWN_ERROR;  // unsupported FDC version
    }

    if (reassembler_ptr) {
        if (reassembler_ptr->is_done(reassembler_ptr->curr_flow)) {
            analysis.flow_state_pkts_needed = false;
        }
        reassembler_ptr->clean_curr_flow();
    }
    return internal_buffer_size - output.writeable_length();
}

bool stateful_pkt_proc::analyze_ip_packet(const uint8_t *packet,
                                          size_t length,
                                              struct timespec *ts,
                                          struct tcp_reassembler *reassembler) {


    struct datum pkt{packet, packet+length};
    struct key k;
    ip ip_pkt{pkt, k};
    protocol x;
    class encapsulations encaps{pkt, ip_pkt, k, selector};
    uint8_t transport_proto = ip_pkt.transport_protocol();

    analysis.reinit();
    if (reassembler) {
        reassembler->dump_pkt = false;
        reassembler_ptr->clean_curr_flow();
    }

    bool truncated_tcp = false;
    bool truncated_udp = false;

    if (ts->tv_sec == 0) {
        tsc_clock time_now;
        ts->tv_sec = time_now.time_in_seconds();
    }

    if (transport_proto == ip::protocol::tcp) {
        tcp_packet tcp_pkt{pkt, &ip_pkt};
        if (!tcp_pkt.is_valid()) {
            return 0;  // incomplete tcp header; can't process packet
         }
        tcp_pkt.set_key(k);
        if (reassembler && global_vars.reassembly) {
            analysis.flow_state_pkts_needed = false;
            if (tcp_pkt.is_SYN() || tcp_pkt.is_SYN_ACK() || tcp_pkt.is_RST()) {
                ; // do nothing
            }
            else {
                bool ret = process_tcp_data(x, pkt, tcp_pkt, k, ts, reassembler);
                if (reassembler->in_progress(reassembler->curr_flow)) {
                    analysis.flow_state_pkts_needed = true;
                }
                if (!ret) {
                    return 0;
                }
            }
        }
        else {
            set_tcp_protocol(x, pkt, false, &tcp_pkt);
            if (tcp_pkt.additional_bytes_needed) {
                truncated_tcp = true;
            }
        }

    } else if (transport_proto == ip::protocol::udp) {
        class udp udp_pkt{pkt};
        udp_pkt.set_key(k);

        if (reassembler && global_vars.reassembly) {
            bool ret = process_udp_data(x, pkt, udp_pkt, k, ts, reassembler);
            if (reassembler->in_progress(reassembler->curr_flow)) {
                analysis.flow_state_pkts_needed = true;
            }
            if (!ret) {
                return 0;
            }
        }
        else {
            process_udp_data(x, pkt, udp_pkt, k, ts, reassembler);
            if (udp_pkt.additional_bytes_needed()) {
                truncated_udp = true;
            }
        }
    }

    // process protocol data element
    //
    if (std::visit(is_not_empty{}, x)) {
        std::visit(compute_fingerprint{analysis.fp, global_vars.fp_format}, x);
        if (global_vars.do_analysis && analysis.fp.get_type() != fingerprint_type_unknown) {

            // re-initialize the structure that holds analysis results
            //
            analysis.result.reinit();
            bool output_analysis = std::visit(do_analysis{k, analysis, c}, x);

            // check for additional classifier agnostic attributes like encrypted dns and domain-faking
            //
            if (!analysis.result.attr.is_initialized() && c) {
                analysis.result.attr.initialize(&(c->get_common_data().attr_name.value()),c->get_common_data().attr_name.get_names_char());
            }
            c->check_additional_attributes(analysis);

            bool output_nbd = false;
            if (global_vars.network_behavioral_detections) {
                output_nbd = std::visit(do_network_behavioral_detections{k, analysis, c, nbd_common_data}, x);
            }

            // note: we only perform observations when analysis is
            // configured, because we rely on do_analysis to set the
            // analysis_.destination
            //
            if (mq) {
                std::visit(do_observation{k, analysis, mq}, x);
            }

            if (reassembler) {
                if (reassembler->is_done(reassembler->curr_flow)) {
                    analysis.flow_state_pkts_needed = false;
                }
                reassembler->clean_curr_flow();
            }

            // if fingerprint truncated, set fp status to unlabeled
            if (truncated_tcp or truncated_udp) {
                analysis.result.status = fingerprint_status::fingerprint_status_unlabled;
            }

            // report port in network byte order
            //
            analysis.destination.dst_port = ntoh(analysis.destination.dst_port);

            return output_analysis || output_nbd;

        } else if (global_vars.network_behavioral_detections) {
            analysis.result.reinit();
            if (!analysis.result.attr.is_initialized()) {
                nbd_common_data.initialize_behavioral_detections();
                analysis.result.attr.initialize(&(nbd_common_data.attr_name.value()),nbd_common_data.attr_name.get_names_char());
            }

            return std::visit(do_network_behavioral_detections{k, analysis, c, nbd_common_data}, x);
        }
    }

    if (reassembler) {
        if (reassembler->is_done(reassembler->curr_flow)) {
            analysis.flow_state_pkts_needed = false;
        }
        reassembler->clean_curr_flow();
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
