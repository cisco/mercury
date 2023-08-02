/*
 * proto_identify.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

/**
 * \file proto_identify.h
 *
 * \brief Protocol identification (header)
 */

#ifndef PROTO_IDENTIFY_H
#define PROTO_IDENTIFY_H

#include <stdint.h>

#include <vector>
#include <array>
#include "match.h"

#include "tls.h"   // tcp protocols
#include "http.h"
#include "ssh.h"
#include "smtp.h"
#include "smb1.h"
#include "smb2.h"
#include "iec60870_5_104.h"

#include "dhcp.h"  // udp protocols
#include "quic.h"
#include "dns.h"
#include "wireguard.h"
#include "dtls.h"
#include "ssdp.h"
#include "stun.h"
#include "dnp3.h"
#include "netbios.h"
#include "udp.h"
#include "openvpn.h"
#include "bittorrent.h"
#include "mysql.hpp"

enum tcp_msg_type {
    tcp_msg_type_unknown = 0,
    tcp_msg_type_http_request,
    tcp_msg_type_http_response,
    tcp_msg_type_tls_client_hello,
    tcp_msg_type_tls_server_hello,
    tcp_msg_type_tls_certificate,
    tcp_msg_type_ssh,
    tcp_msg_type_ssh_kex,
    tcp_msg_type_smtp_client,
    tcp_msg_type_smtp_server,
    tcp_msg_type_dns,
    tcp_msg_type_smb1,
    tcp_msg_type_smb2,
    tcp_msg_type_iec,
    tcp_msg_type_dnp3,
    tcp_msg_type_nbss,
    tcp_msg_type_openvpn,
    tcp_msg_type_bittorrent,
    tcp_msg_type_mysql_server,
    tcp_msg_type_tofsee_initial_message,
};

enum udp_msg_type {
    udp_msg_type_unknown = 0,
    udp_msg_type_dns,
    udp_msg_type_dhcp,
    udp_msg_type_dtls_client_hello,
    udp_msg_type_dtls_server_hello,
    udp_msg_type_dtls_certificate,
    udp_msg_type_wireguard,
    udp_msg_type_quic,
    udp_msg_type_vxlan,
    udp_msg_type_ssdp,
    udp_msg_type_stun,
    udp_msg_type_nbds,
    udp_msg_type_dht,
    udp_msg_type_lsd,
};

template <size_t N>
struct matcher_and_type {
    mask_and_value<N> mv;
    size_t type;
};

template <size_t N>
struct matcher_type_and_offset {
    mask_value_and_offset<N> mv;
    size_t type;
};


template <size_t N>
class protocol_identifier {
    std::vector<matcher_and_type<N>> matchers;
    std::vector<matcher_type_and_offset<N>> matchers_and_offset;

public:

    protocol_identifier() : matchers{}, matchers_and_offset{} {  }

    void add_protocol(const mask_and_value<N> &mv, size_t type) {
        struct matcher_and_type<N> new_proto{mv, type};
        matchers.push_back(new_proto);
    }

    void add_protocol(const mask_value_and_offset<N> &mv, size_t type) {
        struct matcher_type_and_offset<N> new_proto{mv, type};
        matchers_and_offset.push_back(new_proto);
    }

    void compile() {
        // this function is a placeholder for now, but in the future,
        // it may compile a jump table, reorder matchers, etc.
    }

    bool pkt_len_match(datum &pkt, const size_t type) const {
        switch(type) {
        case tcp_msg_type_iec:
        {
            return (iec60870_5_104::get_payload_length(pkt) == pkt.length());
        }
        case tcp_msg_type_dnp3:
        {
            return (dnp3::get_payload_length(pkt) == pkt.length());
        }
        case tcp_msg_type_nbss:
        {
            return (nbss_packet::get_payload_length(pkt) == pkt.length());
        }
        default:
            return true;
        }
    }

    /*
     * For matchers of size 4, along with matching 4 bytes of
     * payload, the packet length can also be used to make the
     * matcher more robust. Currently, this capability is used in matchers of
     * size 4. If required, this can be extended to matchers of other sizes.
     */
    size_t get_msg_type(datum &pkt) const {

        // TODO: process short data fields
        //
        if (pkt.length() < 4) {
            return 0;   // type unknown;
        }
        for (matcher_and_type p : matchers) {
            if (N == 4) {
                if (p.mv.matches(pkt.data, pkt.length()) && pkt_len_match(pkt, p.type)) {
                    return p.type;
                }
            } else if (p.mv.matches(pkt.data, pkt.length())) {
                return p.type;
            }
        }

        for (matcher_type_and_offset p : matchers_and_offset) {
            if (N == 4) {
                if (p.mv.matches_at_offset(pkt.data, pkt.length()) && pkt_len_match(pkt, p.type)) {
                    return p.type;
                }
            } else if (p.mv.matches_at_offset(pkt.data, pkt.length())) {
                return p.type;
            }
        }
        return 0;   // type unknown;
    }

};

// class selector implements a protocol selection policy for TCP and
// UDP traffic
//
class traffic_selector {
    protocol_identifier<4> tcp4;
    protocol_identifier<8> tcp;
    protocol_identifier<8> udp;
    protocol_identifier<16> udp16;

    bool select_tcp_syn;
    bool select_dns;
    bool select_nbns;
    bool select_mdns;
    bool select_arp;
    bool select_cdp;
    bool select_gre;
    bool select_icmp;
    bool select_lldp;
    bool select_ospf;
    bool select_sctp;
    bool select_tcp_syn_ack;
    bool select_nbds;
    bool select_nbss;
    bool select_openvpn_tcp;

public:

    bool tcp_syn() const { return select_tcp_syn; }

    bool dns() const { return select_dns; }

    bool nbns() const { return select_nbns; }

    bool mdns() const { return select_mdns; }

    bool arp() const { return select_arp; }

    bool cdp() const { return select_cdp; }

    bool gre() const { return select_gre; }

    bool icmp() const { return select_icmp; }

    bool lldp() const { return select_lldp; }

    bool ospf() const { return select_ospf; }

    bool sctp() const { return select_sctp; }

    bool tcp_syn_ack() const { return select_tcp_syn_ack; }

    bool nbds() const { return select_nbds; }

    bool nbss() const { return select_nbss; }

    bool openvpn_tcp() const { return select_openvpn_tcp; }

    traffic_selector(std::map<std::string, bool> protocols) :
            tcp{},
            udp{},
            select_tcp_syn{false},
            select_dns{false},
            select_nbns{false},
            select_mdns{false},
            select_arp{false},
            select_cdp{false},
            select_gre{false},
            select_icmp{false},
            select_lldp{false},
            select_ospf{false},
            select_sctp{false},
            select_tcp_syn_ack{false},
            select_nbds{false},
            select_nbss{false},
            select_openvpn_tcp{false} {

        // "none" is a special case; turn off all protocol selection
        //
        if (protocols["none"]) {
            for (auto &pair : protocols) {
                pair.second = false;
            }
        }

        if (protocols["tls"] || protocols["all"]) {
            tcp.add_protocol(tls_client_hello::matcher, tcp_msg_type_tls_client_hello);
            tcp.add_protocol(tls_server_hello::matcher, tcp_msg_type_tls_server_hello);
            tcp.add_protocol(tls_server_certificate::matcher, tcp_msg_type_tls_certificate);
        }
        else if(protocols["tls.client_hello"])
        {
            tcp.add_protocol(tls_client_hello::matcher, tcp_msg_type_tls_client_hello);
        }
        else if(protocols["tls.server_hello"])
        {
            tcp.add_protocol(tls_server_hello::matcher, tcp_msg_type_tls_server_hello);
        }
        else if(protocols["tls.server_certificate"])
        {
            tcp.add_protocol(tls_server_certificate::matcher, tcp_msg_type_tls_certificate);
        }
        if (protocols["ssh"] || protocols["all"]) {
            tcp.add_protocol(ssh_init_packet::matcher, tcp_msg_type_ssh);
            tcp.add_protocol(ssh_kex_init::matcher, tcp_msg_type_ssh_kex);
        }
        if (protocols["smtp"] || protocols["all"]) {
            tcp.add_protocol(smtp_client::matcher, tcp_msg_type_smtp_client);
            tcp.add_protocol(smtp_server::matcher, tcp_msg_type_smtp_server);
        }
        if (protocols["http"] || protocols["all"]) {
            tcp.add_protocol(http_response::matcher, tcp_msg_type_http_response);  // note: must come before http_request::matcher
            tcp.add_protocol(http_request::matcher, tcp_msg_type_http_request);
        }
        else if(protocols["http.request"])
        {
            tcp.add_protocol(http_request::get_matcher, tcp_msg_type_http_request);
            tcp.add_protocol(http_request::post_matcher, tcp_msg_type_http_request);
            tcp.add_protocol(http_request::connect_matcher, tcp_msg_type_http_request);
            tcp.add_protocol(http_request::put_matcher, tcp_msg_type_http_request);
            tcp.add_protocol(http_request::head_matcher, tcp_msg_type_http_request);
        }
        else if(protocols["http.response"])
        {
            tcp.add_protocol(http_response::matcher, tcp_msg_type_http_response);
        }

        // booleans not yet implemented
        //
        if (protocols["tcp"] || protocols["all"]) {
            select_tcp_syn = true;
        }
        if (protocols["tcp.message"]) {
            // select_tcp_syn = 0;
            // tcp_message_filter_cutoff = 1;
        }
        if (protocols["tcp.syn_ack"]) {
            select_tcp_syn_ack = true;
        }
        if (protocols["dhcp"] || protocols["all"]) {
            udp.add_protocol(dhcp_discover::matcher, udp_msg_type_dhcp);
        }
        if (protocols["dns"] || protocols["nbns"] || protocols["mdns"] || protocols["all"]) {
            if (protocols["all"]) {
                select_dns = true;
                select_nbns = true;
                select_mdns = true;
            }
            if (protocols["dns"]) {
                select_dns = true;
            }
            if (protocols["nbns"]) {
                select_nbns = true;
            }
            if (protocols["mdns"]) {
                select_mdns = true;
            }
            udp.add_protocol(dns_packet::matcher, udp_msg_type_dns);
            // udp.add_protocol(dns_packet::client_matcher, udp_msg_type_dns); // older matcher
            // udp.add_protocol(dns_packet::server_matcher, udp_msg_type_dns); // older matcher
        }
        if (protocols["dns"] || protocols["all"]) {
            tcp.add_protocol(dns_packet::tcp_matcher, tcp_msg_type_dns);
        }

        if (protocols["dtls"] || protocols["all"]) {
            udp16.add_protocol(dtls_client_hello::dtls_matcher, udp_msg_type_dtls_client_hello);
            udp16.add_protocol(dtls_server_hello::dtls_matcher, udp_msg_type_dtls_server_hello);
        }
        if (protocols["wireguard"] || protocols["all"]) {
            udp.add_protocol(wireguard_handshake_init::matcher, udp_msg_type_wireguard);
        }
        if (protocols["quic"] || protocols["all"]) {
            udp.add_protocol(quic_initial_packet::matcher, udp_msg_type_quic);
        }
        if (protocols["ssdp"] || protocols["all"]) {
            udp.add_protocol(ssdp::matcher, udp_msg_type_ssdp);
        }
        if (protocols["stun"] || protocols["all"]) {
            udp.add_protocol(stun::message::matcher, udp_msg_type_stun);
        }
        if (protocols["smb"] || protocols["all"]) {
            tcp.add_protocol(smb1_packet::matcher, tcp_msg_type_smb1);
            tcp.add_protocol(smb2_packet::matcher, tcp_msg_type_smb2);
        }
        if (protocols["iec"] || protocols["all"]) {
            tcp4.add_protocol(iec60870_5_104::matcher, tcp_msg_type_iec);
        }
        if (protocols["dnp3"] || protocols["all"]) {
            tcp4.add_protocol(dnp3::matcher, tcp_msg_type_dnp3);
        }
        if (protocols["arp"]) {
            select_arp = true;
        }
        if (protocols["cdp"]) {
            select_cdp = true;
        }
        if (protocols["gre"]) {
            select_gre = true;
        }
        if (protocols["icmp"]) {
            select_icmp = true;
        }
        if (protocols["lldp"]) {
            select_lldp = true;
        }
        if (protocols["ospf"]) {
            select_ospf = true;
        }
        if (protocols["sctp"]) {
            select_sctp = true;
        }
        if (protocols["nbss"]) {
            select_nbss = true;
           // tcp4.add_protocol(nbss_packet::matcher, tcp_msg_type_nbss);
        }
        if (protocols["nbds"]) {
            select_nbds = true;
        }
        if (protocols["openvpn_tcp"] || protocols["all"]) {
            select_openvpn_tcp = true;
        }

        if (protocols["bittorrent"] || protocols["all"]) {
            udp.add_protocol(bittorrent_dht::matcher, udp_msg_type_dht);
            udp.add_protocol(bittorrent_lsd::matcher, udp_msg_type_lsd);
            tcp.add_protocol(bittorrent_handshake::matcher, tcp_msg_type_bittorrent);
        }
        if (protocols["mysql"] || protocols["all"]) {
            tcp.add_protocol(mysql_server_greet::matcher, tcp_msg_type_mysql_server);
        }
        // tell protocol_identification objects to compile lookup tables
        tcp.compile();
        udp.compile();
        udp16.compile();

    }

    size_t get_tcp_msg_type(datum &pkt) const {
        size_t type = tcp.get_msg_type(pkt);
        if (type == tcp_msg_type_unknown)  {
            type = tcp4.get_msg_type(pkt);
        }
        return type;
    }

    size_t get_udp_msg_type(datum &pkt) const {
        size_t type = udp.get_msg_type(pkt);
        if (type == udp_msg_type_unknown)  {
            type = udp16.get_msg_type(pkt);
        }
        return type;
    }

    size_t get_udp_msg_type_from_ports(udp::ports ports) const {
        if (nbds() and ports.src == hton<uint16_t>(138) and ports.dst == hton<uint16_t>(138)) {
            return udp_msg_type_nbds;
        }

        if (ports.dst == hton<uint16_t>(4789)) {
            return udp_msg_type_vxlan;
        }

        return udp_msg_type_unknown;
    }

    size_t get_tcp_msg_type_from_ports(struct tcp_packet *tcp_pkt) const {
        if (tcp_pkt == nullptr or tcp_pkt->header == nullptr) {
            return tcp_msg_type_unknown;
        }

        if (nbss() and (tcp_pkt->header->src_port == hton<uint16_t>(139) or tcp_pkt->header->dst_port == hton<uint16_t>(139))) {
            return tcp_msg_type_nbss;
        }

        if (openvpn_tcp() and (tcp_pkt->header->src_port == hton<uint16_t>(1194) or tcp_pkt->header->dst_port == hton<uint16_t>(1194)) ) {
            return tcp_msg_type_openvpn;
        }

        return tcp_msg_type_unknown;
    }

};

#endif /* PROTO_IDENTIFY_H */
