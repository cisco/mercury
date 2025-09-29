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
#include "ftp.hpp"

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
#include "tofsee.hpp"
#include "socks.h"
#include "rfb.hpp"
#include "gre.h"
#include "geneve.hpp"
#include "vxlan.hpp"
#include "ike.hpp"
#include "esp.hpp"

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
    tcp_msg_type_mysql_login_request,
    tcp_msg_type_tofsee_initial_message,
    tcp_msg_type_socks4,
    tcp_msg_type_socks5_hello,
    tcp_msg_type_socks5_req_resp,
    tcp_msg_type_ldap,
    tcp_msg_type_rfb,
    tcp_msg_type_tacacs,
    tcp_msg_type_ftp_request,
    tcp_msg_type_ftp_response,
    tcp_msg_type_rdp,
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
    udp_msg_type_krb5,
    udp_msg_type_esp,
    udp_msg_type_tftp,
    udp_msg_type_geneve,
    udp_msg_type_gre,
    udp_msg_type_ike
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
        case tcp_msg_type_tofsee_initial_message:
        {
            return (200 == pkt.length());
        }
        case tcp_msg_type_socks4:
        {
            return (socks4_req::get_payload_length(pkt) == pkt.length());
        }
        case tcp_msg_type_socks5_hello:
        {
            return (socks5_hello::get_payload_length(pkt) == pkt.length());
        }
        case tcp_msg_type_socks5_req_resp:
        {
            return (socks5_req_resp::get_payload_length(pkt) == pkt.length());
        }
        case udp_msg_type_stun:
        {
            return (stun::message::packet_length_from_header(pkt) == pkt.length());
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

    void disable_all() {
        matchers.clear();
        matchers_and_offset.clear();
    }

};

// class selector implements a protocol selection policy for TCP and
// UDP traffic
//
class traffic_selector {
    protocol_identifier<4> tcp4;
    protocol_identifier<8> tcp;
    protocol_identifier<4> udp4;
    protocol_identifier<8> udp;
    protocol_identifier<16> udp16;

    bool select_tcp_syn{false};
    bool select_dns{false};
    bool select_nbns{false};
    bool select_mdns{false};
    bool select_arp{false};
    bool select_cdp{false};
    bool select_gre{false};
    bool select_icmp{false};
    bool select_lldp{false};
    bool select_ospf{false};
    bool select_sctp{false};
    bool select_tcp_syn_ack{false};
    bool select_nbds{false};
    bool select_nbss{false};
    bool select_openvpn_tcp{false};
    bool select_ldap{false};
    bool select_krb5{false};
    bool select_ftp_request{false};
    bool select_ftp_response{false};
    bool select_ipsec{false};
    bool select_rfb{false};
    bool select_tacacs{false};
    bool select_rdp{false};
    bool select_tftp{false};
    bool select_geneve{false};
    bool select_vxlan{false};
    bool select_mysql_login_request{false};

public:

    bool tcp_syn() const { return select_tcp_syn; }

    bool dns() const { return select_dns; }

    bool nbns() const { return select_nbns; }

    bool mdns() const { return select_mdns; }

    bool arp() const { return select_arp; }

    bool cdp() const { return select_cdp; }

    bool gre() const { return select_gre; }

    bool icmp() const { return select_icmp; }

    bool krb5() const { return select_krb5; }

    bool ldap() const { return select_ldap; }

    bool ftp_request() const {return select_ftp_request; }

    bool ftp_response() const {return select_ftp_response; }

    bool lldp() const { return select_lldp; }

    bool ospf() const { return select_ospf; }

    bool sctp() const { return select_sctp; }

    bool tftp() const { return select_tftp; }

    bool tcp_syn_ack() const { return select_tcp_syn_ack; }

    bool nbds() const { return select_nbds; }

    bool nbss() const { return select_nbss; }

    bool openvpn_tcp() const { return select_openvpn_tcp; }

    bool ipsec() const { return select_ipsec; }

    bool rfb() const { return select_rfb; }

    bool rdp() const { return select_rdp; }

    bool tacacs() const { return select_tacacs; }

    bool geneve() const { return select_geneve; }

    bool vxlan() const { return select_vxlan; }

    bool mysql_login_request() const { return select_mysql_login_request; }

    void disable_all() {
        tcp.disable_all();
        tcp4.disable_all();
        udp.disable_all();
        udp16.disable_all();

        select_tcp_syn = false;
        select_dns = false;
        select_nbns = false;
        select_mdns = false;
        select_arp = false;
        select_cdp = false;
        select_gre = false;
        select_icmp = false;
        select_lldp = false;
        select_ospf = false;
        select_sctp = false;
        select_tcp_syn_ack = false;
        select_nbds = false;
        select_nbss = false;
        select_openvpn_tcp = false;
        select_ldap = false;
        select_krb5 = false;
        select_ftp_request = false;
        select_ftp_response = false;
        select_ipsec = false;
        select_rfb = false;
        select_tacacs = false;
        select_rdp = false;
        select_tftp = false;
        select_geneve = false;
        select_vxlan = false;
        select_mysql_login_request = false;

    }

    traffic_selector(std::map<std::string, bool> protocols) {

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
        if (protocols["rfb"] || protocols["all"]) {
            tcp.add_protocol(rfb::protocol_version_handshake::matcher, tcp_msg_type_rfb);
        }
        if (protocols["rdp"] || protocols["all"]) {
            select_rdp = true;
        }
        if(protocols["ftp"] || protocols["all"])
        {
            select_ftp_response = true;
            select_ftp_request = true;
            // tcp.add_protocol(ftp::request::user_matcher, tcp_msg_type_ftp_request);
            // tcp.add_protocol(ftp::request::pass_matcher, tcp_msg_type_ftp_request);
            // tcp.add_protocol(ftp::request::stor_matcher, tcp_msg_type_ftp_request);
            // tcp.add_protocol(ftp::request::retr_matcher, tcp_msg_type_ftp_request);
            // tcp4.add_protocol(ftp::response::status_code_matcher, tcp_msg_type_ftp_response);
        }
        else if(protocols["ftp.response"])
        {
            select_ftp_response = true;
            // tcp4.add_protocol(ftp::response::status_code_matcher, tcp_msg_type_ftp_response);
        }
        else if(protocols["ftp.request"])
        {
            select_ftp_request = true;
            // tcp.add_protocol(ftp::request::user_matcher, tcp_msg_type_ftp_request);
            // tcp.add_protocol(ftp::request::pass_matcher, tcp_msg_type_ftp_request);
            // tcp.add_protocol(ftp::request::stor_matcher, tcp_msg_type_ftp_request);
            // tcp.add_protocol(ftp::request::retr_matcher, tcp_msg_type_ftp_request);

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
        if (protocols["ldap"] || protocols["all"]) {
            select_ldap = true;
        }
        if (protocols["kerberos"] || protocols["all"]) {
           //
           // kerberos is not yet ready for integration
           //
           // select_krb5 = true;
        }
        if (protocols["tcp.message"] || protocols["all"]) {
            // select_tcp_syn = 0;
            // tcp_message_filter_cutoff = 1;
        }
        if (protocols["tcp.syn_ack"] || protocols["all"]) {
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
        if (protocols["ssdp"] || protocols["all"]) {
            udp.add_protocol(ssdp::matcher, udp_msg_type_ssdp);
        }
        // if (protocols["stun"] || protocols["all"]) {
        //     udp.add_protocol(stun::message::matcher, udp_msg_type_stun);
        // }
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
        if (protocols["arp"] || protocols["all"]) {
            select_arp = true;
        }
        if (protocols["cdp"] || protocols["all"]) {
            select_cdp = true;
        }
        if (protocols["gre"] || protocols["all"]) {
            select_gre = true;
        }
        if (protocols["icmp"] || protocols["all"]) {
            select_icmp = true;
        }
        if (protocols["lldp"] || protocols["all"]) {
            select_lldp = true;
        }
        if (protocols["ospf"] || protocols["all"]) {
            select_ospf = true;
        }
        if (protocols["sctp"] || protocols["all"]) {
            select_sctp = true;
        }
        if (protocols["nbss"] || protocols["all"]) {
            select_nbss = true;
           // tcp4.add_protocol(nbss_packet::matcher, tcp_msg_type_nbss);
        }
        if (protocols["nbds"] || protocols["all"]) {
            select_nbds = true;
        }
        if (protocols["openvpn_tcp"] || protocols["all"]) {
            select_openvpn_tcp = true;
        }
        if (protocols["ipsec"] || protocols["all"]) {
            select_ipsec = true;
        }
        if (protocols["tftp"] || protocols["all"]) {
            select_tftp = true;
        }

        if (protocols["bittorrent"] || protocols["all"]) {
            udp.add_protocol(bittorrent_dht::matcher, udp_msg_type_dht);
            udp.add_protocol(bittorrent_lsd::matcher, udp_msg_type_lsd);
            tcp.add_protocol(bittorrent_handshake::matcher, tcp_msg_type_bittorrent);
        }
        if (protocols["mysql"] || protocols["all"]) {
            tcp.add_protocol(mysql_server_greet::matcher, tcp_msg_type_mysql_server);
            select_mysql_login_request = true;
        }
        if (protocols["quic"] || protocols["all"]) {
            udp.add_protocol(quic_initial_packet::matcher, udp_msg_type_quic);
        }

        if (protocols["socks"] || protocols["all"]) {
            tcp4.add_protocol(socks4_req::matcher, tcp_msg_type_socks4);
            tcp4.add_protocol(socks5_hello::matcher, tcp_msg_type_socks5_hello);
            //tcp4.add_protocol(socks5_usr_pass::matcher, tcp_msg_type_socks5_usr_pass);
            //tcp4.add_protocol(socks5_gss::matcher, tcp_msg_type_socks5_gss);
            tcp4.add_protocol(socks5_req_resp::matcher, tcp_msg_type_socks5_req_resp);
        }

        // use a length-based stun matcher, which will work for both
        // legacy and modern variants of that protocol
        //
        if (protocols["stun"] || protocols["all"]) {
            udp4.add_protocol(stun::message::matcher, udp_msg_type_stun);
        }

        if (protocols["tacacs"] || protocols["all"]) {
            select_tacacs = true;
        }

        // add tofsee, but keep at the absolute end of matcher lists, as tofsee only
        // has a length based matcher
        if (protocols["tofsee"] || protocols["all"]) {
            tcp4.add_protocol(tofsee_initial_message::matcher, tcp_msg_type_tofsee_initial_message);
        }

        if (protocols["geneve"] || protocols["all"]) {
            select_geneve = true;
        }

        if (protocols["vxlan"] || protocols["all"]) {
            select_vxlan = true;
        }

        // tell protocol_identification objects to compile lookup tables
        tcp4.compile();
        tcp.compile();
        udp4.compile();
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

    size_t get_udp_msg_type(datum &pkt, udp::ports ports) const {
        size_t type = udp_msg_type_unknown;
        if (ipsec() and ports.either_matches_any(esp_default_port)) {   // esp or ike over udp
            if (lookahead<ike::non_esp_marker> non_esp{pkt}) {
                type = udp_msg_type_ike;
            } else {
                type = udp_msg_type_esp;
            }
            return type;
        }

        type = udp.get_msg_type(pkt);
        if (type == udp_msg_type_unknown)  {
            type = udp16.get_msg_type(pkt);
        }
        if (type == udp_msg_type_unknown)  {
            type = udp4.get_msg_type(pkt);
        }

        if (type == udp_msg_type_unknown) {
            type = get_udp_msg_type_from_ports(ports);
        }

        return type;
    }

    udp_msg_type get_udp_msg_type_from_ports(udp::ports ports) const {
        if (ipsec() and ports.either_matches(ike::default_port)) {
            return udp_msg_type_ike;
        }

        if (nbds() and ports.src == hton<uint16_t>(138) and ports.dst == hton<uint16_t>(138)) {
            return udp_msg_type_nbds;
        }

        if (tftp() and (ports.src == hton<uint16_t>(69) or ports.dst == hton<uint16_t>(69)) ) {
            return udp_msg_type_tftp;
        }

        if (krb5() and (ports.src == hton<uint16_t>(88) or ports.dst == hton<uint16_t>(88))) {
            return udp_msg_type_krb5;
        }

        if (vxlan() and ports.dst == hton<uint16_t>(vxlan::dst_port)) {
            return udp_msg_type_vxlan;
        }

        if (geneve() and ports.dst == hton<uint16_t>(geneve::dst_port)) {
            return udp_msg_type_geneve;
        }

        if (gre() and ports.dst == hton<uint16_t>(gre_header::dst_port)) {
            return udp_msg_type_gre;
        }

        return udp_msg_type_unknown;
    }

    size_t get_tcp_msg_type_from_ports(struct tcp_packet *tcp_pkt) const {
        if (tcp_pkt == nullptr or tcp_pkt->header == nullptr) {
            return tcp_msg_type_unknown;
        }

        if (ldap() and ((tcp_pkt->header->src_port == hton<uint16_t>(389)) or (tcp_pkt->header->dst_port == hton<uint16_t>(389)))) {
            return tcp_msg_type_ldap;
        }

        if (nbss() and (tcp_pkt->header->src_port == hton<uint16_t>(139) or tcp_pkt->header->dst_port == hton<uint16_t>(139))) {
            return tcp_msg_type_nbss;
        }

        if (openvpn_tcp() and (tcp_pkt->header->src_port == hton<uint16_t>(1194) or tcp_pkt->header->dst_port == hton<uint16_t>(1194)) ) {
            return tcp_msg_type_openvpn;
        }

        // FTP uses port 21 as its default connection channel, so responses from the server  will originate from this port
        if (ftp_response() and ((tcp_pkt->header->src_port == hton<uint16_t>(21))))
        {
            return tcp_msg_type_ftp_response;
        }

        if (ftp_request() and ((tcp_pkt->header->dst_port == hton<uint16_t>(21))))
        {
            return tcp_msg_type_ftp_request;
        }

        if (tacacs() and (tcp_pkt->header->src_port == hton<uint16_t>(49) or tcp_pkt->header->dst_port == hton<uint16_t>(49)) ) {
            return tcp_msg_type_tacacs;
        }

        if (rdp() and (tcp_pkt->header->src_port == hton<uint16_t>(3389) or tcp_pkt->header->dst_port == hton<uint16_t>(3389)) ) {
            return tcp_msg_type_rdp;
        }

        if (mysql_login_request() and ( (tcp_pkt->header->src_port == hton<uint16_t>(3306)) || (tcp_pkt->header->dst_port == hton<uint16_t>(3306)) ) ) {
            return tcp_msg_type_mysql_login_request;
        }

        return tcp_msg_type_unknown;
    }

};

#endif /* PROTO_IDENTIFY_H */
