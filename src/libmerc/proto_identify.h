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

#include "dhcp.h"  // udp protocols
#include "quic.h"
#include "dns.h"
#include "wireguard.h"
#include "dtls.h"
#include "ssdp.h"

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
    tcp_msg_type_smb2
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
    udp_msg_type_ssdp
};

template <size_t N>
struct matcher_and_type {
    mask_and_value<N> mv;
    size_t type;
};


template <size_t N>
class protocol_identifier {
    std::vector<matcher_and_type<N>> matchers;

public:

    protocol_identifier() : matchers{} {  }

    void add_protocol(const mask_and_value<N> &mv, size_t type) {
        struct matcher_and_type<N> new_proto{mv, type};
        matchers.push_back(new_proto);
    }

    void compile() {
        // this function is a placeholder for now, but in the future,
        // it may compile a jump table, reorder matchers, etc.
    }

    size_t get_msg_type(const uint8_t *data, unsigned int len) const {

        // TODO: process short data fields
        //
        if (len < 8) {
            return 0;   // type unknown;
        }
        for (matcher_and_type p : matchers) {
            if (p.mv.matches(data)) {
                return p.type;
            }
        }
        return 0;   // type unknown;
    }

};

bool set_config(std::map<std::string, bool> &config_map, const char *config_string); // in pkt_proc.cc

// class selector implements a protocol selection policy for TCP and
// UDP traffic
//
class traffic_selector {
    protocol_identifier<8> tcp;
    protocol_identifier<8> udp;
    protocol_identifier<16> udp16;

    bool select_tcp_syn;
    bool select_dns;
    bool select_nbns;
    bool select_mdns;

public:

    bool tcp_syn() const { return select_tcp_syn; }

    bool dns() const { return select_dns; }

    bool nbns() const { return select_nbns; }

    bool mdns() const { return select_mdns; }

    traffic_selector(std::map<std::string, bool> protocols) : tcp{}, udp{}, select_tcp_syn{false}, select_dns{false}, select_nbns{false}, select_mdns{false} {

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
        if (protocols["smb"] || protocols["all"]) {
            tcp.add_protocol(smb1_packet::matcher, tcp_msg_type_smb1);
            tcp.add_protocol(smb2_packet::matcher, tcp_msg_type_smb2);
        }
        // tell protocol_identification objects to compile lookup tables
        //
        tcp.compile();
        udp.compile();
        udp16.compile();

    }

    size_t get_tcp_msg_type(const uint8_t *data, unsigned int len) const {
        return tcp.get_msg_type(data, len);
    }

    size_t get_udp_msg_type(const uint8_t *data, unsigned int len) const {
        size_t type = udp.get_msg_type(data, len);
        if (type == udp_msg_type_unknown)  {
            type = udp16.get_msg_type(data, len);
        }
        return type;
    }

};

#endif /* PROTO_IDENTIFY_H */
