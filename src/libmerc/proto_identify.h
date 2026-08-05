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
#include <cassert>

#include <vector>
#include <array>
#include "match.h"

#include "arp.h"
#include "cdp.h"
#include "eth.h"
#include "icmp.h"
#include "ip.h"
#include "lldp.h"
#include "ospf.h"
#include "ppp.h"
#include "sctp.h"
#include "tcp.h"

#include "tls.h"   // tcp protocols
#include "http.h"
#include "ssh.h"
#include "smtp.h"
#include "smb1.h"
#include "smb2.h"
#include "iec60870_5_104.h"
#include "ftp.hpp"
#include "tcpip.h"
#include "ldap.hpp"
#include "tacacs.hpp"
#include "rdp.hpp"
#include "redis.hpp"
#include "imap.hpp"
#include "telnet.hpp"

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
#include "lex.h"
#include "ike.hpp"
#include "esp.hpp"
#include "mdns.h"
#include "krb5.hpp"
#include "tftp.hpp"
#include "pgsql.hpp"
#include "dcerpc.hpp"

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
    tcp_msg_type_telnet,
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
    tcp_msg_type_krb5,
    tcp_msg_type_pgsql,
    tcp_msg_type_redis_request,
    tcp_msg_type_redis_response,
    tcp_msg_type_imap_request,
    tcp_msg_type_imap_response,
    tcp_msg_type_dcerpc_client,
    tcp_msg_type_dcerpc_server,
};

// Template-based stack-allocated structure to replace std::vector<T>
// Uses a small fixed-size array to avoid heap allocation
// Can be used for tcp_msg_type, udp_msg_type, or other enum types
template<typename MsgType, MsgType UnknownValue = static_cast<MsgType>(0), size_t MaxTypes = 3>
struct msg_types {
    static constexpr size_t max_types = MaxTypes;
    std::array<MsgType, max_types> types;
    size_t count;

    // Constructor for single type
    constexpr msg_types(MsgType type) : types{type, UnknownValue}, count(1) {}

    // Constructor for two types
    constexpr msg_types(MsgType type1, MsgType type2) : types{type1, type2}, count(2) {}

    // Constructor for three types
    constexpr msg_types(MsgType type1, MsgType type2, MsgType type3) : types{type1, type2, type3}, count(3) {}

    // Iterator support for range-based for loops
    constexpr auto begin() const { return types.begin(); }
    constexpr auto end() const { return types.begin() + count; }

    // Size and access methods
    constexpr size_t size() const { return count; }
    constexpr MsgType front() const { return types[0]; }
    constexpr const MsgType& operator[](size_t index) const { return types[index]; }
};

// Type aliases for convenience
using tcp_msg_types = msg_types<tcp_msg_type, tcp_msg_type_unknown, 3>;
//using udp_msg_types = msg_types<udp_msg_type, udp_msg_type_unknown, 2>;

enum udp_msg_type {
    udp_msg_type_unknown = 0,
    udp_msg_type_dns,
    udp_msg_type_dhcp,
    udp_msg_type_dtls_client_hello,
    udp_msg_type_dtls_server_hello,
    udp_msg_type_dtls_certificate,
    udp_msg_type_dtls_hello_verify_request,
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
    udp_msg_type_ike,
    udp_msg_type_snmp,
    udp_msg_type_syslog,
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

// User Defined Literal for converting 4-character strings to uint32_t
// It returns a `uint32_t` whose bytes match those of the input string
// when considered as an unsigned integer in network byte order

constexpr uint32_t operator ""_uint32(const char* str, size_t length) {
    if (str == nullptr || length != 4) {
        throw std::invalid_argument("_uint32 must be exactly 4 characters");
    }
    return (uint32_t)str[0] << 24 | (uint32_t)str[1] << 16 | (uint32_t)str[2] << 8 | (uint32_t)str[3];
}

class tcp_keyword_matcher {
public:
    // Static member for unknown type - can be used anywhere an unknown tcp_msg_types is needed
    inline static const tcp_msg_types unknown_type{tcp_msg_type_unknown};

    // NOTE: every distinct tcp_msg_type used as a value below must also be
    // gated in traffic_selector::keyword_type_enabled().  If you add a new
    // keyword-matched protocol here, add a matching case there or it will be
    // silently skipped during keyword-based detection.
    //
    inline static std::unordered_map<uint32_t, tcp_msg_types> tcp_keyword_map = {
        //HTTP methods taken from https://www.iana.org/assignments/http-methods/http-methods.xhtm
        {"ACL "_uint32,              {tcp_msg_type_http_request}},
        {"BASE"_uint32,              {tcp_msg_type_http_request}},
        {"BIND"_uint32,              {tcp_msg_type_http_request}},
        {"CHEC"_uint32,              {tcp_msg_type_http_request}},
        {"CONN"_uint32,              {tcp_msg_type_http_request}},
        {"COPY"_uint32,              {tcp_msg_type_http_request}},
        {"DELE"_uint32,              tcp_msg_types(tcp_msg_type_http_request, tcp_msg_type_ftp_request)},
        {"GET "_uint32,              {tcp_msg_type_http_request}},
        {"HEAD"_uint32,              {tcp_msg_type_http_request}},
        {"LABE"_uint32,              {tcp_msg_type_http_request}},
        {"LINK"_uint32,              {tcp_msg_type_http_request}},
        {"LOCK"_uint32,              {tcp_msg_type_http_request}},
        {"MERG"_uint32,              {tcp_msg_type_http_request}},
        {"MKAC"_uint32,              {tcp_msg_type_http_request}},
        {"MKCA"_uint32,              {tcp_msg_type_http_request}},
        {"MKCO"_uint32,              {tcp_msg_type_http_request}},
        {"MKRE"_uint32,              {tcp_msg_type_http_request}},
        {"MKWO"_uint32,              {tcp_msg_type_http_request}},
        {"MOVE"_uint32,              {tcp_msg_type_http_request}},
        {"OPTI"_uint32,              {tcp_msg_type_http_request}},
        {"ORDE"_uint32,              {tcp_msg_type_http_request}},
        {"PATC"_uint32,              {tcp_msg_type_http_request}},
        {"POST"_uint32,              {tcp_msg_type_http_request}},
        {"PRI "_uint32,              {tcp_msg_type_http_request}},
        {"PROP"_uint32,              {tcp_msg_type_http_request}},
        {"PUT "_uint32,              {tcp_msg_type_http_request}},
        {"REBI"_uint32,              {tcp_msg_type_http_request}},
        {"REPO"_uint32,              {tcp_msg_type_http_request}},
        {"SEAR"_uint32,              {tcp_msg_type_http_request}},
        {"TRAC"_uint32,              {tcp_msg_type_http_request}},
        {"UNBI"_uint32,              {tcp_msg_type_http_request}},
        {"UNCH"_uint32,              {tcp_msg_type_http_request}},
        {"UNLI"_uint32,              {tcp_msg_type_http_request}},
        {"UNLO"_uint32,              {tcp_msg_type_http_request}},
        {"UPDA"_uint32,              {tcp_msg_type_http_request}},
        {"VERS"_uint32,              {tcp_msg_type_http_request}},
        //Extensions taken from https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions.xhtml
        {"ABOR"_uint32,              {tcp_msg_type_ftp_request}},
        {"ACCT"_uint32,              {tcp_msg_type_ftp_request}},
        {"ADAT"_uint32,              {tcp_msg_type_ftp_request}},
        {"ALGS"_uint32,              {tcp_msg_type_ftp_request}},
        {"ALLO"_uint32,              {tcp_msg_type_ftp_request}},
        {"APPE"_uint32,              {tcp_msg_type_ftp_request}},
        {"AUTH"_uint32,              tcp_msg_types(tcp_msg_type_ftp_request, tcp_msg_type_smtp_client, tcp_msg_type_redis_request)},
        {"CCC "_uint32,              {tcp_msg_type_ftp_request}},
        {"CCC\r"_uint32,             {tcp_msg_type_ftp_request}},
        {"CDUP"_uint32,              {tcp_msg_type_ftp_request}},
        {"CONF"_uint32,              {tcp_msg_type_ftp_request}},
        {"CWD "_uint32,              {tcp_msg_type_ftp_request}},
        {"CWD\r"_uint32,             {tcp_msg_type_ftp_request}},
        {"ENC "_uint32,              {tcp_msg_type_ftp_request}},
        {"ENC\r"_uint32,             {tcp_msg_type_ftp_request}},
        {"EPRT"_uint32,              {tcp_msg_type_ftp_request}},
        {"EPSV"_uint32,              {tcp_msg_type_ftp_request}},
        {"FEAT"_uint32,              {tcp_msg_type_ftp_request}},
        {"HELP"_uint32,              tcp_msg_types(tcp_msg_type_ftp_request, tcp_msg_type_smtp_client)},
        {"HOST"_uint32,              {tcp_msg_type_ftp_request}},
        {"LANG"_uint32,              {tcp_msg_type_ftp_request}},
        {"LIST"_uint32,              {tcp_msg_type_ftp_request}},
        {"LPRT"_uint32,              {tcp_msg_type_ftp_request}},
        {"LPSV"_uint32,              {tcp_msg_type_ftp_request}},
        {"MDTM"_uint32,              {tcp_msg_type_ftp_request}},
        {"MIC "_uint32,              {tcp_msg_type_ftp_request}},
        {"MIC\r"_uint32,             {tcp_msg_type_ftp_request}},
        {"MKD "_uint32,              {tcp_msg_type_ftp_request}},
        {"MKD\r"_uint32,             {tcp_msg_type_ftp_request}},
        {"MLSD"_uint32,              {tcp_msg_type_ftp_request}},
        {"MLST"_uint32,              {tcp_msg_type_ftp_request}},
        {"MODE"_uint32,              {tcp_msg_type_ftp_request}},
        {"NLST"_uint32,              {tcp_msg_type_ftp_request}},
        {"NOOP"_uint32,              tcp_msg_types(tcp_msg_type_ftp_request, tcp_msg_type_smtp_client)},
        {"OPTS"_uint32,              {tcp_msg_type_ftp_request}},
        {"PASS"_uint32,              {tcp_msg_type_ftp_request}},
        {"PASV"_uint32,              {tcp_msg_type_ftp_request}},
        {"PBSZ"_uint32,              {tcp_msg_type_ftp_request}},
        {"PORT"_uint32,              {tcp_msg_type_ftp_request}},
        {"PROT"_uint32,              {tcp_msg_type_ftp_request}},
        {"PWD "_uint32,              {tcp_msg_type_ftp_request}},
        {"PWD\r"_uint32,             {tcp_msg_type_ftp_request}},
        {"QUIT"_uint32,              tcp_msg_types(tcp_msg_type_ftp_request, tcp_msg_type_smtp_client)},
        {"REIN"_uint32,              {tcp_msg_type_ftp_request}},
        {"REST"_uint32,              {tcp_msg_type_ftp_request}},
        {"RETR"_uint32,              {tcp_msg_type_ftp_request}},
        {"RMD "_uint32,              {tcp_msg_type_ftp_request}},
        {"RMD\r"_uint32,             {tcp_msg_type_ftp_request}},
        {"RNFR"_uint32,              {tcp_msg_type_ftp_request}},
        {"RNTO"_uint32,              {tcp_msg_type_ftp_request}},
        {"SITE"_uint32,              {tcp_msg_type_ftp_request}},
        {"SIZE"_uint32,              {tcp_msg_type_ftp_request}},
        {"SMNT"_uint32,              {tcp_msg_type_ftp_request}},
        {"STAT"_uint32,              {tcp_msg_type_ftp_request}},
        {"STOR"_uint32,              {tcp_msg_type_ftp_request}},
        {"STOU"_uint32,              {tcp_msg_type_ftp_request}},
        {"STRU"_uint32,              {tcp_msg_type_ftp_request}},
        {"SYST"_uint32,              {tcp_msg_type_ftp_request}},
        {"TYPE"_uint32,              {tcp_msg_type_ftp_request}},
        {"USER"_uint32,              {tcp_msg_type_ftp_request}},
        {"XCUP"_uint32,              {tcp_msg_type_ftp_request}},
        {"XCWD"_uint32,              {tcp_msg_type_ftp_request}},
        {"XMKD"_uint32,              {tcp_msg_type_ftp_request}},
        {"XPWD"_uint32,              {tcp_msg_type_ftp_request}},
        {"XRMD"_uint32,              {tcp_msg_type_ftp_request}},
        //Extensions not yet present in IANA
        {"CLNT"_uint32,              {tcp_msg_type_ftp_request}},
        //SMTP commands collated from https://mailtrap.io/blog/smtp-commands-and-responses
        {"ATRN"_uint32,              {tcp_msg_type_smtp_client}},
        {"BDAT"_uint32,              {tcp_msg_type_smtp_client}},
        {"DATA"_uint32,              {tcp_msg_type_smtp_client}},
        {"EHLO"_uint32,              {tcp_msg_type_smtp_client}},
        {"ETRN"_uint32,              {tcp_msg_type_smtp_client}},
        {"EXPN"_uint32,              {tcp_msg_type_smtp_client}},
        {"HELO"_uint32,              {tcp_msg_type_smtp_client}},
        {"MAIL"_uint32,              {tcp_msg_type_smtp_client}},
        {"RCPT"_uint32,              {tcp_msg_type_smtp_client}},
        {"STAR"_uint32,              {tcp_msg_type_smtp_client}},
        {"VRFY"_uint32,              {tcp_msg_type_smtp_client}},
        //HTTP response
        {"HTTP"_uint32,              {tcp_msg_type_http_response}},
        //RFB
        {"RFB "_uint32,              {tcp_msg_type_rfb}}
    };

    static const tcp_msg_types& get_tcp_msg_type_from_keyword(uint32_t keyword) {
        auto it = tcp_keyword_map.find(keyword);
        if (it != tcp_keyword_map.end()) {
            return it->second;
        }
        return unknown_type;
    }
};

///
/// \brief Result of a resumable match.
///
/// Holds the matched message type and the index from which to resume
/// scanning on the next call.  The index addresses a virtual concatenation
/// of \c matchers followed by \c matchers_and_offset, so that priority
/// order is preserved across resumed calls.
///
struct match_result {
    size_t type;          ///< tcp/udp msg type, unknown_msg_type if no match
    size_t next_index;    ///< resume index for the following call
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

    /// returns the number of matchers, i.e. the length of the virtual
    /// concatenation of \c matchers and \c matchers_and_offset that
    /// get_msg_type_resumable() indexes into.
    size_t size() const { return matchers.size() + matchers_and_offset.size(); }

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
        return get_msg_type_resumable(pkt, 0).type;
    }

    /// Protocol-agnostic "no match / unknown type" value for
    /// match_result::type.
    /// This template is shared by both TCP and UDP, so it cannot name either
    /// tcp_msg_type_unknown or udp_msg_type_unknown; all three are 0.
    static constexpr size_t unknown_msg_type = 0;

    ///
    /// \brief Identify the message type, resuming the matcher scan at an index.
    ///
    /// Behaves like get_msg_type(), but begins scanning at matcher index
    /// \p start and reports the index to resume from on the next call.  This
    /// lets a caller retry detection from the matcher *after* one whose
    /// protocol parse failed, without rescanning earlier matchers (so the
    /// total matching work across all retries is bounded by a single full
    /// pass).
    ///
    /// \param pkt_in  packet datum to match against; read-only (a local
    ///                16-byte copy is taken, so the caller's view is never
    ///                advanced).
    /// \param start   matcher index to begin scanning from (0 for a fresh
    ///                scan); indexes the virtual concatenation of \c matchers
    ///                then \c matchers_and_offset.
    /// \return a match_result whose \c type is the matched message type (0 /
    ///         unknown if none matched) and whose \c next_index is the index
    ///         to resume from (SIZE_MAX when no further candidates remain).
    ///
    match_result get_msg_type_resumable(const datum &pkt_in, size_t start) const {

        // TODO: process short data fields
        //
        if (pkt_in.length() < 4) {
            return { unknown_msg_type, SIZE_MAX };   // type unknown; no more candidates
        }

        // Local non-owning copy: matching and pkt_len_match() only read from
        // the datum, but pkt_len_match() takes a non-const reference, so we
        // work on a 16-byte copy and never mutate the caller's view.
        //
        datum pkt = pkt_in;

        const size_t n_first = matchers.size();

        for (size_t i = start; i < n_first; i++) {
            const matcher_and_type<N> &p = matchers[i];
            if (N == 4) {
                if (p.mv.matches(pkt.data, pkt.length()) && pkt_len_match(pkt, p.type)) {
                    return { p.type, i + 1 };
                }
            } else if (p.mv.matches(pkt.data, pkt.length())) {
                return { p.type, i + 1 };
            }
        }

        const size_t off_start = (start > n_first) ? (start - n_first) : 0;
        for (size_t i = off_start; i < matchers_and_offset.size(); i++) {
            const matcher_type_and_offset<N> &p = matchers_and_offset[i];
            if (N == 4) {
                if (p.mv.matches_at_offset(pkt.data, pkt.length()) && pkt_len_match(pkt, p.type)) {
                    return { p.type, n_first + i + 1 };
                }
            } else if (p.mv.matches_at_offset(pkt.data, pkt.length())) {
                return { p.type, n_first + i + 1 };
            }
        }

        return { unknown_msg_type, SIZE_MAX };   // type unknown; no more candidates
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
    bool select_snmp{false};
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
    bool select_http_request{false};
    bool select_http_response{false};
    bool select_smtp{false};
    bool select_tofsee{false};
    flow_direction_selector select_ssh_direction{flow_direction_selector::none};
    bool select_dhcp{false};
    bool select_syslog{false};
    bool select_redis_request{false};
    bool select_redis_response{false};
    bool select_imap_request{false};
    bool select_imap_response{false};
    bool select_telnet{false};
    bool select_pgsql{false};

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

    bool snmp() const { return select_snmp; }

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

    bool http_request() const { return select_http_request; }

    bool http_response() const { return select_http_response; }

    bool smtp() const { return select_smtp; }

    bool tofsee() const { return select_tofsee; }

    flow_direction_selector ssh_direction() const { return select_ssh_direction; }

    bool dhcp() const { return select_dhcp; }

    bool syslog() const { return select_syslog; }

    bool redis_request() const { return select_redis_request; }

    bool redis_response() const { return select_redis_response; }

    bool imap_request() const { return select_imap_request; }

    bool imap_response() const { return select_imap_response; }

    bool telnet() const { return select_telnet; }

    bool pgsql() const { return select_pgsql; }

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
        select_http_request = false;
        select_http_response = false;
        select_smtp = false;
        select_tofsee = false;
        select_ssh_direction = flow_direction_selector::none;
        select_dhcp = false;
        select_syslog = false;
        select_redis_request = false;
        select_redis_response = false;
        select_imap_request = false;
        select_imap_response = false;
        select_telnet = false;
        select_pgsql = false;

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
        else {
            if (protocols["tls.client_hello"]) {
                tcp.add_protocol(tls_client_hello::matcher, tcp_msg_type_tls_client_hello);
            }
            if (protocols["tls.server_hello"]) {
                tcp.add_protocol(tls_server_hello::matcher, tcp_msg_type_tls_server_hello);
            }
            if (protocols["tls.server_certificate"]) {
                tcp.add_protocol(tls_server_certificate::matcher, tcp_msg_type_tls_certificate);
            }
        }
        if (protocols["ssh"] || protocols["all"]) {
            select_ssh_direction = flow_direction_selector::any;
            tcp.add_protocol(ssh_init_packet::matcher, tcp_msg_type_ssh);
            tcp.add_protocol(ssh_kex_init::matcher, tcp_msg_type_ssh_kex);
        } else {
            uint8_t ssh_dir_bits = 0;
            if (protocols["ssh.client"]) {
                ssh_dir_bits |= static_cast<uint8_t>(flow_direction_selector::client);
            }
            if (protocols["ssh.server"]) {
                ssh_dir_bits |= static_cast<uint8_t>(flow_direction_selector::server);
            }
            select_ssh_direction = static_cast<flow_direction_selector>(ssh_dir_bits);
            if (select_ssh_direction != flow_direction_selector::none) {
                tcp.add_protocol(ssh_init_packet::matcher, tcp_msg_type_ssh);
                tcp.add_protocol(ssh_kex_init::matcher, tcp_msg_type_ssh_kex);
            }
        }
        if (protocols["smtp"] || protocols["all"]) {
            tcp.add_protocol(smtp_server::matcher, tcp_msg_type_smtp_server);
            select_smtp = true;
        }
        if (protocols["telnet"] || protocols["all"]) {
            select_telnet = true;
        }
        if (protocols["dcerpc"] || protocols["dcerpc.client"] || protocols["all"]) {
            tcp.add_protocol(dcerpc::low_ptype_matcher, tcp_msg_type_dcerpc_client);
            tcp.add_protocol(dcerpc::high_ptype_matcher, tcp_msg_type_dcerpc_client);
        }
        if (protocols["dcerpc"] || protocols["dcerpc.server"] || protocols["all"]) {
            tcp.add_protocol(dcerpc::low_ptype_matcher, tcp_msg_type_dcerpc_server);
            tcp.add_protocol(dcerpc::high_ptype_matcher, tcp_msg_type_dcerpc_server);
        }
        if (protocols["rfb"] || protocols["all"]) {
            select_rfb = true;
        }
        if (protocols["rdp"] || protocols["all"]) {
            select_rdp = true;
        }
        if(protocols["ftp"] || protocols["all"])
        {
            select_ftp_response = true;
            select_ftp_request = true;
        }
        else {
            if (protocols["ftp.response"]) {
                select_ftp_response = true;
                // tcp4.add_protocol(ftp::response::status_code_matcher, tcp_msg_type_ftp_response);
            }
            if (protocols["ftp.request"]) {
                select_ftp_request = true;
            }
        }
        if(protocols["imap"] || protocols["all"])
        {
            select_imap_request = true;
            select_imap_response = true;
        }
        else {
            if (protocols["imap.request"]) {
                select_imap_request = true;
            }
            if (protocols["imap.response"]) {
                select_imap_response = true;
            }
        }
        if (protocols["http"] || protocols["all"])
        {
            select_http_request = true;
            select_http_response = true;
        }
        else {
            if (protocols["http.request"]) {
                select_http_request = true;
            }
            if (protocols["http.response"]) {
                select_http_response = true;
            }
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
           select_krb5 = true;
        }
        if (protocols["snmp"] || protocols["all"]) {
            select_snmp = true;
        }
        if (protocols["tcp.message"] || protocols["all"]) {
            // select_tcp_syn = 0;
            // tcp_message_filter_cutoff = 1;
        }
        if (protocols["tcp.syn_ack"] || protocols["all"]) {
            select_tcp_syn_ack = true;
        }
        if (protocols["dhcp"] || protocols["all"]) {
            select_dhcp = true;
        }
        if (protocols["syslog"] || protocols["all"]) {
            select_syslog = true;
        }
        if (protocols["redis"] || protocols["all"]) {
            select_redis_request = true;
            select_redis_response = true;
        }
        else {
            if (protocols["redis.request"]) {
                select_redis_request = true;
            }
            if (protocols["redis.response"]) {
                select_redis_response = true;
            }
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
            udp16.add_protocol(dtls_hello_verify_request::dtls_matcher, udp_msg_type_dtls_hello_verify_request);
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

        if (protocols["tofsee"] || protocols["all"]) {
            select_tofsee = true;
        }

        if (protocols["geneve"] || protocols["all"]) {
            select_geneve = true;
        }

        if (protocols["vxlan"] || protocols["all"]) {
            select_vxlan = true;
        }

        if (protocols["pgsql"] || protocols["all"]) {
            select_pgsql = true;
        }

        // tell protocol_identification objects to compile lookup tables
        tcp4.compile();
        tcp.compile();
        udp4.compile();
        udp.compile();
        udp16.compile();

    }

    const tcp_msg_types& get_tcp_msg_type_from_keyword(datum pkt) const {
        if (pkt.length() < 4) {
            return tcp_keyword_matcher::unknown_type;
        }

        encoded<uint32_t> keyword{pkt};
        return tcp_keyword_matcher::get_tcp_msg_type_from_keyword(keyword.value());
    }

    ///
    /// \brief Report whether a keyword-matched TCP type is enabled by the
    ///        current selection policy.
    ///
    /// This is the single gating authority for keyword-matched TCP types.
    /// The keyword map is not gated by selection, so set_tcp_protocol()
    /// consults this before attempting a keyword candidate.
    ///
    /// \invariant Every tcp_msg_type that can appear as a value in
    ///            tcp_keyword_matcher::tcp_keyword_map must have a case here;
    ///            any type not listed returns \c false and is silently
    ///            skipped.  Keep this switch in sync with that map (see
    ///            get_tcp_msg_type_from_keyword()).
    ///
    /// \param type  the keyword-matched TCP message type to test.
    /// \return \c true if the protocol identified by \p type is enabled in the
    ///         current selection policy, \c false otherwise.
    ///
    bool keyword_type_enabled(tcp_msg_type type) const {
        switch (type) {
        case tcp_msg_type_http_request:  return http_request();
        case tcp_msg_type_http_response: return http_response();
        case tcp_msg_type_ftp_request:   return ftp_request();
        case tcp_msg_type_smtp_client:   return smtp();
        case tcp_msg_type_redis_request: return redis_request();
        case tcp_msg_type_rfb:           return rfb();
        default:                         return false;
        }
    }

    /// enforces the invariant that every tcp_msg_type used as a value in
    /// tcp_keyword_matcher::tcp_keyword_map has an explicit case in
    /// keyword_type_enabled(); with all protocols enabled each must report
    /// enabled, otherwise a keyword-matched protocol is silently skipped.
    [[maybe_unused]] static bool unit_test() {
        traffic_selector ts{ { {"all", true} } };
        for (const auto &entry : tcp_keyword_matcher::tcp_keyword_map) {
            for (tcp_msg_type type : entry.second) {
                if (!ts.keyword_type_enabled(type)) {
                    return false;
                }
            }
        }
        return true;
    }

    tcp_msg_type get_tcp_msg_type_preference_from_port(const tcp_msg_types& protos,
                                                       struct tcp_packet *tcp_pkt) {
        if (protos.size() == 1) {
            return protos.front();
        }

        if (tcp_pkt == nullptr or tcp_pkt->header == nullptr) {
            return tcp_msg_type_unknown;
        }

        enum tcp_msg_type type = tcp_msg_type_unknown;
        switch(ntoh<uint16_t>(tcp_pkt->header->dst_port)) {
            case 21:
                type = tcp_msg_type_ftp_request;
                break;
            case 25:
                type =  tcp_msg_type_smtp_client;
                break;
            case 6379:
                type = tcp_msg_type_redis_request;
                break;
            default:
                break;
        }
        if (std::find(protos.begin(), protos.end(), type) != protos.end()) {
            return type;
        }
        return tcp_msg_type_unknown;
    }

    ///
    /// \brief Identify a TCP message type across the chained matcher lists,
    ///        resumably.
    ///
    /// Iterates the chained TCP mask/value matcher lists (\c tcp then \c tcp4)
    /// as a single virtual list, returning the matched type and the index to
    /// resume from on the next call.  Used by set_tcp_protocol() to fall
    /// through to the next candidate matcher when a protocol parse fails.
    ///
    /// \param pkt    packet datum to match against (read-only).
    /// \param start  virtual index to resume scanning from (0 for a fresh
    ///               scan); a sentinel offset distinguishes \c tcp from
    ///               \c tcp4 indices.
    /// \return a match_result whose \c type is the matched TCP message type
    ///         (tcp_msg_type_unknown if none) and whose \c next_index is the
    ///         resume index (SIZE_MAX when no further candidates remain).
    ///
    match_result get_tcp_msg_type_resumable(const datum &pkt, size_t start) const {
        // Identifier boundary: indices [0, tcp4_base) address `tcp`,
        // indices >= tcp4_base address `tcp4`. `tcp4_base` is a sentinel offset
        // chosen large enough to never collide with a real matcher index
        // (i.e., larger than any possible index within `tcp`).
        constexpr size_t tcp4_base = (size_t{1} << 20);
        // the sentinel offset must exceed every index within `tcp`
        assert(tcp.size() < tcp4_base);

        if (start < tcp4_base) {
            auto r = tcp.get_msg_type_resumable(pkt, start);
            if (r.type != tcp_msg_type_unknown) {
                return { r.type, r.next_index };
            }
            start = tcp4_base;  // exhausted `tcp`, move on to `tcp4`
        }

        auto r = tcp4.get_msg_type_resumable(pkt, start - tcp4_base);
        if (r.type != tcp_msg_type_unknown) {
            return { r.type, tcp4_base + r.next_index };
        }
        return { tcp_msg_type_unknown, SIZE_MAX };
    }

    ///
    /// \brief Identify a UDP message type across the chained matcher lists,
    ///        resumably.
    ///
    /// Iterates the chained UDP mask/value matcher lists (\c udp, then
    /// \c udp16, then \c udp4) as a single virtual list, returning the matched
    /// type and the index to resume from on the next call.  Used by
    /// set_udp_protocol() to fall through to the next candidate matcher when a
    /// protocol parse fails.  The ESP/IKE-over-UDP and port-based fallbacks
    /// are handled separately by the caller.
    ///
    /// \param pkt    packet datum to match against (read-only).
    /// \param start  virtual index to resume scanning from (0 for a fresh
    ///               scan); sentinel offsets distinguish \c udp, \c udp16, and
    ///               \c udp4 indices.
    /// \return a match_result whose \c type is the matched UDP message type
    ///         (udp_msg_type_unknown if none) and whose \c next_index is the
    ///         resume index (SIZE_MAX when no further mask/value candidates
    ///         remain).
    ///
    match_result get_udp_msg_type_resumable(const datum &pkt, size_t start) const {
        constexpr size_t udp16_base = (size_t{1} << 20);
        constexpr size_t udp4_base  = (size_t{2} << 20);
        // each sentinel offset must exceed every index within its list
        assert(udp.size() < udp16_base);
        assert(udp16.size() < udp4_base - udp16_base);

        if (start < udp16_base) {
            auto r = udp.get_msg_type_resumable(pkt, start);
            if (r.type != udp_msg_type_unknown) {
                return { r.type, r.next_index };
            }
            start = udp16_base;
        }
        if (start < udp4_base) {
            auto r = udp16.get_msg_type_resumable(pkt, start - udp16_base);
            if (r.type != udp_msg_type_unknown) {
                return { r.type, udp16_base + r.next_index };
            }
            start = udp4_base;
        }

        auto r = udp4.get_msg_type_resumable(pkt, start - udp4_base);
        if (r.type != udp_msg_type_unknown) {
            return { r.type, udp4_base + r.next_index };
        }
        return { udp_msg_type_unknown, SIZE_MAX };
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

        if (snmp() and (ports.src == hton<uint16_t>(161) or ports.src == hton<uint16_t>(162)
                        or ports.dst == hton<uint16_t>(161) or ports.dst == hton<uint16_t>(162)) ) {
            return udp_msg_type_snmp;
        }

        if (syslog() and (ports.dst == hton<uint16_t>(514))) {
            return udp_msg_type_syslog;
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

        if (dhcp() and (ports.dst == hton<uint16_t>(67) or ports.dst == hton<uint16_t>(68))) {
            return udp_msg_type_dhcp;
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

        if (tacacs() and (tcp_pkt->header->src_port == hton<uint16_t>(49) or tcp_pkt->header->dst_port == hton<uint16_t>(49)) ) {
            return tcp_msg_type_tacacs;
        }

        if (rdp() and (tcp_pkt->header->src_port == hton<uint16_t>(3389) or tcp_pkt->header->dst_port == hton<uint16_t>(3389)) ) {
            return tcp_msg_type_rdp;
        }

        if (mysql_login_request() and ( (tcp_pkt->header->src_port == hton<uint16_t>(3306)) || (tcp_pkt->header->dst_port == hton<uint16_t>(3306)) ) ) {
            return tcp_msg_type_mysql_login_request;
        }

        if (krb5() and (tcp_pkt->header->src_port == hton<uint16_t>(88) or tcp_pkt->header->dst_port == hton<uint16_t>(88))) {
            return tcp_msg_type_krb5;
        }

        if (redis_request() and (tcp_pkt->header->dst_port == hton<uint16_t>(6379))) {
            return tcp_msg_type_redis_request;
        }

        if (redis_response() and (tcp_pkt->header->src_port == hton<uint16_t>(6379))) {
            return tcp_msg_type_redis_response;
        }

        if (imap_request() and (tcp_pkt->header->dst_port == hton<uint16_t>(143))) {
            return tcp_msg_type_imap_request;
        }

        if (imap_response() and (tcp_pkt->header->src_port == hton<uint16_t>(143))) {
            return tcp_msg_type_imap_response;
        }

        if (telnet() and (tcp_pkt->header->src_port == hton<uint16_t>(23) or tcp_pkt->header->dst_port == hton<uint16_t>(23))) {
            return tcp_msg_type_telnet;
        }

        if (pgsql() and (tcp_pkt->header->src_port == hton<uint16_t>(5432) or tcp_pkt->header->dst_port == hton<uint16_t>(5432))) {
            return tcp_msg_type_pgsql;
        }

        return tcp_msg_type_unknown;
    }

};

#endif /* PROTO_IDENTIFY_H */
