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
#include "event.hpp"
#include "linux_sll2.hpp"

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
#include "snmp.hpp"
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
#include "syslog.hpp"
#include "redis.hpp"
#include "imap.hpp"
#include "telnet.hpp"
#include "pgsql.hpp"
#include "cbor_messages.hpp"
#include "metadata_writer.hpp"
#include "dcerpc.hpp"

// double malware_prob_threshold = -1.0; // TODO: document hidden option

void write_flow_key(struct json_object &o, const struct key &k) {
    k.write_ip_address(o);

    o.print_key_uint8("protocol", k.protocol);
    o.print_key_uint16("src_port", k.src_port);
    o.print_key_uint16("dst_port", k.dst_port);

    // o.b->snprintf(",\"flowhash\":\"%016lx\"", std::hash<struct key>{}(k));
}

// shared no-op writer for the assess-only path (no CBOR/JSON output requested).
// A real object so the feature visitors can bind output_ by reference.
static null_object no_output;

template<typename Object>
struct do_crypto_assessment {
    static_assert(has_array_type_v<Object>,
                  "do_crypto_assessment Object must be a metadata writer "
                  "(json_object / cbor_object / null_object)");
    using Array = typename Object::array_type;

    const std::vector<crypto_policy::assessor *>& ca;   // elements non-const: emit/fill mutate them
    Object &output_;

    do_crypto_assessment(const std::vector<crypto_policy::assessor *>& ca_,
                         Object& output)
        : ca{ca_}, output_{output} {}

    // One assessment pass, protocol-agnostic. Emitting modes (json_object / cbor_object) run the
    // FILL path (each policy populates its own message) then emit; NO_OUTPUT (null_object) runs
    // the compliance-only path and populates/writes nothing.
    template<typename MsgType>
    crypto_assess_result assess_impl(const MsgType &msg) {
        crypto_assess_result result;
        if constexpr (is_emitting_writer_v<Object>) {
            for (auto* assessor : ca) {
                assessor->reset_output();   // clear stale owned message before (maybe defaulted) fill
                result.set(assessor->get_result_idx(), !assessor->assess(msg));
            }
            if constexpr (std::is_same_v<Object, json_object>) {
                Array assessor_record{output_, "cryptographic_security_assessment"};
                for (auto* assessor : ca) { assessor->emit(assessor_record); }
                assessor_record.close();
            } else {
                for (auto* assessor : ca) { assessor->emit(output_); }
            }
        } else {
            for (const auto* assessor : ca) {
                result.set(assessor->get_result_idx(), !assessor->assess(msg));
            }
        }
        return result;
    }

    crypto_assess_result operator()(const tls_client_hello &msg) { return assess_impl(msg); }
    crypto_assess_result operator()(const tls_server_hello &msg) { return assess_impl(msg); }
    crypto_assess_result operator()(const tls_server_hello_and_certificate &msg) { return assess_impl(msg); }
    crypto_assess_result operator()(const dtls_client_hello &msg) { return assess_impl(msg); }
    crypto_assess_result operator()(const dtls_server_hello &msg) { return assess_impl(msg); }

    crypto_assess_result operator()(const quic_init &msg) {
        if (msg.has_tls()) { return assess_impl(msg.get_tls_client_hello()); }
        return crypto_assess_result{};
    }

    crypto_assess_result operator()(const ssh_init_packet &msg) {
        if (msg.kex_pkt.is_not_empty()) { return assess_impl(msg.kex_pkt); }
        return crypto_assess_result{};
    }

    crypto_assess_result operator()(const ssh_kex_init &msg) {
        if (msg.is_not_empty()) { return assess_impl(msg); }
        return crypto_assess_result{};
    }

    template <typename T>
    crypto_assess_result operator()(const T &) { return crypto_assess_result{}; }

    crypto_assess_result operator()(std::monostate &) { return crypto_assess_result{}; }
};

template<typename Object>
struct check_exposed_creds {
    static_assert(has_array_type_v<Object>,
                  "check_exposed_creds Object must be a metadata writer");
    Object &output_;

    explicit check_exposed_creds(Object &out) : output_{out} {}

    // true only when output_ is a real writer. Gating each arm on this lets the
    // arg evaluation (auth-method/username accessors, which parse) be skipped by
    // short-circuit when no CBOR/JSON output is requested.
    static constexpr bool emitting() { return is_emitting_writer_v<Object>; }

    void write_feature(exposed_creds_type type, datum protocol,
                       datum auth_method, datum username) {
        // The assess-only path binds output_ to the null_object sentinel, so emission is
        // gated on the writer type.
        if constexpr (is_emitting_writer_v<Object>) {
            const char* key = nullptr;
            switch (type) {
            case exposed_creds_type::plaintext_password:
                key = exposed_creds_message::KEY_PLAINTEXT; break;
            case exposed_creds_type::plaintext_token:
                key = exposed_creds_message::KEY_TOKEN; break;
            case exposed_creds_type::password_derived:
                key = exposed_creds_message::KEY_DERIVED; break;
            default:
                return;
            }
            exposed_creds_message::construct(key, protocol, auth_method, username)
                .template write<Object>(output_);
        }
    }

    exposed_creds_type operator()(const imap::imap_requests &msg) {
        exposed_creds_type type = msg.check_credential_exposure();
        if (type != exposed_creds_type::none && emitting()) {
            write_feature(type, datum{"imap"}, msg.get_auth_method(), msg.get_username());
        }
        return type;
    }

    exposed_creds_type operator()(const http_request &msg) {
        exposed_creds_type type = msg.check_credential_exposure();
        if (type != exposed_creds_type::none && emitting()) {
            datum auth_hdr = msg.get_header("authorization");
            datum scheme_datum = authorization{auth_hdr}.get_scheme();
            write_feature(type, datum{"http"}, scheme_datum, datum{});
        }
        return type;
    }

    exposed_creds_type operator()(const tacacs::packet &msg) {
        exposed_creds_type type = msg.check_credential_exposure();
        if (type != exposed_creds_type::none && emitting()) {
            write_feature(type, datum{"tacacs"}, msg.get_auth_method(), msg.get_username());
        }
        return type;
    }

    exposed_creds_type operator()(const ldap::message &msg) {
        exposed_creds_type type = msg.check_credential_exposure();
        if (type != exposed_creds_type::none && emitting()) {
            write_feature(type, datum{"ldap"}, msg.get_auth_method(), datum{});
        }
        return type;
    }

    exposed_creds_type operator()(const ftp::request &msg) {
        exposed_creds_type type = msg.check_credential_exposure();
        if (type != exposed_creds_type::none && emitting()) {
            write_feature(type, datum{"ftp"}, datum{"PASS"}, datum{});
        }
        return type;
    }

    exposed_creds_type operator()(const redis::request &msg) {
        exposed_creds_type type = msg.check_credential_exposure();
        if (type != exposed_creds_type::none && emitting()) {
            write_feature(type, datum{"redis"}, datum{"AUTH"}, msg.get_username());
        }
        return type;
    }

    exposed_creds_type operator()(const snmp::packet &msg) {
        exposed_creds_type type = msg.check_credential_exposure();
        if (type != exposed_creds_type::none && emitting()) {
            write_feature(type, datum{"snmp"}, msg.get_auth_method(), datum{});
        }
        return type;
    }

    exposed_creds_type operator()(const pgsql_msg &msg) {
        exposed_creds_type type = msg.check_credential_exposure();
        if (type != exposed_creds_type::none && emitting()) {
            // pgsql PasswordMessage carries no username (it is in the earlier
            // StartupMessage); the auth method is implied by the detection type.
            datum auth_method = (type == exposed_creds_type::password_derived)
                                    ? datum{"md5"} : datum{"password"};
            write_feature(type, datum{"pgsql"}, auth_method, datum{});
        }
        return type;
    }

    template <typename T>
    exposed_creds_type operator()(const T &) {
        return exposed_creds_type::none;
    }

    exposed_creds_type operator()(std::monostate &) { return exposed_creds_type::none; }
};

struct do_observation {
    const struct key &k_;
    struct analysis_context &analysis_;
    class message_queue<event_msg> *mq_;

    do_observation(const struct key &k,
                   struct analysis_context &analysis,
                   class message_queue<event_msg> *mq) :
        k_{k},
        analysis_{analysis},
        mq_{mq}
    {}

    void operator()(tls_client_hello &) {
        // create event and send it to the data/stats aggregator
        mq_->push(event_string::construct_event_string(k_, analysis_));
    }

    void operator()(dtls_client_hello &) {
        // create event and send it to the data/stats aggregator
        mq_->push(event_string::construct_event_string(k_, analysis_));
    }

    void operator()(quic_init &) {
        // create event and send it to the data/stats aggregator
        mq_->push(event_string::construct_event_string(k_, analysis_));
    }

    void operator()(tofsee_initial_message &) {
        // create event and send it to the data/stats aggregator
        mq_->push(event_string::construct_event_string_tofsee(k_, analysis_));
    }

    void operator()(http_request &) {
        // create event and send it to the data/stats aggregator
        mq_->push(event_string::construct_event_string(k_, analysis_));
    }

    void operator()(stun::message &) {
        // create event and send it to the data/stats aggregator
        mq_->push(event_string::construct_event_string(k_, analysis_));
    }

    void operator()(ssh_init_packet &) {
        // create event and send it to the data/stats aggregator
        mq_->push(event_string::construct_event_string(k_, analysis_));
    }

    template <typename T>
    void operator()(T &) { }

};

struct do_cert_label_observation {
    const struct key &k_;
    class message_queue<event_msg> *mq_;

    do_cert_label_observation(const struct key &k,
                              class message_queue<event_msg> *mq) :
        k_{k},
        mq_{mq}
    {}

    void operator()(tls_server_hello_and_certificate &msg) {
        std::string common_name;
        if (msg.get_subject_common_name(common_name) && !common_name.empty()) {
            mq_->push(event_string::construct_cert_label_event(k_, common_name));
        }
    }

    void operator()(tls_certificate &msg) {
        std::string common_name;
        if (msg.get_subject_common_name(common_name) && !common_name.empty()) {
            mq_->push(event_string::construct_cert_label_event(k_, common_name));
        }
    }

    template <typename T>
    void operator()(T &) { }

    void operator()(std::monostate &) { }
};

struct do_snmp_oid_observation {
    const struct key &k_;
    class message_queue<event_msg> *mq_;

    do_snmp_oid_observation(const struct key &k,
                            class message_queue<event_msg> *mq) :
        k_{k},
        mq_{mq}
    {}

    /// Construct an SNMP OID event for each OID in msg by passing in a lambda
    /// function that constructs the event and then pushes it onto mq_.
    ///
    void operator()(snmp::packet &msg) {
        msg.for_each_var_bind_oid([&](const std::string &oid) {
            if (!oid.empty()) {
                mq_->push(event_string::construct_snmp_oid_event(k_, oid));
            }
        });
    }

    template <typename T>
    void operator()(T &) { }

    void operator()(std::monostate &) { }
};

///
/// \brief Construct a protocol parser in a variant, keeping it only if it
///        parsed successfully.
///
/// Constructs a protocol parser of type \c T in the variant \p x, validates
/// that the parse succeeded via is_not_empty(), and on failure resets \p x to
/// std::monostate.  This is the parse-success oracle used by the multi-pass
/// fallback logic: a \c false return tells the caller to restore the packet
/// datum and try the next candidate.  Protocols that require reassembly (TLS
/// client/server hello, TLS certificate, SSH, DTLS client hello) are handled
/// by their own cases, not this helper, since a not-yet-complete parse is a
/// valid classification for them.
///
/// \tparam T     the protocol parser type to construct.
/// \tparam Args  constructor argument types forwarded to \c T.
/// \param x      the protocol variant to emplace into.
/// \param args   arguments forwarded to the \c T constructor.
/// \return \c true if the parse succeeded, or \c false if it failed (in which
///         case \p x is left as std::monostate).
///
template <typename T, typename... Args>
static bool emplace_protocol_if_not_empty(protocol &x, Args&&... args) {
    T &proto = x.emplace<T>(std::forward<Args>(args)...);
    if (!proto.is_not_empty()) {
        x.emplace<std::monostate>();
        return false;
    }
    return true;
}

///
/// \brief Attempt to parse a TCP data field as a specific protocol.
///
/// Attempts to parse \p pkt as the protocol identified by \p msg_type,
/// committing the result to \p x on success.  On parse failure it leaves
/// \p x as std::monostate, so the caller can restore the packet datum and try
/// the next candidate.  Protocols that request reassembly (TLS client hello,
/// SSH) are treated as a successful classification.  \p pkt is
/// consumed/advanced exactly as in the original single-pass implementation;
/// the caller is responsible for restoring it before any retry.
///
/// \param x         the protocol variant to commit a successful parse into.
/// \param pkt       the TCP data field to parse (advanced during parsing).
/// \param msg_type  the candidate protocol message type to attempt.
/// \param tcp_pkt   the enclosing TCP packet, used to drive reassembly
///                  requests; may be \c nullptr.
/// \return \c true if the protocol parsed successfully (or requested
///         reassembly), \c false otherwise.
///
bool stateful_pkt_proc::try_parse_tcp_type(protocol &x,
                                           struct datum &pkt,
                                           tcp_msg_type msg_type,
                                           struct tcp_packet *tcp_pkt) {
    switch(msg_type) {
    case tcp_msg_type_tls_client_hello:
        {
            struct tls_record rec{pkt};
            struct tls_handshake handshake{rec.fragment};
            tls_client_hello &proto = x.emplace<tls_client_hello>(handshake.body);
            if (tcp_pkt && handshake.additional_bytes_needed) {
                tcp_pkt->reassembly_needed(handshake.additional_bytes_needed);
                // Reassembly required: commit the (possibly partial) hello so
                // the segment can seed reassembly, and skip the is_not_empty()
                // parse-success check.
                return true;
            }
            if (!proto.is_not_empty()) {
                x.emplace<std::monostate>();
                return false;
            }
            return true;
        }
    case tcp_msg_type_tls_server_hello:
        {
            tls_server_hello_and_certificate &proto = x.emplace<tls_server_hello_and_certificate>(pkt, tcp_pkt);
            if (proto.additional_bytes_needed()) {
                return true;
            }
            if (!proto.is_not_empty()) {
                x.emplace<std::monostate>();
                return false;
            }
            return true;
        }
    case tcp_msg_type_tls_certificate:
        {
            tls_certificate &proto = x.emplace<tls_certificate>(pkt, tcp_pkt);
            if (proto.additional_bytes_needed()) {
                return true;
            }
            if (!proto.is_not_empty()) {
                x.emplace<std::monostate>();
                return false;
            }
            return true;
        }
    case tcp_msg_type_ssh:
        if (tcp_pkt) {
            if (!(selector.ssh_direction() & tcp_pkt->get_direction_from_ports())) {
                return false;
            }
        }
        {
            ssh_init_packet &proto = x.emplace<ssh_init_packet>(pkt, tcp_pkt ? tcp_pkt->get_direction_from_ports() : flow_direction::unknown);
            uint32_t more_bytes = proto.more_bytes_needed();
            if (tcp_pkt && more_bytes) {
                tcp_pkt->reassembly_needed(more_bytes,(uint8_t)reassembly_type::ssh);
                return true;
            }
            if (!proto.is_not_empty()) {
                x.emplace<std::monostate>();
                return false;
            }
            return true;
        }
    case tcp_msg_type_ssh_kex:
        if (tcp_pkt) {
            if (!(selector.ssh_direction() & tcp_pkt->get_direction_from_ports())) {
                return false;
            }
        }
        {
            struct ssh_binary_packet ssh_pkt{pkt};
            ssh_kex_init &proto = x.emplace<ssh_kex_init>(ssh_pkt, tcp_pkt ? tcp_pkt->get_direction_from_ports() : flow_direction::unknown);
            if (tcp_pkt && ssh_pkt.additional_bytes_needed) {
                tcp_pkt->reassembly_needed((uint32_t)ssh_pkt.additional_bytes_needed);
                return true;
            }
            else if (tcp_pkt) {
                tcp_pkt->set_supplementary_reassembly();
                return true;
            }
            if (!proto.is_not_empty()) {
                x.emplace<std::monostate>();
                return false;
            }
            return true;
        }
    case tcp_msg_type_smtp_server:
        return emplace_protocol_if_not_empty<smtp_server>(x, pkt);
    case tcp_msg_type_tacacs:
        return emplace_protocol_if_not_empty<tacacs::packet>(x, pkt);
    case tcp_msg_type_rdp:
        return emplace_protocol_if_not_empty<rdp::connection_request_pdu>(x, pkt);
    case tcp_msg_type_dns:
    {
        /* Trim the 2 byte length field in case of
         * dns over tcp.
         */
        uint16_t len = 0;
        pkt.read_uint16(&len);
        pkt.trim_to_length(len);
        return emplace_protocol_if_not_empty<dns_packet>(x, pkt);
    }
    case tcp_msg_type_smb1:
        return emplace_protocol_if_not_empty<smb1_packet>(x, pkt);
    case tcp_msg_type_smb2:
        return emplace_protocol_if_not_empty<smb2_packet>(x, pkt);
    case tcp_msg_type_iec:
        return emplace_protocol_if_not_empty<iec60870_5_104>(x, pkt);
    case tcp_msg_type_dnp3:
        return emplace_protocol_if_not_empty<dnp3>(x, pkt);
    case tcp_msg_type_nbss:
        return emplace_protocol_if_not_empty<nbss_packet>(x, pkt);
    case tcp_msg_type_openvpn:
        return emplace_protocol_if_not_empty<openvpn_tcp>(x, pkt);
    case tcp_msg_type_bittorrent:
        return emplace_protocol_if_not_empty<bittorrent_handshake>(x, pkt);
    case tcp_msg_type_mysql_server:
        return emplace_protocol_if_not_empty<mysql_server_greet>(x, pkt);
    case tcp_msg_type_mysql_login_request:
        return emplace_protocol_if_not_empty<mysql_login_request>(x, pkt);
    case tcp_msg_type_tofsee_initial_message:
        return emplace_protocol_if_not_empty<tofsee_initial_message>(x, pkt);
    case tcp_msg_type_socks4:
        return emplace_protocol_if_not_empty<socks4_req>(x, pkt);
    case tcp_msg_type_socks5_hello:
        return emplace_protocol_if_not_empty<socks5_hello>(x, pkt);
    case tcp_msg_type_socks5_req_resp:
        return emplace_protocol_if_not_empty<socks5_req_resp>(x, pkt);
    case tcp_msg_type_ldap:
        return emplace_protocol_if_not_empty<ldap::message>(x, pkt);
    case tcp_msg_type_ftp_request:
        return emplace_protocol_if_not_empty<ftp::request>(x, pkt);
    case tcp_msg_type_ftp_response:
        return emplace_protocol_if_not_empty<ftp::response>(x, pkt);
    case tcp_msg_type_krb5:
        return emplace_protocol_if_not_empty<krb5::packet>(x, pkt);  // tcp record marker detected in constructor
    case tcp_msg_type_imap_request:
        return emplace_protocol_if_not_empty<imap::imap_requests>(x, pkt);
    case tcp_msg_type_imap_response:
        return emplace_protocol_if_not_empty<imap::imap_responses>(x, pkt);
    case tcp_msg_type_redis_response:
        return emplace_protocol_if_not_empty<redis::response>(x, pkt);
    case tcp_msg_type_redis_request:
        return emplace_protocol_if_not_empty<redis::request>(x, pkt);
    case tcp_msg_type_http_request:
        return emplace_protocol_if_not_empty<http_request>(x, pkt);
    case tcp_msg_type_http_response:
        return emplace_protocol_if_not_empty<http_response>(x, pkt);
    case tcp_msg_type_smtp_client:
        return emplace_protocol_if_not_empty<smtp_client>(x, pkt);
    case tcp_msg_type_rfb:
        return emplace_protocol_if_not_empty<rfb::protocol_version_handshake>(x, pkt);
    case tcp_msg_type_telnet:
        return emplace_protocol_if_not_empty<telnet::message>(x, pkt);
    case tcp_msg_type_pgsql:
        if (tcp_pkt == nullptr || tcp_pkt->header == nullptr) {
            return false;   // src_port unavailable; let fallback continue
        }
        return emplace_protocol_if_not_empty<pgsql_msg>(x, pkt, tcp_pkt->header->src_port);
    case tcp_msg_type_dcerpc:
        {
            dcerpc::message &proto = x.emplace<dcerpc::message>(pkt);
            if (!proto.is_not_empty() || !(selector.dcerpc_direction() &
                  (proto.is_client() ? flow_direction::client : flow_direction::server))) {
                x.emplace<std::monostate>();
                return false;
            }
            return true;
        }
    default:
        return false;
    }
}

///
/// \brief Identify and parse the TCP data field, applying multi-pass fallback.
///
/// Sets the protocol variant record \p x to the data structure resulting from
/// parsing the TCP data field, which will be one of the TCP protocols in that
/// variant.  A default value of std::monostate indicates that the protocol
/// matcher did not recognize, or could not parse, the packet.  The class
/// unknown_initial_packet represents the TCP data field of an unrecognized
/// packet that is the first data packet in a flow.
///
/// Multi-pass fallback: when a matcher matches but the protocol parse fails,
/// detection resumes from the next candidate rather than dropping the packet.
/// \p pkt is a non-owning {data, data_end} cursor over immutable packet
/// memory, so it is snapshotted (a 16-byte copy, no allocation) and restored
/// before each parse attempt.
///
/// \param x        the protocol variant to populate with the parsed result.
/// \param pkt      the TCP data field to identify and parse.
/// \param is_new   true if this is the first data packet in the flow.
/// \param tcp_pkt  the enclosing TCP packet, used for port heuristics and
///                 reassembly; may be \c nullptr.
///
void stateful_pkt_proc::set_tcp_protocol(protocol &x,
                                         struct datum &pkt,
                                         bool is_new,
                                         struct tcp_packet *tcp_pkt) {

    // note: std::get<T>() throws exceptions; it might be better to
    // use get_if<T>(), which does not

    const datum pkt_saved = pkt;   // intact snapshot (two pointers)

    auto attempt = [&](tcp_msg_type type) -> bool {
        x.emplace<std::monostate>();   // clear any stale state from a prior attempt
        pkt = pkt_saved;               // restore cursor before each parse
        return try_parse_tcp_type(x, pkt, type, tcp_pkt);
    };

    // Pass 1: mask/value matchers, resuming from the matcher after a failed parse
    for (size_t idx = 0; idx < SIZE_MAX; ) {
        auto mr = selector.get_tcp_msg_type_resumable(pkt_saved, idx);
        if (mr.type == tcp_msg_type_unknown) {
            break;                 // no more mask/value candidates
        }
        if (attempt((tcp_msg_type) mr.type)) {
            return;
        }
        idx = mr.next_index;       // resume at the matcher after the failed one
    }

    // Pass 2: port-based fallback
    enum tcp_msg_type port_type = (tcp_msg_type) selector.get_tcp_msg_type_from_ports(tcp_pkt);
    if (port_type != tcp_msg_type_unknown && attempt(port_type)) {
        return;
    }

    // Pass 3: keyword matcher (may yield several candidate types).  Keyword
    // candidates are only attempted if the corresponding protocol is enabled
    // in the selector, since the keyword map is not gated by selection.  The
    // gating lives in traffic_selector::keyword_type_enabled(), co-located
    // with the keyword map it guards (single source of truth).
    {
        const tcp_msg_types &protos = selector.get_tcp_msg_type_from_keyword(pkt_saved);
        if (protos.front() != tcp_msg_type_unknown) {
            tcp_msg_type preferred = selector.get_tcp_msg_type_preference_from_port(protos, tcp_pkt);
            if (preferred != tcp_msg_type_unknown && selector.keyword_type_enabled(preferred) && attempt(preferred)) {
                return;
            }
            for (const auto type : protos) {
                if (type == preferred) {
                    continue;
                }
                if (selector.keyword_type_enabled(type) && attempt(type)) {
                    return;
                }
            }
        }
    }

    // Pass 4: tofsee length heuristic
    if (selector.tofsee() && pkt_saved.length() == tofsee_initial_message::pkt_length
        && attempt(tcp_msg_type_tofsee_initial_message)) {
        return;
    }

    // No candidate parsed: emit unknown-initial or monostate (unchanged)
    pkt = pkt_saved;
    if (is_new && global_vars.output_tcp_initial_data) {
        x.emplace<unknown_initial_packet>(pkt);
    } else {
        x.emplace<std::monostate>();
    }
}

///
/// \brief Attempt to parse a UDP data field as a specific protocol.
///
/// Attempts to parse \p pkt as the UDP protocol identified by \p msg_type,
/// committing to \p x on success.  On failure it leaves \p x as
/// std::monostate so the caller can restore the packet datum and try the next
/// candidate.  \p pkt is consumed as in the original single-pass
/// implementation; the caller restores it before retries.
///
/// \param x         the protocol variant to commit a successful parse into.
/// \param pkt       the UDP data field to parse (advanced during parsing).
/// \param msg_type  the candidate UDP protocol message type to attempt.
/// \param k         the flow key, used to disambiguate DNS vs mDNS/NBNS.
/// \return \c true if the protocol parsed successfully, \c false otherwise.
///
bool stateful_pkt_proc::try_parse_udp_type(protocol &x,
                                           struct datum &pkt,
                                           udp_msg_type msg_type,
                                           const struct key& k) {
    switch(msg_type) {
    case udp_msg_type_dns:
        if (mdns_packet::check_if_mdns(k)) {
            if (!selector.mdns()) {
                return false;
            }
            return emplace_protocol_if_not_empty<mdns_packet>(x, pkt);
        } else {
            dns_packet packet{pkt};
            if (!packet.is_not_empty()) {
                return false;
            }
            if ((packet.netbios() and !selector.nbns()) or
                (!packet.netbios() and !selector.dns())) {
                return false;
            }
            x = std::move(packet);
            return true;
        }
    case udp_msg_type_syslog:
        return emplace_protocol_if_not_empty<syslog>(x, pkt);
    case udp_msg_type_dhcp:
        return emplace_protocol_if_not_empty<dhcp_message>(x, pkt);
    case udp_msg_type_quic:
        // QUIC uses its own CRYPTO-frame reassembly helper, not the offset trait.
        return emplace_protocol_if_not_empty<quic_init>(x, pkt, quic_crypto);
    case udp_msg_type_dtls_client_hello:
        {
            // Retain the object if it is a complete ClientHello, a first
            // fragment (offset 0, needs more bytes), or a non-first fragment
            // (offset > 0, reports neither signal but is still required to
            // drive offset-based UDP reassembly).  Only a mask-matched packet
            // that is none of these is dropped, so the fallback can continue.
            dtls_client_hello &proto = x.emplace<dtls_client_hello>(pkt);
            if (!proto.is_not_empty()
                && !proto.additional_bytes_needed()
                && proto.get_fragment_offset() == 0) {
                x.emplace<std::monostate>();
                return false;
            }
            return true;
        }
    case udp_msg_type_dtls_server_hello:
        return emplace_protocol_if_not_empty<dtls_server_hello>(x, pkt);
    case udp_msg_type_dtls_hello_verify_request:
        return emplace_protocol_if_not_empty<dtls_hello_verify_request>(x, pkt);
    case udp_msg_type_wireguard:
        return emplace_protocol_if_not_empty<wireguard_handshake_init>(x, pkt);
    case udp_msg_type_esp:
        return emplace_protocol_if_not_empty<esp>(x, pkt);
    case udp_msg_type_ike:
        return emplace_protocol_if_not_empty<ike::packet>(x, pkt);
    case udp_msg_type_ssdp:
        return emplace_protocol_if_not_empty<ssdp>(x, pkt);
    case udp_msg_type_stun:
        return emplace_protocol_if_not_empty<stun::message>(x, pkt);
    case udp_msg_type_nbds:
        return emplace_protocol_if_not_empty<nbds_packet>(x, pkt);
    case udp_msg_type_dht:
        return emplace_protocol_if_not_empty<bittorrent_dht>(x, pkt);
    case udp_msg_type_lsd:
        return emplace_protocol_if_not_empty<bittorrent_lsd>(x, pkt);
    case udp_msg_type_krb5:
        return emplace_protocol_if_not_empty<krb5::packet>(x, pkt);
    case udp_msg_type_snmp:
        return emplace_protocol_if_not_empty<snmp::packet>(x, pkt);
    case udp_msg_type_tftp:
        return emplace_protocol_if_not_empty<tftp::packet>(x, pkt);
    default:
        return false;
    }
}

///
/// \brief Identify and parse the UDP data field, applying multi-pass fallback.
///
/// Sets the protocol variant record \p x to the data structure resulting from
/// parsing the UDP data field, which will be one of the UDP protocols in that
/// variant.  A default value of std::monostate indicates that the protocol
/// matcher did not recognize, or could not parse, the packet.  The class
/// unknown_udp_initial_packet represents the UDP data field of an unrecognized
/// packet that is the first data packet in a flow.
///
/// Multi-pass fallback: when a matcher matches but the protocol parse fails,
/// detection resumes from the next candidate.  \p pkt is a non-owning cursor
/// over immutable packet memory, snapshotted and restored before each attempt.
///
/// \param x        the protocol variant to populate with the parsed result.
/// \param pkt      the UDP data field to identify and parse.
/// \param ports    the source/destination UDP ports, used for fallbacks.
/// \param is_new   true if this is the first data packet in the flow.
/// \param k        the flow key, used to disambiguate DNS vs mDNS/NBNS.
/// \param udp_pkt  the enclosing UDP packet (reassembly state propagated by
///                 the caller).
///
void stateful_pkt_proc::set_udp_protocol(protocol &x,
                      struct datum &pkt,
                      udp::ports ports,
                      bool is_new,
                      const struct key& k,
                      udp &udp_pkt) {
    (void)udp_pkt;  // additional_bytes_needed is propagated by the caller

    // note: std::get<T>() throws exceptions; it might be better to
    // use get_if<T>(), which does not

    const datum pkt_saved = pkt;   // intact snapshot (two pointers)

    auto attempt = [&](udp_msg_type type) -> bool {
        x.emplace<std::monostate>();   // clear any stale state from a prior attempt
        pkt = pkt_saved;               // restore cursor before each parse
        return try_parse_udp_type(x, pkt, type, k);
    };

    // ESP/IKE over UDP special case (port-driven), preserved from the original
    // get_udp_msg_type() pre-check.
    if (selector.ipsec() and ports.either_matches_any(esp_default_port)) {
        pkt = pkt_saved;
        udp_msg_type type = udp_msg_type_esp;
        if (lookahead<ike::non_esp_marker> non_esp{pkt}) {
            type = udp_msg_type_ike;
        }
        if (attempt(type)) {
            return;
        }
    }

    // Pass 1: mask/value matchers, resuming from the matcher after a failed parse
    for (size_t idx = 0; idx < SIZE_MAX; ) {
        auto mr = selector.get_udp_msg_type_resumable(pkt_saved, idx);
        if (mr.type == udp_msg_type_unknown) {
            break;                 // no more mask/value candidates
        }
        if (attempt((udp_msg_type) mr.type)) {
            return;
        }
        idx = mr.next_index;       // resume at the matcher after the failed one
    }

    // Pass 2: port-based fallback
    udp_msg_type port_type = selector.get_udp_msg_type_from_ports(ports);
    if (port_type != udp_msg_type_unknown && attempt(port_type)) {
        return;
    }

    // No candidate parsed: emit unknown-udp-initial or monostate (unchanged)
    pkt = pkt_saved;
    if (is_new) {
        x.emplace<unknown_udp_initial_packet>(pkt);
    } else {
        x.emplace<std::monostate>();
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
        // For FDC flows, the flows are not long-lived. Mercury typically
        // observes around 20 packets per flow, so any traffic seen again
        // after 30 seconds should be treated as a new flow.
        //
        // Packets are forwarded to Mercury only when it explicitly
        // signals that additional packets are required (`more_packets_needed`).
        // In such cases, the number of packets sent is capped at 20.
        //
        bool is_new = false;
        if (global_vars.output_tcp_initial_data) {
            if (tcp_pkt.is_synthetic_pkt()) {
                is_new = tcp_flow_table.is_first_synthetic_data_packet(k, ts->tv_sec);
            } else {
                is_new = tcp_flow_table.is_first_data_packet(k, ts->tv_sec, ntoh(tcp_pkt.header->seq));
            }
        }
        set_tcp_protocol(x, pkt, is_new, &tcp_pkt);
        return true;
    }

    bool is_new = false;
    if (global_vars.output_tcp_initial_data) {
        if (tcp_pkt.is_synthetic_pkt()) {
            is_new = tcp_flow_table.is_first_synthetic_data_packet(k, ts->tv_sec);
        } else {
            is_new = tcp_flow_table.is_first_data_packet(k, ts->tv_sec, ntoh(tcp_pkt.header->seq));
        }

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
        tcp_segment seg{true,tcp_pkt.data_length,tcp_pkt.seq(),tcp_pkt.additional_bytes_needed,(uint64_t)ts->tv_sec, (reassembly_type)tcp_pkt.indefinite_reassembly};
        reassembler->process_tcp_data_pkt(k,ts->tv_sec,seg,pkt_copy);
        reassembler->dump_pkt = true;
    }
    else if (r_state == reassembly_state::reassembly_progress){
        // continue reassembly
        if (!tcp_pkt.seq()) {
            // 0 seq number, inorder reassembly, seq = existing_data
            reassembly_map_iterator curr_flow = reassembler->get_current_flow();
            uint32_t tmp_seq = curr_flow->second.curr_contiguous_data;
            tcp_segment seg{false,tcp_pkt.data_length,tmp_seq,0,(uint64_t)ts->tv_sec, (reassembly_type)tcp_pkt.indefinite_reassembly};
            reassembler->process_tcp_data_pkt(k,ts->tv_sec,seg,pkt_copy);
            reassembler->dump_pkt = true;
        } else {
            tcp_segment seg{false,tcp_pkt.data_length,tcp_pkt.seq(),0,(uint64_t)ts->tv_sec, (reassembly_type)tcp_pkt.indefinite_reassembly};
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

// returns boolean whether to fingerprint/analyze the current udp pkt
bool stateful_pkt_proc::process_udp_data (protocol &x,
                          struct datum &pkt,
                          udp &udp_pkt,
                          struct key &k,
                          struct timespec *ts,
                          struct tcp_reassembler *reassembler) {

    // Core UDP packet identification and parsing.
    //
    // is_new is passed as false: no protocol parser currently consults it,
    // so there is no need to look up the flow table before parsing.  If a
    // future parser needs to know whether this is the first packet in the
    // flow, this code must be refactored to query ip_flow_table.flow_is_new()
    // before calling set_udp_protocol() and pass the result in here.
    //
    // has_payload is captured before parsing, which advances the pkt cursor.
    const bool has_payload = pkt.is_not_empty();
    set_udp_protocol(x, pkt, udp_pkt.get_ports(), /*is_new=*/false, k, udp_pkt);

    // Update UDP flow table, if applicable.
    if (global_vars.output_udp_initial_data) {
        bool is_new = false;
        // Exclude DNS from the flow table.  Due to the high volume of DNS
        // traffic, tracking DNS flows would fill the table too quickly.
        const dns_packet *dns = std::get_if<dns_packet>(&x);
        const bool is_dns = (dns != nullptr && !dns->netbios());
        // has_payload gate keeps empty UDP packets (e.g. scan traffic) from
        // flooding the flow table.
        if (has_payload && !is_dns) {
            is_new = ip_flow_table.flow_is_new(k, ts->tv_sec);
        }
        if (is_new && std::holds_alternative<std::monostate>(x)) {
            x.emplace<unknown_udp_initial_packet>(pkt);
        }
    }

    // Propagate the parser's additional_bytes_needed() onto udp_pkt, so
    // truncation is reported even when reassembly is disabled or skipped
    if (auto *qi = std::get_if<quic_init>(&x)) {
        if (uint32_t more = qi->additional_bytes_needed()) {
            udp_pkt.reassembly_needed(more);
        }
    } else {
        std::visit(check_additional_bytes_needed{udp_pkt}, x);
    }

    if (!reassembler || !global_vars.reassembly) {
        return true;
    }

    // QUIC: CRYPTO-frame sub-segmentation, separate from the offset trait.
    if (std::holds_alternative<quic_init>(x)) {
        if (udp_pkt.additional_bytes_needed() > reassembly_flow_context::max_data_size) {
            return true;
        }
        return process_quic_reassembly(std::get<quic_init>(x), udp_pkt, k, ts, reassembler);
    }

    if (!std::visit(supports_udp_offset_reassembly{}, x)) {
        return true;
    }
    return std::visit(dispatch_udp_offset_reassembly{k, ts, reassembler}, x);
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

// True for truncated TLS/QUIC/DTLS handshakes; gates crypto-assessment.
static inline bool is_truncated_crypto_handshake(const protocol &x,
                                                 bool truncated_tcp,
                                                 bool truncated_udp) {
    return (truncated_tcp &&
            (std::holds_alternative<tls_client_hello>(x) ||
             std::holds_alternative<tls_server_hello_and_certificate>(x)))
        || (truncated_udp &&
            (std::holds_alternative<quic_init>(x) ||
             std::holds_alternative<dtls_client_hello>(x)));
}

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
    bool truncated_udp = false;

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
            truncated_tcp = detect_truncation(tcp_pkt.additional_bytes_needed,
                                              reassembler);
        }

    } else if (transport_proto == ip::protocol::udp) {
        class udp udp_pkt{pkt};
        udp_pkt.set_key(k);

        bool udp_result = process_udp_data(x, pkt, udp_pkt, k, ts, reassembler);
        if (!udp_result) {
            return 0;
        }
        truncated_udp = detect_truncation(udp_pkt.additional_bytes_needed(),
                                          reassembler);
    }

    // process transport/application protocol
    //
    if (std::visit(is_not_empty{}, x)) {
        std::visit(compute_fingerprint{analysis.fp, global_vars.fp_format}, x);
        bool output_analysis = false;
        bool output_attr = false;
        bool truncated_crypto_handshake =
            is_truncated_crypto_handshake(x, truncated_tcp, truncated_udp);
        if (global_vars.do_analysis && analysis.fp.get_type() != fingerprint_type_unknown) {

            output_analysis = std::visit(do_analysis{k, analysis, c}, x);

            // note: we only perform observations when analysis is
            // configured, because we rely on do_analysis to set the

            // check for additional classifier agnostic attributes like encrypted dns and domain-faking
            //
            output_attr = (c && c->check_additional_attributes(analysis)) ? true : output_attr; // set to true only if any additional attribute is set, else keep the previous value

            // analysis_.destination
            //
            if (mq) {
                std::visit(do_observation{k, analysis, mq}, x);
            }
        }
        if (global_vars.do_analysis && mq) {
            if (ip_pkt.src_is_private()) {
                std::visit(do_cert_label_observation{k, mq}, x);
            }
            std::visit(do_snmp_oid_observation{k, mq}, x);
        }

        bool output_nbd = false;
        if (global_vars.network_behavioral_detections) {
            output_nbd = std::visit(do_network_behavioral_detections{k, analysis, c, attribute_common_data}, x);
        }


        // if (malware_prob_threshold > -1.0 && (!output_analysis || analysis.result.malware_prob < malware_prob_threshold)) { return 0; } // TODO - expose hidden command

        struct json_object record{&buf};
        if (analysis.fp.get_type() != fingerprint_type_unknown) {
            analysis.fp.write(record);
        }
        std::visit(write_metadata{record, global_vars.metadata_output, global_vars.certs_json_output, global_vars.dns_json_output}, x);

        if (!crypto_policies.empty() && !truncated_crypto_handshake) {
            crypto_assess_result assessment_result = std::visit(do_crypto_assessment{crypto_policies, record}, x);
            output_attr = set_crypto_assessment_attr(assessment_result) ? true : output_attr;
        }

        if (exposed_creds) {
            exposed_creds_type exposed_creds_ret = std::visit(check_exposed_creds{record}, x);
            output_attr = set_exposed_creds_attr(exposed_creds_ret) ? true : output_attr;
        }

        if (output_analysis || output_nbd || output_attr) {
            analysis.result.write_json(record, "analysis");
        }

//        if (output_nbd) {
//            nbd_analysis.write_json(record, "network_behavioral_detections");
//        }


        // write indication of truncation or reassembly
        //
        write_reassembly_properties(record,
                                    reassembler,
                                    truncated_tcp || truncated_udp,
                                    global_vars.reassembly);

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
    case LINKTYPE_LINUX_SLL2:
        linux_sll2::skip_to_ip(pkt);
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
        break;
    default:
        return 0;   // unsupported link layer type
    }

    if (pkt.is_null()) {
        return 0;   // decapsulation rejected a non-IP payload
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
    case fingerprint_type_ssh_server:
    case fingerprint_type_http_server:
    case fingerprint_type_tls_server:
    case fingerprint_type_dtls:
    case fingerprint_type_dtls_server:
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

    if (k == nullptr or payload == nullptr or buffer == nullptr or buffer_size == nullptr) {
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
            finalize_reassembly_flow(reassembler_ptr, analysis.flow_state_pkts_needed);
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
        //setting synthetic pkt to true to seed a synthetic SYN entry
        tcp_pkt.set_synthetic_pkt();

        struct tcp_reassembler *r =
            (reassembler_ptr && global_vars.reassembly && perform_reassembly)
            ? reassembler_ptr : nullptr;
        if (r) {
            analysis.flow_state_pkts_needed = false;
        }
        bool ret = process_tcp_data(x, pkt, tcp_pkt, k_, &ts, r);
        if (r && r->in_progress(r->curr_flow)) {
            analysis.flow_state_pkts_needed = true;
            return fdc_return::MORE_PACKETS_NEEDED;
        }
        if (!ret) {
            finalize_reassembly_flow(reassembler_ptr, analysis.flow_state_pkts_needed);
            return fdc_return::FDC_NO_DATA;
        }
        truncated_tcp = detect_truncation(tcp_pkt.additional_bytes_needed, r);

    } else if (k->protocol == ip::protocol::udp) {
        udp udp_pseudoheader{k_};
        struct tcp_reassembler *r =
            (reassembler_ptr && global_vars.reassembly && perform_reassembly)
            ? reassembler_ptr : nullptr;

        bool ret = process_udp_data(x, pkt, udp_pseudoheader, k_, &ts, r);
        if (r && r->in_progress(r->curr_flow)) {
            analysis.flow_state_pkts_needed = true;
            return fdc_return::MORE_PACKETS_NEEDED;
        }
        if (!ret) {
            finalize_reassembly_flow(reassembler_ptr, analysis.flow_state_pkts_needed);
            return fdc_return::FDC_NO_DATA;
        }
        truncated_udp = detect_truncation(udp_pseudoheader.additional_bytes_needed(), r);
    }

    analysis.reinit();

    if (std::visit(is_not_empty{}, x)) {
        std::visit(compute_fingerprint{analysis.fp, global_vars.fp_format}, x);
    }

    if (analysis.fp.get_type() == fingerprint_type_unknown && std::get_if<std::monostate>(&x) != nullptr) {
        finalize_reassembly_flow(reassembler_ptr, analysis.flow_state_pkts_needed);
        return fdc_return::FDC_NO_DATA;
    }

    std::visit(do_analysis{k_, analysis, c}, x);

    if (context != nullptr and analysis.analysis_is_valid()) {
        *context = &analysis;
    }

    truncation_status status = compute_truncation_status(reassembler_ptr,
                                                         truncated_tcp || truncated_udp);

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
                finalize_reassembly_flow(reassembler_ptr, analysis.flow_state_pkts_needed);
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
            finalize_reassembly_flow(reassembler_ptr, analysis.flow_state_pkts_needed);
            return fdc_return::FDC_NO_DATA;     // empty message; nothing to report
        }

        // write out the truncation status of the record
        //
        outer_map.print_key_uint("truncation", (uint64_t)status);

        outer_map.close();

        if (output.is_null()) {
            *buffer_size = 2 * internal_buffer_size;
            finalize_reassembly_flow(reassembler_ptr, analysis.flow_state_pkts_needed);
            return fdc_return::FDC_WRITE_INSUFFICIENT_SPACE;
        }

    } else {
        finalize_reassembly_flow(reassembler_ptr, analysis.flow_state_pkts_needed);
        return fdc_return::UNKNOWN_ERROR;  // unsupported FDC version
    }

    finalize_reassembly_flow(reassembler_ptr, analysis.flow_state_pkts_needed);
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
    cbor_buf.reset();
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
        struct tcp_reassembler *r =
            (reassembler && global_vars.reassembly) ? reassembler : nullptr;
        if (r) {
            analysis.flow_state_pkts_needed = false;
            if (tcp_pkt.is_SYN() || tcp_pkt.is_SYN_ACK() || tcp_pkt.is_RST()) {
                // skip handshake control packets in reassembly mode
            }
            else {
                bool ret = process_tcp_data(x, pkt, tcp_pkt, k, ts, r);
                if (r->in_progress(r->curr_flow)) {
                    analysis.flow_state_pkts_needed = true;
                }
                if (!ret) {
                    return 0;
                }
                truncated_tcp = detect_truncation(tcp_pkt.additional_bytes_needed, r);
            }
        }
        else {
            set_tcp_protocol(x, pkt, false, &tcp_pkt);
            truncated_tcp = detect_truncation(tcp_pkt.additional_bytes_needed, nullptr);
        }

    } else if (transport_proto == ip::protocol::udp) {
        class udp udp_pkt{pkt};
        udp_pkt.set_key(k);

        struct tcp_reassembler *r =
            (reassembler && global_vars.reassembly) ? reassembler : nullptr;
        bool ret = process_udp_data(x, pkt, udp_pkt, k, ts, r);
        if (r && r->in_progress(r->curr_flow)) {
            analysis.flow_state_pkts_needed = true;
        }
        if (r && !ret) {
            return 0;
        }
        truncated_udp = detect_truncation(udp_pkt.additional_bytes_needed(), r);
    }

    // process protocol data element
    //
    if (std::visit(is_not_empty{}, x)) {
        bool output_attr = false;
        bool truncated_crypto_handshake =
            is_truncated_crypto_handshake(x, truncated_tcp, truncated_udp);

        if (global_vars.do_analysis && mq) {
            if (ip_pkt.src_is_private()) {
                std::visit(do_cert_label_observation{k, mq}, x);
            }
            std::visit(do_snmp_oid_observation{k, mq}, x);
        }
        std::visit(compute_fingerprint{analysis.fp, global_vars.fp_format}, x);

        if (global_vars.do_analysis && analysis.fp.get_type() != fingerprint_type_unknown) {

            bool output_analysis = std::visit(do_analysis{k, analysis, c}, x);

            // check for additional classifier agnostic attributes like encrypted dns and domain-faking
            //
            output_attr = (c && c->check_additional_attributes(analysis)) ? true : output_attr;

            if (global_vars.cbor_metadata) {
                writeable& cbor_w = cbor_buf.get_writer();
                cbor_object cbor_outer{cbor_w};
                cbor_object cbor_output{cbor_outer, CBOR_METADATA_VERSION_KEY};

                // Emit the packet/handshake truncation status (string form) as a top-level
                // key. A packet-level status, not a feature, so it is written as part of the
                // header, ahead of the mark below, and never counts toward the gate.
                cbor_output.print_key_string(CBOR_METADATA_TRUNCATION_KEY,
                    get_truncation_str(compute_truncation_status(reassembler_ptr, truncated_tcp || truncated_udp)));

                // header is written; record the size so feature writes below can
                // be detected as growth
                const size_t before_features = cbor_buf.bytes_written();

                if (exposed_creds) {
                    auto creds_visitor = check_exposed_creds{cbor_output};
                    exposed_creds_type exposed_creds_ret = std::visit(creds_visitor, x);
                    output_attr = set_exposed_creds_attr(exposed_creds_ret) ? true : output_attr;
                }

                if (!crypto_policies.empty() && !truncated_crypto_handshake) {
                    auto crypto_visitor = do_crypto_assessment{crypto_policies, cbor_output};
                    crypto_assess_result assessment_result = std::visit(crypto_visitor, x);
                    output_attr = set_crypto_assessment_attr(assessment_result) ? true : output_attr;
                }

                // add future feature visitors here (before the growth check)

                // grew past the header => a feature was written (an overrun
                // reports 0 bytes, so this stays false and the buffer is dropped)
                if (cbor_buf.bytes_written() > before_features) {
                    cbor_buf.set_feature_written();
                }

                cbor_output.close();
                cbor_outer.close();
            } else {
                if (exposed_creds) {
                    auto creds_visitor = check_exposed_creds{no_output};
                    exposed_creds_type exposed_creds_ret = std::visit(creds_visitor, x);
                    output_attr = set_exposed_creds_attr(exposed_creds_ret) ? true : output_attr;
                }
                if (!crypto_policies.empty() && !truncated_crypto_handshake) {
                    auto crypto_visitor = do_crypto_assessment{crypto_policies, no_output};
                    crypto_assess_result assessment_result = std::visit(crypto_visitor, x);
                    output_attr = set_crypto_assessment_attr(assessment_result) ? true : output_attr;
                }
            }

            bool output_nbd = false;
            if (global_vars.network_behavioral_detections) {
                output_nbd = std::visit(do_network_behavioral_detections{k, analysis, c, attribute_common_data}, x);
            }

            // note: we only perform observations when analysis is
            // configured, because we rely on do_analysis to set the
            // analysis_.destination
            //
            if (mq) {
                std::visit(do_observation{k, analysis, mq}, x);
            }

            finalize_reassembly_flow(reassembler, analysis.flow_state_pkts_needed);

            // if fingerprint truncated, set fp status to unlabeled
            if (truncated_tcp or truncated_udp) {
                analysis.result.status = fingerprint_status::fingerprint_status_unlabled;
            }

            // report port in network byte order
            //
            analysis.destination.dst_port = ntoh(analysis.destination.dst_port);

            return output_analysis || output_nbd || output_attr;

        } else {
            bool output_nbd = false;

            if (global_vars.network_behavioral_detections) {
                output_nbd = std::visit(do_network_behavioral_detections{k, analysis, c, attribute_common_data}, x);
            }

            if (global_vars.cbor_metadata) {
                writeable& cbor_w = cbor_buf.get_writer();
                cbor_object cbor_outer{cbor_w};
                cbor_object cbor_output{cbor_outer, CBOR_METADATA_VERSION_KEY};

                // The truncation status is a packet-level field rather than a feature, so it
                // is written with the header and does not count toward the growth check.
                cbor_output.print_key_string(CBOR_METADATA_TRUNCATION_KEY,
                    get_truncation_str(compute_truncation_status(reassembler_ptr, truncated_tcp || truncated_udp)));

                // Record the header size; a feature write shows up as growth past it.
                const size_t before_features = cbor_buf.bytes_written();

                if (!crypto_policies.empty() && !truncated_crypto_handshake) {
                    auto crypto_visitor = do_crypto_assessment{crypto_policies, cbor_output};
                    crypto_assess_result crypto_result = std::visit(crypto_visitor, x);
                    output_attr = set_crypto_assessment_attr(crypto_result) ? true : output_attr;
                }
                if (exposed_creds) {
                    auto creds_visitor = check_exposed_creds{cbor_output};
                    exposed_creds_type exposed_creds_ret = std::visit(creds_visitor, x);
                    output_attr = set_exposed_creds_attr(exposed_creds_ret) ? true : output_attr;
                }

                // add future feature visitors here (before the growth check)

                // Growth past the header means a feature was written. An overrun reports
                // zero bytes, leaving this false so the buffer is dropped.
                if (cbor_buf.bytes_written() > before_features) {
                    cbor_buf.set_feature_written();
                }

                cbor_output.close();
                cbor_outer.close();
            } else {
                if (!crypto_policies.empty() && !truncated_crypto_handshake) {
                    auto crypto_visitor = do_crypto_assessment{crypto_policies, no_output};
                    crypto_assess_result crypto_result = std::visit(crypto_visitor, x);
                    output_attr = set_crypto_assessment_attr(crypto_result) ? true : output_attr;
                }
                if (exposed_creds) {
                    auto creds_visitor = check_exposed_creds{no_output};
                    exposed_creds_type exposed_creds_ret = std::visit(creds_visitor, x);
                    output_attr = set_exposed_creds_attr(exposed_creds_ret) ? true : output_attr;
                }
            }

            finalize_reassembly_flow(reassembler, analysis.flow_state_pkts_needed);
            return output_nbd || output_attr;
        }
    }

    finalize_reassembly_flow(reassembler, analysis.flow_state_pkts_needed);

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

bool stateful_pkt_proc::analyze_sll_packet(const uint8_t *packet,
                                           size_t length,
                                           struct timespec *ts,
                                           struct tcp_reassembler *reassembler) {

    struct datum pkt{packet, packet+length};
    linux_sll::skip_to_ip(pkt);
    if (pkt.is_null()) {
        return false;   // not an IP packet
    }

    return analyze_ip_packet(pkt.data, pkt.length(), ts, reassembler);
}

bool stateful_pkt_proc::analyze_sll2_packet(const uint8_t *packet,
                                            size_t length,
                                            struct timespec *ts,
                                            struct tcp_reassembler *reassembler) {

    struct datum pkt{packet, packet+length};
    linux_sll2::skip_to_ip(pkt);
    if (pkt.is_null()) {
        return false;   // not an IP packet
    }

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
    case LINKTYPE_LINUX_SLL:
        return analyze_sll_packet(eth_packet, length, ts, reassembler);
        break;
    case LINKTYPE_LINUX_SLL2:
        return analyze_sll2_packet(eth_packet, length, ts, reassembler);
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
