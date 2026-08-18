
// dcerpc.hpp
//
// Copyright (c) 2026 Cisco Systems, Inc. All rights reserved.  License at
// https://github.com/cisco/mercury/blob/master/LICENSE
//
///
/// \file dcerpc.hpp
/// \brief Connection-oriented DCE/RPC protocol parser.
///

#ifndef DCERPC_HPP
#define DCERPC_HPP

#include <cstdio>
#include "datum.h"
#include "json_object.h"
#include "protocol.h"
#include "match.h"

namespace dcerpc {

    static constexpr uint8_t connection_oriented_version = 5;
    static constexpr uint8_t pfc_object_uuid = 0x80;

    ///
    /// \brief Connection-oriented DCE/RPC PDU types supported by this parser.
    ///
    enum class pdu_type : uint8_t {
        request = 0,
        // Connectionless PDU types are intentionally unsupported.
        // ping = 1,
        response = 2,
        fault = 3,
        // working = 4,
        // nocall = 5,
        // reject = 6,
        // ack = 7,
        // cl_cancel = 8,
        // fack = 9,
        // cancel_ack = 10,
        bind = 11,
        bind_ack = 12,
        bind_nak = 13,
        alter_context = 14,
        alter_context_resp = 15,
        auth_3 = 16,
        shutdown = 17,
        co_cancel = 18,
        orphaned = 19
    };

    static constexpr mask_and_value<8> low_ptype_matcher{
        {0xff, 0xfe, 0xf0, 0x00, 0xef, 0xfc, 0xff, 0xff},
        {0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

    static constexpr mask_and_value<8> high_ptype_matcher{
        {0xff, 0xfe, 0xfc, 0x00, 0xef, 0xfc, 0xff, 0xff},
        {0x05, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00}};

    ///
    /// \brief Returns the JSON name for a supported PDU type.
    ///
    static const char *pdu_type_name(pdu_type type) {
        switch (type) {
            case pdu_type::request:
                return "request";
            // case pdu_type::ping:
            //     return "ping";
            case pdu_type::response:
                return "response";
            case pdu_type::fault:
                return "fault";
            // case pdu_type::working:
            //     return "working";
            // case pdu_type::nocall:
            //     return "nocall";
            // case pdu_type::reject:
            //     return "reject";
            // case pdu_type::ack:
            //     return "ack";
            // case pdu_type::cl_cancel:
            //     return "cl_cancel";
            // case pdu_type::fack:
            //     return "fack";
            // case pdu_type::cancel_ack:
            //     return "cancel_ack";
            case pdu_type::bind:
                return "bind";
            case pdu_type::bind_ack:
                return "bind_ack";
            case pdu_type::bind_nak:
                return "bind_nak";
            case pdu_type::alter_context:
                return "alter_context";
            case pdu_type::alter_context_resp:
                return "alter_context_resp";
            case pdu_type::auth_3:
                return "auth_3";
            case pdu_type::shutdown:
                return "shutdown";
            case pdu_type::co_cancel:
                return "co_cancel";
            case pdu_type::orphaned:
                return "orphaned";
            default:
                return nullptr;
        }
    }

    ///
    /// \brief Returns whether a PDU type is sent by a client.
    ///
    static bool is_client_pdu_type(pdu_type type) {
        switch (type) {
            case pdu_type::request:
            case pdu_type::bind:
            case pdu_type::alter_context:
            case pdu_type::auth_3:
            case pdu_type::co_cancel:
            case pdu_type::orphaned:
                return true;
            default:
                return false;
        }
    }

    ///
    /// \brief Parses an interface or transfer-syntax identifier.
    ///
    class syntax_id {
        encoded<uint32_t> time_low;
        encoded<uint16_t> time_mid;
        encoded<uint16_t> time_hi_and_version;
        datum clock_seq_and_node;
        encoded<uint16_t> version_major;
        encoded<uint16_t> version_minor;
        bool valid;

        static datum parse_clock_seq_and_node(datum &d) {
            return d.is_null() ? datum{} : datum{d, 8};
        }

        const char *known_name() const {
            struct named_uuid {
                uint32_t time_low;
                uint16_t time_mid;
                uint16_t time_hi_and_version;
                std::array<uint8_t, 8> clock_seq_and_node;
                const char *name;
            };
            static constexpr named_uuid known_uuids[] = {
                {0xe1af8308, 0x5d1f, 0x11c9, {0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa}, "epm"},
                {0x12345778, 0x1234, 0xabcd, {0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac}, "samr"},
                {0x12345778, 0x1234, 0xabcd, {0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab}, "lsarpc"},
                {0x12345678, 0x1234, 0xabcd, {0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb}, "netlogon"},
                {0xe3514235, 0x4b06, 0x11d1, {0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}, "drsuapi"},
                {0x4b324fc8, 0x1670, 0x01d3, {0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88}, "srvsvc"},
                {0x6bffd098, 0xa112, 0x3610, {0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a}, "wkssvc"},
                {0x367abb81, 0x9844, 0x35f1, {0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03}, "svcctl"},
                {0x338cd001, 0x2244, 0x31f1, {0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03}, "winreg"},
                {0x12345678, 0x1234, 0xabcd, {0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab}, "rprn"},
                {0x000001a0, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}, "dcomscm"},
                {0xa8e0653c, 0x2744, 0x4389, {0xa6, 0x1d, 0x73, 0x73, 0xdf, 0x8b, 0x22, 0x92}, "fsrvp"},
                {0x3dde7c30, 0x165d, 0x11d1, {0xab, 0x8f, 0x00, 0x80, 0x5f, 0x14, 0xdb, 0x40}, "bkrp"},
                {0x82273fdc, 0xe32a, 0x18c3, {0x3f, 0x78, 0x82, 0x79, 0x29, 0xdc, 0x23, 0xea}, "eventlog"},
                {0x1ff70682, 0x0a51, 0x30e8, {0x07, 0x6d, 0x74, 0x0b, 0xe8, 0xce, 0xe9, 0x8b}, "atsvc"},
                {0x51c82175, 0x844e, 0x4750, {0xb0, 0xd8, 0xec, 0x25, 0x55, 0x55, 0xbc, 0x06}, "kms"},
            };

            for (const auto &known_uuid : known_uuids) {
                if (time_low == known_uuid.time_low && time_mid == known_uuid.time_mid &&
                    time_hi_and_version == known_uuid.time_hi_and_version &&
                    clock_seq_and_node == datum{known_uuid.clock_seq_and_node}) {
                    return known_uuid.name;
                }
            }
            return nullptr;
        }

    public:

        syntax_id(datum &d, bool little_endian) : time_low{d, little_endian},
                                                  time_mid{d, little_endian},
                                                  time_hi_and_version{d, little_endian},
                                                  clock_seq_and_node{parse_clock_seq_and_node(d)},
                                                  version_major{d, little_endian},
                                                  version_minor{d, little_endian},
                                                  valid{!d.is_null()} {
        }

        void write(buffer_stream &b) const {
            if (!valid) {
                return;
            }
            b.write_hex_uint(time_low);
            b.write_char('-');
            b.write_hex_uint(time_mid);
            b.write_char('-');
            b.write_hex_uint(time_hi_and_version);
            b.write_char('-');
            size_t i = 0;
            for (uint8_t byte : clock_seq_and_node) {
                if (i++ == 2) {
                    b.write_char('-');
                }
                b.write_hex_uint(byte);
            }
        }

        bool is_not_empty() const { return valid; }

        void write_json(json_object &o) const {
            o.print_key_value("uuid", *this);
            if (const char *name = known_name()) {
                o.print_key_string("name", name);
            }
            o.print_key_uint("version_major", version_major);
            o.print_key_uint("version_minor", version_minor);
        }

        void write_json(json_object &o, null_terminated_string name) const {
            json_object s{o, name};
            write_json(s);
            s.close();
        }
    };

    ///
    /// \brief Authentication service identifiers used by security trailers.
    ///
    enum class authentication_type : uint8_t {
        none = 0,
        dce_private = 1,
        dce_public = 2,
        gss_negotiate = 9,
        winnt = 10,
        gss_schannel = 14,
        gss_kerberos = 16,
        netlogon = 68
    };

    static const char *authentication_type_name(authentication_type type) {
        switch (type) {
            case authentication_type::none:
                return "none";
            case authentication_type::dce_private:
                return "dce_private";
            case authentication_type::dce_public:
                return "dce_public";
            case authentication_type::gss_negotiate:
                return "gss_negotiate"; // SPNEGO (wraps NTLM or Kerberos)
            case authentication_type::winnt:
                return "winnt";
            case authentication_type::gss_schannel:
                return "gss_schannel";
            case authentication_type::gss_kerberos:
                return "gss_kerberos";
            case authentication_type::netlogon:
                return "netlogon";
            default:
                return nullptr;
        }
    }

    ///
    /// \brief Results of presentation-context negotiation.
    ///
    enum class context_result : uint16_t {
        acceptance = 0,
        user_rejection = 1,
        provider_rejection = 2,
        negotiate_ack = 3
    };

    static const char *context_result_name(context_result result) {
        switch (result) {
            case context_result::acceptance:
                return "acceptance";
            case context_result::user_rejection:
                return "user_rejection";
            case context_result::provider_rejection:
                return "provider_rejection";
            case context_result::negotiate_ack:
                return "negotiate_ack";
            default:
                return nullptr;
        }
    }

    ///
    /// \brief Reasons for rejecting a presentation context.
    ///
    enum class context_rejection_reason : uint16_t {
        reason_not_specified = 0,
        abstract_syntax_not_supported = 1,
        proposed_transfer_syntaxes_not_supported = 2,
        local_limit_exceeded = 3
    };

    static const char *context_rejection_reason_name(context_rejection_reason reason) {
        switch (reason) {
            case context_rejection_reason::reason_not_specified:
                return "reason_not_specified";
            case context_rejection_reason::abstract_syntax_not_supported:
                return "abstract_syntax_not_supported";
            case context_rejection_reason::proposed_transfer_syntaxes_not_supported:
                return "proposed_transfer_syntaxes_not_supported";
            case context_rejection_reason::local_limit_exceeded:
                return "local_limit_exceeded";
            default:
                return nullptr;
        }
    }

    ///
    /// \brief Protection levels used by security trailers.
    ///
    enum class authentication_level : uint8_t {
        default_level = 0,
        none = 1,
        connect = 2,
        call = 3,
        packet = 4,
        packet_integrity = 5,
        packet_privacy = 6
    };

    static const char *authentication_level_name(authentication_level level) {
        switch (level) {
            case authentication_level::default_level:
                return "default";
            case authentication_level::none:
                return "none";
            case authentication_level::connect:
                return "connect";
            case authentication_level::call:
                return "call";
            case authentication_level::packet:
                return "packet";
            case authentication_level::packet_integrity:
                return "packet_integrity";
            case authentication_level::packet_privacy:
                return "packet_privacy";
            default:
                return nullptr;
        }
    }

    class request_body {
        skip_bytes<4> ignored_alloc_hint;
        encoded<uint16_t> context_id;
        encoded<uint16_t> opnum;
        bool valid;

    public:

        request_body(datum &d, bool little_endian) :
            ignored_alloc_hint{d},
            context_id{d, little_endian},
            opnum{d, little_endian},
            valid{!d.is_null()} {
        }

        void write_json(json_object &o) const {
            if (!valid) {
                return;
            }
            o.print_key_uint("context_id", context_id);
            o.print_key_uint("opnum", opnum);
        }
    };

    class bind_body {
        skip_bytes<8> ignored_fragment_sizes_and_group;
        encoded<uint8_t> context_count;
        literal_byte<0, 0, 0> required_reserved;
        datum contexts;
        bool little_endian;
        bool valid;

        static bool contexts_are_valid(datum d, uint8_t count, bool little_endian) {
            for (uint8_t i = 0; i < count; ++i) {
                skip_bytes<2> ignored_context_id{d};
                encoded<uint8_t> transfer_syntax_count{d};
                literal_byte<0> required_reserved{d};
                syntax_id abstract_syntax{d, little_endian};
                (void)ignored_context_id;
                (void)required_reserved;
                if (!abstract_syntax.is_not_empty()) {
                    return false;
                }
                for (uint8_t j = 0; j < transfer_syntax_count; ++j) {
                    syntax_id transfer_syntax{d, little_endian};
                    if (!transfer_syntax.is_not_empty()) {
                        return false;
                    }
                }
            }
            return d.is_empty();
        }

    public:

        bind_body(datum &d, bool little_endian_) :
            ignored_fragment_sizes_and_group{d},
            context_count{d},
            required_reserved{d},
            contexts{d},
            little_endian{little_endian_},
            valid{!d.is_null() && contexts_are_valid(contexts, context_count.value(), little_endian)} {
            if (valid) {
                d.set_empty();
            } else {
                d.set_null();
            }
        }

        bool is_not_empty() const { return valid; }

        void write_json(json_object &o) const {
            if (!valid) {
                return;
            }
            datum d{contexts};
            json_array proposed_contexts{o, "proposed_contexts", true};
            for (uint8_t i = 0; i < context_count; i++) {
                encoded<uint16_t> context_id{d, little_endian};
                encoded<uint8_t> transfer_syntax_count{d};
                literal_byte<0> required_reserved{d};
                syntax_id abstract_syntax{d, little_endian};
                (void)required_reserved;

                json_object context{proposed_contexts};
                context.print_key_uint("id", context_id);
                abstract_syntax.write_json(context, "abstract_syntax");

                json_array transfer_syntaxes{context, "transfer_syntaxes", true};
                for (uint8_t j = 0; j < transfer_syntax_count; ++j) {
                    syntax_id transfer_syntax{d, little_endian};
                    json_object syntax{transfer_syntaxes};
                    transfer_syntax.write_json(syntax);
                    syntax.close();
                }
                transfer_syntaxes.close();
                context.close();
            }
            proposed_contexts.close();
        }
    };

    class context_response_body {
        skip_bytes<8> ignored_fragment_sizes_and_group;
        encoded<uint16_t> secondary_address_length;
        datum ignored_secondary_address;
        datum ignored_padding;
        encoded<uint8_t> result_count;
        literal_byte<0, 0, 0> required_reserved;
        datum results;
        bool little_endian;
        bool valid;

        static constexpr size_t result_length = 24;

        static datum parse_bytes(datum &d, size_t length) {
            if (d.is_null()) {
                return {};
            }
            return datum{d, static_cast<ssize_t>(length)};
        }

        static size_t padding_length(uint16_t address_length) {
            return (4 - ((2 + static_cast<size_t>(address_length)) % 4)) % 4;
        }

    public:

        context_response_body(datum &d, bool little_endian_) :
            ignored_fragment_sizes_and_group{d},
            secondary_address_length{d, little_endian_},
            ignored_secondary_address{parse_bytes(d, secondary_address_length)},
            ignored_padding{parse_bytes(d, padding_length(secondary_address_length))},
            result_count{d},
            required_reserved{d},
            results{d},
            little_endian{little_endian_},
            valid{!d.is_null() && results.length() == static_cast<ssize_t>(result_count.value() * result_length)} {
            if (valid) {
                d.set_empty();
            } else {
                d.set_null();
            }
        }

        bool is_not_empty() const { return valid; }

        void write_json(json_object &o) const {
            if (!valid) {
                return;
            }
            datum d{results};
            json_array context_results{o, "context_results", true};
            for (uint8_t i = 0; i < result_count; ++i) {
                encoded<uint16_t> result_code{d, little_endian};
                encoded<uint16_t> result_detail{d, little_endian};
                syntax_id transfer_syntax{d, little_endian};
                json_object entry{context_results};
                entry.print_key_string_or_unknown_code("result", context_result_name(static_cast<context_result>(result_code.value())), result_code.value());
                if (result_code == static_cast<uint16_t>(context_result::acceptance)) {
                    transfer_syntax.write_json(entry, "selected_transfer_syntax");
                } else if (result_code == static_cast<uint16_t>(context_result::negotiate_ack)) {
                    entry.print_key_uint("features", result_detail);
                } else if (result_code == static_cast<uint16_t>(context_result::user_rejection) ||
                         result_code == static_cast<uint16_t>(context_result::provider_rejection)) {
                    entry.print_key_string_or_unknown_code("reason", context_rejection_reason_name(static_cast<context_rejection_reason>(result_detail.value())), result_detail.value());
                }
                entry.close();
            }
            context_results.close();
        }
    };

    ///
    /// \brief Parses a connection-oriented DCE/RPC PDU.
    ///
    class message : public base_protocol {
        literal_byte<connection_oriented_version> required_version;
        encoded<uint8_t> minor_version;
        encoded<uint8_t> packet_type;
        encoded<uint8_t> flags;
        encoded<uint8_t> integer_representation;
        encoded<uint8_t> floating_point_representation;
        literal_byte<0, 0> required_drep_reserved;
        bool little_endian;
        encoded<uint16_t> fragment_length;
        encoded<uint16_t> authentication_length;
        encoded<uint32_t> call_id;
        datum body;
        datum authentication_trailer;
        bool valid;

        pdu_type type() const {
            return static_cast<pdu_type>(packet_type.value());
        }

        ///
        /// \brief Returns the minimum body size for this PDU type.
        ///
        size_t minimum_body_length() const {
            switch (type()) {
                case pdu_type::request:
                    return 8 + ((flags.value() & pfc_object_uuid) ? 16 : 0);
                case pdu_type::response:
                    return 8;
                case pdu_type::fault:
                case pdu_type::bind_ack:
                case pdu_type::alter_context_resp:
                    return 16;
                case pdu_type::bind:
                case pdu_type::alter_context:
                    return 12;
                case pdu_type::bind_nak:
                    return 3;
                case pdu_type::auth_3:
                    return 4;
                default:
                    return 0;
            }
        }

        // sec_trailer header (auth_type, auth_level, authentication_padding_length, reserved,
        // auth_context_id) precedes auth_value; authentication_length covers only auth_value
        // (MS-RPCE 2.2.2.11), so it sits in addition to these 8 bytes.
        static constexpr size_t security_trailer_header_length = 8;

        bool common_header_is_valid() const {
            return (minor_version == 0 || minor_version == 1) && pdu_type_name(type()) != nullptr &&
                (integer_representation == 0x10 || integer_representation == 0x00) && floating_point_representation <= 3 &&
                fragment_length >= 16 &&
                (authentication_length == 0 || static_cast<size_t>(authentication_length) + security_trailer_header_length <= static_cast<size_t>(fragment_length) - 16);
        }

        bool body_is_valid() const {
            datum d{body};
            switch (type()) {
                case pdu_type::bind:
                case pdu_type::alter_context:
                    return bind_body{d, little_endian}.is_not_empty();
                case pdu_type::bind_ack:
                case pdu_type::alter_context_resp:
                    return context_response_body{d, little_endian}.is_not_empty();
                default:
                    return true;
            }
        }

        void write_auth_verifier(json_object &o) const {
            datum d{authentication_trailer};
            encoded<uint8_t> auth_type{d};
            encoded<uint8_t> auth_level{d};
            skip_bytes<2> ignored_padding_and_reserved{d};
            encoded<uint32_t> auth_context_id{d, little_endian};
            (void)ignored_padding_and_reserved;
            json_object verifier{o, "auth_verifier"};
            verifier.print_key_string_or_unknown_code("auth_type", authentication_type_name(static_cast<authentication_type>(auth_type.value())), auth_type.value());
            verifier.print_key_string_or_unknown_code("auth_level", authentication_level_name(static_cast<authentication_level>(auth_level.value())), auth_level.value());
            verifier.print_key_uint("auth_context_id", auth_context_id);
            verifier.close();
        }

    public:

        message(datum &d) : required_version{d},
                            minor_version{d},
                            packet_type{d},
                            flags{d},
                            integer_representation{d},
                            floating_point_representation{d},
                            required_drep_reserved{d},
                            little_endian{integer_representation == 0x10},
                            fragment_length{d, little_endian},
                            authentication_length{d, little_endian},
                            call_id{d, little_endian},
                            body{},
                            authentication_trailer{},
                            valid{false} {
            if (d.is_null() || !common_header_is_valid()) {
                d.set_null();
                return;
            }

            const size_t body_length = static_cast<size_t>(fragment_length) - 16;
            body.parse(d, body_length);
            if (d.is_null()) {
                return;
            }
            if (authentication_length) {
                const size_t trailer_length = authentication_length + security_trailer_header_length;
                authentication_trailer = body;
                authentication_trailer.skip(body.length() - trailer_length);
                const auto authentication_padding_length = authentication_trailer[2];
                const size_t pdu_body_length = body.length() - trailer_length;
                if (*authentication_padding_length > pdu_body_length) {
                    d.set_null();
                    return;
                }
                body.trim(trailer_length + *authentication_padding_length);
            }
            if (body.length() < static_cast<ssize_t>(minimum_body_length()) || !body_is_valid()) {
                d.set_null();
                return;
            }
            valid = true;
        }

        bool is_not_empty() const { return valid; }

        bool is_client() const { return is_client_pdu_type(type()); }

        bool is_server() const { return !is_client(); }

        void write_json(json_object &record, bool) const {
            if (!valid) {
                return;
            }
            const pdu_type pdu = type();
            json_object dcerpc{record, "dcerpc"};
            json_object o{dcerpc, is_client() ? "client" : "server"};
            o.print_key_string("type", pdu_type_name(pdu));
            o.print_key_uint("call_id", call_id);
            if (pdu == pdu_type::bind || pdu == pdu_type::alter_context) {
                datum d{body};
                bind_body parsed_body{d, little_endian};
                parsed_body.write_json(o);
            } else if (pdu == pdu_type::bind_ack || pdu == pdu_type::alter_context_resp) {
                datum d{body};
                context_response_body parsed_body{d, little_endian};
                parsed_body.write_json(o);
            } else if (pdu == pdu_type::request) {
                datum d{body};
                request_body parsed_body{d, little_endian};
                parsed_body.write_json(o);
            }
            if (authentication_length) {
                write_auth_verifier(o);
            }
            o.close();
            dcerpc.close();
        }

        void write_l7_metadata(cbor_object &o, bool) {
            cbor_array protocols{o, "protocols"};
            protocols.print_string("dcerpc");
            protocols.close();
        }
    };

    // LCOV_EXCL_START
    [[maybe_unused]] inline bool unit_test(FILE *f = nullptr) {
        uint8_t bind_pdu[] = {
            0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
            0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00,
            0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11,
            0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
            0x03, 0x00, 0x00, 0x00,
            0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
            0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
            0x02, 0x00, 0x00, 0x00};
        datum bind_data{bind_pdu};
        message bind{bind_data};

        uint8_t request_pdu[] = {
            0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
            0x18, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00};
        datum request_data{request_pdu};
        message request{request_data};

        request_pdu[3] = 0x83;
        datum request_with_missing_object_data{request_pdu};
        message request_with_missing_object{request_with_missing_object_data};
        request_pdu[3] = 0x03;

        bind_pdu[8] = 0x1c;
        datum bind_with_incomplete_context_data{bind_pdu};
        message bind_with_incomplete_context{bind_with_incomplete_context_data};
        bind_pdu[8] = 0x48;

        uint8_t short_call_pdu[] = {
            0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        datum response_with_short_body_data{short_call_pdu};
        message response_with_short_body{response_with_short_body_data};
        short_call_pdu[2] = static_cast<uint8_t>(pdu_type::fault);
        short_call_pdu[8] = 0x18;
        datum fault_with_short_body_data{short_call_pdu};
        message fault_with_short_body{fault_with_short_body_data};

        uint8_t header_only_pdu[] = {
            0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
        const pdu_type body_required_types[] = {
            pdu_type::bind, pdu_type::bind_ack, pdu_type::bind_nak,
            pdu_type::alter_context, pdu_type::alter_context_resp, pdu_type::auth_3};
        bool body_required_pdus_rejected = true;
        for (const auto body_required_type : body_required_types) {
            header_only_pdu[2] = static_cast<uint8_t>(body_required_type);
            datum header_only_data{header_only_pdu};
            message header_only{header_only_data};
            body_required_pdus_rejected &=
                !header_only.is_not_empty() && header_only_data.is_null();
        }

        uint8_t auth3_pdu[] = {
            0x05, 0x00, 0x10, 0x03, 0x10, 0x00, 0x00, 0x00,
            0x20, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,
            0xd0, 0x16, 0x00, 0x00,
            0x0a, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0xde, 0xad, 0xbe, 0xef
        };
        datum auth3_data{auth3_pdu};
        message auth3{auth3_data};

        auth3_pdu[10] = 0;
        datum auth3_without_auth_data{auth3_pdu};
        message auth3_without_auth{auth3_without_auth_data};
        auth3_pdu[10] = 4;

        auth3_pdu[22] = 5;
        datum auth3_bad_padding_data{auth3_pdu};
        message auth3_bad_padding{auth3_bad_padding_data};
        auth3_pdu[22] = 0;

        uint8_t incomplete_syntax_bytes[19] = {};
        datum incomplete_syntax_data{incomplete_syntax_bytes};
        syntax_id incomplete_syntax{incomplete_syntax_data, true};

        uint8_t bad_pdu[] = {0x05, 0x00, 0x0b, 0x03};
        datum bad_data{bad_pdu};
        message bad{bad_data};

        uint8_t truncated_header_pdu[] = {
            0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x00, 0x00};
        datum truncated_header_data{truncated_header_pdu};
        message truncated_header{truncated_header_data};

        uint8_t partial_request_pdu[] = {
            0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
            0x18, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00};
        datum partial_request_data{partial_request_pdu};
        message partial_request{partial_request_data};

        uint8_t bind_nak_pdu[] = {
            0x05, 0x00, 0x0d, 0x03, 0x10, 0x00, 0x00, 0x00,
            0x13, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
            0x04, 0x00, 0x01};
        datum bind_nak_data{bind_nak_pdu};
        message bind_nak{bind_nak_data};

        uint8_t context_response_pdu[] = {
            0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00,
            0x54, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0xd0, 0x16, 0xd0, 0x16, 0x00, 0x00, 0x00, 0x00,
            0x04, 0x00, '1', '3', '5', 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
            0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
            0x02, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00};
        datum bind_ack_data{context_response_pdu};
        message bind_ack{bind_ack_data};
        context_response_pdu[8] = 0x24;
        datum bind_ack_with_incomplete_results_data{context_response_pdu};
        message bind_ack_with_incomplete_results{bind_ack_with_incomplete_results_data};
        context_response_pdu[8] = 0x54;
        char json_buffer[2048];
        buffer_stream incomplete_syntax_buffer{json_buffer, sizeof(json_buffer)};
        incomplete_syntax.write(incomplete_syntax_buffer);
        bool incomplete_syntax_write_empty = incomplete_syntax_buffer.length() == 0;
        bool request_json_valid = false;
        bool bind_json_valid = false;
        {
            buffer_stream buf{json_buffer, sizeof(json_buffer)};
            json_object json{&buf};
            bind.write_json(json, false);
            json.close();
            buf.write_char(0);
            bind_json_valid = strstr(json_buffer, "\"uuid\":\"e1af8308-5d1f-11c9-91a4-08002b14a0fa\"") &&
                strstr(json_buffer, "\"name\":\"epm\"") &&
                strstr(json_buffer, "\"uuid\":\"8a885d04-1ceb-11c9-9fe8-08002b104860\"");
        }
        uint8_t fsrvp_syntax_bytes[] = {
            0x3c, 0x65, 0xe0, 0xa8, 0x44, 0x27, 0x89, 0x43,
            0xa6, 0x1d, 0x73, 0x73, 0xdf, 0x8b, 0x22, 0x92,
            0x01, 0x00, 0x00, 0x00};
        datum fsrvp_syntax_data{fsrvp_syntax_bytes};
        syntax_id fsrvp_syntax{fsrvp_syntax_data, true};
        bool fsrvp_syntax_json_valid = false;
        {
            buffer_stream buf{json_buffer, sizeof(json_buffer)};
            json_object json{&buf};
            fsrvp_syntax.write_json(json);
            json.close();
            buf.write_char(0);
            fsrvp_syntax_json_valid = strstr(json_buffer, "\"uuid\":\"a8e0653c-2744-4389-a61d-7373df8b2292\"") &&
                strstr(json_buffer, "\"name\":\"fsrvp\"") &&
                strstr(json_buffer, "\"version_major\":1") &&
                strstr(json_buffer, "\"version_minor\":0");
        }
        fsrvp_syntax_bytes[16] = 0x00;
        fsrvp_syntax_bytes[18] = 0x51;
        datum split_version_data{fsrvp_syntax_bytes};
        syntax_id split_version{split_version_data, true};
        bool split_version_json_valid = false;
        {
            buffer_stream buf{json_buffer, sizeof(json_buffer)};
            json_object json{&buf};
            split_version.write_json(json);
            json.close();
            buf.write_char(0);
            split_version_json_valid = strstr(json_buffer, "\"version_major\":0") &&
                strstr(json_buffer, "\"version_minor\":81");
        }
        uint8_t big_endian_syntax_bytes[20] = {};
        big_endian_syntax_bytes[17] = 1;
        big_endian_syntax_bytes[19] = 2;
        datum big_endian_syntax_data{big_endian_syntax_bytes};
        syntax_id big_endian_syntax{big_endian_syntax_data, false};
        bool big_endian_syntax_json_valid = false;
        {
            buffer_stream buf{json_buffer, sizeof(json_buffer)};
            json_object json{&buf};
            big_endian_syntax.write_json(json);
            json.close();
            buf.write_char(0);
            big_endian_syntax_json_valid = strstr(json_buffer, "\"version_major\":1") &&
                strstr(json_buffer, "\"version_minor\":2");
        }
        {
            buffer_stream buf{json_buffer, sizeof(json_buffer)};
            json_object json{&buf};
            request.write_json(json, false);
            json.close();
            buf.write_char(0);
            request_json_valid = strstr(json_buffer, "\"context_id\":0") &&
                strstr(json_buffer, "\"opnum\":3");
        }
        bool bind_nak_json_valid = false;
        {
            buffer_stream buf{json_buffer, sizeof(json_buffer)};
            json_object json{&buf};
            bind_nak.write_json(json, false);
            json.close();
            buf.write_char(0);
            bind_nak_json_valid = strstr(json_buffer, "\"type\":\"bind_nak\"");
        }
        bool incomplete_json_empty = false;
        {
            buffer_stream buf{json_buffer, sizeof(json_buffer)};
            json_object json{&buf};
            partial_request.write_json(json, false);
            json.close();
            buf.write_char(0);
            incomplete_json_empty = strcmp(json_buffer, "{}") == 0;
        }
        bool auth3_json_valid = false;
        {
            buffer_stream buf{json_buffer, sizeof(json_buffer)};
            json_object json{&buf};
            auth3.write_json(json, false);
            json.close();
            buf.write_char('\0');
            auth3_json_valid = strstr(json_buffer, "auth_verifier");
        }
        uint8_t auth_pdu[] = {
            0x05, 0x00, 0x03, 0x03, 0x10, 0x00, 0x00, 0x00,
            0x2c, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0a, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0xde, 0xad, 0xbe, 0xef};
        const pdu_type authenticated_ptypes[] = {
            pdu_type::fault, pdu_type::bind_nak, pdu_type::shutdown, pdu_type::co_cancel, pdu_type::orphaned};
        bool auth_fields_valid = true;
        for (const auto authenticated_ptype : authenticated_ptypes) {
            auth_pdu[2] = static_cast<uint8_t>(authenticated_ptype);
            datum auth_data{auth_pdu};
            message auth_message{auth_data};
            buffer_stream buf{json_buffer, sizeof(json_buffer)};
            json_object json{&buf};
            auth_message.write_json(json, false);
            json.close();
            buf.write_char('\0');
            const bool auth_message_valid = auth_message.is_not_empty() &&
                strstr(json_buffer, "\"auth_type\":\"winnt\"") &&
                strstr(json_buffer, "\"auth_level\":\"packet_privacy\"") &&
                strstr(json_buffer, "\"auth_context_id\":1");
            auth_fields_valid &= auth_message_valid;
        }
        auth_pdu[32] = 0xff;
        auth_pdu[33] = 0xff;
        datum unknown_auth_data{auth_pdu};
        message unknown_auth{unknown_auth_data};
        bool unknown_auth_fields_valid = false;
        {
            buffer_stream buf{json_buffer, sizeof(json_buffer)};
            json_object json{&buf};
            unknown_auth.write_json(json, false);
            json.close();
            buf.write_char('\0');
            unknown_auth_fields_valid = strstr(json_buffer, "\"auth_type\":\"UNKNOWN (ff)\"") &&
                strstr(json_buffer, "\"auth_level\":\"UNKNOWN (ff)\"");
        }
        bool bind_ack_json_valid = false;
        {
            buffer_stream buf{json_buffer, sizeof(json_buffer)};
            json_object json{&buf};
            bind_ack.write_json(json, false);
            json.close();
            buf.write_char('\0');
            bind_ack_json_valid = strstr(json_buffer, "\"context_results\"") &&
                strstr(json_buffer, "\"selected_transfer_syntax\"") &&
                strstr(json_buffer, "\"result\":\"provider_rejection\"") &&
                strstr(json_buffer, "\"reason\":\"abstract_syntax_not_supported\"");
        }

        context_response_pdu[2] = static_cast<uint8_t>(pdu_type::alter_context_resp);
        datum alter_context_resp_data{context_response_pdu};
        message alter_context_resp{alter_context_resp_data};
        bool alter_context_resp_json_valid = false;
        {
            buffer_stream buf{json_buffer, sizeof(json_buffer)};
            json_object json{&buf};
            alter_context_resp.write_json(json, false);
            json.close();
            buf.write_char('\0');
            alter_context_resp_json_valid = strstr(json_buffer, "\"type\":\"alter_context_resp\"") &&
                strstr(json_buffer, "\"context_results\"");
        }

        context_response_pdu[36] = 0xff;
        context_response_pdu[37] = 0xff;
        datum unknown_context_result_data{context_response_pdu};
        message unknown_context_result{unknown_context_result_data};
        bool unknown_context_result_valid = false;
        {
            buffer_stream buf{json_buffer, sizeof(json_buffer)};
            json_object json{&buf};
            unknown_context_result.write_json(json, false);
            json.close();
            buf.write_char('\0');
            unknown_context_result_valid = strstr(json_buffer, "\"result\":\"UNKNOWN (ffff)\"");
        }

        uint8_t dnp3_pdu[] = {0x05, 0x64, 0x05, 0xc4, 0x01, 0x00, 0x00, 0x04};
        // SOCKS5 CONNECT to 16.0.0.0:443 satisfies the 8-byte matcher; the
        // 16-byte common header requirement in message() rejects it.
        uint8_t socks5_collision[] = {0x05, 0x01, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x01, 0xbb};
        datum socks5_collision_data{socks5_collision};
        message socks5_collision_message{socks5_collision_data};

        auto check = [f](const char *name, bool result) {
            if (!result && f) {
                fprintf(f, "dcerpc::unit_test(): %s failed\n", name);
            }
            return result;
        };
        bool passed = true;
        passed &= check("bind", bind.is_not_empty() && bind_json_valid &&
                        !bind_with_incomplete_context.is_not_empty() && bind_with_incomplete_context_data.is_null());
        passed &= check("syntax_id", fsrvp_syntax_json_valid && split_version_json_valid &&
                        big_endian_syntax_json_valid &&
                        incomplete_syntax_write_empty && !incomplete_syntax.is_not_empty() &&
                        incomplete_syntax_data.is_null());
        passed &= check("request", request.is_not_empty() && request_json_valid &&
                        !request_with_missing_object.is_not_empty() && request_with_missing_object_data.is_null() &&
                        !partial_request.is_not_empty() && partial_request_data.is_null() && incomplete_json_empty);
        passed &= check("response_and_fault", !response_with_short_body.is_not_empty() &&
                        response_with_short_body_data.is_null() && !fault_with_short_body.is_not_empty() &&
                        fault_with_short_body_data.is_null());
        passed &= check("minimum_body_lengths", body_required_pdus_rejected);
        passed &= check("bind_nak", bind_nak.is_not_empty() && bind_nak_data.is_empty() && bind_nak_json_valid);
        passed &= check("bind_ack", bind_ack.is_not_empty() && bind_ack_json_valid &&
                        !bind_ack_with_incomplete_results.is_not_empty() &&
                        bind_ack_with_incomplete_results_data.is_null() && unknown_context_result_valid);
        passed &= check("alter_context_resp", alter_context_resp.is_not_empty() && alter_context_resp_json_valid);
        passed &= check("auth_3", auth3.is_not_empty() && auth3_json_valid &&
                        auth3_without_auth.is_not_empty() && auth3_without_auth_data.is_empty() &&
                        !auth3_bad_padding.is_not_empty() && auth3_bad_padding_data.is_null());
        passed &= check("authentication", auth_fields_valid && unknown_auth_fields_valid &&
                        strcmp(authentication_level_name(authentication_level::default_level), "default") == 0 &&
                        strcmp(authentication_level_name(authentication_level::none), "none") == 0 &&
                        strcmp(authentication_level_name(authentication_level::connect), "connect") == 0 &&
                        strcmp(authentication_level_name(authentication_level::call), "call") == 0 &&
                        strcmp(authentication_level_name(authentication_level::packet), "packet") == 0 &&
                        strcmp(authentication_level_name(authentication_level::packet_integrity), "packet_integrity") == 0 &&
                        strcmp(authentication_level_name(authentication_level::packet_privacy), "packet_privacy") == 0 &&
                        authentication_level_name(static_cast<authentication_level>(7)) == nullptr);
        passed &= check("common_header", !bad.is_not_empty() && !truncated_header.is_not_empty() &&
                        truncated_header_data.is_null());
        passed &= check("direction", is_client_pdu_type(pdu_type::bind) &&
                        is_client_pdu_type(pdu_type::request) && is_client_pdu_type(pdu_type::auth_3) &&
                        !is_client_pdu_type(pdu_type::response) && !is_client_pdu_type(pdu_type::fault) &&
                        !is_client_pdu_type(pdu_type::bind_ack));
        passed &= check("matchers", low_ptype_matcher.matches(bind_pdu, sizeof(bind_pdu)) &&
                        low_ptype_matcher.matches(request_pdu, sizeof(request_pdu)) &&
                        high_ptype_matcher.matches(auth3_pdu, sizeof(auth3_pdu)) &&
                        !low_ptype_matcher.matches(dnp3_pdu, sizeof(dnp3_pdu)) &&
                        !high_ptype_matcher.matches(dnp3_pdu, sizeof(dnp3_pdu)) &&
                        low_ptype_matcher.matches(socks5_collision, sizeof(socks5_collision)) &&
                        !socks5_collision_message.is_not_empty());
        return passed;
    }
    // LCOV_EXCL_STOP

}

[[maybe_unused]] inline int dcerpc_message_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<dcerpc::message>(data, size);
}

#endif
