
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

#include "datum.h"
#include "json_object.h"
#include "protocol.h"
#include "match.h"

namespace dcerpc
{

    static constexpr uint8_t connection_oriented_version = 5;

    ///
    /// \brief Connection-oriented DCE/RPC PDU types supported by this parser.
    ///
    enum class pdu_type : uint8_t
    {
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
    static const char *pdu_type_name(pdu_type type)
    {
        switch (type)
        {
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
    static bool is_client_pdu_type(pdu_type type)
    {
        switch (type)
        {
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
    class syntax_id
    {
        datum uuid;
        encoded<uint32_t> version;
        bool valid;

    public:

        syntax_id(datum &d, bool little_endian) : uuid{d, 16},
                                                  version{d, little_endian},
                                                  valid{!d.is_null()}
        {
        }

        bool is_not_empty() const { return valid; }

        void write_json(json_object &o) const
        {
            o.print_key_hex("uuid", uuid);
            o.print_key_uint("version", version);
        }

        void write_json(json_object &o, const char *name) const
        {
            json_object s{o, name};
            write_json(s);
            s.close();
        }
    };

    ///
    /// \brief Authentication service identifiers used by security trailers.
    ///
    enum class authentication_type : uint8_t
    {
        none = 0,
        dce_private = 1,
        dce_public = 2,
        gss_negotiate = 9,
        winnt = 10,
        gss_schannel = 14,
        gss_kerberos = 16,
        netlogon = 68
    };

    static const char *authentication_type_name(authentication_type type)
    {
        switch (type)
        {
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
    enum class context_result : uint16_t
    {
        acceptance = 0,
        user_rejection = 1,
        provider_rejection = 2,
        negotiate_ack = 3
    };

    static const char *context_result_name(context_result result)
    {
        switch (result)
        {
            case context_result::acceptance:
                return "acceptance";
            case context_result::user_rejection:
            case context_result::provider_rejection:
                return "rejected";
            case context_result::negotiate_ack:
                return "negotiate_ack";
            default:
                return nullptr;
        }
    }

    ///
    /// \brief Protection levels used by security trailers.
    ///
    enum class authentication_level : uint8_t
    {
        default_level = 0,
        none = 1,
        connect = 2,
        call = 3,
        packet = 4,
        packet_integrity = 5,
        packet_privacy = 6
    };

    static const char *authentication_level_name(authentication_level level)
    {
        switch (level)
        {
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

    class request_body
    {
        skip_bytes<4> ignored_alloc_hint;
        encoded<uint16_t> context_id;
        encoded<uint16_t> opnum;
        bool valid;

    public:

        request_body(datum &d, bool little_endian) :
            ignored_alloc_hint{d},
            context_id{d, little_endian},
            opnum{d, little_endian},
            valid{!d.is_null()}
        {
        }

        void write_json(json_object &o) const
        {
            if (!valid)
            {
                return;
            }
            o.print_key_uint("context_id", context_id);
            o.print_key_uint("opnum", opnum);
        }
    };

    class bind_body
    {
        skip_bytes<8> ignored_fragment_sizes_and_group;
        encoded<uint8_t> context_count;
        literal_byte<0, 0, 0> required_reserved;
        datum contexts;
        bool little_endian;
        bool valid;

    public:

        bind_body(datum &d, bool little_endian_) :
            ignored_fragment_sizes_and_group{d},
            context_count{d},
            required_reserved{d},
            contexts{d},
            little_endian{little_endian_},
            valid{!d.is_null()}
        {
            if (valid)
            {
                d.set_empty();
            }
        }

        void write_json(json_object &o) const
        {
            if (!valid)
            {
                return;
            }
            datum d{contexts};
            json_array proposed_contexts{o, "proposed_contexts", true};
            for (uint8_t i = 0; i < context_count; i++)
            {
                encoded<uint16_t> context_id{d, little_endian};
                encoded<uint8_t> transfer_syntax_count{d};
                literal_byte<0> required_reserved{d};
                syntax_id abstract_syntax{d, little_endian};
                if (!abstract_syntax.is_not_empty())
                {
                    break;
                }
                (void)required_reserved;

                json_object context{proposed_contexts};
                context.print_key_uint("id", context_id);
                abstract_syntax.write_json(context, "abstract_syntax");

                json_array transfer_syntaxes{context, "transfer_syntaxes", true};
                for (uint8_t j = 0; j < transfer_syntax_count; ++j)
                {
                    syntax_id transfer_syntax{d, little_endian};
                    if (!transfer_syntax.is_not_empty())
                    {
                        break;
                    }
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

    class context_response_body
    {
        skip_bytes<8> ignored_fragment_sizes_and_group;
        encoded<uint16_t> secondary_address_length;
        datum ignored_secondary_address;
        datum ignored_padding;
        encoded<uint8_t> result_count;
        literal_byte<0, 0, 0> required_reserved;
        datum results;
        bool little_endian;
        bool valid;

        static datum parse_bytes(datum &d, size_t length)
        {
            if (d.is_null())
            {
                return {};
            }
            return datum{d, length};
        }

        static size_t padding_length(uint16_t address_length)
        {
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
            valid{!d.is_null()}
        {
            if (valid)
            {
                d.set_empty();
            }
        }

        void write_json(json_object &o) const
        {
            if (!valid)
            {
                return;
            }
            datum d{results};
            json_array context_results{o, "context_results", true};
            for (uint8_t i = 0; i < result_count; ++i)
            {
                encoded<uint16_t> result_code{d, little_endian};
                encoded<uint16_t> result_detail{d, little_endian};
                syntax_id transfer_syntax{d, little_endian};
                if (!transfer_syntax.is_not_empty())
                {
                    break;
                }

                json_object entry{context_results};
                entry.print_key_string_or_unknown_code("result", context_result_name(static_cast<context_result>(result_code.value())), result_code);
                if (result_code == static_cast<uint16_t>(context_result::acceptance))
                {
                    transfer_syntax.write_json(entry, "selected_transfer_syntax");
                }
                else if (result_code == static_cast<uint16_t>(context_result::negotiate_ack))
                {
                    entry.print_key_uint("features", result_detail);
                }
                entry.close();
            }
            context_results.close();
        }
    };

    ///
    /// \brief Parses a connection-oriented DCE/RPC PDU.
    ///
    class message : public base_protocol
    {
        literal_byte<connection_oriented_version> required_version;
        encoded<uint8_t> minor_version;
        encoded<uint8_t> packet_type;
        skip_bytes<1> ignored_flags;
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
        bool truncated;

        pdu_type type() const
        {
            return static_cast<pdu_type>(packet_type.value());
        }

        // sec_trailer header (auth_type, auth_level, authentication_padding_length, reserved,
        // auth_context_id) precedes auth_value; authentication_length covers only auth_value
        // (MS-RPCE 2.2.2.11), so it sits in addition to these 8 bytes.
        static constexpr size_t security_trailer_header_length = 8;

        bool common_header_is_valid() const
        {
            return (minor_version == 0 || minor_version == 1) && pdu_type_name(type()) != nullptr &&
                (integer_representation == 0x10 || integer_representation == 0x00) && floating_point_representation <= 3 &&
                fragment_length >= 16 &&
                (authentication_length == 0 || static_cast<size_t>(authentication_length) + security_trailer_header_length <= static_cast<size_t>(fragment_length) - 16);
        }

        void write_auth_verifier(json_object &o) const
        {
            datum d{authentication_trailer};
            encoded<uint8_t> auth_type{d};
            encoded<uint8_t> auth_level{d};
            skip_bytes<2> ignored_padding_and_reserved{d};
            encoded<uint32_t> auth_context_id{d, little_endian};
            (void)ignored_padding_and_reserved;
            json_object verifier{o, "auth_verifier"};
            verifier.print_key_string_or_unknown_code("auth_type", authentication_type_name(static_cast<authentication_type>(auth_type.value())), auth_type);
            verifier.print_key_string_or_unknown_code("auth_level", authentication_level_name(static_cast<authentication_level>(auth_level.value())), auth_level);
            verifier.print_key_uint("auth_context_id", auth_context_id);
            verifier.close();
        }

    public:

        message(datum &d) : required_version{d},
                            minor_version{d},
                            packet_type{d},
                            ignored_flags{d},
                            integer_representation{d},
                            floating_point_representation{d},
                            required_drep_reserved{d},
                            little_endian{integer_representation == 0x10},
                            fragment_length{d, little_endian},
                            authentication_length{d, little_endian},
                            call_id{d, little_endian},
                            body{},
                            authentication_trailer{},
                            valid{false},
                            truncated{false}
        {
            if (d.is_null() || !common_header_is_valid())
            {
                d.set_null();
                return;
            }

            const size_t body_length = static_cast<size_t>(fragment_length) - 16;
            // Retain valid headers for incomplete TCP fragments; parse bodies only when complete.
            body.parse_soft_fail(d, body_length);
            if (static_cast<size_t>(body.length()) < body_length)
            {
                valid = true;
                truncated = true;
                return;
            }
            if (authentication_length)
            {
                const size_t trailer_length = authentication_length + security_trailer_header_length;
                authentication_trailer = body;
                authentication_trailer.skip(body.length() - trailer_length);
                const auto authentication_padding_length = authentication_trailer[2];
                const size_t pdu_body_length = body.length() - trailer_length;
                if (*authentication_padding_length > pdu_body_length)
                {
                    d.set_null();
                    return;
                }
                body.trim(trailer_length + *authentication_padding_length);
            }
            valid = true;
        }

        bool is_not_empty() const { return valid; }

        bool is_truncated() const { return truncated; }

        bool is_client() const { return is_client_pdu_type(type()); }

        bool is_server() const { return !is_client(); }

        void write_json(json_object &record, bool) const
        {
            if (!valid)
            {
                return;
            }
            const pdu_type pdu = type();
            json_object o{record, is_client() ? "dcerpc_client" : "dcerpc_server"};
            o.print_key_string("type", pdu_type_name(pdu));
            o.print_key_uint("call_id", call_id);
            if (truncated)
            {
                o.print_key_bool("truncated", true);
                o.close();
                return;
            }
            if (pdu == pdu_type::bind || pdu == pdu_type::alter_context)
            {
                datum d{body};
                bind_body parsed_body{d, little_endian};
                parsed_body.write_json(o);
            }
            else if (pdu == pdu_type::bind_ack || pdu == pdu_type::alter_context_resp)
            {
                datum d{body};
                context_response_body parsed_body{d, little_endian};
                parsed_body.write_json(o);
            }
            else if (pdu == pdu_type::request)
            {
                datum d{body};
                request_body parsed_body{d, little_endian};
                parsed_body.write_json(o);
            }
            if (authentication_length)
            {
                write_auth_verifier(o);
            }
            o.close();
        }

        void write_l7_metadata(cbor_object &o, bool)
        {
            cbor_array protocols{o, "protocols"};
            protocols.print_string(is_client() ? "dcerpc_client" : "dcerpc_server");
            protocols.close();
        }
    };

    class client : public message
    {
    public:

        client(datum &d) : message{d} {}

        bool is_not_empty() const { return message::is_not_empty() && is_client(); }
    };

    class server : public message
    {
    public:

        server(datum &d) : message{d} {}

        bool is_not_empty() const { return message::is_not_empty() && is_server(); }
    };


    // LCOV_EXCL_START
    [[maybe_unused]] inline bool unit_test()
    {
        uint8_t bind_pdu[] = {
            0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
            0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00,
            0xe1, 0xaf, 0x83, 0x08, 0x5d, 0x1c, 0xc9, 0x11,
            0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
            0x02, 0x00, 0x00, 0x00,
            0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
            0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
            0x02, 0x00, 0x00, 0x00};
        datum bind_data{bind_pdu};
        message bind{bind_data};

        uint8_t request_pdu[] = {
            0x05, 0x00, 0x00, 0x83, 0x10, 0x00, 0x00, 0x00,
            0x18, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00};
        datum request_data{request_pdu};
        message request{request_data};

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
        bool request_json_valid = false;
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
        bool truncated_json_valid = false;
        {
            buffer_stream buf{json_buffer, sizeof(json_buffer)};
            json_object json{&buf};
            partial_request.write_json(json, false);
            json.close();
            buf.write_char(0);
            truncated_json_valid = strstr(json_buffer, "truncated") &&
                !strstr(json_buffer, "context_id") && !strstr(json_buffer, "opnum");
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
        for (const auto authenticated_ptype : authenticated_ptypes)
        {
            auth_pdu[2] = static_cast<uint8_t>(authenticated_ptype);
            datum auth_data{auth_pdu};
            message auth_message{auth_data};
            buffer_stream buf{json_buffer, sizeof(json_buffer)};
            json_object json{&buf};
            auth_message.write_json(json, false);
            json.close();
            buf.write_char('\0');
            auth_fields_valid = auth_fields_valid && auth_message.is_not_empty() &&
                strstr(json_buffer, "\"auth_verifier\"");
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
                strstr(json_buffer, "\"result\":\"rejected\"");
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

        uint8_t dnp3_pdu[] = {0x05, 0x64, 0x05, 0xc4, 0x01, 0x00, 0x00, 0x04};
        uint8_t socks5_pdu[] = {0x05, 0x01, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01};

        return bind.is_not_empty() && request.is_not_empty() && request_json_valid && auth3.is_not_empty() && auth3_json_valid &&
            bind_with_incomplete_context.is_not_empty() && bind_with_incomplete_context_data.is_not_empty() &&
            response_with_short_body.is_not_empty() && response_with_short_body_data.is_not_empty() &&
            fault_with_short_body.is_not_empty() && fault_with_short_body_data.is_empty() &&
            bind_nak.is_not_empty() && bind_nak_data.is_empty() && bind_nak_json_valid &&
            bind_ack_with_incomplete_results.is_not_empty() && bind_ack_with_incomplete_results_data.is_not_empty() &&
            auth3_without_auth.is_not_empty() && auth3_without_auth_data.is_empty() &&
            !auth3_bad_padding.is_not_empty() && auth3_bad_padding_data.is_null() &&
            !incomplete_syntax.is_not_empty() && incomplete_syntax_data.is_null() && !bad.is_not_empty() &&
            truncated_json_valid &&
            bind_ack.is_not_empty() && bind_ack_json_valid &&
            auth_fields_valid &&
            alter_context_resp.is_not_empty() && alter_context_resp_json_valid &&
            !truncated_header.is_not_empty() && truncated_header_data.is_null() &&
            partial_request.is_not_empty() && partial_request.is_truncated() && partial_request_data.is_empty() &&
            strcmp(authentication_level_name(authentication_level::default_level), "default") == 0 &&
            strcmp(authentication_level_name(authentication_level::none), "none") == 0 &&
            strcmp(authentication_level_name(authentication_level::connect), "connect") == 0 &&
            strcmp(authentication_level_name(authentication_level::call), "call") == 0 &&
            strcmp(authentication_level_name(authentication_level::packet), "packet") == 0 &&
            strcmp(authentication_level_name(authentication_level::packet_integrity), "packet_integrity") == 0 &&
            strcmp(authentication_level_name(authentication_level::packet_privacy), "packet_privacy") == 0 &&
            authentication_level_name(static_cast<authentication_level>(7)) == nullptr &&
            is_client_pdu_type(pdu_type::bind) &&
            is_client_pdu_type(pdu_type::request) &&
            is_client_pdu_type(pdu_type::auth_3) &&
            !is_client_pdu_type(pdu_type::response) &&
            !is_client_pdu_type(pdu_type::fault) &&
            !is_client_pdu_type(pdu_type::bind_ack) &&
            low_ptype_matcher.matches(bind_pdu, sizeof(bind_pdu)) &&
            low_ptype_matcher.matches(request_pdu, sizeof(request_pdu)) &&
            high_ptype_matcher.matches(auth3_pdu, sizeof(auth3_pdu)) &&
            !low_ptype_matcher.matches(dnp3_pdu, sizeof(dnp3_pdu)) &&
            !high_ptype_matcher.matches(dnp3_pdu, sizeof(dnp3_pdu)) &&
            !low_ptype_matcher.matches(socks5_pdu, sizeof(socks5_pdu)) &&
            !high_ptype_matcher.matches(socks5_pdu, sizeof(socks5_pdu));
    }
    // LCOV_EXCL_STOP

    [[maybe_unused]] inline int message_fuzz_test(const uint8_t *data, size_t size)
    {
        return json_output_fuzzer<message>(data, size);
    }
}

#endif
