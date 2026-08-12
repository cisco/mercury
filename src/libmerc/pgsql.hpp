/*
 * pgsql.hpp
 *
 * Copyright (c) 2025 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

/*
 * \file pgsql.hpp
 *
 * \brief PostgreSQL frontend/backend protocol v3 parser (TCP/5432).
 *
 * Wire format reference:
 * https://www.postgresql.org/docs/current/protocol-message-formats.html
 *
 * Two packet shapes are parsed:
 *
 *   Regular (tagged) message:
 *     +-------+----------------+-------------------+
 *     | type  | length (BE32)  |     payload       |
 *     +-------+----------------+-------------------+
 *       1 B          4 B           length - 4 B
 *   `length` includes itself but not the 1-byte tag.
 *
 *   "Special" first-contact packet (StartupMessage, SSL/GSS/Cancel
 *   request): no type tag, discriminated by `tag`:
 *     +----------------+----------------+-------------------+
 *     | length (BE32)  |   tag (BE32)   |     payload       |
 *     +----------------+----------------+-------------------+
 *         4 B               4 B            length - 8 B
 *   Reserved tags: 80877103 SSL, 80877104 GSSAPI, 80877102 Cancel.
 *   Anything else is the protocol version => StartupMessage, whose
 *   payload is `key\0value\0 ... \0` (empty key terminates).
 */
#ifndef PGSQL_HPP
#define PGSQL_HPP

#include "json_object.h"
#include "protocol.h"
#include "cbor_object.hpp"
#include "lex.h"
#include "exposed_creds.hpp"

class pgsql_msg : public base_protocol {

    enum class auth_codes : uint32_t {
        success = 0,
        kerb4 = 1,
        kerb5 = 2,
        plain_pass = 3,
        crypt_pass = 4,
        md5_pass = 5,
        scm_cred = 6,
        gssapi = 7,
        gss_sspi_cont = 8,
        sspi = 9,
        sasl = 10,
        sasl_cont = 11,
        sasl_comp = 12,
        unknown = 13
    };

    static const char *get_auth_type(auth_codes code) {
        static constexpr const char *kAuthTypeNames[] = {
            "success",              // 0
            "kerberos_v4",          // 1
            "kerberos_v5",          // 2
            "plaintext_password",   // 3
            "crypted_password",     // 4
            "md5_password",         // 5
            "scm_credentials",      // 6
            "gssapi",               // 7
            "gssapi_sspi_continue", // 8
            "sspi_authentication",  // 9
            "sasl_authentication",  // 10
            "sasl_continue",        // 11
            "sasl_complete",        // 12
            "unknown"               // 13
        };
        static constexpr size_t kAuthTypeCount =
            sizeof(kAuthTypeNames) / sizeof(kAuthTypeNames[0]);

        uint32_t idx = static_cast<uint32_t>(code);
        if (idx >= kAuthTypeCount) {
            idx = static_cast<uint32_t>(auth_codes::unknown);
        }
        return kAuthTypeNames[idx];
    }

    static null_terminated_string get_auth_data_type(auth_codes code) {
        // TODO: identify what type of content the other auth types have
        switch (code) {
        case auth_codes::md5_pass:
            return "salt";
        case auth_codes::plain_pass:
            return "password";
        default:
            return "content";
        };
    };

    static constexpr uint32_t ssl_request_code = 80877103;  // {1234}{5679}
    static constexpr uint32_t cancel_request_code = 80877102;   // {1234}{5678}
    static constexpr uint32_t gss_encrypt_code = 80877104;  // {1234}{5680}

    static null_terminated_string get_special_msg_type (uint32_t type) {
        switch (type) {
        case ssl_request_code:
            return "ssl_request";
        case cancel_request_code:
            return "cancel_request";
        case gss_encrypt_code:
            return "gss_encrypt_request";

        default:
            return "startup_message";
        };
    }

    static null_terminated_string get_client_message_code (const char &c) {
        switch (c) {
        case 'p':
            return "authentication_msg";
        case 'Q':
            return "query";
        case 'P':
            return "parse";
        case 'B':
            return "bind";
        case 'E':
            return "execute";
        case 'D':
            return "describe";
        case 'C':
            return "close";
        case 'H':
            return "flush";
        case 'S':
            return "sync";
        case 'F':
            return "function_call";
        case 'd':
            return "copy_data";
        case 'c':
            return "copy_complete";
        case 'f':
            return "copy_failure";
        case 'X':
            return "termination";

        default:
            return "unknown_client_message";
        };
    }

    static null_terminated_string get_server_message_code (const char &c) {
        switch (c) {
        case 'R':
            return "authentication_request";
        case 'K':
            return "backend_key_data";
        case 'S':
            return "parameter_status";
        case '1':
            return "parse_complete";
        case '2':
            return "bind_complete";
        case '3':
            return "close_complete";
        case 'C':
            return "command_complete";
        case 't':
            return "parameter_description";
        case 'T':
            return "row_description";
        case 'D':
            return "data_row";
        case 'I':
            return "empty_query";
        case 'n':
            return "no_data";
        case 'E':
            return "error";
        case 'N':
            return "notice";
        case 's':
            return "portal_suspend";
        case 'Z':
            return "ready_for_query";
        case 'A':
            return "notification";
        case 'V':
            return "function_call_response";
        case 'G':
            return "copy_in_response";
        case 'H':
            return "copy_out_response";
        case 'd':
            return "copy_data";
        case 'c':
            return "copy_complete";
        case 'v':
            return "negotiate_protocol_version";

        default:
            return "unknown_server_message";
        };
    }

    /// Tagged regular pgsql message: `type | length(BE32) | payload`.
    /// `length` includes itself but not `type`, so `msg_data` is `len-4`.
    struct pgsql_pkt {
        encoded<uint8_t> msg_type;
        encoded<uint32_t> len;
        datum msg_data;

        pgsql_pkt(datum &d) : msg_type{d}, len{d} {
            if (len < 4) {
                msg_data.set_null();
                return;
            }
            msg_data.parse(d,len-4);
        };

        pgsql_pkt() : msg_type{0}, len{0}, msg_data{} {};

        pgsql_pkt(const pgsql_pkt &pkt) : msg_type{pkt.msg_type}, len{pkt.len}, msg_data{pkt.msg_data} {}

        pgsql_pkt& operator = (const pgsql_pkt &pkt) {
            msg_type = pkt.msg_type;
            len = pkt.len;
            msg_data = pkt.msg_data;
            return *this;
        };

        bool is_valid() { return msg_data.is_not_null(); };

        /// Character class for the printable-ASCII heuristic used to
        /// distinguish a cleartext password from a binary SASL/GSS payload
        /// that shares the 'p' message code.
        class printable_ascii : public one_or_more<printable_ascii> {
        public:
            inline static bool in_class(uint8_t x) {
                return x >= 0x20 && x <= 0x7e;
            }
        };

        /// SCRAM-SHA-{1,256} messages share the 'p' code with cleartext
        /// PasswordMessage. Client-first messages start with the gs2-header
        /// `n,,` (or `y,,`), client-final messages with `c=`, and
        /// server-final messages with `v=`. Detecting these prefixes lets
        /// us avoid mis-classifying a base64-encoded SCRAM payload as a
        /// plaintext password (the bytes are all printable ASCII).
        static bool looks_like_scram(const datum &body) {
            datum tmp = body;
            if (lookahead<literal_byte<'n', ',', ','>>{tmp}) { return true; }
            if (lookahead<literal_byte<'y', ',', ','>>{tmp}) { return true; }
            if (lookahead<literal_byte<'c', '='>>{tmp})      { return true; }
            if (lookahead<literal_byte<'v', '='>>{tmp})      { return true; }
            return false;
        }

        /// Classify the credential exposure represented by this message.
        /// Only client password messages ('p') are considered. For SASL/GSS
        /// exchanges and md5-hashed passwords we report a non-plaintext
        /// type. This is a heuristic since 'p' is used for several
        /// authentication-response sub-types without a discriminator.
        exposed_creds_type credential_exposure() const {
            if (msg_type.value() != 'p' || msg_data.is_null() || msg_data.is_empty()) {
                return exposed_creds_type::none;
            }
            datum body = msg_data;
            // PasswordMessage is a NUL-terminated string; drop a single
            // trailing NUL if present so the size match below is exact.
            ssize_t blen = body.length();
            if (blen > 0 && body.data[blen - 1] == 0) {
                body.data_end = body.data + blen - 1;
                blen--;
            }
            if (blen <= 0) {
                return exposed_creds_type::none;
            }
            // md5-hashed password: literal "md5" + exactly 32 hex digits.
            if (blen == 35) {
                datum tmp = body;
                literal_byte<'m', 'd', '5'> md5_prefix{tmp};
                exactly_n<hex_digits> hex{tmp, 32};
                if (hex.is_not_null()) {
                    return exposed_creds_type::password_derived;
                }
            }
            // SCRAM-SHA payloads are base64 and therefore printable ASCII,
            // so check for SCRAM framing before the plaintext heuristic.
            if (looks_like_scram(body)) {
                return exposed_creds_type::none;
            }
            // Treat as plaintext only when *every* byte is printable ASCII
            // (no embedded NULs, control chars, or binary). SASL/GSS
            // payloads are typically binary and will not match.
            datum tmp = body;
            exactly_n<printable_ascii> printable{tmp, (size_t)blen};
            if (printable.is_not_null()) {
                return exposed_creds_type::plaintext_password;
            }
            return exposed_creds_type::none;
        }

        void write_json(json_array &a, bool client) {
            // TODO: identify what data to report for other msg types
            if (msg_type.value() == 'p') {
                // auth message
                json_object o(a);
                json_object r(o,get_client_message_code('p'));
                r.print_key_string("content_type", "password_message");
                r.print_key_json_string("content",msg_data);
                r.close();
                o.close();
            }
            else if (msg_type.value() == 'R') {
                // auth request: 4-byte auth code followed by optional payload.
                // Use a local datum so a truncated payload doesn't silently
                // get decoded as auth_code = 0 (success).
                datum d = msg_data;
                encoded<uint32_t> auth_type{d};
                if (d.is_null()) {
                    return;
                }
                auth_codes auth_code = static_cast<auth_codes>(auth_type.value());
                json_object o(a);
                json_object r(o, get_server_message_code('R'));
                r.print_key_string("content_type", get_auth_type(auth_code));
                if (auth_code == auth_codes::md5_pass) {
                    r.print_key_hex(get_auth_data_type(auth_code), d);
                } else {
                    r.print_key_json_string(get_auth_data_type(auth_code), d);
                }
                r.close();
                o.close();
            }
            else if (msg_type.value() == 'S' && !client) {
                // parameter status: param_name '\0' param_value '\0'
                one_or_more_up_to_delimiter<'\0'> param_name{msg_data};
                one_or_more_up_to_delimiter<'\0'> param_value{msg_data};
                if (param_name.is_not_null() && param_value.is_not_null()) {
                    json_object o(a);
                    json_object r(o,get_server_message_code('S'));
                    r.print_key_json_string("param_type",param_name);
                    r.print_key_json_string("param_value",param_value);
                    r.close();
                    o.close();
                }

            }
            else if (msg_type.value() == 'K' && !client) {
                // pid and key
                if (msg_data.length() != 8 ) {
                    return;
                }
                encoded<uint32_t> pid{msg_data};
                encoded<uint32_t> key{msg_data};
                json_object o(a);
                json_object r(o,get_server_message_code('K'));
                r.print_key_int("pid",pid);
                r.print_key_int("key",key);
                r.close();
                o.close();

            }
            else if (client) {
                json_object o(a);
                json_object r(o,get_client_message_code(msg_type.value()));
                r.print_key_int("msg_len", msg_data.length());
                r.close();
                o.close();
            }
            else {
                json_object o(a);
                json_object r(o, get_server_message_code(msg_type.value()));
                r.print_key_int("msg_len", msg_data.length());
                r.close();
                o.close();
            }
        }

    };

    /// Untagged first-contact packet: `length(BE32) | tag(BE32) | payload`.
    /// `tag` is one of the reserved request codes; any other value is a
    /// protocol version and marks the packet as a StartupMessage.
    struct pgsql_special_pkt {
        encoded<uint32_t> len;
        encoded<uint32_t> tag;
        datum msg_data;
        bool startup = false;

        pgsql_special_pkt(datum &d) : len{d}, tag{d} {
            if (len < 8) {
                msg_data.set_null();
                return;
            }
            msg_data.parse(d,len-8);
            if (tag != ssl_request_code && tag != gss_encrypt_code && tag != cancel_request_code) {
                startup = true;
            }
        };

        pgsql_special_pkt() : len{0}, tag{0}, msg_data{} {};

        pgsql_special_pkt(const pgsql_special_pkt &pkt) : len{pkt.len}, tag{pkt.tag}, msg_data{pkt.msg_data}, startup{pkt.startup} {};

        pgsql_special_pkt& operator = (const pgsql_special_pkt &pkt) {
            len = pkt.len;
            tag = pkt.tag;
            msg_data = pkt.msg_data;
            startup = pkt.startup;
            return *this;
        };

        bool is_valid() { return msg_data.is_not_null(); };

        void write_json(json_array &record, [[maybe_unused]]bool metadata ) {
            json_object o(record);
            json_object r(o, get_special_msg_type(tag.value()));
            if (startup) {
                // Protocol version is encoded in the tag for StartupMessage:
                // high 16 bits = major, low 16 bits = minor.
                r.print_key_uint("protocol_major", tag.value() >> 16);
                r.print_key_uint("protocol_minor", tag.value() & 0xffff);

                // Deferred array: omit `parameters` entirely when no pairs.
                json_array params{r, "parameters", /*omit_if_empty=*/true};
                datum tmp = msg_data;
                while (tmp.is_not_empty()) {
                    if (lookahead<literal_byte<'\0'>>{tmp}) {
                        tmp.skip(1);
                        break;
                    }
                    one_or_more_up_to_delimiter<'\0'> k{tmp};
                    one_or_more_up_to_delimiter<'\0'> v{tmp};
                    if (k.is_null() || v.is_null()) { break; }
                    if (k.is_not_empty() && v.is_not_empty()) {
                        json_object kv{params};
                        kv.print_key_json_string("key", k);
                        kv.print_key_json_string("value", v);
                        kv.close();
                    }
                }
                params.close();
            } else {
                // SSL/GSS/Cancel requests have no payload of interest, but we
                // still emit a stable field so the record is never an empty
                // object (per the JSON output guidelines).
                r.print_key_uint("msg_len", len.value());
            }
            r.close();
            o.close();
        }

    };

    bool is_client = false;
    bool has_special_pkt = false;   // special pkt, no message list - either startup, SSL request, GSSAPI request or cancel request pkt


    static constexpr uint8_t max_msg_count = 10;    // report messages less than or equal to max_msg_count
    pgsql_pkt msg_list[max_msg_count];
    uint8_t msg_count = 0;
    pgsql_special_pkt special_pkt;
    bool valid = true;



    /// Returns true when `pkt` begins with a special "first-contact"
    /// PostgreSQL packet (StartupMessage, SSL/GSS/Cancel request).
    ///
    /// Discrimination by "first byte == 0" alone is unreliable: it
    /// assumes the length field's MSB is zero, which fails for
    /// (admittedly rare) packets >= 16 MiB. Instead we peek at the
    /// 4-byte tag at offset 4 and accept only the three reserved
    /// request codes or a recognised v3 protocol version
    /// (high 16 bits == 0x0003).
    static bool looks_like_special(const datum &pkt) {
        datum tmp = pkt;
        lookahead<encoded<uint32_t>> len{tmp};
        if (!len) {
            return false;
        }
        lookahead<encoded<uint32_t>> tag{len};
        if (!tag) {
            return false;
        }
        uint32_t t = tag.value.value();
        if (t == ssl_request_code
            || t == gss_encrypt_code
            || t == cancel_request_code) {
            return true;
        }
        // StartupMessage: high 16 bits encode the protocol major version.
        // Only v3 (0x0003) is defined; treat that as the discriminator
        // rather than "any non-reserved value", to avoid accidentally
        // matching tagged messages.
        return (t >> 16) == 0x0003;
    }

public:
    pgsql_msg (datum pkt, uint16_t src_port){
        is_client = (src_port != hton<uint16_t>(5432));
        if (pkt.is_not_readable()) {
            valid = false;
            return;
        }
        if (looks_like_special(pkt)) {
            has_special_pkt = true;
            special_pkt = pgsql_special_pkt{pkt};
            valid = special_pkt.is_valid();
            return;
        }
        else {
            while (pkt.is_not_empty() && msg_count < max_msg_count) {
                msg_list[msg_count] = pgsql_pkt{pkt};
                if (!msg_list[msg_count].is_valid()) {
                    valid = false;
                    return;
                }
                msg_count++;
            }
        }

        if (!has_special_pkt && !msg_count) {
            valid = false;
        }
    };

    bool is_not_empty() { return valid; }

    void write_json(json_object &record, bool metadata) {
        json_object pgsql_record(record,"pgsql");
        pgsql_record.print_key_bool("client",is_client);
        if (has_special_pkt) {
            json_array msg_list_json (pgsql_record, "pgsql_pkts");
            special_pkt.write_json(msg_list_json,metadata);
            msg_list_json.close();
            pgsql_record.close();
            return;
        }
        else {
            json_array msg_list_json (pgsql_record, "pgsql_pkts");
            for (size_t i = 0; i < msg_count; i++) {
                msg_list[i].write_json(msg_list_json, is_client);
            }
            msg_list_json.close();
            pgsql_record.close();
            return;
        }
    }

    /// Returns the type of credential exposed in this message, if any.
    ///
    /// A client PasswordMessage ('p') may carry a plaintext password;
    /// md5-hashed responses are reported as ``password_derived``. SASL and
    /// GSS payloads (which share the 'p' message code) are not classified
    /// as exposed credentials.
    exposed_creds_type check_credential_exposure() const {
        if (!valid || has_special_pkt || !is_client) {
            return exposed_creds_type::none;
        }
        exposed_creds_type worst = exposed_creds_type::none;
        for (size_t i = 0; i < msg_count; ++i) {
            exposed_creds_type t = msg_list[i].credential_exposure();
            // plaintext_password is strictly more severe than password_derived.
            if (t == exposed_creds_type::plaintext_password) {
                return t;
            }
            if (t == exposed_creds_type::password_derived) {
                worst = t;
            }
        }
        return worst;
    }

    // Advertise "pgsql" in the protocols list regardless of the metadata
    // flag (matches telnet/mysql/redis conventions).
    void write_l7_metadata(cbor_object &o, bool) {
        if (!valid) {
            return;
        }
        cbor_array protocols{o, "protocols"};
        protocols.print_string("pgsql");
        protocols.close();
    }

#ifndef NDEBUG
    static bool test_json_output_with_port(const uint8_t *raw_data,
                                           size_t raw_size,
                                           uint16_t src_port,
                                           datum expected_output,
                                           FILE *verbose_output=nullptr) {
        datum raw_input{raw_data, raw_data + raw_size};
        pgsql_msg pkt{raw_input, hton<uint16_t>(src_port)};
        // Every call site of this helper expects the input to parse
        // successfully; surface parse failures as a test failure.
        if (!pkt.is_not_empty()) {
            return false;
        }

        dynamic_buffer_stream buf{(size_t)expected_output.length() + 512};
        json_object json{&buf};
        pkt.write_json(json, false);
        json.close();

        datum result = buf.get_datum();
        if (verbose_output) {
            buf.write_line(verbose_output);
        }
        return result.cmp(expected_output) == 0;
    }

    static bool test_credential_exposure(const uint8_t *raw_data,
                                         size_t raw_size,
                                         uint16_t src_port,
                                         exposed_creds_type expected) {
        datum raw_input{raw_data, raw_data + raw_size};
        pgsql_msg pkt{raw_input, hton<uint16_t>(src_port)};
        if (!pkt.is_not_empty()) {
            return expected == exposed_creds_type::none;
        }
        return pkt.check_credential_exposure() == expected;
    }

    static bool unit_test() {
        // client authentication message: 'p'
        static constexpr uint8_t client_auth_msg[] = {
            0x70, 0x00, 0x00, 0x00, 0x0a, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74
        };
        if (!test_json_output_with_port(
                client_auth_msg, sizeof(client_auth_msg), 1,
                datum{R"({"pgsql":{"client":true,"pgsql_pkts":[{"authentication_msg":{"content_type":"password_message","content":"secret"}}]}})"})) {
            return false;
        }

        // server auth request: md5 with 4-byte salt
        static constexpr uint8_t server_auth_md5[] = {
            0x52, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04
        };
        if (!test_json_output_with_port(
                server_auth_md5, sizeof(server_auth_md5), 5432,
                datum{R"({"pgsql":{"client":false,"pgsql_pkts":[{"authentication_request":{"content_type":"md5_password","salt":"01020304"}}]}})"})) {
            return false;
        }

        // server auth request: success, no extra payload field
        static constexpr uint8_t server_auth_success[] = {
            0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00
        };
        if (!test_json_output_with_port(
                server_auth_success, sizeof(server_auth_success), 5432,
                datum{R"({"pgsql":{"client":false,"pgsql_pkts":[{"authentication_request":{"content_type":"success"}}]}})"})) {
            return false;
        }

        // server parameter status: S
        static constexpr uint8_t server_param_status[] = {
            0x53, 0x00, 0x00, 0x00, 0x19,
            0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00,
            0x55, 0x54, 0x46, 0x38, 0x00
        };
        if (!test_json_output_with_port(
                server_param_status, sizeof(server_param_status), 5432,
                datum{R"({"pgsql":{"client":false,"pgsql_pkts":[{"parameter_status":{"param_type":"client_encoding","param_value":"UTF8"}}]}})"})) {
            return false;
        }

        // special startup packet (first byte is zero, non-special tag => startup_message)
        // single key ("user") followed by the empty-value terminator.
        static constexpr uint8_t startup_msg[] = {
            0x00, 0x00, 0x00, 0x0e, 0x00, 0x03, 0x00, 0x00,
            0x75, 0x73, 0x65, 0x72, 0x00, 0x00
        };
        // The minimal startup carries no real parameters (the "user" entry
        // has an empty value), so only the fixed protocol-version fields
        // appear in the output (no empty `parameters` array).
        if (!test_json_output_with_port(
                startup_msg, sizeof(startup_msg), 1,
                datum{R"({"pgsql":{"client":true,"pgsql_pkts":[{"startup_message":{"protocol_major":3,"protocol_minor":0}}]}})"})) {
            return false;
        }

        // startup packet with full user/database key-value pairs.
        // length = 4 + 4 + len("user") + 1 + len("alice") + 1
        //              + len("database") + 1 + len("postgres") + 1 + 1
        //       = 8 + 5 + 6 + 9 + 9 + 1 = 38 = 0x26
        static constexpr uint8_t startup_msg_full[] = {
            0x00, 0x00, 0x00, 0x26, 0x00, 0x03, 0x00, 0x00,
            'u','s','e','r', 0x00, 'a','l','i','c','e', 0x00,
            'd','a','t','a','b','a','s','e', 0x00,
            'p','o','s','t','g','r','e','s', 0x00,
            0x00
        };
        if (!test_json_output_with_port(
                startup_msg_full, sizeof(startup_msg_full), 1,
                datum{R"({"pgsql":{"client":true,"pgsql_pkts":[{"startup_message":{"protocol_major":3,"protocol_minor":0,"parameters":[{"key":"user","value":"alice"},{"key":"database","value":"postgres"}]}}]}})"})) {
            return false;
        }

        // SSL request: no payload, but we still emit a stable `msg_len` so
        // that the JSON record is never an empty object.
        static constexpr uint8_t ssl_request[] = {
            0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f
        };
        if (!test_json_output_with_port(
                ssl_request, sizeof(ssl_request), 1,
                datum{R"({"pgsql":{"client":true,"pgsql_pkts":[{"ssl_request":{"msg_len":8}}]}})"})) {
            return false;
        }

        // unknown client message type should use safe fallback key
        static constexpr uint8_t unknown_client_msg[] = {
            0x59, 0x00, 0x00, 0x00, 0x04
        };
        if (!test_json_output_with_port(
                unknown_client_msg, sizeof(unknown_client_msg), 1,
                datum{R"({"pgsql":{"client":true,"pgsql_pkts":[{"unknown_client_message":{"msg_len":0}}]}})"})) {
            return false;
        }

        // parameter_status with multiple consecutive key/value pairs in a
        // single message (exercises the one_or_more_up_to_delimiter loop).
        // length = 4 + len("server_version") + 1 + len("16.0") + 1 = 24 = 0x18
        static constexpr uint8_t server_param_status_version[] = {
            0x53, 0x00, 0x00, 0x00, 0x18,
            's','e','r','v','e','r','_','v','e','r','s','i','o','n', 0x00,
            '1','6','.','0', 0x00
        };
        if (!test_json_output_with_port(
                server_param_status_version, sizeof(server_param_status_version), 5432,
                datum{R"({"pgsql":{"client":false,"pgsql_pkts":[{"parameter_status":{"param_type":"server_version","param_value":"16.0"}}]}})"})) {
            return false;
        }

        // credential exposure: client PasswordMessage with plaintext password.
        // Same bytes as client_auth_msg above.
        if (!test_credential_exposure(
                client_auth_msg, sizeof(client_auth_msg), 1,
                exposed_creds_type::plaintext_password)) {
            return false;
        }

        // credential exposure: client PasswordMessage with md5-hashed password
        // ("md5" prefix + 32 hex chars + trailing NUL).
        static constexpr uint8_t client_md5_pass_msg[] = {
            'p', 0x00, 0x00, 0x00, 0x28,
            'm','d','5',
            '0','1','2','3','4','5','6','7','8','9',
            'a','b','c','d','e','f',
            '0','1','2','3','4','5','6','7','8','9',
            'a','b','c','d','e','f',
            0x00
        };
        if (!test_credential_exposure(
                client_md5_pass_msg, sizeof(client_md5_pass_msg), 1,
                exposed_creds_type::password_derived)) {
            return false;
        }

        // credential exposure: SASL-like binary payload should NOT be flagged
        // as a plaintext password.
        static constexpr uint8_t client_binary_pass_msg[] = {
            'p', 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x02, 0x03
        };
        if (!test_credential_exposure(
                client_binary_pass_msg, sizeof(client_binary_pass_msg), 1,
                exposed_creds_type::none)) {
            return false;
        }

        // credential exposure: SCRAM-SHA-256 SASLResponse payloads are
        // base64 (so all-printable) but must not be reported as plaintext.
        // Client-first ("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", 36 bytes;
        // total length includes the 4-byte length field, so 40 = 0x28).
        static constexpr uint8_t client_scram_first[] = {
            'p', 0x00, 0x00, 0x00, 0x28,
            'n', ',', ',', 'n', '=', 'u', 's', 'e', 'r', ',',
            'r', '=', 'f', 'y', 'k', 'o', '+', 'd', '2', 'l',
            'b', 'b', 'F', 'g', 'O', 'N', 'R', 'v', '9', 'q',
            'k', 'x', 'd', 'a', 'w', 'L'
        };
        if (!test_credential_exposure(
                client_scram_first, sizeof(client_scram_first), 1,
                exposed_creds_type::none)) {
            return false;
        }
        // Client-final ("c=biws,r=abc,p=v0X8V3RlI=" = 25 bytes; length
        // field includes itself, so 29 = 0x1d).
        static constexpr uint8_t client_scram_final[] = {
            'p', 0x00, 0x00, 0x00, 0x1d,
            'c', '=', 'b', 'i', 'w', 's', ',',
            'r', '=', 'a', 'b', 'c', ',',
            'p', '=', 'v', '0', 'X', '8', 'V', '3', 'R', 'l', 'I', '='
        };
        if (!test_credential_exposure(
                client_scram_final, sizeof(client_scram_final), 1,
                exposed_creds_type::none)) {
            return false;
        }

        // credential exposure: a server message ('R') never exposes credentials
        // from the client side.
        if (!test_credential_exposure(
                server_auth_md5, sizeof(server_auth_md5), 5432,
                exposed_creds_type::none)) {
            return false;
        }

        // credential exposure: startup messages alone do not expose credentials
        // (the username is not treated as a credential).
        if (!test_credential_exposure(
                startup_msg_full, sizeof(startup_msg_full), 1,
                exposed_creds_type::none)) {
            return false;
        }

        // credential exposure: a non-password client message ('Q' query) is
        // not classified as credential exposure.
        static constexpr uint8_t client_query_msg[] = {
            'Q', 0x00, 0x00, 0x00, 0x0d, 'S','E','L','E','C','T',' ','1', 0x00
        };
        if (!test_credential_exposure(
                client_query_msg, sizeof(client_query_msg), 1,
                exposed_creds_type::none)) {
            return false;
        }

        // empty packet: must not be misclassified as a special packet
        // (an empty pkt would otherwise hit `encoded<uint8_t>` default
        // val = 0 and be treated as a startup message).
        {
            datum empty_in{};
            pgsql_msg empty_pkt{empty_in, hton<uint16_t>(1)};
            if (empty_pkt.is_not_empty()) {
                return false;
            }
        }

        // Tagged message with a length whose MSB happens to be zero
        // (which would have fooled the old "first byte == 0" heuristic
        // had the type tag itself been zero). Here we exercise a normal
        // 'Q' message and ensure it is NOT classified as a special pkt.
        // (Same bytes as client_query_msg above; this assertion is
        // implicit in the JSON-output tests, but adding an explicit
        // case documents the contract.)
        {
            datum in{client_query_msg,
                     client_query_msg + sizeof(client_query_msg)};
            pgsql_msg pkt{in, hton<uint16_t>(1)};
            if (!pkt.is_not_empty()) {
                return false;
            }
            // A regular tagged 'Q' must not produce a special-pkt JSON
            // shape (which would have a `startup_message` / `ssl_request`
            // / ... entry instead of `unknown_client_message`-style).
            if (!test_json_output_with_port(
                    client_query_msg, sizeof(client_query_msg), 1,
                    datum{R"({"pgsql":{"client":true,"pgsql_pkts":[{"query":{"msg_len":9}}]}})"})) {
                return false;
            }
        }

        // Truncated AuthenticationRequest 'R': only 4 bytes of payload
        // claimed but the auth-code field is missing. Must not be
        // mis-reported as auth_code = success.
        static constexpr uint8_t server_auth_truncated[] = {
            'R', 0x00, 0x00, 0x00, 0x05, 0x00
        };
        {
            datum in{server_auth_truncated,
                     server_auth_truncated + sizeof(server_auth_truncated)};
            pgsql_msg pkt{in, hton<uint16_t>(5432)};
            // The truncated 'R' produces a valid (1-message) pgsql_msg
            // but write_json() for that message must NOT print a
            // misleading content_type. We verify by checking that the
            // output does not contain the string "content_type":"success".
            dynamic_buffer_stream buf{512};
            json_object json{&buf};
            if (pkt.is_not_empty()) {
                pkt.write_json(json, false);
            }
            json.close();
            datum result = buf.get_datum();
            const char *needle = "\"content_type\":\"success\"";
            size_t nlen = strlen(needle);
            bool found = false;
            for (ssize_t i = 0; i + (ssize_t)nlen <= result.length(); ++i) {
                if (memcmp(result.data + i, needle, nlen) == 0) {
                    found = true; break;
                }
            }
            if (found) {
                return false;
            }
        }

        return true;
    }
#endif
};

namespace {

    [[maybe_unused]] inline int pgsql_client_fuzz_test(const uint8_t *data, size_t size) {
        struct datum pkt_data{data, data + size};
        char buffer[8192];
        struct buffer_stream buf_json(buffer, sizeof(buffer));
        struct json_object record(&buf_json);
        pgsql_msg pkt_pgsql{pkt_data, hton<uint16_t>(1)};
        if (pkt_pgsql.is_not_empty()) {
            pkt_pgsql.write_json(record, true);
        }

        return 0;
    }

    [[maybe_unused]] inline int pgsql_server_fuzz_test(const uint8_t *data, size_t size) {
        struct datum pkt_data{data, data + size};
        char buffer[8192];
        struct buffer_stream buf_json(buffer, sizeof(buffer));
        struct json_object record(&buf_json);
        pgsql_msg pkt_pgsql{pkt_data, hton<uint16_t>(5432)};
        if (pkt_pgsql.is_not_empty()) {
            pkt_pgsql.write_json(record, true);
        }

        return 0;
    }

}  // namespace

#endif  // PGSQL_HPP
