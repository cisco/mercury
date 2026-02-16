/*
 * pgsql.hpp
 *
 * Copyright (c) 2025 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

/*
 * \file pgsql.hpp
 *
 * \brief PostgreSQL protocol parser implementation and interface
 */
#ifndef PGSQL_HPP
#define PGSQL_HPP

#include "json_object.h"
#include "protocol.h"
#include "cbor_object.hpp"

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

    static const char *get_auth_data_type(auth_codes code) {
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

    static constexpr uint32_t startup_code = 196608;
    static constexpr uint32_t ssl_request_code = 80877103;  // {1234}{5679}
    static constexpr uint32_t cancel_request_code = 80877102;   // {1234}{5678}
    static constexpr uint32_t gss_encrypt_code = 80877104;  // {1234}{5680}

    static const char *get_special_msg_type (uint32_t type) {
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

    static const char *get_client_message_code (const char &c) {
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

    static const char *get_server_message_code (const char &c) {
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

        void write_json(json_array &a, bool client) {
            // TODO: identify what data to report for other msg types
            if (msg_type.value() == 'p') {
                // auth message
                json_object o(a);
                json_object r(o,get_client_message_code('p'));
                //o.print_key_string("msg_type",get_client_message_code('p'));
                r.print_key_string("content_type", "password_message");
                r.print_key_json_string("content",msg_data);
                r.close();
                o.close();
            }
            else if (msg_type.value() == 'R') {
                // auth request
                json_object o(a);
                json_object r(o, get_server_message_code('R'));
                //o.print_key_string("msg_type",get_server_message_code('R'));
                encoded<uint32_t> auth_type{msg_data};
                auth_codes auth_code = static_cast<auth_codes>(auth_type.value());
                r.print_key_string("content_type", get_auth_type(auth_code));
                if (auth_code == auth_codes::md5_pass) {
                    r.print_key_hex(get_auth_data_type(auth_code), msg_data);
                } else {
                    r.print_key_json_string(get_auth_data_type(auth_code), msg_data);
                }
                r.close();
                o.close();
            }
            else if (msg_type.value() == 'S' && !client) {
                // parameter status
                datum param_name{};
                datum param_value{};
                param_name.parse_up_to_delim(msg_data, '\0');
                if (msg_data.is_not_readable() || lookahead<encoded<uint8_t>>{msg_data}.value.value() != '\0') {
                    return;
                }
                msg_data.skip(1);
                param_value.parse_up_to_delim(msg_data, '\0');
                if (msg_data.is_not_readable() || lookahead<encoded<uint8_t>>{msg_data}.value.value() != '\0') {
                    return;
                }
                msg_data.skip(1);
                if (param_name.is_not_null() && param_value.is_not_null() && msg_data.is_not_null()) {
                    json_object o(a);
                    json_object r(o,get_server_message_code('S'));
                    //o.print_key_string("msg_type",get_server_message_code('S'));
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
                //o.print_key_string("msg_type",get_server_message_code('K'));
                r.print_key_int("pid",pid);
                r.print_key_int("key",key);
                r.close();
                o.close();

            }
            else if (client) {
                json_object o(a);
                json_object r(o,get_client_message_code(msg_type.value()));
                //o.print_key_char("msg_type",get_client_message_code(msg_type.value()));
                r.print_key_int("msg_len", msg_data.length());
                r.close();
                o.close();
            }
            else {
                json_object o(a);
                json_object r(o, get_server_message_code(msg_type.value()));
                //o.print_key_char("msg_type",get_server_message_code(msg_type.value()));
                r.print_key_int("msg_len", msg_data.length());
                r.close();
                o.close();
            }
        }

    };

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
                datum tmp = msg_data;
                // TODO: Optionally parse PostgreSQL startup message key/value pairs into
                // individual JSON fields instead of emitting raw msg_data.
                if (tmp.is_not_empty()) {
                    r.print_key_json_string("msg_data", tmp);
                }
            }
            r.close();
            o.close();
        }
    };

    bool is_client = false;
    bool startup_msg = false;
    bool has_special_pkt = false;   // special pkt, no message list - either startup, SSL request, GSSAPI request or cancel request pkt


    static constexpr uint8_t max_msg_count = 10;    // report messages less than or equal to max_msg_count
    pgsql_pkt msg_list[max_msg_count];
    uint8_t msg_count = 0;
    pgsql_special_pkt special_pkt;
    bool valid = true;



public:
    pgsql_msg (datum pkt, uint16_t src_port){
        is_client = (src_port != hton<uint16_t>(5432));
        encoded<uint8_t> first_byte = lookahead<encoded<uint8_t> >{pkt}.value;
        if (!first_byte.value()) {
            has_special_pkt = true;
        }
        if (has_special_pkt) {
            // read the special pkt
            special_pkt = pgsql_special_pkt{pkt};
            startup_msg = special_pkt.startup;
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

    // write L7 metadata so that "pgsql" appears in the protocols list
    void write_l7_metadata(cbor_object &o, bool metadata) {
        if (!metadata || !valid) {
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
        if (!raw_input.is_not_null()) {
            return false;
        }

        dynamic_buffer_stream buf{(size_t)expected_output.length() + 512};
        json_object json{&buf};
        if (pkt.is_not_empty()) {
            pkt.write_json(json, false);
        }
        json.close();

        datum result = buf.get_datum();
        if (verbose_output) {
            buf.write_line(verbose_output);
        }
        return result.cmp(expected_output) == 0;
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
        static constexpr uint8_t startup_msg[] = {
            0x00, 0x00, 0x00, 0x0e, 0x00, 0x03, 0x00, 0x00,
            0x75, 0x73, 0x65, 0x72, 0x00, 0x00
        };
        if (!test_json_output_with_port(
                startup_msg, sizeof(startup_msg), 1,
                datum{R"({"pgsql":{"client":true,"pgsql_pkts":[{"startup_message":{"msg_data":"user\u0000\u0000"}}]}})"})) {
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

        return true;
    }

    static inline bool unit_test_passed = unit_test();
#endif
};

namespace {

    [[maybe_unused]] int pgsql_client_fuzz_test(const uint8_t *data, size_t size) {
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

    [[maybe_unused]] int pgsql_server_fuzz_test(const uint8_t *data, size_t size) {
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
