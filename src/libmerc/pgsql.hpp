/*
 * pqsql.hpp
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

/*
 * \file pqsql.hpp
 *
 * \brief interface file for postgresql messages
 */
#ifndef PGSQL_HPP
#define PGSQL_HPP

#include "json_object.h"
#include "protocol.h"

class pgsql_msg : public base_protocol {

    enum class auth_codes : uint16_t {
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
        switch (code) {
        case auth_codes::success:
            return "success";
        case auth_codes::kerb4:
            return "kerberos_v4";
        case auth_codes::kerb5:
            return "kerberos_v5";
        case auth_codes::plain_pass:
            return "plaintext_password";
        case auth_codes::crypt_pass:
            return "crypted_password";
        case auth_codes::md5_pass:
            return "md5_password";
        case auth_codes::scm_cred:
            return "scm_credentials";
        case auth_codes::gssapi:
            return "gssapi";
        case auth_codes::gss_sspi_cont:
            return "gssapi_sspi_continue";
        case auth_codes::sspi:
            return "sspi_authentication";
        case auth_codes::sasl:
            return "sasl_authentication";
        case auth_codes::sasl_cont:
            return "sasl_continue";
        case auth_codes::sasl_comp:
            return "sasl_complete";
        default:
            return "unknown";
        };
    }

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
            return &c;
        };
    }

    static const char *get_server_message_code (const char &c) {
        switch (c) {
        case 'R':
            return "authentication_request";
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
            return &c;
        };
    }

    struct pgsql_pkt {
        encoded<uint8_t> msg_type;
        encoded<uint32_t> len;
        datum msg_data;

        pgsql_pkt(datum &d) : msg_type{d}, len{d} {
            msg_data.parse(d,len);
        };

        pgsql_pkt() : msg_type{0}, len{0}, msg_data{} {};

        pgsql_pkt operator = (const pgsql_pkt &pkt) {
            msg_type = pkt.msg_type;
            len = pkt.len;
            msg_data = pkt.msg_data;
            return *this;
        };

        bool is_valid() { return msg_data.is_not_null() && len == (4 + 4 + msg_data.length()); };

    };

    struct pgsql_special_pkt {
        encoded<uint32_t> len;
        encoded<uint32_t> tag;
        datum msg_data;
        bool startup = false;

        pgsql_special_pkt(datum &d) : len{d}, tag{d} {
            msg_data.parse(d,len);
            if (tag != ssl_request_code && tag != gss_encrypt_code && tag != cancel_request_code) {
                startup = true;
            }
        };

        pgsql_special_pkt() : len{0}, tag{0}, msg_data{} {};

        pgsql_special_pkt operator = (const pgsql_special_pkt &pkt) {
            len = pkt.len;
            tag = pkt.tag;
            msg_data = pkt.msg_data;
            startup = pkt.startup;
            return *this;
        };

        bool is_valid() { return msg_data.is_not_null() && len == (4 + 4 + msg_data.length()); };

        void write_json(json_object &record, bool metadata ) {
            record.print_key_string("msg_type", get_special_msg_type(tag.value()));
            if (startup) {
                datum tmp = msg_data;
                while (tmp.is_not_empty()) {
                    if (! lookahead<encoded<uint8_t> >{tmp}.value.value() ) {
                        // null character reached, break
                        break;
                    }
                    datum field_name{};
                    datum field_value{};
                    field_name.parse_up_to_delim(tmp, '\0');
                    tmp.skip(1);
                    field_value.parse_up_to_delim(tmp, '\0');
                    tmp.skip(1);
                    if (field_name.is_not_null() && field_value.is_not_null() && tmp.is_not_null()) {
                        record.print_key_json_string(field_name,field_value);
                    }
                }
                return;
            }
        }
    };

    bool is_client = false;
    bool startup_msg = false;
    bool has_special_pkt = false;   // special pkt, no message list - either startup, SSL request, GSSAPI request or cancel request pkt
    datum body;

    static constexpr uint8_t max_msg_count = 10;    // report messages less than or equal to max_msg_count
    pgsql_pkt msg_list[max_msg_count];
    uint8_t msg_count = 0;
    pgsql_special_pkt special_pkt;
    bool is_valid = true;



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
            is_valid = special_pkt.is_valid();
            return;
        }
        else {
            while (pkt.is_not_empty() && msg_count < max_msg_count) {
                msg_list[msg_count] = pgsql_pkt{pkt};
                if (!msg_list[msg_count].is_valid()) {
                    is_valid = false;
                    return;
                }
                msg_count++;
            }
        }
    };

    bool is_valid() { return is_valid;}

    void write_json(json_object &record, bool metadata) {
        json_object pgsql_record(record,"pgsql");
        if (has_special_pkt) {
            special_pkt.write_json(pgsql_record,metadata);
            pgsql_record.close();
            return;
        }
        else {

        }
    }
};

#endif  // PGSQL_HPP 