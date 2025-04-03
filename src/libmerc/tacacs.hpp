// tacacs.hpp

#ifndef TACACS_HPP
#define TACACS_HPP

#include "datum.h"
#include "protocol.h"
#include "json_object.h"
#include "match.h"

namespace tacacs {


    //  5.1. The Authentication START Packet Body
    //
    //  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
    // +----------------+----------------+----------------+----------------+
    // |    action      |    priv_lvl    |  authen_type   | authen_service |
    // +----------------+----------------+----------------+----------------+
    // |    user_len    |    port_len    |  rem_addr_len  |    data_len    |
    // +----------------+----------------+----------------+----------------+
    // |    user ...
    // +----------------+----------------+----------------+----------------+
    // |    port ...
    // +----------------+----------------+----------------+----------------+
    // |    rem_addr ...
    // +----------------+----------------+----------------+----------------+
    // |    data...
    // +----------------+----------------+----------------+----------------+
    //
    class authentication_start {
        encoded<uint8_t> action;
        encoded<uint8_t> priv_lvl;
        encoded<uint8_t> authen_type;
        encoded<uint8_t> authen_service;
        encoded<uint8_t> user_len;
        encoded<uint8_t> port_len;
        encoded<uint8_t> rem_addr_len;
        encoded<uint8_t> data_len;
        datum user;
        datum port;
        datum rem_addr;
        datum data;

    public:

        authentication_start(datum &d) :
            action{d},
            priv_lvl{d},
            authen_type{d},
            authen_service{d},
            user_len{d},
            port_len{d},
            rem_addr_len{d},
            data_len{d},
            user{d, user_len},
            port{d, port_len},
            rem_addr{d, rem_addr_len},
            data{d, data_len}
        { }

        bool is_valid() const { return data.is_not_null(); }

        void write_json(json_object &o) const {
            if (!is_valid()) {
                return;
            }
            json_object auth_start_json{o, "authentication_start"};
            auth_start_json.print_key_uint("action", action);
            auth_start_json.print_key_uint("priv_lvl", priv_lvl);
            auth_start_json.print_key_uint("authen_type", authen_type);
            auth_start_json.print_key_uint("authen_service", authen_service);
            auth_start_json.print_key_json_string("user", user);
            auth_start_json.print_key_json_string("port", port);
            auth_start_json.print_key_json_string("rem_addr", rem_addr);
            auth_start_json.print_key_json_string("data", data);
            auth_start_json.close();
        }
    };

    // 4.1. The TACACS+ Packet Header
    //
    // All TACACS+ packets begin with the following 12-byte header. The header describes the remainder of the packet:
    //
    //  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
    // +----------------+----------------+----------------+----------------+
    // |major  | minor  |                |                |                |
    // |version| version|      type      |     seq_no     |   flags        |
    // +----------------+----------------+----------------+----------------+
    // |                                                                   |
    // |                            session_id                             |
    // +----------------+----------------+----------------+----------------+
    // |                                                                   |
    // |                              length                               |
    // +----------------+----------------+----------------+----------------+
    //
    class packet : public base_protocol {
        encoded<uint8_t> version;
        encoded<uint8_t> type;
        encoded<uint8_t> seq_no;
        encoded<uint8_t> flags;
        encoded<uint32_t> session_id;
        encoded<uint32_t> length;
        datum body;

    public:

        packet(datum &d) :
            version{d},
            type{d},
            seq_no{d},
            flags{d},
            session_id{d},
            length{d},
            body{d}
        { }

        bool is_not_empty() const {
            //
            // consistency checks, as per RFC 8907:
            //
            //    - accept versions 12.0 and 12.1
            //    - accept type = 0, 1, 2, or 3
            //    - require that body.lenth() == length.value()
            //
            return ((version.value() & 0xfe) == 0xc0) and ((type.value() & 0xfc) == 0x00) and body.length() == length.value();
        }

        void write_json(json_object &o, bool) const {
            if (!is_not_empty()) {
                return;
            }
            json_object tacacs_json{o, "tacacs_plus"};
            tacacs_json.print_key_uint("major_version", version.slice<0,4>());
            tacacs_json.print_key_uint("minor_version", version.slice<4,8>());
            print_type_code(tacacs_json);
            tacacs_json.print_key_uint("seq_no", seq_no);
            print_flags(tacacs_json);
            tacacs_json.print_key_uint_hex("session_id", session_id.value());

            if (flags.bit<7>()) {             // unencrypted
                if (type.value() == 0x01) {
                    if (lookahead<authentication_start> as{body}) {
                        as.value.write_json(tacacs_json);
                    }
                } else {
                    tacacs_json.print_key_hex("unencrypted_body", body);
                }
            } else {                          // encrypted
                tacacs_json.print_key_hex("encrypted_body", body);
            }
            tacacs_json.close();
        }

        void print_type_code(json_object &o) const {
            const char *result = nullptr;
            switch(type.value()) {
            case 0x01:
                result = "authentication";  // TAC_PLUS_AUTHEN := 0x01 (Authentication)
                break;
            case 0x02:
                result = "authorization";   // TAC_PLUS_AUTHOR := 0x02 (Authorization)
                break;
            case 0x03:
                result = "accounting";      // TAC_PLUS_ACCT := 0x03 (Accounting)
                break;
            default:
                ;
            }
            if (result) {
                o.print_key_string("type", result);
            } else {
                o.print_key_unknown_code("type", type);
            }
        }

        void print_flags(json_object &o) const {
            if (flags.value()) {
                json_array flags_array{o, "flags"};
                if (flags.bit<7>()) {
                    flags_array.print_string("unencrypted");
                }
                if (flags.bit<5>()) {
                    flags_array.print_string("single_connect");
                }
                flags_array.close();
            }
        }

    };

    [[maybe_unused]] static bool unit_test()  {

        uint8_t reference[] = {
            0xc1, 0x01, 0x01, 0x21, 0xdf, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x24, 0x01, 0x01, 0x02, 0x01,
            0x05, 0x01, 0x0e, 0x08, 0x61, 0x64, 0x6d, 0x69,
            0x6e, 0x30, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36,
            0x38, 0x2e, 0x31, 0x31, 0x2e, 0x32, 0x32, 0x32,
            0x70, 0x61, 0x35, 0x35, 0x77, 0x30, 0x72, 0x64
        };
        datum reference_data{reference, reference + sizeof(reference)};

        uint8_t expected_json[] = {
            0x7b, 0x22, 0x74, 0x61, 0x63, 0x61, 0x63, 0x73, 0x5f, 0x70, 0x6c, 0x75,
            0x73, 0x22, 0x3a, 0x7b, 0x22, 0x6d, 0x61, 0x6a, 0x6f, 0x72, 0x5f, 0x76,
            0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x3a, 0x31, 0x32, 0x2c, 0x22,
            0x6d, 0x69, 0x6e, 0x6f, 0x72, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
            0x6e, 0x22, 0x3a, 0x31, 0x2c, 0x22, 0x74, 0x79, 0x70, 0x65, 0x22, 0x3a,
            0x22, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74,
            0x69, 0x6f, 0x6e, 0x22, 0x2c, 0x22, 0x73, 0x65, 0x71, 0x5f, 0x6e, 0x6f,
            0x22, 0x3a, 0x31, 0x2c, 0x22, 0x66, 0x6c, 0x61, 0x67, 0x73, 0x22, 0x3a,
            0x5b, 0x22, 0x75, 0x6e, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65,
            0x64, 0x22, 0x5d, 0x2c, 0x22, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
            0x5f, 0x69, 0x64, 0x22, 0x3a, 0x22, 0x64, 0x66, 0x30, 0x31, 0x30, 0x30,
            0x30, 0x30, 0x22, 0x2c, 0x22, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74,
            0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x73, 0x74, 0x61, 0x72,
            0x74, 0x22, 0x3a, 0x7b, 0x22, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x22,
            0x3a, 0x31, 0x2c, 0x22, 0x70, 0x72, 0x69, 0x76, 0x5f, 0x6c, 0x76, 0x6c,
            0x22, 0x3a, 0x31, 0x2c, 0x22, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x5f,
            0x74, 0x79, 0x70, 0x65, 0x22, 0x3a, 0x32, 0x2c, 0x22, 0x61, 0x75, 0x74,
            0x68, 0x65, 0x6e, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x22,
            0x3a, 0x31, 0x2c, 0x22, 0x75, 0x73, 0x65, 0x72, 0x22, 0x3a, 0x22, 0x61,
            0x64, 0x6d, 0x69, 0x6e, 0x22, 0x2c, 0x22, 0x70, 0x6f, 0x72, 0x74, 0x22,
            0x3a, 0x22, 0x30, 0x22, 0x2c, 0x22, 0x72, 0x65, 0x6d, 0x5f, 0x61, 0x64,
            0x64, 0x72, 0x22, 0x3a, 0x22, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38,
            0x2e, 0x31, 0x31, 0x2e, 0x32, 0x32, 0x32, 0x22, 0x2c, 0x22, 0x64, 0x61,
            0x74, 0x61, 0x22, 0x3a, 0x22, 0x70, 0x61, 0x35, 0x35, 0x77, 0x30, 0x72,
            0x64, 0x22, 0x7d, 0x7d, 0x7d
        };

        return test_json_output<tacacs::packet>(reference, sizeof(reference), expected_json, sizeof(expected_json));

    }

};


#endif // TACACS_HPP
