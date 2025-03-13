// tacacs.hpp

#ifndef TACACS_HPP
#define TACACS_HPP

#include "datum.h"
#include "protocol.h"
#include "json_object.h"
#include "match.h"

namespace tacacs {

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

        bool is_not_empty() const { return body.is_not_null(); }

        void write_json(json_object &o, bool) const {
            if (!is_not_empty()) {
                return;
            }
            json_object tacacs_json{o, "tacacs+"};
            tacacs_json.print_key_uint("major_version", version.slice<0,4>());
            tacacs_json.print_key_uint("minor_version", version.slice<4,8>());
            print_type_code(tacacs_json);
            tacacs_json.print_key_uint("seq_no", seq_no);
            tacacs_json.print_key_hex("body", body);
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

};


#endif // TACACS_HPP
