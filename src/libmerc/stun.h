// stun.h
//

#ifndef STUN_H
#define STUN_H

#include "datum.h"
#include "json_object.h"
#include "match.h"
#include "fingerprint.h"

namespace stun {

#include "stun_params.h"

    // Magic Cookie MUST contain the fixed value 0x2112A442
    //
    static constexpr uint32_t magic = 0x2112a442;

    enum addr_family : uint16_t { ipv4 = 1, ipv6 = 2 };

    static const char *addr_family_get_name(uint16_t f) {
        switch(f) {
        case addr_family::ipv4: return "ipv4";
        case addr_family::ipv6: return "ipv6";
        default:
            ;
            return "UNKNOWN";
        }
    }

    // The format of the MAPPED-ADDRESS attribute is:
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |0 0 0 0 0 0 0 0|    Family     |           Port                |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                                                               |
    //    |                 Address (32 bits or 128 bits)                 |
    //    |                                                               |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //             Figure 5: Format of MAPPED-ADDRESS Attribute
    //
    // The address family can take on the following values:
    //
    // 0x01:IPv4
    // 0x02:IPv6
    //
    // From RFC 5780: Whenever an attribute contains a transport IP
    // address and port, it has the same format as MAPPED-ADDRESS.
    // Similarly, the XOR- attributes have the same format as
    // XOR-MAPPED-ADDRESS.
    //
    class mapped_address {
        encoded<uint8_t> zeros;
        encoded<uint8_t> family;
        encoded<uint16_t> port;
        datum address;

    public:

        mapped_address(datum &d) :
            zeros{d}, // ignored
            family{d},
            port{d},
            address{d, family == ipv6 ? 16 : 4}
        { }

        bool valid() const { return address.is_not_empty(); }

        void write_json(json_object &o) const {
            if (!valid()) { return; }
            o.print_key_string("family", addr_family_get_name(family));
            o.print_key_uint("port", port);
            switch(family) {
            case ipv4:
                if (address.length() == 4) {
                    o.print_key_ipv4_addr("address", address.data);
                }
                break;
            case ipv6:
                if (address.length() == 4) {
                    o.print_key_ipv6_addr("address", address.data);
                }
                break;
            default:
                o.print_key_string("address", "malformed");
            }
        }

    };


    // The format of the XOR-MAPPED-ADDRESS is:
    //
    //    0                   1                   2                   3
    //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   |x x x x x x x x|    Family     |         X-Port                |
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   |                X-Address (Variable)
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    // X-Port is computed by taking the mapped port in host byte
    // order, XOR'ing it with the most significant 16 bits of the
    // magic cookie, and then the converting the result to network
    // byte order.  If the IP address family is IPv4, X-Address is
    // computed by taking the mapped IP address in host byte order,
    // XOR'ing it with the magic cookie, and converting the result to
    // network byte order.  If the IP address family is IPv6,
    // X-Address is computed by taking the mapped IP address in host
    // byte order, XOR'ing it with the concatenation of the magic
    // cookie and the 96-bit transaction ID, and converting the result
    // to network byte order.

    class xor_mapped_address {
        encoded<uint8_t> xxx;
        encoded<uint8_t> family;
        encoded<uint16_t> x_port;
        datum x_address;

    public:

        xor_mapped_address(datum &d) :
            xxx{d}, // ignored
            family{d},
            x_port{d},
            x_address{d, family == ipv6 ? 16 : 4}
        { }

        bool valid() const { return x_address.is_not_empty(); }

        void write_json(json_object &o) const {
            if (!valid()) { return; }
            o.print_key_string("family", addr_family_get_name(family));
            uint16_t port = x_port ^ (magic >> 16);
            o.print_key_uint("x_port", port);
            if (family == addr_family::ipv4) {
                datum tmp{x_address};
                encoded<uint32_t> addr{tmp};
                addr = htonl(addr ^ magic);
                o.print_key_ipv4_addr("x_address", (uint8_t *)&addr); // TODO: byte order???
            } else {
                o.print_key_hex("x_address", x_address); // TODO: handle IPv6
            }
        }

    };

    class utf8_string_and_padding {
        datum name;
        pad padding;
    public:
        utf8_string_and_padding(datum &d) : name{d}, padding{d, pad_len(name.length())} { }

        void write_json(json_object &o) {
            o.print_key_json_string("value", name); // TODO: support UTF-8
        }
    };

    // The ERROR-CODE attribute is used in error response messages.  It
    // contains a numeric error code value in the range of 300 to 699 plus a
    // textual reason phrase encoded in UTF-8 [RFC3629], and is consistent
    // in its code assignments and semantics with SIP [RFC3261] and HTTP
    // [RFC2616].  The reason phrase is meant for user consumption, and can
    // be anything appropriate for the error code.  Recommended reason
    // phrases for the defined error codes are included in the IANA registry
    // for error codes.  The reason phrase MUST be a UTF-8 [RFC3629] encoded
    // sequence of less than 128 characters (which can be as long as 763
    // bytes).
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |           Reserved, should be 0         |Class|     Number    |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |      Reason Phrase (variable)                                ..
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    class error_code {
        encoded<uint32_t> reserved_class_number;
        datum reason_phrase;
        pad padding;
    public:
        error_code(datum &d) :
            reserved_class_number{d},
            reason_phrase{d},
            padding{d, pad_len(reason_phrase.length())}
        { }

        void write_json(json_object &o) {
            if (reason_phrase.is_not_null()) {
                o.print_key_uint("class", reserved_class_number.slice<21, 24>());
                o.print_key_uint("number", reserved_class_number.slice<24, 32>());
                o.print_key_json_string("reason_phrase", reason_phrase);
            }
        }
    };


    //   After the STUN header are zero or more attributes.  Each attribute
    //   MUST be TLV encoded, with a 16-bit type, 16-bit length, and value.
    //   Each STUN attribute MUST end on a 32-bit boundary.  As mentioned
    //   above, all fields in an attribute are transmitted most significant
    //   bit first.
    //
    //       0                   1                   2                   3
    //       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //      |         Type                  |            Length             |
    //      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //      |                         Value (variable)                ....
    //      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //                    Figure 4: Format of STUN Attributes
    //
    class attribute {
        encoded<uint16_t> type;
        encoded<uint16_t> length;
        datum value;
        pad padding;

    public:

        attribute(datum&d) :
            type{d},
            length{d},
            value{d, length.value()},
            padding{d, pad_len(length.value())}
        { }

        void write_json(json_array &a) const {
            json_object o{a};
            const char *name = attribute_type_get_name(type);
            o.print_key_string("type", name);
            if (name == unknown) {
                o.print_key_uint("type_code", type);
            }
            o.print_key_uint("length", length);
            switch (type) {
            case attribute_type::MAPPED_ADDRESS:
            case attribute_type::ALTERNATE_SERVER:
            case attribute_type::RESPONSE_ORIGIN:
            case attribute_type::OTHER_ADDRESS:
                {
                    datum tmp = value;
                    mapped_address addr{tmp};
                    addr.write_json(o);
                }
                break;
            case attribute_type::XOR_MAPPED_ADDRESS:
                {
                    datum tmp = value;
                    xor_mapped_address addr{tmp};
                    addr.write_json(o);
                }
                break;
            case attribute_type::SOFTWARE:
            case attribute_type::USERNAME:
            case attribute_type::REALM:
            case attribute_type::NONCE:
                {
                    datum tmp = value;
                    utf8_string_and_padding u{tmp};
                    u.write_json(o);
                }
                break;
            case attribute_type::ERROR_CODE:
                {
                    datum tmp = value;
                    error_code ec{tmp};
                    ec.write_json(o);
                }
                break;
            case attribute_type::FINGERPRINT:
            case attribute_type::MESSAGE_INTEGRITY:
            default:
                o.print_key_hex("value", value);
            }
            o.close();
        }

        void write_raw_features(json_array &a) {
            json_array attr{a};
            attr.print_uint16_hex(type);
            attr.print_hex(value);
            attr.close();
        }
    };

    // STUN Message Header format (following RFC 5389, Figure 2)
    //
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |0 0|     STUN Message Type     |         Message Length        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                         Magic Cookie                          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // |                     Transaction ID (96 bits)                  |
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    // STUN Message Type Field format (following Figure 3)
    //
    //         0                 1
    //         2  3  4 5 6 7 8 9 0 1 2 3 4 5
    //
    //        +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
    //        |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
    //        |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
    //        +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    static const uint16_t msg_type_mask = 0x0110;

    class header {
        encoded<uint16_t> message_type_field;
        encoded<uint16_t> message_length;
        literal<4> magic_cookie;
        datum transaction_id;                   // note: always 12 bytes in length

        enum message_type : uint16_t {
            request      = 0x0000,
            indication   = 0x0010,
            success_resp = 0x0100,
            err_resp     = 0x0110
        };

        uint16_t get_method_type() const {
            return (message_type_field & 0x0f)
                | ((message_type_field & 0xe0) >> 1)
                | ((message_type_field & 0x3e00) >> 2);
        }

        static const char *message_type_string(uint16_t type) {
            switch(type) {
            case message_type::request: return "request";
            case message_type::indication: return "indication";
            case message_type::success_resp: return "success_resp";
            case message_type::err_resp: return "err_resp";
            default:
                ;
            }
            return "UNKNOWN";
        }

    public:

        header(datum &d) :
            message_type_field{d},
            message_length{d},
            magic_cookie{d, {0x21, 0x12, 0xa4, 0x42}},
            transaction_id{d, 12}
        { }

        bool is_valid() const { return transaction_id.is_not_empty(); }

        void write_json(json_object &o) const  {
            if (is_valid()) {
                const char *method_name = method_type_get_name(get_method_type());
                o.print_key_string("method", method_type_get_name(get_method_type()));
                if (method_name == unknown) {
                    o.print_key_uint("method_type_code", get_method_type());
                }
                const char *type_name = message_type_string(message_type_field & msg_type_mask);
                o.print_key_string("message_type", type_name);
                if (type_name == unknown) {
                    o.print_key_uint("message_type_code", message_type_field & msg_type_mask);
                }
                o.print_key_uint("message_length", message_length);
                o.print_key_hex("transaction_id", transaction_id);
            }
        }

        void write_raw_features(json_array &a) const {
            json_array h{a};
            h.print_uint16_hex(message_type_field);
            h.close();
        }

        uint16_t get_message_length() const { return message_length; }

    };

    class message {
        header hdr;
        datum body;

    public:
        message(datum &d) : hdr{d}, body{d, hdr.get_message_length()} { }

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata; // ignore
            if (hdr.is_valid()) {
                json_object stun_obj{o, "stun"};
                hdr.write_json(stun_obj);
                json_array a{stun_obj, "attributes"};
                datum tmp{body};
                while (tmp.is_not_empty()) {
                    stun::attribute attr{tmp};
                    attr.write_json(a);
                }
                a.close();
                write_raw_features(stun_obj);
                stun_obj.close();
            }
        }

        void write_raw_features(json_object &o) const {
            json_array a{o, "features"};
            hdr.write_raw_features(a);
            datum tmp{body};
            json_array attr_array{a};
            while (tmp.is_not_empty()) {
                stun::attribute attr{tmp};
                attr.write_raw_features(attr_array);
            }
            attr_array.close();
            a.close();
        }

        static constexpr mask_and_value<8> matcher{
            { 0x00, 0x00, // type
              0x00, 0x00, // length
              0xff, 0xff, 0xff, 0xff // magic cookie
            },
            { 0x00, 0x00, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42 }
        };

        bool is_not_empty() const {
            return hdr.is_valid();
        }

        void compute_fingerprint(fingerprint &) {
            if (!hdr.is_valid()) { return; }
            // TODO
        }
    };

} // namespace stun

[[maybe_unused]] static int stun_fuzz_test(const uint8_t *data, size_t size) {
    struct datum request_data{data, data+size};
    char buffer_1[8192];
    struct buffer_stream buf_json(buffer_1, sizeof(buffer_1));
    char buffer_2[8192];
    struct buffer_stream buf_fp(buffer_2, sizeof(buffer_2));
    struct json_object record(&buf_json);

    stun::message stun_msg{request_data};
    if (stun_msg.is_not_empty()) {
        stun_msg.write_json(record, true);
        // TODO: test fingerprint
    }

    return 0;
}

#endif // STUN_H