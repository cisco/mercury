// stun.h
//

#ifndef STUN_H
#define STUN_H

#include "datum.h"
#include "protocol.h"
#include "json_object.h"
#include "util_obj.h"      // for utf8_string
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
    //
    // The XOR-PEER-ADDRESS attribute specifies the address and port
    // of the peer as seen from the TURN server. (For example, the
    // peer's server-reflexive transport address if the peer is behind
    // a NAT.) It is encoded in the same way as the XOR-MAPPED-ADDRESS
    // attribute.
    //
    // The XOR-RELAYED-ADDRESS attribute is present in Allocate
    // responses. It specifies the address and port that the server
    // allocated to the client. It is encoded in the same way as the
    // XOR-MAPPED-ADDRESS attribute].
    //
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
                addr = hton(addr ^ magic);
                o.print_key_ipv4_addr("x_address", (uint8_t *)&addr); // TODO: byte order???
            } else {
                o.print_key_hex("x_address", x_address); // TODO: handle IPv6
            }
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
    public:
        error_code(datum &d) :
            reserved_class_number{d},
            reason_phrase{d}
        { }

        void write_json(json_object &o) {
            if (reason_phrase.is_not_null()) {
                o.print_key_uint("class", reserved_class_number.slice<21, 24>());
                o.print_key_uint("number", reserved_class_number.slice<24, 32>());
                o.print_key_json_string("reason_phrase", reason_phrase);
            }
        }
    };

    //  The CHANNEL-NUMBER attribute contains the number of the
    //  channel. The value portion of this attribute is 4 bytes long
    //  and consists of a 16-bit unsigned integer followed by a
    //  two-octet RFFU (Reserved For Future Use) field, which MUST be
    //  set to 0 on transmission and MUST be ignored on reception.
    //
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |        Channel Number         |         RFFU = 0              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    class channel_number {
        encoded<uint16_t> number;
        ignore<uint16_t> rffu;
        bool valid;

    public:
        channel_number(datum &d) : number{d}, rffu{d}, valid{d.is_not_null()} { }

        void write_json(json_object &o) {
            if (valid) {
                o.print_key_uint("channel_number", number);
            }
        }
    };

    // The LIFETIME attribute represents the duration for which the
    // server will maintain an allocation in the absence of a
    // refresh. The TURN client can include the LIFETIME attribute
    // with the desired lifetime in Allocate and Refresh requests. The
    // value portion of this attribute is 4 bytes long and consists of
    // a 32-bit unsigned integral value representing the number of
    // seconds remaining until expiration.
    //
    class lifetime {
        encoded<uint32_t> seconds;
    public:
        lifetime(datum &d) : seconds{d} { }

        void write_json(json_object &o) {
            o.print_key_uint("seconds", seconds);
        }
    };

    //  REQUESTED-TRANSPORT is used by the client to request a
    //  specific transport protocol for the allocated transport
    //  address. The value of this attribute is 4 bytes with the
    //  following format:
    //
    // 0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |    Protocol   |                    RFFU                       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    class requested_transport {
        encoded<uint8_t> protocol;
        skip_bytes<3> rffu;
    public:
        requested_transport(datum &d) : protocol{d}, rffu{d} { }

        void write_json(json_object &o) const {
            o.print_key_uint("protocol", protocol);
        }
    };

    // Microsoft Attributes (from
    // https://docs.microsoft.com/en-us/openspecs/office_protocols/ms-turn/0e0491de-b648-4347-bae4-503c7347abbe)
    //
    class ms_implementation_version {
    };

    class ms_bandwidth_admission_control_message {
        skip_bytes<2> reserved;
        encoded<uint16_t> message_type;
    public:
        ms_bandwidth_admission_control_message(datum &d) : reserved{d}, message_type{d} { }

        void write_json(json_object &o) const {
            const char *msg_type = nullptr;
            switch (message_type) {
            case 0x0000:
                msg_type = "reservation_check";
                break;
            case 0x0001:
                msg_type = "reservation_commit";
                break;
            case 0x0002:
                msg_type = "reservation_update";
                break;
            default:
                ;
            }
            if (msg_type == nullptr) {
                o.print_key_unknown_code("message_type", message_type);
            } else {
                o.print_key_string("message_type", msg_type);
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
        bool valid;

    public:

        attribute(datum&d) :
            type{d},
            length{d},
            value{d, length.value()},
            padding{d, pad_len(length.value())},
            valid{d.is_not_null()}
        { }

        void write_json(json_array &a) const {
            if (!valid) { return; }
            json_object o{a};
            attribute_type<uint16_t>{type}.write_json(o);
            // const char *name = attribute_type_get_name(type);
            // o.print_key_string("type", name);
            // if (name == unknown) {
            //     o.print_key_uint("type_code", type);
            //     o.print_key_uint_hex("type_code_hex", type); // TODO: check number of zeros
            // }
            o.print_key_uint("length", length);
            switch (type) {
            case attribute_type<uint16_t>::USE_CANDIDATE:
                // no data in value field
                break;
            case attribute_type<uint16_t>::MAPPED_ADDRESS:
            case attribute_type<uint16_t>::ALTERNATE_SERVER:
            case attribute_type<uint16_t>::RESPONSE_ORIGIN:
            case attribute_type<uint16_t>::OTHER_ADDRESS:
                if (lookahead<mapped_address> addr{value}) {
                    addr.value.write_json(o);
                }
                break;
            case attribute_type<uint16_t>::XOR_MAPPED_ADDRESS:
            case attribute_type<uint16_t>::XOR_PEER_ADDRESS:
            case attribute_type<uint16_t>::XOR_RELAYED_ADDRESS:
                if (lookahead<xor_mapped_address> addr{value}) {
                    addr.value.write_json(o);
                }
                break;
            case attribute_type<uint16_t>::SOFTWARE:
            case attribute_type<uint16_t>::USERNAME:
            case attribute_type<uint16_t>::NONCE:
                if (lookahead<utf8_string> s{value}) {
                    o.print_key_value("value", s.value);
                }
                break;
            case attribute_type<uint16_t>::ERROR_CODE:
                if (lookahead<error_code> ec{value}) {
                    ec.value.write_json(o);
                }
                break;
            case attribute_type<uint16_t>::PRIORITY:
                if (lookahead<encoded<uint32_t>> priority{value}) {
                    o.print_key_uint("priority", priority.value);
                }
                break;
            case attribute_type<uint16_t>::ICE_CONTROLLED:
                if (lookahead<encoded<uint64_t>> tiebreaker{value}) {
                    o.print_key_uint_hex("tiebreaker", tiebreaker.value);
                }
                break;
            case attribute_type<uint16_t>::ICE_CONTROLLING:
                if (lookahead<encoded<uint64_t>> tiebreaker{value}) {
                    o.print_key_uint_hex("tiebreaker", tiebreaker.value);
                }
                break;
            case attribute_type<uint16_t>::CHANNEL_NUMBER:
                if (lookahead<channel_number> cn{value}) {
                    cn.value.write_json(o);
                }
                break;
            case attribute_type<uint16_t>::LIFETIME:
                if (lookahead<lifetime> lt{value}) {
                    lt.value.write_json(o);
                }
                break;
            case attribute_type<uint16_t>::REQUESTED_TRANSPORT:
                if (lookahead<requested_transport> rt{value}) {
                    rt.value.write_json(o);
                }
                break;
            case attribute_type<uint16_t>::MS_BANDWIDTH_ADMISSION_CONTROL_MESSAGE:
                if (lookahead<ms_bandwidth_admission_control_message> bacm{value}) {
                    bacm.value.write_json(o);
                }
                break;
            case attribute_type<uint16_t>::MS_IMPLEMENTATION_VERSION:
                if (lookahead<encoded<uint32_t>> iv{value}) {
                    o.print_key_uint("number", iv.value);
                }
                break;
            case attribute_type<uint16_t>::FINGERPRINT:
            case attribute_type<uint16_t>::MESSAGE_INTEGRITY:
            case attribute_type<uint16_t>::REALM:             // note: should be utf8, but too often is not
            case attribute_type<uint16_t>::DATA:              // note: DATA could be processed as udp.data
            default:
                o.print_key_hex("hex_value", value);
            }
            o.close();
        }

        void write_raw_features(writeable &buf) {
            buf.copy('[');
            buf.copy('"');
            type.write_hex(buf);
            buf.copy('"');
            buf.copy(',');
            buf.copy('"');
            buf.write_hex(value.data, value.length());
            buf.copy('"');
            buf.copy(']');
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
            return nullptr;
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
                method<uint16_t>{get_method_type()}.write_json(o);
                const char *type_name = message_type_string(message_type_field & msg_type_mask);
                if (type_name == nullptr) {
                    o.print_key_unknown_code("message_type", (uint16_t)(message_type_field & msg_type_mask));
                } else {
                    o.print_key_string("message_type", type_name);
                }
                o.print_key_uint("message_length", message_length);
                o.print_key_hex("transaction_id", transaction_id);
            }
        }

        void write_raw_features(writeable &w) const {
            w.copy('"');
            message_type_field.write_hex(w);
            w.copy('"');
        }

        uint16_t get_message_length() const { return message_length; }

    };

    class message : public base_protocol {
        header hdr;
        datum body;

    public:
        message(datum &d) : hdr{d}, body{d, hdr.get_message_length()} { }

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata; // ignore
            if (hdr.is_valid()) {
                json_object stun_obj{o, "stun"};
                if (hdr.get_message_length() % 4) {
                    stun_obj.print_key_bool("malformed", true);
                }
                hdr.write_json(stun_obj);
                json_array a{stun_obj, "attributes"};
                datum tmp{body};
                while (tmp.is_not_empty()) {
                    if (lookahead<stun::attribute> attr{tmp}) {
                        attr.value.write_json(a);
                        tmp = attr.advance();
                    } else {
                        json_object unparseable{a};
                        unparseable.print_key_hex("unparseable", tmp);
                        unparseable.close();
                        tmp.set_null(); // terminate loop
                    }
                }
                a.close();
                write_raw_features(stun_obj);
                stun_obj.close();
            }
        }

        void write_raw_features(json_object &o) const {
            data_buffer<2048> buf;
            buf.copy('[');
            hdr.write_raw_features(buf);
            buf.copy(',');
            buf.copy('[');
            datum tmp{body};
            bool first = true;
            while (tmp.is_not_empty()) {
                if (acceptor<stun::attribute> attr{tmp}) {
                    if (!first) { buf.copy(','); } else { first = false; }
                    attr.value.write_raw_features(buf);
                } else {
                    break;
                }
            }
            buf.copy(']');
            buf.copy(']');
            if (buf.readable_length() == 0) {
                o.print_key_string("features", "[]");
            } else {
                o.print_key_json_string("features", buf.contents());
            }
        }

        static constexpr mask_and_value<8> matcher{
            { 0x00, 0x00,            // type
              0x00, 0x00,            // length
              0xff, 0xff, 0xff, 0xff // magic cookie
            },
            { 0x00, 0x00,            // type
              0x00, 0x00,            // length
              0x21, 0x12, 0xa4, 0x42 // magic cookie
            }
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
