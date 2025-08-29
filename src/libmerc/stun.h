// stun.h
//

#ifndef STUN_H
#define STUN_H

#include "datum.h"
#include "protocol.h"
#include "json_object.h"
#include "utf8.hpp"
#include "match.h"
#include "fingerprint.h"
#include "result.h"
#include <unordered_map>

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
        ignore<encoded<uint16_t>> rffu;
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
            case attribute_type<uint16_t>::RESPONSE_ADDRESS:
            case attribute_type<uint16_t>::SOURCE_ADDRESS:
            case attribute_type<uint16_t>::CHANGED_ADDRESS:
            case attribute_type<uint16_t>::REFLECTED_FROM:
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
            case attribute_type<uint16_t>::BANDWIDTH:
                if (lookahead<encoded<uint32_t>> bandwidth{value}) {
                    o.print_key_uint("kbps", bandwidth.value);
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

        void write_type(buffer_stream &buf) {
            buf.write_char('(');
            buf.write_hex_uint(type);
            buf.write_char(')');
        }

        void write_type_length(buffer_stream &buf) {
            buf.write_char('(');
            buf.write_hex_uint(type);
            buf.write_hex_uint(length);
            buf.write_char(')');
        }

        void write_type_length_value(buffer_stream &buf) {
            buf.write_char('(');
            buf.write_hex_uint(type);
            buf.write_hex_uint(length);
            buf.raw_as_hex(value.data, value.length());
            buf.write_char(')');
        }

        uint16_t get_type() const { return type; }

        datum get_value() const { return value; }

    };


    /// identifies how a stun message is being used
    ///
    enum usage {
        unknown       = 0b000,    /// Usage unknown
        stun          = 0b001,    /// Basic STUN protocol
        turn          = 0b010,    /// Traversal Using Relays around NAT (TURN)
        ice           = 0b100,    /// Interactive Connectivity Establisihment (ICE)
        stun_and_turn = 0b011,    /// STUN + TURN = TURN
        stun_and_ice  = 0b101,    /// STUN + ICE = ICE
    };

    /// returns the printable constant string corresponding to a \ref
    /// stun::usage enumeration
    ///
    static const char *usage_string(enum usage u) {
        switch (u) {
        case stun:
            return "stun";
        case turn:
        case stun_and_turn:
            return "turn";
        case ice:
        case stun_and_ice:
            return "ice";
        default:
            ;
        }
        return "unknown";
    }

    /// returns the \ref stun::usage corresponding to a stun method
    ///
    static usage method_usage(uint16_t method) {
        switch (method) {
        case 0x001:     // Binding
        case 0x002:     // SharedSecret
            return usage::stun;
        case 0x003:     // Allocate
        case 0x004:     // Refresh
        case 0x006:     // Send
        case 0x007:     // Data
        case 0x008:     // CreatePermission
        case 0x009:     // ChannelBind
            return usage::turn;
        default:
            ;
        }
        return usage::unknown;
    }

    /// returns the \ref stun::usage corresponding to a stun attribute
    /// type
    ///
    static usage attribute_type_usage(uint16_t attr_type) {
        switch (attr_type) {
        case 0x0001:	// MAPPED-ADDRESS
        case 0x0002:	// Reserved; was RESPONSE-ADDRESS
        case 0x0003:	// Reserved; was CHANGE-REQUEST
        case 0x0004:	// Reserved; was SOURCE-ADDRESS
        case 0x0005:	// Reserved; was CHANGED-ADDRESS
        case 0x0006:	// USERNAME	                 [RFC8489]
        case 0x0007:	// Reserved; was PASSWORD
        case 0x0008:	// MESSAGE-INTEGRITY
        case 0x0009:	// ERROR-CODE
        case 0x000A:	// UNKNOWN-ATTRIBUTES
        case 0x000B:	// Reserved; was REFLECTED-FROM
        case 0x0010:	// Reserved (was BANDWIDTH)
        case 0x0014:	// REALM	                 [RFC8489]
        case 0x0015:	// NONCE	                 [RFC8489]
        case 0x001C:	// MESSAGE-INTEGRITY-SHA256	 [RFC8489]
        case 0x001D:	// PASSWORD-ALGORITHM	     [RFC8489]
        case 0x001E:	// USERHASH	                 [RFC8489]
        case 0x0020:	// XOR-MAPPED-ADDRESS	     [RFC8489]
        case 0x8002:	// PASSWORD-ALGORITHMS	     [RFC8489]
        case 0x8003:	// ALTERNATE-DOMAIN	         [RFC8489]
        case 0x8022:	// SOFTWARE	                 [RFC8489]
        case 0x8023:	// ALTERNATE-SERVER	         [RFC8489]
        case 0x8028:	// FINGERPRINT	             [RFC8489]
            return usage::stun;
        case 0x000C:	// CHANNEL-NUMBER	         [RFC8656]
        case 0x000D:	// LIFETIME	                 [RFC8656]
        case 0x0012:	// XOR-PEER-ADDRESS	         [RFC8656]
        case 0x0013:	// DATA	                     [RFC8656]
        case 0x0016:	// XOR-RELAYED-ADDRESS	     [RFC8656]
        case 0x0017:	// REQUESTED-ADDRESS-FAMILY	 [RFC8656]
        case 0x0018:	// EVEN-PORT	             [RFC8656]
        case 0x0019:	// REQUESTED-TRANSPORT	     [RFC8656]
        case 0x001A:	// DONT-FRAGMENT	         [RFC8656]
        case 0x0021:	// Reserved (was TIMER-VAL)	 [RFC8656]
        case 0x0022:	// RESERVATION-TOKEN	     [RFC8656]
        case 0x8000:	// ADDITIONAL-ADDRESS-FAMILY [RFC8656]
        case 0x8001:	// ADDRESS-ERROR-CODE	     [RFC8656]
        case 0x8004:	// ICMP	                     [RFC8656]
            return usage::turn;
        case 0x0024:	// PRIORITY	                 [RFC8445]
        case 0x0025:	// USE-CANDIDATE	         [RFC8445]
        case 0x8029:	// ICE-CONTROLLED	         [RFC8445]
        case 0x802A:	// ICE-CONTROLLING	         [RFC8445]
            return usage::ice;
        default:
            ;
        }

        return usage::unknown;

        // the following attributes are registered with IANA, but will
        // be categorized as "unknown" by this function
        //
        // 0x001B	// ACCESS-TOKEN	[RFC7635]
        // 0x0026	// PADDING	[RFC5780]
        // 0x0027	// RESPONSE-PORT	[RFC5780]
        // 0x002A	// CONNECTION-ID	[RFC6062]
        // 0x8025	// TRANSACTION_TRANSMIT_COUNTER	[RFC7982]
        // 0x8027	// CACHE-TIMEOUT	[RFC5780]
        // 0x802B	// RESPONSE-ORIGIN	[RFC5780]
        // 0x802C	// OTHER-ADDRESS	[RFC5780]
        // 0x802D	// ECN-CHECK STUN	[RFC6679]
        // 0x802E	// THIRD-PARTY-AUTHORIZATION	[RFC7635]
        // 0x8030	// MOBILITY-TICKET	[RFC8016]
        // 0xC000	// CISCO-STUN-FLOWDATA	[Dan_Wing]
        // 0xC001	// ENF-FLOW-DESCRIPTION	[Pål_Erik_Martinsen]
        // 0xC002	// ENF-NETWORK-STATUS	[Pål_Erik_Martinsen]
        // 0xC003	// CISCO-WEBEX-FLOW-INFO	[Stefano_Giorcelli]
        // 0xC056	// CITRIX-TRANSACTION-ID	[Paras_Babbar]
        // 0xC057	// GOOG-NETWORK-INFO	[Jonas_Oreland]
        // 0xC058	// GOOG-LAST-ICE-CHECK-RECEIVED	[Jonas_Oreland]
        // 0xC059	// GOOG-MISC-INFO	[Jonas_Oreland]
        // 0xC05A	// GOOG-OBSOLETE-1	[Jonas_Oreland]
        // 0xC05B	// GOOG-CONNECTION-ID	[Jonas_Oreland]
        // 0xC05C	// GOOG-DELTA	[Jonas_Oreland]
        // 0xC05D	// GOOG-DELTA-ACK	[Jonas_Oreland]
        // 0xC05E	// GOOG-DELTA-SYNC-REQ	[Jonas_Oreland]
        // 0xC060	// GOOG-MESSAGE-INTEGRITY-32	[Jonas_Oreland]
    }




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
    static const uint16_t msg_class_mask = 0x0110;

    class header {
        encoded<uint16_t> message_type_field;
        encoded<uint16_t> message_length;
        // literal<4> magic_cookie;
        datum transaction_id;                   // note: always 16 bytes in length
        bool tid_has_magic_cookie{false};

        enum message_class : uint16_t {
            request      = 0x0000,
            indication   = 0x0010,
            success_resp = 0x0100,
            err_resp     = 0x0110
        };

        static const char *message_class_string(uint16_t masked_type) {
            switch(masked_type) {
            case message_class::request: return "request";
            case message_class::indication: return "indication";
            case message_class::success_resp: return "success_resp";
            case message_class::err_resp: return "err_resp";
            default:
                ;
            }
            return nullptr;
        }

    public:

        header(datum &d) :
            message_type_field{d},
            message_length{d},
            transaction_id{d, 16},
            tid_has_magic_cookie{transaction_id.matches(magic_cookie)}
        { }

        static constexpr std::array<uint8_t,4> magic_cookie{0x21, 0x12, 0xa4, 0x42};

        bool is_valid() const { return transaction_id.is_not_empty(); }

        bool has_magic_cookie() const { return tid_has_magic_cookie; }

        // return the number of zero bytes in the transaction_id
        //
        size_t tid_zero_count() const {
            size_t count = 0;
            for (const auto & x : transaction_id) {
                if (x == 0) {
                    ++count;
                }
            }
            return count;
        }

        /// returns `true` if the \ref message_type_field of this
        /// header object is valid for classic STUN, and `false`
        /// otherwise.
        ///
        bool message_type_is_valid_for_classic_stun() const {
            switch (message_type_field) {
            case 0x0001:     // Binding Request
            case 0x0101:     // Binding Response
            case 0x0111:     // Binding Error Response
            case 0x0002:     // Shared Secret Request
            case 0x0102:     // Shared Secret Response
            case 0x0112:     // Shared Secret Error Response
                return true;
            default:
                ;
            }
            return false;
        }

        static constexpr size_t length = 20;    // number of bytes in header

        void write_json(json_object &o) const {
            if (is_valid()) {
                method<uint16_t>{get_method_type()}.write_json(o);

                const char *class_name = message_class_string(message_type_field & msg_class_mask);
                if (class_name == nullptr) {
                    o.print_key_unknown_code("class", (uint16_t)(message_type_field & msg_class_mask));
                } else {
                    o.print_key_string("class", class_name);
                }
                o.print_key_uint("message_length", message_length);
                datum tmp{transaction_id};
                if (tid_has_magic_cookie) {
                    tmp.skip(magic_cookie.size());
                }
                o.print_key_hex("transaction_id", tmp);
                o.print_key_bool("magic_cookie", tid_has_magic_cookie);
            }
        }

        void write_raw_features(writeable &w) const {
            w.copy('"');
            message_type_field.write_hex(w);
            w.copy('"');
        }

        uint16_t get_message_length() const { return message_length; }

        uint16_t get_method_type() const {
            return (message_type_field & 0x0f)
                | ((message_type_field & 0xe0) >> 1)
                | ((message_type_field & 0x3e00) >> 2);
        }

        uint8_t get_message_class() const {
            return (message_type_field & 0x100) >> 7 | (message_type_field & 0x10) >> 4;
        }

        void write_fingerprint(buffer_stream &buf) const {
            if (!is_valid()) {
                return;
            }
            buf.write_char('(');
            buf.write_hex_uint(get_message_class());
            buf.write_char(')');

            buf.write_char('(');
            buf.write_hex_uint(get_method_type());
            buf.write_char(')');

            buf.write_char('(');
            buf.write_hex_uint((uint8_t)tid_has_magic_cookie);
            buf.write_char(')');
        }

    };

    class message : public base_protocol {
        header hdr;
        datum body;
        datum software;

    public:

        static inline bool output_raw_features = false;
        static void set_raw_features(bool value) { output_raw_features = value; }

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
                stun::usage u{method_usage(hdr.get_method_type())};
                while (tmp.is_not_empty()) {
                    if (lookahead<stun::attribute> attr{tmp}) {
                        attr.value.write_json(a);
                        u = (stun::usage)((int)u | (int)attribute_type_usage(attr.value.get_type()));
                        tmp = attr.advance();
                    } else {
                        json_object unparseable{a};
                        unparseable.print_key_hex("unparseable", tmp);
                        unparseable.close();
                        tmp.set_null(); // terminate loop
                    }
                }
                a.close();

                stun_obj.print_key_string("usage", usage_string(u));
                if (output_raw_features) {
                    write_raw_features(stun_obj);
                }
                stun_obj.close();
            }
        }

        void write_l7_metadata(cbor_object &o, bool) {
            cbor_array protocols{o, "protocols"};
            protocols.print_string("stun");
            protocols.close();

            if (software.is_not_empty()) {
                cbor_object stun{o, "stun"};
                stun.print_key_string("software", software);
                stun.close();
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

        // static constexpr mask_and_value<8> matcher{
        //     { 0x00, 0x00,            // type
        //       0x00, 0x00,            // length
        //       0xff, 0xff, 0xff, 0xff // magic cookie
        //     },
        //     { 0x00, 0x00,            // type
        //       0x00, 0x00,            // length
        //       0x21, 0x12, 0xa4, 0x42 // magic cookie
        //     }
        // };

        /// returns the length of the stun packet pkt as indicated by
        /// the length field of the header, if \param pkt contains a
        /// complete header, or -1 otherwise.
        ///
        /// This function does not attempt to fully parse the packet,
        /// and thus is suitable for use in protocol identification.
        ///
        static ssize_t packet_length_from_header(datum pkt) {
            encoded<uint16_t> ignore{pkt};
            encoded<uint16_t> length{pkt};
            pkt.skip(12);
            if (pkt.is_not_null()) {
                return header::length + length.value();
            }
            return -1;  // error: not a valid stun packet
        }

        // we use a null four-byte matcher, because we rely on the
        // correspondence between the length of the packet and the
        // length field
        //
        static constexpr mask_and_value<4> matcher{
            { 0x00, 0x00, 0x00, 0x00 },
            { 0x00, 0x00, 0x00, 0x00 }
        };

        bool is_not_empty() const {
            if (!hdr.is_valid() or (hdr.get_message_length() != body.length())) {
                return false;
            }
            if (hdr.has_magic_cookie()) {
                return true;            // very highly likely that we are modern STUN
            }
            if (body.length() == 0) {
                return hdr.message_type_is_valid_for_classic_stun() and hdr.tid_zero_count() < 2;
            }
            return (bool)lookahead<stun::attribute>{body};  // body must contain at least one valid attribute
        }

        void compute_fingerprint(fingerprint &fp) {
            if (!hdr.is_valid()) { return; }

            constexpr size_t format_version = 1;
            fp.set_type(fingerprint_type_stun, format_version);
            fp.add(*this);
            fp.final();
        }

        void fingerprint(struct buffer_stream &buf) {
            if (!hdr.is_valid()) {
                return;
            }

            hdr.write_fingerprint(buf);

            // the attr_fingerprint_type determines what data from a
            // particular attribute type will be included in a
            // fingerprint
            //
            enum attr_fingerprint_type {
                type_length_data,
                type_length,
                type
            };

            using attr_type = attribute_type<uint16_t>::code; // for readability

            std::unordered_map<uint16_t, attr_fingerprint_type> attr_fp_type {
                { attr_type::USERNAME,                  type },
                { attr_type::MESSAGE_INTEGRITY,         type },
                { attr_type::XOR_MAPPED_ADDRESS,        type },
                { 0x8007,                               type },
                { attr_type::MS_VERSION,                type },
                { attr_type::SOFTWARE,                  type },
                { attr_type::FINGERPRINT,               type },
                { attr_type::MS_APP_ID,                 type_length_data },
                { attr_type::MS_IMPLEMENTATION_VERSION, type_length_data },
                { 0xc003,                               type },
                { attr_type::GOOG_NETWORK_INFO,         type },
                { 0xdaba,                               type },
            };

            // loop over attributes
            //
            buf.write_char('(');
            datum tmp{body};
            while (tmp.is_not_empty()) {
                if (acceptor<stun::attribute> attr{tmp}) {

                    // write attribute data into fingerprint,
                    // depending on its attribute fingerprint type
                    //
                    auto result = attr_fp_type.find(attr.value.get_type());
                    if (result != attr_fp_type.end()) {
                        switch (result->second) {
                        case type_length_data:
                            attr.value.write_type_length_value(buf);
                            break;
                        case type_length:
                            attr.value.write_type_length(buf);
                            break;
                        case type:
                            attr.value.write_type(buf);
                            break;
                        default:
                            break;
                        }
                    } else {
                        ;  // by default, attribute information is not included in fingerprint
                    }

                    // remember SOFTWARE for later use in analysis
                    //
                    if (attr.value.get_type() == attr_type::SOFTWARE) {
                        software = attr.value.get_value();
                    }

                } else {
                    break;
                }
            }
            buf.write_char(')');

        }

        // analyzes the dst_ip, dst_port, and SOFTWARE attribute
        // value, using a classifier selected by the stun fingerprint
        //
        // request format: dst_addr, dst_port
        // response format: src_addr, src_port

        bool do_analysis(const struct key &flow_key, struct analysis_context &ac, classifier*) {

            // create a json-friendly utf8 copy of the SOFTWARE atribute's value field
            //
            utf8_safe_string<MAX_USER_AGENT_LEN> utf8_software{software};

            // handle message classes appropriately: reverse the
            // addresses and ports in the flow key for responses,
            // leave the flow key untouched for requests, and ignore
            // all other message classes
            //
            key k{flow_key};
            if ((hdr.get_message_class() & 0b10) == 0b10) {
                //
                // success_resp and error_resp: swap addrs and ports
                //
                k.reverse();
            }
            ac.destination.init({nullptr,nullptr},         // domain name
                                utf8_software.get_datum(), // user agent
                                {nullptr,nullptr},         // alpn
                                k                          // flow key, used for dst_addr and dst_port
                                );

            return false;
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

// STUN implementation notes
//
// RFC 5389 and later STUN defines the Message Type as a combination
// of the Message Class (request, success response, failure response,
// or indication) and the Message Method (the primary function) of the
// STUN message. These two fields are interleaved according to the
// following mapping to the first 16 bits of the STUN header.
//
//       0                      1
//       0 1  2  3  4 5 6 7 8 9 0 1 2 3 4 5
//      +-+-+--+--+-+-+-+-+-+-+-+-+-+-+-+-+
//      | | |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
//      | | |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
//      +-+-+--+--+-+-+-+-+-+-+-+-+-+-+-+-+
//
// RFC 3489 defines those 16 bits as follows:
//
//       Field                         Hex       Binary
//       ---------------------------------------------------------
//       Binding Request               0x0001    0000000000000001
//       Binding Response              0x0101    0000000100000001
//       Binding Error Response        0x0111    0000000100010001
//       Shared Secret Request         0x0002    0000000000000010
//       Shared Secret Response        0x0102    0000000100000010
//       Shared Secret Error Response  0x0112    0000000100010010
//                                                   ^^^^^^^^^^^^
//                                                   ||||||||||||
//                                                   MMMCMMMCMMMM
//                                                   987165403210
//
//       Field                         Binary            Method            Class
//       ---------------------------------------------------------------------------------
//       Binding Request               0000000000000001  0000000000000001  000000000000000
//       Binding Response              0000000100000001  0000000000000001  000000000000010
//       Binding Error Response        0000000100010001  0000000000000001  000000000000011
//       Shared Secret Request         0000000000000010  0000000000000010  000000000000000
//       Shared Secret Response        0000000100000010  0000000000000010  000000000000010
//       Shared Secret Error Response  0000000100010010  0000000000000010  000000000000011
//                                         ^^^^^^^^^^^^
//                                         ||||||||||||
//                                         MMMCMMMCMMMM
//                                         987165403210



#endif // STUN_H
