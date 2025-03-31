// ike.hpp
//
// internet key exchange

#ifndef IKE_H
#define IKE_H

namespace ike {

#include "datum.h"
#include "protocol.h"
#include "ikev2_params.h"

    // The non-ESP marker is used to distinguish IKE from
    // ESP-over-UDP.  In the context of the IKEv2 protocol, it is an
    // optional field that may appear before the IKE header; see
    // https://datatracker.ietf.org/doc/html/rfc3948#section-2.2.
    //
    class non_esp_marker {
        literal<4> value;
    public:
        non_esp_marker(datum &d) : value{d, {0x00, 0x00, 0x00, 0x00}} { }
    };

    // by default, IKE runs on UDP port 500, though it can also use
    // UDP port 4500, in which case it is usually multiplexed with
    // ESP-over-UDP
    //
    static constexpr uint16_t default_port = hton<uint16_t>(500);

    //                          1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                       IKE SA Initiator's SPI                  |
    //    |                                                               |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                       IKE SA Responder's SPI                  |
    //    |                                                               |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |  Next Payload | MjVer | MnVer | Exchange Type |     Flags     |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                          Message ID                           |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                            Length                             |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //                     Figure 4:  IKE Header Format
    //
    //    o  Initiator's SPI (8 octets) - A value chosen by the initiator to
    //       identify a unique IKE Security Association.  This value MUST NOT
    //       be zero.
    //
    //    o  Responder's SPI (8 octets) - A value chosen by the responder to
    //       identify a unique IKE Security Association.  This value MUST be
    //       zero in the first message of an IKE initial exchange (including
    //       repeats of that message including a cookie).
    //
    //    o  Next Payload (1 octet) - Indicates the type of payload that
    //       immediately follows the header.  The format and value of each
    //       payload are defined below.
    //
    //    o  Major Version (4 bits) - Indicates the major version of the IKE
    //       protocol in use.  Implementations based on this version of IKE
    //       MUST set the major version to 2.  Implementations based on
    //       previous versions of IKE and ISAKMP MUST set the major version to
    //       1.  Implementations based on this version of IKE MUST reject or
    //       ignore messages containing a version number greater than 2 with an
    //       INVALID_MAJOR_VERSION notification message as described in Section
    //       2.5.
    //
    //    o  Minor Version (4 bits) - Indicates the minor version of the IKE
    //       protocol in use.  Implementations based on this version of IKE
    //       MUST set the minor version to 0.  They MUST ignore the minor
    //       version number of received messages.
    //
    //    o  Exchange Type (1 octet) - Indicates the type of exchange being
    //       used.  This constrains the payloads sent in each message in an
    //       exchange.  The values in the following table are only current as
    //       of the publication date of RFC 4306.  Other values may have been
    //       added since then or will be added after the publication of this
    //       document.  Readers should refer to [IKEV2IANA] for the latest
    //       values.
    //
    //       Exchange Type             Value
    //       ----------------------------------
    //       IKE_SA_INIT               34
    //       IKE_AUTH                  35
    //       CREATE_CHILD_SA           36
    //       INFORMATIONAL             37
    //
    //    o  Flags (1 octet) - Indicates specific options that are set for the
    //       message.  Presence of options is indicated by the appropriate bit
    //       in the flags field being set.  The bits are as follows:
    //
    //         +-+-+-+-+-+-+-+-+
    //         |X|X|R|V|I|X|X|X|
    //         +-+-+-+-+-+-+-+-+
    //
    //    In the description below, a bit being 'set' means its value is '1',
    //    while 'cleared' means its value is '0'.  'X' bits MUST be cleared
    //    when sending and MUST be ignored on receipt.
    //
    //       *  R (Response) - This bit indicates that this message is a
    //          response to a message containing the same Message ID.  This bit
    //          MUST be cleared in all request messages and MUST be set in all
    //          responses.  An IKE endpoint MUST NOT generate a response to a
    //          message that is marked as being a response (with one exception;
    //          see Section 2.21.2).
    //
    //       *  V (Version) - This bit indicates that the transmitter is
    //          capable of speaking a higher major version number of the
    //          protocol than the one indicated in the major version number
    //          field.  Implementations of IKEv2 MUST clear this bit when
    //          sending and MUST ignore it in incoming messages.
    //
    //       *  I (Initiator) - This bit MUST be set in messages sent by the
    //          original initiator of the IKE SA and MUST be cleared in
    //          messages sent by the original responder.  It is used by the
    //          recipient to determine which eight octets of the SPI were
    //          generated by the recipient.  This bit changes to reflect who
    //          initiated the last rekey of the IKE SA.
    //
    //    o  Message ID (4 octets, unsigned integer) - Message identifier used
    //       to control retransmission of lost packets and matching of requests
    //       and responses.  It is essential to the security of the protocol
    //       because it is used to prevent message replay attacks.  See
    //       Sections 2.1 and 2.2.
    //
    //    o  Length (4 octets, unsigned integer) - Length of the total message
    //       (header + payloads) in octets.
    //
    class header {
        optional<non_esp_marker> marker;
        //non_esp_marker marker;
        datum initiator_spi;
        datum responder_spi;
        payload_type<uint8_t> next_payload;
        encoded<uint8_t> version;
        exchange_type<uint8_t> exchange;
        encoded<uint8_t> flags;
        encoded<uint32_t> message_id;
        encoded<uint32_t> length;
        bool valid;

    public:

        static constexpr size_t bytes_in_header = 28;

        size_t body_length() const { return length - bytes_in_header; }

        header(datum &d) :
            marker{d},
            initiator_spi{d, 8},
            responder_spi{d, 8},
            next_payload{d},
            version{d},
            exchange{d},
            flags{d},
            message_id{d},
            length{d},
            valid{d.is_not_null() and version == 0x20 and exchange.get_name() != UNKNOWN}
        { }

        uint16_t get_next_payload() const {
            return next_payload;
        }

        bool is_valid() const { return valid; }

        void write_json(json_object &o) const {
            if (!valid) { return; }
            o.print_key_hex("initiator_spi", initiator_spi);
            o.print_key_hex("responder_spi", responder_spi);
            o.print_key_uint("major_version", version.slice<0,4>());
            o.print_key_uint("minor_version", version.slice<4,8>());
            exchange.write_json(o);
            o.print_key_bool("response", flags.bit<2>());
            o.print_key_bool("version", flags.bit<3>());
            o.print_key_bool("initiator", flags.bit<4>());
            o.print_key_uint("message_id", message_id);
            o.print_key_uint("length", length);
        }
    };

    // Notify Payload (following RFC 7296, Fig. 16)
    //
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Next Payload  |C|  RESERVED   |         Payload Length        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |  Protocol ID  |   SPI Size    |      Notify Message Type      |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~                Security Parameter Index (SPI)                 ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~                       Notification Data                       ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    class notify {
        security_protocol_type<uint8_t> protocol_id;
        encoded<uint8_t> spi_size;
        encoded<uint16_t> message_type;
        datum spi;
        datum data;
        bool valid;

        static constexpr uint16_t max_err_type = 16383;

    public:
        notify(datum &d) :
            protocol_id{d},
            spi_size{d},
            message_type{d},
            spi{d, spi_size},
            data{d},
            valid{d.is_not_null()}
        {}

        void write_json(json_object &o) {
            protocol_id.write_json(o);
            if (message_type < max_err_type) {
                notify_message_error_type<uint16_t>{message_type}.write_json(o);
            } else {
                notify_message_status_type<uint16_t>{message_type}.write_json(o);
            }
            o.print_key_hex("spi", spi);
            o.print_key_hex("data", data);
        }

    };

    // Key Exchange Payload Format (following RFC 7296, Fig. 10)
    //
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Next Payload  |C|  RESERVED   |         Payload Length        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   Diffie-Hellman Group Num    |           RESERVED            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~                       Key Exchange Data                       ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    class key_exchange {
        diffie_hellman_group_type<uint16_t> group_num;
        skip_bytes<2> reserved;
        datum data;
        bool valid;

    public:

        key_exchange(datum &d) :
            group_num{d},
            reserved{d},
            data{d},
            valid{d.is_not_null()}
        {}

        void write_json(json_object &o) const {
            if (!valid) { return; }
            group_num.write_json(o);
            o.print_key_hex("data", data);
        }
    };

    //  Transform Data Attributes (following RFC 7296, Fig. 9)
    //
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |A|       Attribute Type        |    AF=0  Attribute Length     |
    // |F|                             |    AF=1  Attribute Value      |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                   AF=0  Attribute Value                       |
    // |                   AF=1  Not Transmitted                       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    class transform_attribute {
        encoded<uint16_t> attribute_type;
        bool af;
        encoded<uint16_t> attribute_length_or_value;
        datum value;
        bool valid;
    public:

        transform_attribute(datum &d) :
            attribute_type{d},
            af{attribute_type.bit<0>()},
            attribute_length_or_value{d},
            value{d, af ? 0 : attribute_length_or_value.value()},
            valid{d.is_not_null()}
        {
            attribute_type = attribute_type.slice<1,16>();
        }

        void write_json(json_array &a) {
            json_object o{a};
            o.print_key_uint("af", af);
            o.print_key_uint("attribute_type", attribute_type);
            if (af) {
                o.print_key_uint_hex("value", attribute_length_or_value);
            } else {
                o.print_key_hex("value", value);
            }
            o.close();
        }

        explicit operator bool() const { return valid; }

    };

    // Transform Substructure (following RFC 7296, Fig. 8)
    //
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Last Substruc |   RESERVED    |        Transform Length       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |Transform Type |   RESERVED    |          Transform ID         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~                      Transform Attributes                     ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    class transform {
        encoded<uint8_t> last_transform;
        skip_bytes<1> reserved;
        encoded<uint16_t> transform_length;
        transform_type<uint8_t> type;
        skip_bytes<1> reserved2;
        encoded<uint16_t> transform_id;
        datum attributes;
        bool valid;

        static constexpr size_t bytes_in_transform_header = 8;

    public:
        transform(datum &d) :
            last_transform{d},
            reserved{d},
            transform_length{d},
            type{d},
            reserved2{d},
            transform_id{d},
            attributes{d, transform_length - bytes_in_transform_header},
            valid{d.is_not_null()}
        {}

        void write_json(json_array &a) const {
            json_object o{a};
            o.print_key_uint("last_transform", last_transform);
            o.print_key_uint("transform_length", transform_length);
            type.write_json(o); // o.print_key_("transform_type", transform_type);
            switch(type) {
            case transform_type<uint8_t>::code::Encryption_Algorithm:
                encryption_transform_type<uint16_t>{transform_id}.write_json(o);
                break;
            case transform_type<uint8_t>::code::Pseudo_random_Function:
                pseudorandom_function_type<uint16_t>{transform_id}.write_json(o);
                break;
            case transform_type<uint8_t>::code::Integrity_Algorithm:
                integrity_transform_type<uint16_t>{transform_id}.write_json(o);
                break;
            case transform_type<uint8_t>::code::Key_Exchange_Method:
                diffie_hellman_group_type<uint16_t>{transform_id}.write_json(o);
                break;
            case transform_type<uint8_t>::code::Extended_Sequence_Numbers:
                extended_sequence_numbers_type<uint16_t>{transform_id}.write_json(o);
                break;
            default:
                o.print_key_uint("transform_id", transform_id);
            }
            if (attributes.is_not_empty()) {
                json_array attrs{o, "attributes"};
                datum tmp = attributes;
                while (tmp.is_not_empty()) {
                    transform_attribute a{tmp};
                    a.write_json(attrs);
                }
                attrs.close();
            }
            o.close();
        }

        explicit operator bool() const { return valid; }
    };


    // Proposal Substructure (following RFC 7296, Fig. 7)
    //
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Last Substruc |   RESERVED    |         Proposal Length       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Proposal Num  |  Protocol ID  |    SPI Size   |Num  Transforms|
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // ~                        SPI (variable)                         ~
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~                        <Transforms>                           ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    class proposal {
        encoded<uint8_t> last_proposal;
        skip_bytes<1> reserved;
        encoded<uint16_t> proposal_length;
        encoded<uint8_t> proposal_num;
        encoded<uint8_t> protocol_id;
        encoded<uint8_t> spi_size;
        encoded<uint8_t> num_transforms;
        datum spi;
        datum transforms;
        bool valid;

        static constexpr size_t bytes_in_proposal_header = 8;

    public:

        proposal(datum &d) :
            last_proposal{d},
            reserved{d},
            proposal_length{d},
            proposal_num{d},
            protocol_id{d},
            spi_size{d},
            num_transforms{d},
            spi{d, spi_size},
            transforms{d, proposal_length - bytes_in_proposal_header - spi_size},
            valid{d.is_not_null()}
        { }

        void write_json(json_array &a) {
            if (!valid) { return; }
            json_object p{a};
            p.print_key_uint("last_proposal", last_proposal);
            p.print_key_uint("proposal_length", proposal_length);
            p.print_key_uint("proposal_num", proposal_num);
            p.print_key_uint("protocol_id", protocol_id);
            p.print_key_uint("spi_size", spi_size);
            p.print_key_uint("num_transforms", num_transforms);
            p.print_key_hex("spi", spi);
            // p.print_key_hex("transforms", transforms);
            json_array transform_array{p, "transforms"};
            //fprintf(stderr, "proposal transforms:"); transforms.fprint_hex(stderr); fputc('\n', stderr);
            datum tmp = transforms;
            while (tmp.is_not_empty()) {
                transform t{tmp};
                t.write_json(transform_array);
            }
            transform_array.close();
            p.close();
        }
    };

    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Next Payload  |C|  RESERVED   |         Payload Length        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //                    Figure 5:  Generic Payload Header
    //
    class generic_payload {
        encoded<uint8_t> next_payload;
        encoded<uint8_t> c_reserved;
        encoded<uint16_t> payload_length_;
        bool valid;
        payload_type<uint8_t> this_payload;
        datum payload;

        static constexpr size_t bytes_in_generic_payload_header = 4;

    public:

        generic_payload(datum &d, uint8_t payload_type) :
            next_payload{d},
            c_reserved{d},
            payload_length_{d},
            valid{d.is_not_null()},
            this_payload{payload_type},
            payload{d, payload_length_ - bytes_in_generic_payload_header}
        { }

        uint16_t payload_length() const {
            return payload_length_ - bytes_in_generic_payload_header;
        }

        uint8_t get_next_payload() const {
            return next_payload;
        }

        void write_json(json_object &o) const {
            this_payload.write_json(o);
            o.print_key_bool("critical", c_reserved.bit<0>());
            o.print_key_uint("payload_length", payload_length_);

            switch(this_payload) {
            case payload_type<uint8_t>::code::Security_Association:
                {
                    json_array props_array{o, "proposals"};
                    datum tmp = payload;
                    while (tmp.is_not_empty()) {
                        proposal prop{tmp};
                        prop.write_json(props_array);
                    }
                    props_array.close();
                }
                break;
            case payload_type<uint8_t>::code::Vendor_ID:
                if (false) { // payload.is_printable()) {
                    o.print_key_json_string("vendor_id", payload);
                } else {
                    o.print_key_hex("vendor_id_hex", payload);
                }
                break;
            case payload_type<uint8_t>::code::Nonce:
                o.print_key_hex("nonce", payload);
                break;
            case payload_type<uint8_t>::code::Notify:
                if (lookahead<notify> n{payload}) {
                    n.value.write_json(o);
                }
                break;
            case payload_type<uint8_t>::code::Key_Exchange:
                if (lookahead<key_exchange> kex{payload}) {
                    kex.value.write_json(o);
                }
                break;
            default:
                o.print_key_hex("payload", payload);
            }
        }
    };

    class packet : public base_protocol {
        header hdr;
        datum body;
    public:
        packet(datum &d) :
            hdr{d},
            body{d, hdr.body_length()}
        { }

        bool is_not_empty() const { return is_valid(); }

        bool is_valid() const { return hdr.is_valid() and body.is_not_null(); }

        void write_json(json_object &o, bool output_metadata=false) const {
            (void)output_metadata;
            if (!is_valid()) { return; }
            json_object ike_json{o, "ike"};
            hdr.write_json(ike_json);
            uint16_t payload_type = hdr.get_next_payload();
            json_array payloads{ike_json, "payloads"};
            datum tmp = body;
            while (tmp.is_not_empty()) {
                json_object p{payloads};
                generic_payload gp{tmp, payload_type};
                gp.write_json(p);
                p.close();
                payload_type = gp.get_next_payload();
            }
            payloads.close();
            ike_json.close();
        }

    };
};

[[maybe_unused]] inline int ike_packet_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<ike::packet>(data, size);
}

#endif // IKE_H
