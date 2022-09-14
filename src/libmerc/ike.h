// ike.h
//
// internet key exchange

#ifndef IKE_H
#define IKE_H

namespace ike {

#include "ikev2_params.h"

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
        //literal<4> marker;
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
            //            marker{d, {0x00, 0x00, 0x00, 0x00}},
            initiator_spi{d, 8},
            responder_spi{d, 8},
            next_payload{d},
            version{d},
            exchange{d},
            flags{d},
            message_id{d},
            length{d},
            valid{d.is_not_null()}
        { }

        uint16_t get_next_payload() const {
            return next_payload;
        }

        bool is_valid() const { return valid; }

        void write_json(json_object &o) const {
            if (!valid) { return; }
            o.print_key_hex("initiator_spi", initiator_spi);
            o.print_key_hex("responder_spi", responder_spi);
            o.print_key_uint("major version", version.slice<0,4>());
            o.print_key_uint("minor version", version.slice<4,8>());
            exchange.write_json(o);
            o.print_key_uint("flags", flags);
            o.print_key_uint("message_id", message_id);
            o.print_key_uint("length", length);
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
    class generic_payload_header {
        encoded<uint8_t> next_payload;
        encoded<uint8_t> c_reserved;
        encoded<uint16_t> payload_length_;
        bool valid;
        payload_type<uint8_t> this_payload;

        static constexpr size_t bytes_in_generic_payload_header = 4;

    public:

        generic_payload_header(datum &d, uint8_t payload_type) :
            next_payload{d},
            c_reserved{d},
            payload_length_{d},
            valid{d.is_not_null()},
            this_payload{payload_type}
        { }

        uint16_t payload_length() const {
            return payload_length_ - bytes_in_generic_payload_header;
        }

        uint8_t get_next_payload() const {
            return next_payload;
        }

        void write_json(json_object &o) const {
            this_payload.write_json(o);
            o.print_key_bool("c", c_reserved.bit<0>());
            o.print_key_uint("payload_length", payload_length_);
        }
    };

    class packet {
        header hdr;
        datum body;
    public:
        packet(datum &d) :
            hdr{d},
            body{d, hdr.body_length()}
        { }

        bool is_valid() const { return body.is_not_null(); }

        void write_json(json_object &o) const {
            if (!is_valid()) { return; }
            hdr.write_json(o);
            uint16_t payload_type = hdr.get_next_payload();
            datum tmp = body;
            json_array payloads{o, "payloads"};
            while (tmp.is_not_empty()) {
                generic_payload_header gph{tmp, payload_type};
                datum payload{tmp, gph.payload_length()};
                if (tmp.is_not_null()) {
                    json_object p{payloads};
                    gph.write_json(p);
                    p.print_key_hex("payload", payload);
                    p.close();
                    payload_type = gph.get_next_payload();
                }
            }
            payloads.close();
            o.print_key_hex("trailer", tmp);
        }

    };
};

#endif // IKE_H
