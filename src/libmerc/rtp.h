// rtp.h
//
// real-time transport protocol

#ifndef RTP_H
#define RTP_H

#include "datum.h"
#include "match.h"
#include "json_object.h"

namespace rtp {

    // RTP Header Extension format (following RFC 3550 Sec. 5.3.1)
    //
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      defined by profile       |           length              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                        header extension                       |
    // |                             ....                              |
    //
    class header_extension {
        encoded<uint16_t> identifier;
        encoded<uint16_t> length;
        datum body;
    public:
        header_extension(datum &d) :
            identifier{d},
            length{d},
            body{d, length}
        {}

        bool is_valid() const { return body.is_not_null(); }
    };

    //   RTP header (following RFC3550, Sec. 5.1)
    //
    //    0                   1                   2                   3
    //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   |V=2|P|X|  CC   |M|     PT      |       sequence number         |
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   |                           timestamp                           |
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   |           synchronization source (SSRC) identifier            |
    //   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
    //   |            contributing source (CSRC) identifiers             |
    //   |                             ....                              |
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //   Version (V): 2 bits - identifies the version of RTP.  The
    //   version defined by RFC 3550 is two.
    //
    //   Padding (P): 1 bit - if set, the packet contains one or more
    //   additional padding octets at the end which are not part of
    //   the payload.  The last octet of the padding contains a count
    //   of how many padding octets should be ignored, including
    //   itself.
    //
    //   Extension (X): 1 bit - if set, the fixed header MUST be
    //   followed by exactly one header extension.
    //
    //   CSRC count (CC): 4 bits - contains the number of CSRC
    //   identifiers that follow the fixed header.
    //
    //   Marker (M): 1 bit - the interpretation is defined by a profile.
    //
    //   Payload type (PT): 7 bits - identifies the format of the RTP
    //   payload; an RTP profile MAY specify a default static mapping
    //   of payload type codes to payload formats.
    //
    //       Note: payload type values between 64 and 95, inclusive,
    //       may be RTCP packets, not RTP.  See RFC5761, Sec. 4.
    //
    class header {
        encoded<uint8_t> vpxcc;
        encoded<uint8_t> mpt;
        encoded<uint16_t> sequence_number;
        encoded<uint32_t> timestamp;
        encoded<uint32_t> ssrc;
        datum csrc_list;

    public:

        header(datum &d) :
            vpxcc{d},
            mpt{d},
            sequence_number{d},
            timestamp{d},
            ssrc{d},
            csrc_list{d, vpxcc.slice<5,8>() * 4}
        {}

        bool is_valid() const { return csrc_list.is_not_null(); }

        void write_json(json_object &o) const {
            if (!is_valid()) { return; }
            o.print_key_uint("version", vpxcc.slice<0,2>());
            o.print_key_bool("extension", vpxcc.bit<3>());
            o.print_key_uint("csrc_count", vpxcc.slice<5,8>());
            o.print_key_uint("marker", mpt.bit<0>());
            o.print_key_uint("payload_type", mpt.slice<1,8>());
        }
    };

    class packet {
        header hdr;
        datum payload;
    public:
        packet(datum &d) : hdr{d}, payload{d} { }

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata;
            json_object rtp{o, "rtp"};
            hdr.write_json(rtp);
            rtp.print_key_uint("payload_length", payload.length());
            rtp.print_key_hex("payload", payload);
            rtp.close();
        }

        void write_l7_metadata(cbor_object &o, bool) {
            cbor_array protocols{o, "protocols"};
            protocols.print_string("rtp");
            protocols.close();
        }

        bool is_not_empty() const { return hdr.is_valid(); }

        static constexpr mask_and_value<8> matcher{
            { 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
        };

    };

    // RTCP
    //
    // TBD

};  // end of namespace rtp

[[maybe_unused]] static int rtp_fuzz_test(const uint8_t *data, size_t size) {
    datum rtp_data{data, data+size};
    rtp::packet rtp_pkt{rtp_data};

    output_buffer<2048> obuf;
    json_object record{&obuf};
    if (rtp_pkt.is_not_empty()) {
        rtp_pkt.write_json(record);
    }
    record.close();
    obuf.write_line(stdout);

    return 0;
}

#endif // RTP_H
