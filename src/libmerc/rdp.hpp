// rdp.hpp
//
// microsoft remote desktop protocol

#ifndef RDP_HPP
#define RDP_HPP

#include "datum.h"
#include "json_object.h"
#include "protocol.h"

class data_dumper {
    datum raw_data;

public:

    data_dumper(datum &d) : raw_data{d} { }

    void dump(const char *name, FILE *f=stderr) const {
        raw_data.fprint_c_array(f, name);
    }
};

/// accepts a string consisting of one or more bytes not equal to
/// \param delim1, followed by the byte \param delim1 and any other
/// optional delimiter bytes \param optional_delimiter_bytes.
///
template <uint8_t delim1, uint8_t ...optional_delimiter_bytes>
class one_or_more_up_to_delimiter : public datum {
public:

    /// accepts a string consisting of one or more bytes not equal to
    /// \param delim1, followed by the byte \param delim1 and any other
    /// optional delimiter bytes \param optional_delimiter_bytes.
    ///
    one_or_more_up_to_delimiter(datum &d) {
        if (d.data == nullptr || d.data == d.data_end) {
            d.set_null();
            return;
        }
        const uint8_t *location = (const uint8_t *)memchr(d.data, delim1, d.length());
        if (location == nullptr) {
            this->set_null();
            d.set_null();
            return;
        }
        data_end = location;
        data = d.data;
        d.data = location + 1; // set location to right after the delimiter

        (d.accept(optional_delimiter_bytes),...);
    }
};

namespace rdp {

#ifdef _WIN32
    static uint16_t default_port = hton<uint16_t>(3389);
#else
    static constexpr uint16_t default_port = hton<uint16_t>(3389);
#endif

    // A TPKT consists of two parts: a packet-header and a TPDU.  The
    // format of the header is constant regardless of the type of
    // packet.  The format of the packet-header is as follows:
    //
    //   0                   1                   2                   3
    //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |      vrsn     |    reserved   |          packet length        |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    // where:
    //
    // vrsn                         8 bits
    //
    // This field is always 3 for the version of the protocol described in
    // this memo.
    //
    // packet length                16 bits (min=7, max=65535)
    //
    class tpkt_header {
        literal_byte<0x03, 0x00> vrsn_reserved;
        encoded<uint16_t> packet_length;

    public:

        tpkt_header(datum &d) :
            vrsn_reserved{d},
            packet_length{d}
        { }

    };


    // ISO 8073 Connection-Oriented Transport Protocol (COTP)
    // Connection Request TPDU (following RFC 905, Section 13.3)
    //
    //  1    2        3        4       5   6    7    8    p  p+1...end
    // +--+------+---------+---------+---+---+------+-------+---------+
    // |LI|CR CDT|     DST - REF     |SRC-REF|CLASS |VARIAB.|USER     |
    // |  |1110  |0000 0000|0000 0000|   |   |OPTION|PART   |DATA     |
    // +--+------+---------+---------+---+---+------+-------+---------+
    //
    class cotp_connection_request {
        encoded<uint8_t> length;
        literal_byte<0b11100000> cr_cdt;
        literal_byte<0x00, 0x00> dst_ref;
        encoded<uint16_t> src_ref;
        encoded<uint8_t> class_option;

    public:

        cotp_connection_request(datum &d) :
            length{d},
            cr_cdt{d},
            dst_ref{d},
            src_ref{d},
            class_option{d}
            //
            // variable part not implemented yet
            //
        { }

    };

    static constexpr uint8_t TYPE_RDP_NEG_REQ = 0x01;

    class rdp_neg_req {
        literal_byte<TYPE_RDP_NEG_REQ> type;
        encoded<uint8_t> flags;
        literal_byte<0x08, 0x00> length;       // length MUST be 0x0008, in network byte order
        encoded<uint32_t> requested_protocols;
        bool valid;

    public:

        rdp_neg_req(datum &d) :
            type{d},
            flags{d},
            length{d},
            requested_protocols{d, true},
            valid{d.is_not_null()}
        {}

        void write_json(json_object &o) const {
            if (!valid) { return; }

            json_object neg_req{o, "negotiation_request"};

            json_array flags_array{neg_req, "flags"};
            if (flags.bit<7>()) {
                flags_array.print_string("RESTRICTED_ADMIN_MODE_REQUIRED");
            }
            if (flags.bit<6>()) {
                flags_array.print_string("REDIRECTED_AUTHENTICATION_MODE_REQUIRED");
            }
            if (flags.bit<4>()) {
                flags_array.print_string("CORRELATION_INFO_PRESENT");
            }
            //
            //  note: it would be best to print out other "unknown" flags, if there are any present
            //
            flags_array.close();

            json_array rp_array{neg_req, "requested_protocols"};
            if (requested_protocols.bit<31>()) {
                rp_array.print_string("PROTOCOL_SSL");
            }
            if (requested_protocols.bit<30>()) {
                rp_array.print_string("PROTOCOL_HYBRID");
            }
            if (requested_protocols.bit<29>()) {
                rp_array.print_string("PROTOCOL_RDSTLS");
            }
            if (requested_protocols.bit<28>()) {
                rp_array.print_string("PROTOCOL_HYBRID_EX");
            }
            if (requested_protocols.bit<27>()) {
                rp_array.print_string("PROTOCOL_RDSAAD");
            }
            //
            //  note: it would be best to print out other "unknown" flags, if there are any present
            //
            rp_array.close();

            neg_req.close();
        }

    };

    // Client X.224 Connection Request PDU (following Remote Desktop
    // Protocol: Basic Connectivity and Graphics Remoting
    // [MS-RDPBCGR], Section 2.2.1.1)
    //
    // cookie (variable): An optional and variable-length ANSI
    // character string terminated by a 0x0D0A two-byte sequence. This
    // text string MUST be "Cookie: mstshash=IDENTIFIER", where
    // IDENTIFIER is an ANSI character string (an example cookie
    // string is shown in section 4.1.1). The length of the entire
    // cookie string and CR+LF sequence is included in the X.224
    // Connection Request Length Indicator field. This field MUST NOT
    // be present if the routingToken field is present.
    //
    // rdpNegReq (8 bytes): An optional RDP Negotiation Request
    // (section 2.2.1.1.1) structure. The length of this field is
    // included in the X.224 Connection Request Length Indicator
    // field.
    //
    // rdpCorrelationInfo (36 bytes): An optional Correlation Info
    // (section 2.2.1.1.2) structure. The length of this field is
    // included in the X.224 Connection Request Length Indicator
    // field. This field MUST be present if the
    // CORRELATION_INFO_PRESENT (0x08) flag is set in the flags field
    // of the RDP Negotiation Request structure, encapsulated within
    // the optional rdpNegReq field. If the CORRELATION_INFO_PRESENT
    // (0x08) flag is not set, then this field MUST NOT be present.
    //
    class connection_request_pdu : public base_protocol {
        tpkt_header tpkt;
        cotp_connection_request cotp;
        datum body;
        bool valid;

    public:

        connection_request_pdu(datum &d) :
            tpkt{d},
            cotp{d},
            body{d},
            valid{d.is_not_null()}
        { }

        bool is_not_empty() const { return valid; }

        void write_json(json_object &o, bool metadata=false) const {
            if (!valid) { return; }
            (void)metadata;

            json_object rdp{o, "rdp"};
            datum tmp{body};
            if (lookahead<one_or_more_up_to_delimiter<'\r', '\n'>> cookie{tmp}) {
                rdp.print_key_json_string("cookie", cookie.value);
                tmp = cookie.advance();
            }
            if (lookahead<rdp_neg_req> negotiation_request{tmp}) {
                negotiation_request.value.write_json(rdp);
                tmp = negotiation_request.advance();
            }

            rdp.close();
        }

        void write_l7_metadata(writeable &buf, bool) {
            cbor_object o{buf, false};
            cbor_object rdp{o, "rdp"};
            rdp.close();
            o.close();
        }

    };

    [[maybe_unused]] static bool unit_test() {

        // input: an RDP Connection Request PDU
        //
        uint8_t rdp[] = {
            0x03, 0x00, 0x00, 0x24, 0x1f, 0xe0, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x43, 0x6f, 0x6f, 0x6b, 0x69,
            0x65, 0x3a, 0x20, 0x6d, 0x73, 0x74, 0x73, 0x68,
            0x61, 0x73, 0x68, 0x3d, 0x41, 0x37, 0x30, 0x30,
            0x36, 0x37, 0x0d, 0x0a
        };
        datum rdp_data{rdp, rdp + sizeof(rdp)};

        // expected JSON output: {"rdp":{"cookie":"Cookie: mstshash=A70067"},"src_ip":"10.226.41.226","dst_ip":"10.226.24.52","protocol":6,"src_port":10446,"dst_port":3389,"event_start":1193266689.119209}
        //
        uint8_t json_output[] = {
            0x7b, 0x22, 0x72, 0x64, 0x70, 0x22, 0x3a, 0x7b, 0x22, 0x63, 0x6f, 0x6f,
            0x6b, 0x69, 0x65, 0x22, 0x3a, 0x22, 0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65,
            0x3a, 0x20, 0x6d, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68, 0x3d, 0x41,
            0x37, 0x30, 0x30, 0x36, 0x37, 0x22, 0x7d, 0x2c, 0x22, 0x73, 0x72, 0x63,
            0x5f, 0x69, 0x70, 0x22, 0x3a, 0x22, 0x31, 0x30, 0x2e, 0x32, 0x32, 0x36,
            0x2e, 0x34, 0x31, 0x2e, 0x32, 0x32, 0x36, 0x22, 0x2c, 0x22, 0x64, 0x73,
            0x74, 0x5f, 0x69, 0x70, 0x22, 0x3a, 0x22, 0x31, 0x30, 0x2e, 0x32, 0x32,
            0x36, 0x2e, 0x32, 0x34, 0x2e, 0x35, 0x32, 0x22, 0x2c, 0x22, 0x70, 0x72,
            0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x22, 0x3a, 0x36, 0x2c, 0x22, 0x73,
            0x72, 0x63, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x22, 0x3a, 0x31, 0x30, 0x34,
            0x34, 0x36, 0x2c, 0x22, 0x64, 0x73, 0x74, 0x5f, 0x70, 0x6f, 0x72, 0x74,
            0x22, 0x3a, 0x33, 0x33, 0x38, 0x39, 0x2c, 0x22, 0x65, 0x76, 0x65, 0x6e,
            0x74, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x22, 0x3a, 0x31, 0x31, 0x39,
            0x33, 0x32, 0x36, 0x36, 0x36, 0x38, 0x39, 0x2e, 0x31, 0x31, 0x39, 0x32,
            0x30, 0x39, 0x7d
        };

        connection_request_pdu pdu{rdp_data};
        if (pdu.is_not_empty()) {
            output_buffer<1024> buf;
            json_object record{&buf};
            pdu.write_json(record);
            if (buf.memcmp(json_output, sizeof(json_output)) == 0) {
                return true;
            }
        }
        return false;
    }

}

#endif // RDP_HPP
