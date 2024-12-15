// rdp.hpp
//
// microsoft remote desktop protocol

#ifndef RDP_HPP
#define RDP_HPP

#include "datum.h"

namespace rdp {

    static constexpr default_port = hton<uint16_t>(3389);

    //     A TPKT consists of two parts:  a packet-header and a TPDU.  The
    // format of the header is constant regardless of the type of packet.
    // The format of the packet-header is as follows:
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
    class connection_request_pdu {
        tpkt_header tpkt;
        cotp_connection_request cotp;

        // optional fields not yet implemented

    public:

        connection_request_pdu(datum &d) :
            tpkt{d},
            cotp{d}
        { }

    };

}

#endif // RDP_HPP
