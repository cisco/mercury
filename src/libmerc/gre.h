// gre.h
//
// Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
// https://github.com/cisco/mercury/blob/master/LICENSE


#ifndef GRE_H
#define GRE_H

#include "datum.h"

//
//  Generic Routing Encapsulation (GRE) as per RFC 2784
//
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |C|       Reserved0       | Ver |         Protocol Type         |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |      Checksum (optional)      |       Reserved1 (Optional)    |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//  Note: RFC 1701 defines an obsolete and more elaborate earlier
//  variant of the GRE header, which is little seen on modern
//  networks.
//
class gre_header {
    encoded<uint16_t> c_reserved_ver;
    encoded<uint16_t> protocol_type;
public:

    gre_header(struct datum &d) : c_reserved_ver{d}, protocol_type{d} {
        if (c_reserved_ver.bit<0>()) {
            d.skip(4);  // skip over Checksum and Reserved1 fields
        }
        if (d.is_null()) {
            protocol_type = 0x0000; // ETH_TYPE_NONE
            return;
        }
    }

    // get_protocol_type() returns the protocol_type value in the GRE
    // header, if there were no errors, and otherwise returns
    // ETH_TYPE_NONE (0x0000).  The protocol_type field should be
    // interpreted as an ETHERTYPE, as defined at
    // https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml.
    //
    uint16_t get_protocol_type() const { return protocol_type; }
};

#endif
