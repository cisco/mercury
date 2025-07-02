/*
 * udp.h
 *
 * UDP protocol processing
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef UDP_H
#define UDP_H

#include "datum.h"
#include "flow_key.h"

//    UDP header (from RFC 768)
//
//                   0      7 8     15 16    23 24    31
//                  +--------+--------+--------+--------+
//                  |     Source      |   Destination   |
//                  |      Port       |      Port       |
//                  +--------+--------+--------+--------+
//                  |                 |                 |
//                  |     Length      |    Checksum     |
//                  +--------+--------+--------+--------+
//                  |
//                  |          data octets ...
//                  +---------------- ...
//
//    Length is the length in octets of this user datagram including this
//    header and the data.  (This means the minimum value of the length
//    is eight.)
//
//    Checksum is the 16-bit one's complement of the one's complement sum
//    of a pseudo header of information from the IP header, the UDP
//    header, and the data, padded with zero octets at the end (if
//    necessary) to make a multiple of two octets.
//
//    If the computed checksum is zero, it is transmitted as all ones
//    (the equivalent in one's complement arithmetic).  An all zero
//    transmitted checksum value means that the transmitter generated no
//    checksum (for debugging or for higher level protocols that don't
//    care).
//

class udp {

    // struct header represents a UDP header
    //
#ifdef _WIN32

#pragma pack(1)
struct header {
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t length;
        uint16_t checksum;
    };
#pragma pack()

    const struct header *header;
    uint32_t more_bytes_needed;
    // ports if header is null
    uint16_t src_port;
    uint16_t dst_port;

#else

    struct header {
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t length;
        uint16_t checksum;
    } __attribute__ ((__packed__));

    const struct header *header;
    uint32_t more_bytes_needed;
    // ports if neader is null
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

#endif

public:

    udp(struct datum &d, bool payload_only=false) : header{NULL}, more_bytes_needed{0} { 
        if(payload_only) {
            return;
        }
        parse(d);
    };

    void parse(struct datum &d) {
        header = d.get_pointer<struct header>();
        if (header == nullptr) {
            return;
        }

    }

    // struct ports is a simple public helper used to return port info
    //
    struct ports {
        uint16_t src;
        uint16_t dst;

        /// returns true if either the source port or the destination
        /// port matches \param nbo_value, a \ref uint16_t in network
        /// byte order.
        ///
        bool either_matches(uint16_t nbo_value) const {
            return (dst == nbo_value) || (src == nbo_value);
        }

        /// returns true if either the source port or the destination
        /// port matches any of the inputs, each of which must be \ref
        /// uint16_t in network byte order.
        ///
        template<typename... Args>
        bool either_matches_any(Args... nbo_value) { return (... or ((nbo_value == src) || (nbo_value == dst))); }

    };

    // get_ports() returns the source and destination ports, if this
    // is a valid UDP packet; otherwise, { 0, 0 } is returned to
    // indicate that the packet is not valid.  Zero is a reserved
    // value that should not appear on the wire (see
    // https://www.iana.org/assignments/service-names-port-numbers/)
    //
    struct ports get_ports() const {
        if (header) {
            return { header->src_port, header->dst_port };
        }
        else if (src_port && dst_port) {
            return {src_port,dst_port};
        }
        return { 0, 0 };
    }

    // set_key(k) sets the source and destination port number for the
    // flow key k
    //
    void set_key(struct key &k) const {
        if (header) {
            k.src_port = ntoh(header->src_port);
            k.dst_port = ntoh(header->dst_port);
            k.protocol = 17; // udp
        }
    }

    void set_ports(const key &k) {
        src_port = hton(k.src_port);
        dst_port = hton(k.dst_port);
    }

    uint16_t get_len() const {
        if (header) {
            return ntoh(header->length);
        }
        return 0;
    }

    void reassembly_needed (uint32_t bytes) {
        more_bytes_needed = bytes;
    }

    uint32_t additional_bytes_needed() {
        return more_bytes_needed;
    }

};

#endif  // UDP_H

