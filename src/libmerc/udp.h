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
    struct header {
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t length;
        uint16_t checksum;
    } __attribute__ ((__packed__));

    const struct header *header;

public:

    udp(struct datum &d) : header{NULL} { parse(d); };

    void parse(struct datum &d) {
        header = d.get_pointer<struct header>();
        if (header == nullptr) {
            return;
        }

    }

    // struct ports is a simple public helper used to return port info
    //
    struct ports { uint16_t src; uint16_t dst; };

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

};

//   From RFC 7348 (VXLAN)
//
//   #define VXLAN_PORT 4789
//
//   VXLAN Header:
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |R|R|R|R|I|R|R|R|            Reserved                           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                VXLAN Network Identifier (VNI) |   Reserved    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//

#define VXLAN_HDR_LEN 8

class vxlan : public datum {
    vxlan(datum &d) : datum{d} {
        if (d.skip(VXLAN_HDR_LEN) == false) {
            d.set_empty();
        }
    }
    // note: we ignore the VXLAN Network Identifier for now, which
    // makes little difference as long as they are all identical
    //
};

#endif  // UDP_H

