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

#include "fixed_datum.hpp"
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

struct udp_source_port_field { };
struct udp_destination_port_field { };
struct udp_length_field { };
struct udp_checksum_field { };

using udp_header_view = fixed_datum<
    8,
    fixed_datum_field<udp_source_port_field, uint16_t>,
    fixed_datum_field<udp_destination_port_field, uint16_t>,
    fixed_datum_field<udp_length_field, uint16_t>,
    fixed_datum_field<udp_checksum_field, uint16_t>>;

static_assert(sizeof(udp_header_view) == sizeof(uint8_t *));

class udp {

    udp_header_view header;
    uint32_t more_bytes_needed;
    // ports if header is null
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

public:

    /// construct a udp object by parsing a UDP header from datum
    /// \param d
    ///
    udp(struct datum &d) : header{}, more_bytes_needed{0} {
        parse(d);
    };

    /// construct a udp pseudoheader object from the flow key \param
    /// k; this should only be done when there is no UDP header to be
    /// parsed.
    ///
    udp(const key &k) :
        header{},
        more_bytes_needed{0},
        src_port{k.src_port},
        dst_port{k.dst_port}
    { }

    void parse(struct datum &d) {
        header = udp_header_view{d};
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
            return {
                header.field<udp_source_port_field>(),
                header.field<udp_destination_port_field>()
            };
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
            k.src_port = ntoh(header.field<udp_source_port_field>());
            k.dst_port = ntoh(header.field<udp_destination_port_field>());
            k.protocol = 17; // udp
        }
    }

    uint16_t get_len() const {
        if (header) {
            return ntoh(header.field<udp_length_field>());
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

#ifndef NDEBUG
// LCOV_EXCL_START
inline bool udp_unit_test() {
    const uint8_t packet[] = {
        0x12, 0x34,
        0xab, 0xcd,
        0x00, 0x08,
        0xde, 0xad,
        0xff
    };

    datum header_data{packet, packet + sizeof(packet)};
    udp_header_view header{header_data};
    if (!header || header_data.length() != 1) return false;
    if (ntoh(header.field<udp_source_port_field>()) != 0x1234) return false;
    if (ntoh(header.field<udp_destination_port_field>()) != 0xabcd) return false;
    if (ntoh(header.field<udp_length_field>()) != 8) return false;
    if (header.read<uint8_t, 7>() != 0xad) return false;

    datum truncated_header{packet, packet + 7};
    udp_header_view missing{truncated_header};
    if (missing || !truncated_header.is_null()) return false;

    datum d{packet, packet + sizeof(packet)};
    udp parsed{d};
    udp::ports ports = parsed.get_ports();
    if (ports.src != 0x3412 || ports.dst != 0xcdab) return false;
    if (parsed.get_len() != 8) return false;

    key k{};
    parsed.set_key(k);
    if (k.src_port != 0x1234 || k.dst_port != 0xabcd || k.protocol != 17) return false;
    if (d.length() != 1) return false;

    datum truncated{packet, packet + 7};
    udp invalid{truncated};
    if (invalid.get_ports().src != 0 || invalid.get_ports().dst != 0) return false;
    if (!truncated.is_null()) return false;

    return true;
}
// LCOV_EXCL_STOP
#endif // NDEBUG

#endif  // UDP_H
