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

#include "extractor.h"

extern bool select_mdns;                    // defined in extractor.cc


enum udp_msg_type udp_get_message_type(const uint8_t *udp_data, unsigned int len);

struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__ ((__packed__));

struct udp_packet {
    const struct udp_header *header;
    enum udp_msg_type msg_type = udp_msg_type_unknown;

    udp_packet(struct datum &d) : header{NULL} { parse(d); };

    void parse(struct datum &d) {
        header = d.get_pointer<udp_header>();
        if (header == nullptr) {
            return;
        }

        msg_type = udp_get_message_type(d.data, d.length());
        if (msg_type == udp_msg_type_unknown) {
            msg_type = estimate_msg_type_from_ports();
        }
    }

    enum udp_msg_type get_msg_type() const { return msg_type; }

    void set_key(struct key &k) {
        if (header) {
            k.src_port = ntohs(header->src_port);
            k.dst_port = ntohs(header->dst_port);
            k.protocol = 17; // udp
        }
    }

    enum udp_msg_type estimate_msg_type_from_ports() {

        // TODO: make select_mdns a function argument, not an extern
        //
        if (header) {
            // if (header->src_port == htons(53) || header->dst_port == htons(53)) {
            //     return udp_msg_type_dns;
            // }
            if (select_mdns && (header->src_port == htons(5353) || header->dst_port == htons(5353))) {
                return udp_msg_type_dns;
            }
            if (header->dst_port == htons(4789)) {
                return udp_msg_type_vxlan;
            }
        }
        return udp_msg_type_unknown;
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
        if (datum_skip(&d, VXLAN_HDR_LEN) != status_ok) {
            d.set_empty();
        }
    }
    // note: we ignore the VXLAN Network Identifier for now, which
    // makes little difference as long as they are all identical
    //
};

#endif  // UDP_H

