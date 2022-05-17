/*
 * mdns.h
 *
 * Copyright (c) 2022 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

/**
 * \file mdns.h
 *
 * \brief interface file for mDNS code
 */
#ifndef MDNS_H
#define MDNS_H

#include "dns.h"

/*
 * Summary of mDNS (from RFC 6762)
 *
 * Multicast DNS borrows heavily from the existing DNS protocol
 * [RFC1034] [RFC1035] [RFC6195], using the existing DNS message
 * structure, name syntax, and resource record types.
 *
 * The source UDP port in all Multicast DNS responses MUST be 5353.
 *
 * The destination UDP port in all Multicast DNS responses MUST be 5353.
 *
 * One-Shot Multicast DNS Queries MUST NOT be sent using UDP source port 5353.
 *
 * Destination address MUST be the mDNS IPv4 link-local
 * multicast address 224.0.0.251 or its IPv6 equivalent FF02::FB, except
 * when generating a reply to a query that explicitly requested a
 * unicast response.
 * 
 * Multicast DNS implementations
 * MUST silently ignore any Multicast DNS responses they receive where
 * the source UDP port is not 5353.
 */

#define MDNS_V4ADDR 0xE00000FB /* Hex representation of 224.0.0.251 */
/* Mdns Multicast IPv6 address ff02::fb */
#define MDNS_V6_ADDR_0 0xff020000
#define MDNS_V6_ADDR_1 0x0
#define MDNS_V6_ADDR_2 0x0
#define MDNS_V6_ADDR_3 0xFB

bool check_if_mdns(const struct key& k) {
    if (k.src_port == 5353 and k.dst_port == 5353) {
        return true;
    }
    /* Below condition is to detect One shot multicast dns queries */
    if (k.ip_vers == 4) {
        return (k.addr.ipv4.dst == ntohl(MDNS_V4ADDR));
    }
    else {
        return (k.addr.ipv6.dst.a ==  ntohl(MDNS_V6_ADDR_0)
                and k.addr.ipv6.dst.b ==  ntohl(MDNS_V6_ADDR_1)
                and k.addr.ipv6.dst.c ==  ntohl(MDNS_V6_ADDR_2)
                and k.addr.ipv6.dst.d ==  ntohl(MDNS_V6_ADDR_3));
    }
}

struct mdns_packet {
    dns_packet dns_pkt;

    mdns_packet(struct datum &d) : dns_pkt{d} { }

    struct datum get_datum() const {
        return (dns_pkt.get_datum());
    }
    bool is_not_empty() {
        return (dns_pkt.is_not_empty());
    }

    void write_json(struct json_object &o) const {
        dns_pkt.write_json(o);
    }
};

#endif /* MDNS_H */
