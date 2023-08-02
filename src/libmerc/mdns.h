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

struct mdns_packet : public base_protocol {
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

    static bool check_if_mdns(const struct key& k) {
        static constexpr uint32_t mdns_v4_addr = 0xE00000FB; /* Hex representation of 224.0.0.251 */
        /* Mdns Multicast IPv6 address ff02::fb */
        static constexpr uint32_t mdns_v6_addr_0 = 0xff020000;
        static constexpr uint32_t mdns_v6_addr_1 = 0;
        static constexpr uint32_t mdns_v6_addr_2 = 0;
        static constexpr uint32_t mdns_v6_addr_3 = 0xfb;

        if (k.src_port == 5353 and k.dst_port == 5353) {
            return true;
        }
        /* Below condition is to detect One shot multicast dns queries */
        if (k.ip_vers == 4) {
            return (k.addr.ipv4.dst == ntoh(mdns_v4_addr));
        }
        else {
            return (k.addr.ipv6.dst.a ==  ntoh(mdns_v6_addr_0)
                and k.addr.ipv6.dst.b ==  ntoh(mdns_v6_addr_1)
                and k.addr.ipv6.dst.c ==  ntoh(mdns_v6_addr_2)
                and k.addr.ipv6.dst.d ==  ntoh(mdns_v6_addr_3));
        }
    }
};

namespace {

    [[maybe_unused]] int mdns_fuzz_test(const uint8_t *data, size_t size) {
        datum pkt_data{data, data+size};
        mdns_packet mdns_record{pkt_data};

        char buffer[8192];
        struct buffer_stream buf_json(buffer, sizeof(buffer));
        struct json_object record(&buf_json);

        if (mdns_record.is_not_empty()) {
            mdns_record.write_json(record);
        }

        return 0;
    }

}; // end of namespace

#endif /* MDNS_H */
