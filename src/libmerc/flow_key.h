/*
 * flow_key.h
 *
 * Copyright (c) 2019-2023 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef FLOW_KEY_H
#define FLOW_KEY_H

#include "ip_address.hpp"
#include "json_object.h"
#include "libmerc.h" // flow_key_ext

#define MAX_ADDR_STR_LEN 48
#define MAX_PORT_STR_LEN 6

struct key {
    uint16_t src_port;   // source port in network byte order
    uint16_t dst_port;   // destination port in network byte order
    uint8_t protocol;    // ipv4 protocol or ipv6 "next header"
    uint8_t ip_vers;     // protocol version (4, 6, or 0 == undefined)
    union {
        struct {
            uint32_t src;    // ipv4 source address in network byte order
            uint32_t dst;    // ipv4 dstination address in network byte order
        } ipv4;
        struct {
            ipv6_address src;  // ipv6 source address in network byte order
            ipv6_address dst;  // ipv6 destination address in network byte order
        } ipv6;
    } addr;

    key(uint16_t sp, uint16_t dp, uint32_t sa, uint32_t da, uint8_t proto) {
        src_port = sp;
        dst_port = dp;
        protocol = proto;
        ip_vers = 4;
        addr.ipv6.src = { 0, 0, 0, 0 };   /* zeroize v6 src addr */
        addr.ipv6.dst = { 0, 0, 0, 0 };   /* zeroize v6 dst addr */
        addr.ipv4.src = sa;
        addr.ipv4.dst = da;
    }
    key(uint16_t sp, uint16_t dp, ipv6_address sa, ipv6_address da, uint8_t proto) {
        src_port = sp;
        dst_port = dp;
        protocol = proto;
        ip_vers = 6;
        addr.ipv6.src = sa;
        addr.ipv6.dst = da;
    }
    key() {
        src_port = 0;
        dst_port = 0;
        protocol = 0;
        ip_vers = 0;       // null key can be distinguished by ip_vers field
        addr.ipv6.src = { 0, 0, 0, 0 };
        addr.ipv6.dst = { 0, 0, 0, 0 };
    }
    key(struct flow_key_ext k) {
        src_port = k.src_port;
        dst_port = k.dst_port;
        protocol = k.protocol;
        ip_vers = k.ip_vers;
        if (ip_vers == 4) {
            addr.ipv4.src = k.addr.ipv4.src;
            addr.ipv4.dst = k.addr.ipv4.dst;
        }
        else if (ip_vers == 6) { // ip_vers == 6
            addr.ipv6.src.a[0] = k.addr.ipv6.src.a;
            addr.ipv6.src.a[1] = k.addr.ipv6.src.b;
            addr.ipv6.src.a[2] = k.addr.ipv6.src.c;
            addr.ipv6.src.a[3] = k.addr.ipv6.src.d;

            addr.ipv6.dst.a[0] = k.addr.ipv6.dst.a;
            addr.ipv6.dst.a[1] = k.addr.ipv6.dst.b;
            addr.ipv6.dst.a[2] = k.addr.ipv6.dst.c;
            addr.ipv6.dst.a[3] = k.addr.ipv6.dst.d;
        }
        else {
            src_port = 0;
            dst_port = 0;
            protocol = 0;
            ip_vers = 0;       // null key can be distinguished by ip_vers field
            addr.ipv6.src = { 0, 0, 0, 0 };
            addr.ipv6.dst = { 0, 0, 0, 0 };
        }
    }
    void zeroize() {
        ip_vers = 0;
    }
    bool is_zero() const {
        return ip_vers == 0;
    }
    bool operator==(const key &k) const {
        switch (ip_vers) {
        case 4:
            return src_port == k.src_port
                && dst_port == k.dst_port
                && protocol == k.protocol
                && k.ip_vers == 4
                && addr.ipv4.src == k.addr.ipv4.src
                && addr.ipv4.dst == k.addr.ipv4.dst;
            break;
        case 6:
            return src_port == k.src_port
                && dst_port == k.dst_port
                && protocol == k.protocol
                && k.ip_vers == 6
                && addr.ipv6.src == k.addr.ipv6.src
                && addr.ipv6.dst == k.addr.ipv6.dst;
        default:
            return 0;
        }
    }

    void sprint_src_addr(char src_addr[MAX_ADDR_STR_LEN]) const {
        if (ip_vers == 4) {
            uint8_t *sa = (uint8_t *)&addr.ipv4.src;
            snprintf(src_addr, MAX_ADDR_STR_LEN, "%u.%u.%u.%u", sa[0], sa[1], sa[2], sa[3]);
        } else {
            uint8_t *sa = (uint8_t *)&addr.ipv6.src;
            sprintf_ipv6_addr(src_addr, sa);
        }
    }

    void sprint_src_port(char src_port_string[MAX_PORT_STR_LEN]) const {
        snprintf(src_port_string, MAX_PORT_STR_LEN, "%u", src_port);
    }

    void sprint_dst_port(char dst_port_string[MAX_PORT_STR_LEN]) const {
        snprintf(dst_port_string, MAX_PORT_STR_LEN, "%u", dst_port);
    }

    bool src_is_global() const {
        if (ip_vers == 4) {
            ipv4_address a{addr.ipv4.src};
            return a.is_global();
        }
        return addr.ipv6.src.is_global();
    }

    bool dst_is_global() const {
        if (ip_vers == 4) {
            ipv4_address a{addr.ipv4.dst};
            return a.is_global();
        }
        return addr.ipv6.dst.is_global();
    }

    // write out the destination address
    //
    void sprintf_dst_addr(char *dst_addr_str) const {

        if (ip_vers == 4) {
            ipv4_address tmp_addr{addr.ipv4.dst};
            uint8_t *d = (uint8_t *)&tmp_addr;
            snprintf(dst_addr_str,
                     MAX_ADDR_STR_LEN,
                     "%u.%u.%u.%u",
                     d[0], d[1], d[2], d[3]);

        } else if (ip_vers == 6) {
            ipv6_address tmp_addr{addr.ipv6.dst};
            uint8_t *d = (uint8_t *)&tmp_addr;
            sprintf_ipv6_addr(dst_addr_str, d);
        } else {
            dst_addr_str[0] = '\0'; // make sure that string is null-terminated
        }
    }

    static void sprintf_ipv6_addr(char *addr_str, const uint8_t *ipv6_addr) {
        int trunc = 0;
        int offset = 0;
        int len;
        len = append_ipv6_addr(addr_str, &offset, MAX_ADDR_STR_LEN, &trunc, ipv6_addr);
        addr_str[len] = '\0';
    }

    uint16_t get_dst_port() const {
        return dst_port;
    }

    // swap the source and destination ports and addresses
    //
    void reverse() {
        std::swap(src_port, dst_port);
        switch (ip_vers) {
        case 4:
            std::swap(addr.ipv4.src, addr.ipv4.dst);
            break;
        case 6:
            std::swap(addr.ipv6.src, addr.ipv6.dst);
            break;
        default:
            ;
        }
    }


    // hash() returns a size_t, and returns a hash of this flow key,
    // suitable for use in STL containers
    //
    std::size_t hash() const {

        size_t multiplier = 2862933555777941757;  // source: https://nuclear.llnl.gov/CNP/rng/rngman/node3.html

        std::size_t x;
        if (ip_vers == 4) {
            uint32_t sa = addr.ipv4.src;
            uint32_t da = addr.ipv4.dst;
            uint16_t sp = src_port;
            uint16_t dp = dst_port;
            uint8_t  pr = protocol;
            x = ((uint64_t) sp * da) + ((uint64_t) dp * sa);
            x *= multiplier;
            x += sa + da + sp + dp + pr;
            x *= multiplier;
        } else {
            uint64_t *sa = (uint64_t *)&addr.ipv6.src;
            uint64_t *da = (uint64_t *)&addr.ipv6.dst;
            uint16_t sp = src_port;
            uint16_t dp = dst_port;
            uint8_t  pr = protocol;
            x = ((uint64_t) sp * da[0] * da[1]) + ((uint64_t) dp * sa[0] * sa[1]);
            x *= multiplier;
            x += sa[0] + sa[1] + da[0] + da[1] + sp + dp + pr;
            x *= multiplier;
        }

        return x;

    }

    void write_ip_address(struct json_object &o) const {
        if (ip_vers == 6) {
            const uint8_t *s = (const uint8_t *)&addr.ipv6.src;
            o.print_key_ipv6_addr("src_ip", s);

            const uint8_t *d = (const uint8_t *)&addr.ipv6.dst;
            o.print_key_ipv6_addr("dst_ip", d);

        } else {

            const uint8_t *s = (const uint8_t *)&addr.ipv4.src;
            o.print_key_ipv4_addr("src_ip", s);

            const uint8_t *d = (const uint8_t *)&addr.ipv4.dst;
            o.print_key_ipv4_addr("dst_ip", d);

        }

    }
};

namespace std {

    // define a hash<key> object suitable for use in STL containers
    //
    template <>  struct hash<key>  {
        std::size_t operator()(const key& k) const {
            return k.hash();
        }
    };
}


#endif // FLOW_KEY_H
