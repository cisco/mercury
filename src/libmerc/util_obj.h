// util_obj.h
//
// utility objects
//
// Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
// License at https://github.com/cisco/mercury/blob/master/LICENSE


#ifndef UTIL_OBJ_H
#define UTIL_OBJ_H

#include "datum.h"
#include "buffer_stream.h"

struct ipv4_addr : public datum {
    static const unsigned int bytes_in_addr = 4;
    ipv4_addr() : datum{} { }

    void parse(struct datum &d) {
        datum::parse(d, bytes_in_addr);
    }

    void operator()(struct buffer_stream &b) const {
        if (data) {
            b.write_ipv4_addr(data);
        }
    }
};

struct ipv6_addr : public datum {
    static const unsigned int bytes_in_addr = 16;
    ipv6_addr() : datum{} { }

    void parse(struct datum &d) {
        datum::parse(d, bytes_in_addr);
    }

    void operator()(struct buffer_stream &b) const {
        if (data) {
            b.write_ipv6_addr(data);
        }
    }
};

struct ipv6_address {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;

    bool operator==(const ipv6_address &rhs) const {
        return a == rhs.a && b == rhs.b && c == rhs.c && d == rhs.d;
    }
};

struct ip_address {
    enum ip_version { v4, v6 };
    enum ip_version version;
    union address {
        address(uint32_t a)     : ipv4{a} {}
        address(ipv6_address a) : ipv6{a} {}
        uint32_t ipv4;
        ipv6_address ipv6;
    } value;

    explicit ip_address(uint32_t v4_addr)     : version{ip_version::v4}, value{v4_addr} {}
    explicit ip_address(ipv6_address v6_addr) : version{ip_version::v6}, value{v6_addr} {}
};

struct key {
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t ip_vers;
    union {
        struct {
            uint32_t src;
            uint32_t dst;
        } ipv4;
        struct {
            ipv6_address src;
            ipv6_address dst;
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

#define MAX_ADDR_STR_LEN 48

    void sprint_src_addr(char src_addr[MAX_ADDR_STR_LEN]) const {
        if (ip_vers == 4) {
            uint8_t *sa = (uint8_t *)&addr.ipv4.src;
            snprintf(src_addr, MAX_ADDR_STR_LEN, "%u.%u.%u.%u", sa[0], sa[1], sa[2], sa[3]);
        } else {
            uint8_t *sa = (uint8_t *)&addr.ipv6.src;
            snprintf(src_addr, MAX_ADDR_STR_LEN, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                    sa[0], sa[1], sa[2], sa[3], sa[4], sa[5], sa[6], sa[7], sa[8], sa[9], sa[10], sa[11], sa[12], sa[13], sa[14], sa[15]);
        }
    }

#define MAX_PORT_STR_LEN 6
    void sprint_dst_port(char dst_port_string[MAX_PORT_STR_LEN]) const {
        snprintf(dst_port_string, MAX_PORT_STR_LEN, "%u", dst_port);
    }

};

struct eth_addr : public datum {
    static const unsigned int bytes_in_addr = 6;

    eth_addr(datum &d) : datum{d} { }

    void parse(struct datum &d) {
        datum::parse(d, bytes_in_addr);
    }

    void operator()(struct buffer_stream &b) const {
        if (data) {
            b.raw_as_hex(data, datum::length());  // TODO: write colon-delimited hex
        }
    }
};

#endif // UTIL_OBJ_H

