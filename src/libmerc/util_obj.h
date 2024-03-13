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
#include "utils.h"

struct ipv4_addr : public datum {
    static const unsigned int bytes_in_addr = 4;
    ipv4_addr() : datum{} { }

    ipv4_addr(struct datum &d) :  datum{} {
        datum::parse(d, bytes_in_addr);
    }

    void parse(struct datum &d) {
        datum::parse(d, bytes_in_addr);
    }

    void fingerprint(struct buffer_stream &b) const {
        if (data) {
            b.write_ipv4_addr(data);
        }
    }
};

struct ipv6_addr : public datum {
    static const unsigned int bytes_in_addr = 16;
    ipv6_addr() : datum{} { }

    ipv6_addr(struct datum &d) :  datum{} {
        datum::parse(d, bytes_in_addr);
    }

    void parse(struct datum &d) {
        datum::parse(d, bytes_in_addr);
    }

    void fingerprint(struct buffer_stream &b) const {
        if (data) {
            b.write_ipv6_addr(data);
        }
    }
};

class ipv4_address {
    encoded<uint32_t> value;

public:

    ipv4_address(uint32_t init) : value{init} { }

    void fingerprint(struct buffer_stream &b) const {
        uint32_t tmp = value;
        swap_byte_order(tmp);
        b.write_ipv4_addr((uint8_t *)&tmp);
    }

    //
    //
    //
    /*
    0.0.0.0/8	"This network"	[RFC791], Section 3.2	1981-09	N/A	True	False	False	False	True
    0.0.0.0/32	"This host on this network"	[RFC1122], Section 3.2.1.3	1981-09	N/A	True	False	False	False	True
    10.0.0.0/8	Private-Use	[RFC1918]	1996-02	N/A	True	True	True	False	False
    100.64.0.0/10	Shared Address Space	[RFC6598]	2012-04	N/A	True	True	True	False	False
    127.0.0.0/8	Loopback	[RFC1122], Section 3.2.1.3	1981-09	N/A	False [1]	False [1]	False [1]	False [1]	True
    169.254.0.0/16	Link Local	[RFC3927]	2005-05	N/A	True	True	False	False	True
    172.16.0.0/12	Private-Use	[RFC1918]	1996-02	N/A	True	True	True	False	False
    192.0.0.0/24 [2]	IETF Protocol Assignments	[RFC6890], Section 2.1	2010-01	N/A	False	False	False	False	False
    192.0.0.0/29	IPv4 Service Continuity Prefix	[RFC7335]	2011-06	N/A	True	True	True	False	False
    192.0.0.8/32	IPv4 dummy address	[RFC7600]	2015-03	N/A	True	False	False	False	False
    192.0.0.9/32	Port Control Protocol Anycast	[RFC7723]	2015-10	N/A	True	True	True	True	False
    192.0.0.10/32	Traversal Using Relays around NAT Anycast	[RFC8155]	2017-02	N/A	True	True	True	True	False
    192.0.0.170/32, 192.0.0.171/32	NAT64/DNS64 Discovery	[RFC8880][RFC7050], Section 2.2	2013-02	N/A	False	False	False	False	True
    192.0.2.0/24	Documentation (TEST-NET-1)	[RFC5737]	2010-01	N/A	False	False	False	False	False
    192.31.196.0/24	AS112-v4	[RFC7535]	2014-12	N/A	True	True	True	True	False
    192.52.193.0/24	AMT	[RFC7450]	2014-12	N/A	True	True	True	True	False
    192.88.99.0/24	Deprecated (6to4 Relay Anycast)	[RFC7526]	2001-06	2015-03
    192.168.0.0/16	Private-Use	[RFC1918]	1996-02	N/A	True	True	True	False	False
    192.175.48.0/24	Direct Delegation AS112 Service	[RFC7534]	1996-01	N/A	True	True	True	True	False
    198.18.0.0/15	Benchmarking	[RFC2544]	1999-03	N/A	True	True	True	False	False
    198.51.100.0/24	Documentation (TEST-NET-2)	[RFC5737]	2010-01	N/A	False	False	False	False	False
    203.0.113.0/24	Documentation (TEST-NET-3)	[RFC5737]	2010-01	N/A	False	False	False	False	False
    240.0.0.0/4	Reserved	[RFC1112], Section 4	1989-08	N/A	False	False	False	False	True
    255.255.255.255/32	Limited Broadcast	[RFC8190] [RFC919], Section 7
    */

    enum addr_type {
        unknown  = 0,
        priv     = 1,
        routable = 2,
    };

    addr_type get_addr_type() const {
        if (((value & 0x000000ff) == 0x0000000a) or // 10.0.0.0/8
            ((value & 0x0000f0ff) == 0x000010ac) or // 172.16.0.0/12
            ((value & 0x0000ffff) == 0x0000a8c0)) { // 192.168.0.0/16
            return priv;
        }
        return routable;
    }

    addr_type get_addr_type_nbo() const {
        if (((value & 0xff000000) == 0x0a000000) or // 10.0.0.0/8
            ((value & 0xfff00000) == 0xac100000) or // 172.16.0.0/12
            ((value & 0xffff0000) == 0xc0a80000)) { // 192.168.0.0/16
            return priv;
        }
        return routable;
    }

    bool is_global() const {
        return get_addr_type_nbo() == routable;
    }

};

struct ipv6_address {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;

public:

    // construct an ipv6_address with the default all-zero address,
    // which refers to "this machine"
    //
    // ipv6_address() : a{0}, b{0}, c{0}, d{d} { }
    //
    // ipv6_address(__uint128_t &in) {
    //     a = in >> 96;
    //     b = (in >> 64) & 0xffffffff;
    //     c = (in >> 32) & 0xffffffff;
    //     d = in & 0xffffffff;
    // }
    //
    // ipv6_address(uint32_t a_in, uint32_t b_in, uint32_t c_in, uint32_t d_in) :
    //     a{a_in}, b{b_in}, c{c_in}, d{d_in}
    // { }

    bool operator==(const ipv6_address &rhs) const {
        return a == rhs.a && b == rhs.b && c == rhs.c && d == rhs.d;
    }

    void fingerprint(struct buffer_stream &buf) const {
        uint32_t tmp[4] = {
            // swap_byte_order(a),
            // swap_byte_order(b),
            // swap_byte_order(c),
            // swap_byte_order(d)
            a,b,c,d
        };
        buf.write_ipv6_addr((uint8_t *)&tmp);
    }

    void print_uint32_binary(FILE *f, uint32_t x) const {
        uint32_t mask = 1 << 31;
        while (mask != 0) {
            fputc(mask & x ? '1' : '0', f);
            mask = mask >> 1;
        }
    }

    void print_binary(FILE *f, const char *tail=nullptr) const {
        print_uint32_binary(f, hton(a));
        print_uint32_binary(f, hton(b));
        print_uint32_binary(f, hton(c));
        print_uint32_binary(f, hton(d));
        if (tail) {
            fprintf(f, "%s", tail);
        }
    }

    /*

      IPv6 Address Prefixes (other than "Reserved")

      2000::/3   Global Unicast,[RFC3513][RFC4291],"The IPv6 Unicast
                 space encompasses the entire IPv6 address range with
                 the exception of ff00::/8, per [RFC4291]. IANA
                 unicast address assignments are currently limited to
                 the IPv6 unicast address range of 2000::/3. IANA
                 assignments from this block are registered in [IANA
                 registry ipv6-unicast-address-assignments].

      fc00::/7   Unique Local Unicast,[RFC4193],"For complete
                 registration details, see [IANA registry
                 iana-ipv6-special-registry]."

      fe80::/10  Link-Scoped Unicast,[RFC3513][RFC4291],"Reserved by
                 protocol. For authoritative registration, see [IANA
                 registry iana-ipv6-special-registry]."

      ff00::/8   Multicast,[RFC3513][RFC4291],IANA assignments from this
                 block are registered in [IANA registry
                 ipv6-multicast-addresses].

      fec0::/10  Deprecated, was site-local (until 2004)

      2000::/3      001xxxxxxxxxxxxx      global unicast
      FC00::/7      1111110xxxxxxxxx      unique local unicast
      FE80::/10     1111111010xxxxxx      link scoped unicast
      FF00::/8      11111111xxxxxxxx      multiast

      IPv4-Mapped IPv6 Addresses: 0000..............................0000|FFFF

    */
    enum ipv6_addr_type {
        global_unicast,
        unique_local_unicast,
        link_scoped_unicast,
        multicast
    };

    // bool is_global_unicast() const {
    //     return (a & 0xe0000000) == 0x20000000;
    // }
    bool is_global_unicast() const {
        // fprintf(stderr, "check: %08x\t%08x==%08x\n", a, (a & hton<uint32_t>(0xe0000000)),  hton<uint32_t>(0x20000000));
        return (a & hton<uint32_t>(0xe0000000)) == hton<uint32_t>(0x20000000);
    }
    bool is_unique_local_unicast() const {
        return (a & hton<uint32_t>(0xfe000000)) == hton<uint32_t>(0xfc000000);
    }
    bool is_link_scoped_unicast() const {
        return (a & hton<uint32_t>(0xffc00000)) == hton<uint32_t>(0xfe800000);
    }
    bool is_deprecated_site_local() const {
        return (a & hton<uint32_t>(0xffc00000)) == hton<uint32_t>(0xfec00000);
    }
    bool is_multicast() const {
        return (a & hton<uint32_t>(0xff000000)) == hton<uint32_t>(0xff000000);
    }
    bool is_global() const {
        return is_global_unicast();   // TODO: consider global multicast
    }
    bool is_ipv4_mapped() const {
        return (a == 0 && b == 0 && c == hton<uint32_t>(0x0000ffff));
    }

    void normalize() {
        if (not is_global()) {
            ;
        }
    }

    
    static bool unit_test() {

        // ipv6_address addr;

        return true;   // tests passed
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
            sprintf_ipv6_addr(src_addr, sa);
        }
    }

#define MAX_PORT_STR_LEN 6
    void sprint_dst_port(char dst_port_string[MAX_PORT_STR_LEN]) const {
        snprintf(dst_port_string, MAX_PORT_STR_LEN, "%u", dst_port);
    }


    bool dst_is_global() const {
        if (ip_vers == 4) {
            ipv4_address a{addr.ipv4.dst};
            return a.is_global();
        }
        return addr.ipv6.dst.is_global();
    }

    void normalize() {
        if (ip_vers == 4 and dst_is_global()) {
            addr.ipv4.dst = 0x0a00000a;  // 10.0.0.1
        }
    }

};

struct eth_addr : public datum {
    static const unsigned int bytes_in_addr = 6;

    eth_addr(datum &d) : datum{} {
        datum::parse(d, bytes_in_addr);
    }

    void fingerprint(struct buffer_stream &b) const {
        if (datum::is_not_null()) {
            b.write_mac_addr(data);
        }
    }
};

class utf8_string : public datum {
public:
    utf8_string(datum &d) : datum{d} { }

    void fingerprint(struct buffer_stream &b) const {
        if (datum::is_not_null()) {
            b.write_utf8_string(data, length());
        }
    }
};

#endif // UTIL_OBJ_H

