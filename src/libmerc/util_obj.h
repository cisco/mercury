// util_obj.h
//
// utility objects
//
// Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
// License at https://github.com/cisco/mercury/blob/master/LICENSE


#ifndef UTIL_OBJ_H
#define UTIL_OBJ_H

#include <algorithm>
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

    std::string get_dns_label() const {
        std::string a;
        a += std::to_string(value       & 0xff);
        a += '-';
        a += std::to_string(value >>  8 & 0xff);
        a += '-';
        a += std::to_string(value >> 16 & 0xff);
        a += '-';
        a += std::to_string(value >> 24 & 0xff);
        a += '.';
        return a;
    }

    std::string get_string() const {
        std::string a;
        a += std::to_string(value       & 0xff);
        a += '.';
        a += std::to_string(value >>  8 & 0xff);
        a += '.';
        a += std::to_string(value >> 16 & 0xff);
        a += '.';
        a += std::to_string(value >> 24 & 0xff);
        return a;
    }

    // Special IPv4 Addresses as defined by IANA (2024)
    //
    // 0.0.0.0/8	       "This network" [RFC791]
    // 0.0.0.0/32	       "This host on this network" [RFC1122]
    // 10.0.0.0/8	       Private-Use [RFC1918]
    // 100.64.0.0/10	   Shared Address Space	[RFC6598]
    // 127.0.0.0/8	       Loopback	[RFC1122]
    // 169.254.0.0/16	   Link Local [RFC3927]
    // 172.16.0.0/12	   Private-Use [RFC1918]
    // 192.0.0.0/24 	   IETF Protocol Assignments [RFC6890]
    // 192.0.0.0/29	       IPv4 Service Continuity Prefix [RFC7335]
    // 192.0.0.8/32	       IPv4 dummy address [RFC7600]
    // 192.0.0.9/32	       Port Control Protocol Anycast [RFC7723]
    // 192.0.0.10/32	   Traversal Using Relays around NAT Anycast [RFC8155]
    // 192.0.0.170/322	   NAT64/DNS64 Discovery [RFC8880][RFC7050]
    // 192.0.0.171/32	   NAT64/DNS64 Discovery [RFC8880][RFC7050]
    // 192.0.2.0/24	       Documentation (TEST-NET-1) [RFC5737]
    // 192.31.196.0/24	   AS112-v4	[RFC7535]
    // 192.52.193.0/24	   AMT [RFC7450]
    // 192.88.99.0/24	   Deprecated (6to4 Relay Anycast) [RFC7526]
    // 192.168.0.0/16	   Private-Use [RFC1918]
    // 192.175.48.0/24	   Direct Delegation AS112 Service [RFC7534]
    // 198.18.0.0/15	   Benchmarking	[RFC2544]
    // 198.51.100.0/24	   Documentation (TEST-NET-2) [RFC5737]
    // 203.0.113.0/24	   Documentation (TEST-NET-3) [RFC5737]
    // 240.0.0.0/4	       Reserved	[RFC1112]
    // 255.255.255.255/32  Limited Broadcast [RFC8190][RFC919]

    enum addr_type {
        unknown     = 0,
        private_use = 1,
        global      = 2,
    };

    addr_type get_addr_type() const {
        if (((value & 0x000000ff) == 0x0000000a) or // 10.0.0.0/8
            ((value & 0x0000f0ff) == 0x000010ac) or // 172.16.0.0/12
            ((value & 0x0000ffff) == 0x0000a8c0)) { // 192.168.0.0/16
            return private_use;
        }
        return global;
    }

    addr_type get_addr_type_nbo() const {
        if (((value & 0xff000000) == 0x0a000000) or // 10.0.0.0/8
            ((value & 0xfff00000) == 0xac100000) or // 172.16.0.0/12
            ((value & 0xffff0000) == 0xc0a80000)) { // 192.168.0.0/16
            return private_use;
        }
        return global;
    }

    bool is_global() const {
        return get_addr_type() == global;
    }

    struct test_case {
        uint32_t addr;
        addr_type type;
    };

    static inline bool unit_test(FILE *output=nullptr);

};

bool ipv4_address::unit_test(FILE *output) {  // output=nullptr by default
    test_case test_cases[] = {
        {
            0x0101a8c0,     // 192.168.1.1
            ipv4_address::addr_type::private_use
        },
        {
            0x010210ac,     // 172.16.2.1
            ipv4_address::addr_type::private_use
        },
        {
            0x0100000a,     // 10.0.0.1
            ipv4_address::addr_type::private_use
        },
        {
            0x08080808,     // 8.8.8.8
            ipv4_address::addr_type::global
        },
        {
            0xa4416597,     // 151.101.65.164
            ipv4_address::addr_type::global
        }
    };
    auto test_addr_str = [](const test_case &tc, FILE *f=stdout) {

        if (ipv4_address{tc.addr}.get_addr_type() != tc.type) {
            if (f) {
                fprintf(f, "error: wrong type for address\n");
            }
            return false;
        }

        // char buffer[1024];
        // buffer_stream buf{buffer, sizeof(buffer)};
        // a.fingerprint(buf);
        // buf.write_line(f);

        return true;
    };

    bool all_passed = true;
    for (const auto & tc : test_cases) {
        all_passed &= test_addr_str(tc, output);
    }

    return all_passed;
}

struct ipv6_address {
    uint32_t a[4];

public:

    // ipv6_address(uint32_t w, uint32_t x, uint32_t y, uint32_t z) {
    //     a[0] = w;
    //     a[1] = x;
    //     a[2] = y;
    //     a[3] = z;
    // }
    //
    // ipv6_address(uint32_t in[4]) {
    //     memcpy(a, in, sizeof(a));
    // }
    //
    // ipv6_address(const std::array<uint8_t, 16> &init) {
    //     //     memcpy(tmp, addr.data(), sizeof(tmp));
    // }

    bool operator==(const ipv6_address &rhs) const {
        return a[0] == rhs.a[0] && a[1] == rhs.a[1] && a[2] == rhs.a[2] && a[3] == rhs.a[3];
    }

    void fingerprint(struct buffer_stream &buf) const {
        buf.write_ipv6_addr((uint8_t *)&a);
    }

    std::string get_dns_label() const {

        output_buffer<48> ipv6_addr_buffer;
        this->fingerprint(ipv6_addr_buffer);
        std::string out{ipv6_addr_buffer.data(), ipv6_addr_buffer.content_size()};
        std::replace(out.begin(), out.end(), ':', '-');
        out.back() = '.';
        return out;
    }

    std::string get_string() const {

        output_buffer<48> ipv6_addr_buffer;
        this->fingerprint(ipv6_addr_buffer);
        std::string out{ipv6_addr_buffer.data(), ipv6_addr_buffer.content_size()};
        return out;
    }

    void print_uint32_binary(FILE *f, uint32_t x) const {
        uint32_t mask = 1 << 31;
        while (mask != 0) {
            fputc(mask & x ? '1' : '0', f);
            mask = mask >> 1;
        }
    }

    void print_binary(FILE *f, const char *tail=nullptr) const {
        for (const auto & x : a) {
            print_uint32_binary(f, hton(x));
        }
        if (tail) {
            fprintf(f, "%s", tail);
        }
    }

    // IPv6 Address Prefixes (other than "Reserved")
    //
    // 2000::/3   Global Unicast,[RFC3513][RFC4291],"The IPv6 Unicast
    //            space encompasses the entire IPv6 address range with
    //            the exception of ff00::/8, per [RFC4291]. IANA
    //            unicast address assignments are currently limited to
    //            the IPv6 unicast address range of 2000::/3. IANA
    //            assignments from this block are registered in [IANA
    //            registry ipv6-unicast-address-assignments].
    //
    // fc00::/7   Unique Local Unicast,[RFC4193],"For complete
    //            registration details, see [IANA registry
    //            iana-ipv6-special-registry]."
    //
    // fe80::/10  Link-Scoped Unicast,[RFC3513][RFC4291],"Reserved by
    //            protocol. For authoritative registration, see [IANA
    //            registry iana-ipv6-special-registry]."
    //
    // ff00::/8   Multicast,[RFC3513][RFC4291],IANA assignments from this
    //            block are registered in [IANA registry
    //            ipv6-multicast-addresses].
    //
    // fec0::/10  Deprecated, was site-local (until 2004)
    //
    // 2000::/3      001xxxxxxxxxxxxx      global unicast
    // FC00::/7      1111110xxxxxxxxx      unique local unicast
    // FE80::/10     1111111010xxxxxx      link scoped unicast
    // FF00::/8      11111111xxxxxxxx      multiast
    //
    // IPv4-Mapped IPv6 Addresses: 0000..............................0000|FFFF

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
        return (a[0] & hton<uint32_t>(0xe0000000)) == hton<uint32_t>(0x20000000);
    }
    bool is_unique_local_unicast() const {
        return (a[0] & hton<uint32_t>(0xfe000000)) == hton<uint32_t>(0xfc000000);
    }
    bool is_link_scoped_unicast() const {
        return (a[0] & hton<uint32_t>(0xffc00000)) == hton<uint32_t>(0xfe800000);
    }
    bool is_deprecated_site_local() const {
        return (a[0] & hton<uint32_t>(0xffc00000)) == hton<uint32_t>(0xfec00000);
    }
    bool is_multicast() const {
        return (a[0] & hton<uint32_t>(0xff000000)) == hton<uint32_t>(0xff000000);
    }
    bool is_global() const {
        return is_global_unicast();   // TODO: consider global multicast
    }
    bool is_ipv4_mapped() const {
        return (a[0] == 0 && a[1] == 0 && a[2] == hton<uint32_t>(0x0000ffff));
    }

    static inline bool unit_test();

};

inline bool ipv6_address::unit_test() {

    // ipv6_address addr;

    return true;   // tests passed
}

inline ipv6_address get_ipv6_address(const std::array<uint8_t, 16> &in) {
    const uint8_t *raw = in.data();
    ipv6_address out;
    memcpy(out.a, raw, 16);
    return out;
}

/// The Internet Protocol (IP) addresses of devices on internal
/// networks varies across different organizations.  Private Address
/// Normalization (PAN) maps private internal addresses to
/// representative values, and leaves other addresses unchanged.  PAN
/// is useful for anonymization, and for analyzing destination
/// address.  The latter case especially holds when a model is
/// constructed using knowledge of internet destinations, but without
/// knowledge about the destiniation addresses on a particular
/// internal network.  This situation occurs whenever a model is
/// trained on global internet data, and then applied to traffic at
/// distinct organizations.
///
/// In PAN, an address is normalized by setting it to `10.0.0.1` if it
/// is in the IPv4 private address range (RFC 1918), or setting it to
/// `fd00::1` if it is in the IPv6 unique local address range (RFC
/// 4193).  The IPv4 private address ranges consist of the subnets
/// `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`.  The IPv6
/// unique local address range consists of the subnet `fd00::/8`.
///
namespace normalized {

    /// the representative ipv4 private use address
    ///
    static const ipv4_address ipv4_private_use{ 0x0100000a };

    /// the representative ipv6 unique local address
    ///
    static const ipv6_address ipv6_unique_local{0x000000fd, 0x00000000, 0x00000000, 0x01000000 };
};

inline void normalize(ipv4_address &a) {
    if (!a.is_global()) {
        a = normalized::ipv4_private_use;
    }
}

inline void normalize(ipv6_address &a) {
    if (!a.is_global()) {
        a = normalized::ipv6_unique_local;
    }
}

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

    // write out the (optionally normalized) destination address
    //
    void sprintf_dst_addr(char *dst_addr_str, bool norm=true) const {

        if (ip_vers == 4) {
            ipv4_address tmp_addr{addr.ipv4.dst};
            if (norm) {
                normalize(tmp_addr);
            }
            uint8_t *d = (uint8_t *)&tmp_addr;
            snprintf(dst_addr_str,
                     MAX_ADDR_STR_LEN,
                     "%u.%u.%u.%u",
                     d[0], d[1], d[2], d[3]);

        } else if (ip_vers == 6) {
            ipv6_address tmp_addr{addr.ipv6.dst};
            if (norm) {
                normalize(tmp_addr);
            }
            uint8_t *d = (uint8_t *)&tmp_addr;
            sprintf_ipv6_addr(dst_addr_str, d);
        } else {
            dst_addr_str[0] = '\0'; // make sure that string is null-terminated
        }
    }

    uint16_t get_dst_port() const {
        return ntoh(dst_port);
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

