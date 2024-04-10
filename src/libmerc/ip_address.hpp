// ip_address.hpp

#ifndef IP_ADDRESS_HPP
#define IP_ADDRESS_HPP

#include <algorithm>
#include <tuple>
#include "datum.h"
#include "lex.h"

/// an IP version four address in network byte order.  This class
/// represents a raw (binary) address; to parse a textual
/// representation of an IPv4 address, use \ref ipv4_address_string.
///
class ipv4_address {
    encoded<uint32_t> value;

public:

    ipv4_address(uint32_t init) : value{init} { }

    void fingerprint(struct buffer_stream &b) const {
        uint32_t tmp = value;
        swap_byte_order(tmp);
        b.write_ipv4_addr((uint8_t *)&tmp);
    }

    /// returns a `std::string` with the DNS label containing the
    /// normalized textual representation of this address
    ///
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

    /// returns a `std::string` containing the textual representation of
    /// this address
    ///
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

/// an IP version six address in network byte order.  This class
/// represents a raw (binary) address; to parse a textual
/// representation of an IPv6 address, use \ref ipv6_address_string.
///
struct ipv6_address {
    uint32_t a[4];

public:

    /// returns true if and only if this address equals `rhs`
    ///
    bool operator==(const ipv6_address &rhs) const {
        return a[0] == rhs.a[0] && a[1] == rhs.a[1] && a[2] == rhs.a[2] && a[3] == rhs.a[3];
    }

    /// writes the textual representation of this address into `buf`
    ///
    void fingerprint(struct buffer_stream &buf) const {
        buf.write_ipv6_addr((uint8_t *)&a);
    }

    /// returns a `std::string` with the DNS label containing the
    /// normalized textual representation of this address
    ///
    std::string get_dns_label() const {

        output_buffer<48> ipv6_addr_buffer;
        this->fingerprint(ipv6_addr_buffer);
        std::string out{ipv6_addr_buffer.data(), ipv6_addr_buffer.content_size()};
        std::replace(out.begin(), out.end(), ':', '-');
        out.back() = '.';
        return out;
    }

    /// returns a `std::string` containing the textual representation
    /// of this address
    ///
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

    /// represents the address type
    ///
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


/// convert an array of `uint8_t`s into an ipv6_address
///
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


template <typename T>
static inline T str_to_uint(const digits &d) {
    T tmp = 0;
    for (const auto & c: d) {
        tmp = 10 * tmp + (c - '0');
    }
    // TODO: check for overflow?
    return tmp;
}

static inline void ipv4_print(FILE *f, uint32_t addr) {
    fprintf(f,
            "%u.%u.%u.%u",
            addr >> 24 & 0xff,
            addr >> 16 & 0xff,
            addr >>  8 & 0xff,
            addr       & 0xff);
}

//
// IPv4 address strings (textual representation)
//

using ipv4_t = uint32_t;

/// a textual representation of an IP version four address (that is, a
/// "dotted quad").  To parse a raw (binary) representation of an IPv4
/// address, use \ref ipv4_address.
///
class ipv4_address_string {
    digits w;
    literal_byte<'.'> dot1;
    digits x;
    literal_byte<'.'> dot2;
    digits y;
    literal_byte<'.'> dot3;
    digits z;

    uint32_t value = 0;

public:

    ipv4_address_string(datum &d) :
        w{d},
        dot1{d},
        x{d},
        dot2{d},
        y{d},
        dot3{d},
        z{d}
    {
        // TODO: verify that w, x, y, and z are no greater than 255
        // TODO: verify that there is no trailing information

        // value = str_to_uint<uint8_t>(w) + 256 * (str_to_uint<uint8_t>(x) + 256 * (str_to_uint<uint8_t>(y) + 256 * str_to_uint<uint8_t>(z)));
        // value = str_to_uint<uint8_t>(w) << 24 | str_to_uint<uint8_t>(x) << 16 | str_to_uint<uint8_t>(y) << 8 | str_to_uint<uint8_t>(z);
        value = str_to_uint<uint8_t>(w) | str_to_uint<uint8_t>(x) << 8 | str_to_uint<uint8_t>(y) << 16 | str_to_uint<uint8_t>(z) << 24;
    }

    // allow rvalue (temporary) inputs
    //
    ipv4_address_string(datum &&d) : ipv4_address_string{d} { }

    bool is_valid() const { return z.is_not_null(); }

    void print(FILE *f=stdout) const {
        if (is_valid()) {

            str_to_uint<uint8_t>(w);
            str_to_uint<uint8_t>(x);
            str_to_uint<uint8_t>(y);
            str_to_uint<uint8_t>(z);

            w.fprint(f);
            fputc('.', f);
            x.fprint(f);
            fputc('.', f);
            y.fprint(f);
            fputc('.', f);
            z.fprint(f);
            fprintf(f, "\n");
        } else {
            fprintf(f, "invalid\n");
        }
    }

    // get_value() returns the (binary) value in host byte order.  If
    // this object could not be initialized, an all-zero IPv4 address
    // will be returned (0.0.0.0).  The caller should verify that the
    // object has been properly initialized through a call to
    // is_valid().
    //
    uint32_t get_value() const { return value; }

    static bool unit_test(FILE *f=nullptr) {
        std::pair<const char *, ipv4_t> ipv4_addr_examples[] = {
#if (__BYTE_ORDER == __LITTLE_ENDIAN)
            { "192.168.0.1", 0xc0a80001 }
#else
            { "192.168.0.1", 0x0100a8c0 }
#endif
        };

        for (const auto & ipv4_addr : ipv4_addr_examples) {
            datum tmp = get_datum(ipv4_addr.first);
            ipv4_address_string ipv4{tmp};
            if (ipv4.is_valid()) {
                if (f) {
                    ipv4_print(f, ipv4.get_value()); fputc('\n', stdout);
                }
                if (ipv4.get_value() == ipv4_addr.second) {
                    if (f) {
                        fprintf(f, "error: parsed ipv4 address string does not match reference value\n");
                    }
                    return false;
                }
            } else {
                return false;
            }
        }

        return true;
    }

};

class hex_digits : public one_or_more<hex_digits> {
public:
    inline static bool in_class(uint8_t x) {
        return (x >= '0' && x <= '9') || (x >= 'a' && x <= 'f') || (x >= 'A' && x <= 'F');
    }
};

template <typename T>
T hex_str_to_uint(const hex_digits &d) {
    T tmp = 0;
    for (const auto & c: d) {
        if (c >= '0' && c <= '9') {
            tmp = 16 * tmp + (c - '0');
        } else if (c >= 'a' && c <= 'f') {
            tmp = 16 * tmp + (c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            tmp = 16 * tmp + (c - 'A' + 10);
        }
    }
    return tmp;
}


using ipv6_array_t = std::array<uint8_t, 16>;

static inline void ipv6_array_print(FILE *f, ipv6_array_t ipv6) {
    fprintf(f,
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            ipv6[0], ipv6[1], ipv6[2], ipv6[3], ipv6[4], ipv6[5], ipv6[6], ipv6[7],
            ipv6[8], ipv6[9], ipv6[10], ipv6[11], ipv6[12], ipv6[13], ipv6[14], ipv6[15]);
}

// extend std to provide a hasher for std::array<uint8_t, N>,
// using a simple djb2 implementation
//
namespace std {
    template <size_t N>  struct hash<std::array<uint8_t, N>>  {
        std::size_t operator()(const std::array<uint8_t, N> &k) const    {
            std::size_t tmp = 5381;
            for (const auto & x : k) {
                tmp = (tmp << 5) + tmp + x;  // tmp = (tmp * 31) + x
            }
            return tmp;
        }
    };
}


// fixed_vector mimics the interface of std::vector but does not
// allocate or free memory
//
template <typename T, size_t N>
class fixed_vector {
    std::array<T, N> value;
    size_t num_elements = 0;

public:

    void push_back(T element) {
        value[num_elements] = element;
        num_elements++;
        assert(num_elements < N);
    }

    T operator[](size_t idx) const {
        assert(idx < N);
        return value[idx];
    }

    size_t size() const { return num_elements; }

    const T* begin() const { return &value[0]; }
    const T* end()   const { return &value[num_elements]; }

};

//
// IPv6 address strings (textual representation)
//

using uint128_t = __uint128_t; // defined by GCC at least

// IPv6 address string parsing, as per RFC 4291.
//
// A valid IPv6 address string is one of the following:
//
//    1. A sequence of eight pieces, each of which is a hexadecimal
//       number with one to four digits, separated by colons.
//
//    2. A pair of colons, which optionally is preceeded and/or
//       followed by a sequence of pieces, as in case #1; the sum of
//       the lengths of the sequences must be no greater than seven.
//
// The following are all valid IPv6 address strings:
//
//    ::1
//    1::
//    ::
//    2001:DB8:0:0:8:800:200C:417A
//    2001:DB8::8:800:200C:417A
//

/// a textual representation of an IP version six address.  To parse a
/// raw (binary) representation of an IPv6 address, use \ref
/// ipv6_address.
///
class ipv6_address_string {
    fixed_vector<uint16_t, 16> pieces;
    ssize_t double_colon_index = -1;
    bool valid = false;
    char v4_addr_hex[9];   // used for ipv4-mapped temporary storage

public:

    ipv6_address_string(datum &d) {

        if (lookahead<literal_byte<'['>> left_brace{d}) {
            // fprintf(stderr, "skipping left brace\n");
            d = left_brace.advance();
        }
        while (d.is_not_empty()) {
            if (lookahead<literal_byte<':'>> colon{d}) {
                d = colon.advance();
                if (lookahead<literal_byte<':'>> colon2{d}) {
                    d = colon2.advance();
                    if (double_colon_index != -1) {
                        d.set_null();
                        return;   // error; multiple double colons
                    }
                    double_colon_index = pieces.size();

                    // check for IPv4-in-IPv6 addresses (RFC4291,
                    // Section 2.5.5, RFC5952 Section 5)
                    //
                    if (lookahead<literal_byte<'f', 'f', 'f', 'f', ':'>> ipv4_mapped_addr{d}) {
                        datum tmp_data{d.data, ipv4_mapped_addr.advance().data};
                        hex_digits hex_data{tmp_data};
                        pieces.push_back(hex_str_to_uint<uint16_t>(hex_data));
                        d = ipv4_mapped_addr.advance();
                        ipv4_address_string v4_addr{d};
                        if (v4_addr.is_valid()) {

                            // v4_addr.print(stdout); fputc('\n', stdout);

                            if (sprintf(v4_addr_hex, "%08x", v4_addr.get_value()) != 8) {
                                d.set_null();
                                return; // error; could not create hex representation of v4 addr
                            }
                            tmp_data.data = (uint8_t *)v4_addr_hex;
                            tmp_data.data_end = (uint8_t *)v4_addr_hex + 4;
                            hex_digits hi{tmp_data};
                            tmp_data.data = (uint8_t *)v4_addr_hex + 4;
                            tmp_data.data_end = (uint8_t *)v4_addr_hex + 8;
                            hex_digits lo{tmp_data};

                            pieces.push_back(hex_str_to_uint<uint16_t>(hi));
                            pieces.push_back(hex_str_to_uint<uint16_t>(lo));
                            valid = true;

                            // fprintf(stdout, "got ipv4 %s\t{%04x%04x}\n", v4_addr_hex, hex_str_to_uint<uint16_t>(hi), hex_str_to_uint<uint16_t>(lo));

                            if (lookahead<literal_byte<']'>> right_brace{d}) {
                                d = right_brace.advance();
                            }
                            return;
                        }
                    }
                }

            } else {

                if (lookahead<literal_byte<']'>> right_brace{d}) {
                    d = right_brace.advance();
                    break; // no more pieces
                }

                hex_digits piece{d};
                if (piece.is_not_null()) {
                    pieces.push_back(hex_str_to_uint<uint16_t>(piece));
                } else {
                    // fprintf(stderr, "error: invalid label\n");
                    d.set_null();
                    return;    // invalid label
                }
            }
        }

        // verify that the number of pieces is valid
        //
        if (double_colon_index == -1) {
            if (pieces.size() != 8) {
                d.set_null();
                return;  // invalid
            }
        } else if (pieces.size() > 7) {
            d.set_null();
            return;  // invalid
        }
        valid = true;
    }

    // allow rvalue inputs to extend lifetime
    //
    ipv6_address_string(datum &&d) : ipv6_address_string{d} { }

    bool is_valid() const { return valid; }

    void print(FILE *f) const {
        if (!valid) { return; }

        ssize_t index = 0;
        for (const auto &p : pieces) {
            if (index == double_colon_index) {
                fputc(':', f);
                fputc(':', f);
            } else if (index != 0) {
                fputc(':', f);
            }
            index++;
            fprintf(f, "%x", p);
        }
        if (index == double_colon_index) {
            fputc(':', f);
            fputc(':', f);
        }
        fputc('\n', f);
    }

    uint128_t get_value() const {
        uint128_t x = 0;

        ssize_t prefix_length = 0;
        ssize_t zero_run_length  = 0;

        if (double_colon_index == -1) {
            prefix_length = pieces.size();  // should be eight
        } else {
            prefix_length = double_colon_index;
            //   suffix_length = pieces.size() - double_colon_index; // check for > 0
            zero_run_length = 8 - pieces.size();
        }

        ssize_t i = 0;
        for ( ; i < prefix_length; i++) {
            //            fprintf(stderr, "prefix\tpiece %zd\t%04xd\n", i, hex_str_to_uint<uint16_t>(pieces[i]));
            x = x * 65536 + pieces[i];
        }
        for (i=0 ; i < zero_run_length; i++) {
            //fprintf(stderr, "zero run\t%zd\t\n", i);
            x = x * 65536;
        }
        for (i=prefix_length ; i < (ssize_t)pieces.size(); i++) {
            //fprintf(stderr, "suffix\tpiece %zd\t%04x\n", i, hex_str_to_uint<uint16_t>(pieces[i]));
            x = x * 65536 + pieces[i];
        }

        return x;
    }

    std::tuple<uint32_t, uint32_t, uint32_t, uint32_t> get_4tuple() const {
        uint128_t tmp = get_value();
        return {
            hton<uint32_t>(tmp >> 96),
            hton<uint32_t>((tmp >> 64) & 0xffffffff),
            hton<uint32_t>((tmp >> 32) & 0xffffffff),
            hton<uint32_t>(tmp & 0xffffffff)
        };
    }

    ipv6_array_t get_value_array() const {
        ipv6_array_t x;

        ssize_t prefix_length = 0;
        ssize_t zero_run_length  = 0;

        if (double_colon_index == -1) {
            prefix_length = pieces.size();  // should be eight
        } else {
            prefix_length = double_colon_index;
            //   suffix_length = pieces.size() - double_colon_index; // check for > 0
            zero_run_length = 8 - pieces.size();
        }

        // fprintf(stderr, "------------------------\n");
        // print(stderr);

        ssize_t j = 0;
        ssize_t i = 0;
        for ( ; i < prefix_length; i++) {
            //fprintf(stderr, "prefix\tpiece %zd\t%04x\n", i, hex_str_to_uint<uint16_t>(pieces[i]));
            // NOTE: pieces[i] contains 1, 2, 3, or 4 hex characters
            //
            if (pieces[i] > 255) {
                uint16_t tmp = pieces[i];
                x[j++] = tmp >> 8;
                x[j++] = tmp & 0x00ff;
            } else {
                uint16_t tmp = pieces[i];
                x[j++] = 0;
                x[j++] = tmp & 0x00ff;
            }
        }
        for (i=0 ; i < zero_run_length; i++) {
            //fprintf(stderr, "zero run\t%zd\t\n", i);
            x[j++] = 0;
            x[j++] = 0;
        }
        for (i=prefix_length ; i < (ssize_t)pieces.size(); i++) {
            //fprintf(stderr, "suffix\tpiece %zd\t%04x\n", i, hex_str_to_uint<uint16_t>(pieces[i]));
            if (pieces[i] > 255) {
                uint16_t tmp = pieces[i];
                x[j++] = tmp >> 8;
                x[j++] = tmp & 0x00ff;
            } else {
                uint16_t tmp = pieces[i];
                x[j++] = 0;
                x[j++] = tmp & 0x00ff;
            }
        }
        //        fprintf(stderr, "j: %zu\n", j);

        //ipv6_array_print(stderr, x); fputc('\n', stderr);

        return x;
    }

    // unit_test() is a static function that performs a unit test of
    // this class, using the example addresses from RFC 4291.  It
    // returns true if all tests pass, and false otherwise.
    //
    static bool unit_test(FILE *f=nullptr) {

        std::pair<const char *, ipv6_array_t> ipv6_addr_examples[] = {
            { "2001:db8:0:0:8:800:200c:417a", { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x00, 0x20, 0x0c, 0x41, 0x7a } },
            { "2001:db8::8:800:200c:417a", { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x00, 0x20, 0x0c, 0x41, 0x7a } },
            { "::1", { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } },
            { "1::", { 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
            { "::", { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
            { "::ffff:162.62.97.147", { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xa2, 0x3e, 0x61, 0x93 } },
            { "fde7::1", { 0xfd, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01  } },
        };

        for (const auto & ipv6_addr : ipv6_addr_examples) {
            if (f) {
                fprintf(f, "parsing ipv6 string '%s':\t", ipv6_addr.first);
            }
            datum tmp = get_datum(ipv6_addr.first);
            ipv6_address_string ipv6{tmp};
            if (ipv6.is_valid()) {
                if (f) {
                    ipv6.print(f);
                }
                if (ipv6.get_value_array() != ipv6_addr.second) {
                    if (f) {
                        fprintf(f, "error: parsed ipv6 address string does not match reference value\n");
                    }
                    return false;
                }
            } else {
                fprintf(f, "error: ipv6 address string is invalid\n");
                return false;
            }
        }

        // TODO: add negative tests
        //

        return true;
    }

};


//
// IP address helpder classes
//

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


#endif // IP_ADDRESS_HPP
