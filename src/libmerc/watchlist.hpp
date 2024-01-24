///
/// \file watchlist.hpp
///
/// an implementation of ipv4/ipv6/dns_name watchlists

#ifndef WATCHLIST_HPP
#define WATCHLIST_HPP

#include <cstdio>
#include <string>
#include <vector>
#include <unordered_set>
#include <optional>
#include <variant>
#include <iostream>
#include <fstream>
#include "datum.h"
#include "lex.h"

// get_datum(std::string &s) returns a datum that corresponds to the
// std::string s.
//
static inline datum get_datum(const std::string &s) {
    uint8_t *data = (uint8_t *)s.c_str();
    return { data, data + s.length() };
}

// get_datum(const char *c) returns a datum that corresponds to the
// null-terminated character string c.  The value c must not be
// nullptr, and must be null-terminated.
//
static inline datum get_datum(const char *c) {
    uint8_t *data = (uint8_t *)c;
    return { data, data + strlen(c) };
}

template <typename T>
static inline T str_to_uint(const digits &d) {
    T tmp = 0;
    for (const auto & c: d) {
        tmp = 10 * tmp + (c - '0');
    }
    // TODO: check for overflow?
    return tmp;
}

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

using ipv4_t = uint32_t;

static inline void ipv4_print(FILE *f, uint32_t addr) {
    fprintf(f,
            "%u.%u.%u.%u",
            addr >> 24 & 0xff,
            addr >> 16 & 0xff,
            addr >>  8 & 0xff,
            addr       & 0xff);
}

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
        value = str_to_uint<uint8_t>(w) << 24 | str_to_uint<uint8_t>(x) << 16 | str_to_uint<uint8_t>(y) << 8 | str_to_uint<uint8_t>(z);
    }

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

    static bool unit_test() {
        std::vector<std::pair<const char *, ipv4_t>> ipv4_addr_examples {
#if (__BYTE_ORDER == __LITTLE_ENDIAN)
            { "192.168.0.1", 0x0100a8c0 }
#else
            { "192.168.0.1", 0xc0a80001 }
#endif
        };

        for (const auto & ipv4_addr : ipv4_addr_examples) {
            datum tmp = get_datum(ipv4_addr.first);
            ipv4_address_string ipv4{tmp};
            if (ipv4.is_valid()) {
                // ipv4_print(stdout, ipv4.get_value()); fputc('\n', stdout);
                if (ipv4.get_value() == ipv4_addr.second) {
                    return false;
                }
            } else {
                return false;
            }
        }

        return true;
    }

};

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
class ipv6_address_string {
    std::vector<hex_digits> pieces;
    ssize_t double_colon_index = -1;
    bool valid = false;

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
                        return;   // error; multiple double colons
                    }
                    double_colon_index = pieces.size();

                    // check for IPv4-in-IPv6 addresses (RFC4291,
                    // Section 2.5.5, RFC5952 Section 5)
                    //
                    if (lookahead<literal_byte<'f', 'f', 'f', 'f', ':'>> ipv4_mapped_addr{d}) {
                        datum tmp_data{d.data, ipv4_mapped_addr.advance().data};
                        hex_digits hex_data{tmp_data};
                        pieces.push_back(hex_data);
                        d = ipv4_mapped_addr.advance();
                        ipv4_address_string v4_addr{d};
                        if (v4_addr.is_valid()) {

                            char v4_addr_hex[9];
                            if (sprintf(v4_addr_hex, "%08x", v4_addr.get_value()) != 8) {
                                return; // error; could not create hex representation of v4 addr
                            }
                            tmp_data.data = (uint8_t *)v4_addr_hex;
                            tmp_data.data_end = (uint8_t *)v4_addr_hex + 4;
                            hex_digits hi{tmp_data};
                            tmp_data.data = (uint8_t *)v4_addr_hex + 4;
                            tmp_data.data_end = (uint8_t *)v4_addr_hex + 8;
                            hex_digits lo{tmp_data};

                            pieces.push_back(hi);
                            pieces.push_back(lo);
                            valid = true;

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
                    pieces.push_back(piece);
                } else {
                    // fprintf(stderr, "error: invalid label\n");
                    return;    // invalid label
                }
            }
        }

        // verify that the number of pieces is valid
        //
        if (double_colon_index == -1) {
            if (pieces.size() != 8) {
                return;  // invalid
            }
        } else {
            if (pieces.size() > 7) {
                return;  // invalid
            }
        }
        valid = true;
    }

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
            fprintf(f, "%x", hex_str_to_uint<uint16_t>(p));
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
            x = x * 65536 + hex_str_to_uint<uint16_t>(pieces[i]);
        }
        for (i=0 ; i < zero_run_length; i++) {
            //fprintf(stderr, "zero run\t%zd\t\n", i);
            x = x * 65536;
        }
        for (i=prefix_length ; i < (ssize_t)pieces.size(); i++) {
            //fprintf(stderr, "suffix\tpiece %zd\t%04x\n", i, hex_str_to_uint<uint16_t>(pieces[i]));
            x = x * 65536 + hex_str_to_uint<uint16_t>(pieces[i]);
        }

        return x;
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
            if (pieces[i].length() > 2) {
                uint16_t tmp = hex_str_to_uint<uint16_t>(pieces[i]);
                x[j++] = tmp >> 8;
                x[j++] = tmp & 0x00ff;
            } else {
                uint16_t tmp = hex_str_to_uint<uint16_t>(pieces[i]);
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
            if (pieces[i].length() > 2) {
                uint16_t tmp = hex_str_to_uint<uint16_t>(pieces[i]);
                x[j++] = tmp >> 8;
                x[j++] = tmp & 0x00ff;
            } else {
                uint16_t tmp = hex_str_to_uint<uint16_t>(pieces[i]);
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

        std::vector<std::pair<const char *, ipv6_array_t>> ipv6_addr_examples{
            { "2001:db8:0:0:8:800:200c:417a", { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x00, 0x20, 0x0c, 0x41, 0x7a } },
            { "2001:db8::8:800:200c:417a", { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x00, 0x20, 0x0c, 0x41, 0x7a } },
            { "::1", { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } },
            { "1::", { 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
            { "::", { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
            { "::ffff:162.62.97.147", { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xa2, 0x3e, 0x61, 0x93 } },
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

// From Section 2.1 of RFC 1123:
//
//     If a dotted-decimal number can be entered without such
//     identifying delimiters, then a full syntactic check must be
//     made, because a segment of a host domain name is now allowed to
//     begin with a digit and could legally be entirely numeric (see
//     Section 6.1.2.4). However, a valid host name can never have the
//     dotted-decimal form #.#.#.#, since at least the highest-level
//     component label will be alphabetic.
//
// To be conservative, we only require that the TLD label contain at
// least one alphabetic character.
//
// From Section 3.2.2 of RFC 2396, the TLD label in a URI has the
// syntax:
//
//     toplabel      = alpha | alpha *( alphanum | "-" ) alphanum
//
// But this RFC does *not* supercede RFC 1123; it specifies URIs, not
// DNS names.
//
// The current list of TLDs (February 2023) contains several toplabels
// that contain digits and hyphens, and even consecutive hyphens, but
// all of these start and end with alphabetic characters.
//
class dns_label_string : public one_or_more<dns_label_string> {
public:
    inline static bool in_class(uint8_t x) {
        return (x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z') || (x >= '0' && x <= '9') || x == '-' || x == '_';
    }
};

class dns_string {
    std::vector<datum> label_vector;
    bool valid = false;

public:

    dns_string(datum &d) {

        if (d.is_not_readable()) {
            return;
        }

        // the first domain may be a wildcard (*)
        //
        if (lookahead<literal_byte<'*'>> wildcard{d}) {
            datum label{d.data, wildcard.advance().data};
            d = wildcard.advance();
            label_vector.push_back(label);
            literal_byte<'.'> dot{d};
        }

        while (d.is_not_empty()) {
            // fprintf(stdout, "dns_string has data "); d.fprint(stdout); fputc('\n', stdout);
            dns_label_string label{d};
            if (label.is_not_null()) {
                // fprintf(stdout, "label: %.*s\n", (int)label.length(), label.data);
                label_vector.push_back(label);
                if (lookahead<literal_byte<'.'>> dot{d}) {
                    d = dot.advance();
                } else {
                    break; // unexpected character
                    // if (!d.is_not_empty()) {
                    // label_vector.push_back(label);
                }
            } else {
                break;        // TODO: verify correctness
                // return;    // invalid label
            }
        }
        // for (const auto & x : label_vector) {
        //     fprintf(stdout, "label_vector: %.*s\n", (int)x.length(), x.data);
        // }

        if (label_vector.size() == 0) {
            d.set_null();
            return;           // not a valid dns_string
        }

        // a valid top level domain name contains at least one
        // alphabetic character
        //

        datum tld = label_vector.back();
        bool tld_is_valid = false;
        for (const auto &x : tld ) {
            if ((x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z')) {
                tld_is_valid = true;
                break;
            }
        }
        // fprintf(stdout, "tld: %.*s\n", (int)tld.length(), tld.data);

        if (!tld_is_valid) {
            d.set_null();
            return;   // not a valid tld, possibly an IPv4 dotted quad
        }

        valid = true;
    }

    bool is_valid() const {
        return valid;
    }

    size_t label_count() const { return label_vector.size(); }

    void print() const {
        if (!valid) { return; }
        bool first = true;
        for (const auto & label : label_vector) {
            if (!first) {
                fputc('.', stdout);
            }
            first = false;
            label.fprint(stdout);
        }
        fputc('\n', stdout);
    }

    std::string get_string() const {
        std::string tmp;
        if (!valid) { return tmp; }
        bool first = true;
        for (const auto & label : label_vector) {
            if (!first) {
                tmp.push_back('.');
            }
            first = false;
            tmp += label.get_string();
        }
        return tmp;
    }

    const std::vector<datum> & get_value() const { return label_vector; }
};

class port_number {
    literal_byte<':'> colon;
    digits number;
    bool valid;

public:

    port_number(datum &d) : colon{d}, number{d}, valid{d.is_not_null()} { }

    bool is_valid() const { return valid; }

    uint16_t get_value() const {
        if (!valid) {
            return 0;
        }
        uint16_t value = 0;
        for (const auto & x : number) {
            value *= 10;
            value += (x - '0');
        }
        return value;
    }

};

/// dns_name_t is the type used in a \ref host_identifier variant; its
/// underlying type is a `std::string`.
///
using dns_name_t      = std::string;

/// `host_identifier` is a domain name or address be initialized from
/// a text string; it should be initialized with \ref
/// host_identifier_constructor.
///
/// A `host_identifier` is well suited for use in watchlists,
/// configuration files, and other structured inputs where it is
/// useful to allow addresses or domain names.  To parse addresses and
/// hostnames that appear in network protocols like HTTP, TLS, and
/// QUIC, the \ref server_identifier is more suitable, because it can
/// include a trailing port number.
///
using host_identifier = std::variant<std::monostate, ipv4_t, ipv6_array_t, dns_name_t>;

/// Returns a \ref host_identifier constructed by parsing the text
/// string in a datum.
///
static inline host_identifier host_identifier_constructor(datum d) {

    if (d.is_null()            // null line
        || !d.is_not_empty()   // empty line
        || *d.data == '#'      // comment line
        ) {
        return std::monostate{};
    }

    if (lookahead<space> whitespace{d}) {
        d = whitespace.advance();           // skip over leading whitespace, if any
    }

    if (lookahead<dns_string> dns{d}) {
        datum tmp = dns.advance();
        if (tmp.is_empty()) {
            d = dns.advance();
            return dns.value.get_string();
        }

        // if there is still readable data in d, it must be a port
        // number
        //
        if (lookahead<port_number> port{tmp}) {
            d = port.advance();
            return dns.value.get_string();
        }
    }
    if (lookahead<ipv4_address_string> ipv4{d}) {
        d = ipv4.advance();
        return ipv4.value.get_value();

    }
    if (lookahead<ipv6_address_string> ipv6{d}) {
        d = ipv6.advance();
        return ipv6.value.get_value_array();

    } else {
        printf_err(log_warning, "invalid host identifier string\n");
    }
    return std::monostate{};
}


/// \class server_identifier
///
/// identifies a server as a \ref host_identifier (domain name, ipv4
/// address, or ipv6 address) and an optional port; it can be
/// initialized from a text string as in the HTTP host field or the
/// TLS/QUIC Server Name extension.
///
class server_identifier {
    host_identifier host_id;
    std::optional<uint16_t> port;
    size_t label_count = 0;

public:

    /// construct a server_identifier object by parsing and accepting
    /// text from a `datum`
    ///
    /// The constructor will recognize and accept the following forms:
    ///
    ///   * fully qualified domain names, with or without a trailing
    ///     colon and port number, such as `example.com:80`,
    ///
    ///   * domain names with a single label, with or without a
    ///     trailing colon and port number, such as `localhost:443`,
    ///
    ///   * "wilcard" domain names whose first label consists soley of
    ///     an asterisk (`*`), with or without a trailing colon and
    ///     port number, such as `*.tplinkcloud.com`,
    ///
    ///   * IPv4 addresses, with or without a trailing colon and port
    ///     number, such as `192.168.1.1`,
    ///
    ///   * IPv6 addresses surrounded by square braces, with or
    ///     without a trailing colon and port number, such as
    ///     `[2408:862e:ff:ff03:1b::]:8080`, and
    ///
    ///   * IPv6 address without square braces, such as
    ///    `::ffff:162.62.97.147` or `2001:b28:f23f:f005::a`.
    ///
    server_identifier(datum d) {

        if (d.is_null()            // null line
            || !d.is_not_empty()   // empty line
            || *d.data == '#'      // comment line
            ) {
            return;                // error; not a valid server identifier
        }

        if (lookahead<space> whitespace{d}) {
            d = whitespace.advance();           // skip over leading whitespace, if any
        }

        if (lookahead<dns_string> dns{d}) {
            datum tmp = dns.advance();
            if (tmp.is_empty()) {
                d = dns.advance();
                host_id = dns.value.get_string();
                label_count = dns.value.label_count();
                return;
            }

            // if there is still readable data in tmp, it must be a
            // port number
            //
            if (lookahead<port_number> port_digits{tmp}) {
                port = port_digits.value.get_value();
                d = port_digits.advance();
                host_id = dns.value.get_string();
                return;
            }
        }
        if (lookahead<ipv4_address_string> ipv4{d}) {
            d = ipv4.advance();
            host_id = ipv4.value.get_value();

        } else if (lookahead<ipv6_address_string> ipv6{d}) {
            d = ipv6.advance();
            host_id = ipv6.value.get_value_array();

        }

        // if there is still readable data in d, it must be a port
        // number
        //
        if (lookahead<port_number> port_digits{d}) {
            port = port_digits.value.get_value();
            d = port_digits.advance();
        }

    }

    /// construct a server_identifier object by parsing text from a
    /// `std::string`
    ///
    server_identifier(const std::string &s) : server_identifier{get_datum(s)} { }

    /// return a `std::string` containing a normalized domain name
    ///
    /// While server identifiers are often Fully Qualified Domain
    /// Names (FQDNs), they can also be addresses or other special
    /// cases.  A normalized domain name maps a server identifier into
    /// the domain name hierarchy by leaving FQDNs unchanged and
    /// otherwise mapping the identifier into the special-use
    /// subdomain `invalid` (RFC 6761), as follows:
    ///
    ///    * IPv4 addresses are mapped to `address.invalid`,
    ///
    ///    * IPv6 addresses are mapped to `address.invalid`,
    ///
    ///    * Unqualified domains are mapped to `unqualified.invalid`,
    ///
    ///    * Empty or missing domain names are mapped to `missing.invalid`,
    ///
    ///    * Text strings that cannot be parsed as addresses or domain
    ///    * names are mapped to `other.invalid`.
    ///
    std::string get_normalized_domain_name(bool detail=false) const {
        (void)detail;  // ignore for now

        if (std::holds_alternative<ipv4_t>(host_id) || std::holds_alternative<ipv6_array_t>(host_id)) {
            return "address.invalid";
        }
        if (std::holds_alternative<std::monostate>(host_id)) {
            return "other.invalid";
        }
        if (std::holds_alternative<dns_name_t>(host_id)) {
            std::string domain_name = std::get<dns_name_t>(host_id);
            if (domain_name == "None") {
                return "missing.invalid";
            }
            if (label_count == 1 and domain_name != "localhost") {
                return "unqualified.invalid";
            }
            return domain_name;
        }
        return "unknown";
    }

    /// returns a `std::optional<uint16_t>` that contains the port
    /// number, if one is present in the server identifier.
    ///
    std::optional<uint16_t> get_port_number() const {
        return port;
    }

    //
    // unit test cases for the server_identifier class
    //
    struct test_case {
        const char *input;
        const char *output;
        std::optional<uint16_t> port;
    };

    static bool unit_test(FILE *f=nullptr) {
        std::vector<test_case> test_cases = {
            { "ocsp.digicert.com", "ocsp.digicert.com", {} },                           // FQDN
            { "ookla.mbspeed.net:8080", "ookla.mbspeed.net", 8080 },                    // FQDN with port number
            { "10.124.145.64", "address.invalid", {} },                                 // IPv4 address
            { "10.237.97.140:8443", "address.invalid", 8443 },                          // IPv4 address with port number
            { "[240e:390:38:1b00:211:32ff:fe78:d4ab]:10087","address.invalid", 10087 }, // IPv6 address with square braces and port number
            { "[2408:862e:ff:ff03:1b::]", "address.invalid", {} },                      // IPv6 address with square braces
            { "[2001:b28:f23f:f005::a]:80", "address.invalid", 80 },                    // IPv6 address with zero compression, square braces, and port number
            { "::ffff:162.62.97.147", "address.invalid", {} },                          // IPv6 addr with embedded IPv6 addr (RFC4291, Section 2.5.5)
            { "[::ffff:91.222.113.90]:5000", "address.invalid", 5000 },                 // IPv6 addr with embedded ipv4 addr, square braces, and port number
            { "240d:c000:1010:1200::949b:1928:b134", "address.invalid", {} },           // IPv6 addr with zero compression
            { "240d:c000:2010:1a58:0:95fe:d8b7:5a8f", "address.invalid", {} },          // IPv6 addr without zero compression
            { "*.tplinkcloud.com", "*.tplinkcloud.com", {} },                           // wildcard subdomain
            { "18.158.72.38.nip.io", "18.158.72.38.nip.io", {} },                       // subdomains look like dotted quad
            { " www.google.com", "www.google.com", {} },                                // leading  whitespace
            { "None", "missing.invalid", {} },                                          // "None" means missing
            { "localhost:443", "localhost", 443 },                                      // "localhost" with a port number
            { "www", "unqualified.invalid", {} },                                       // unqualified domain name (not an FQDN)
        };

        bool passed = true;
        for (const auto & tc : test_cases) {
            std::string in{tc.input};
            std::string out{tc.output};
            datum d = get_datum(in);
            server_identifier server_id{d};
            std::string test = server_id.get_normalized_domain_name();
            std::optional<uint16_t> p = server_id.get_port_number();
            if (test != out) {
                if (f) {
                    fprintf(f, "error: unit test case failed (input: '%s', expected output: '%s', actual output: '%s')\n",
                            tc.input, tc.output, test.c_str());
                }
                passed = false;

            } else if (p != tc.port or ((p == true) and *p != *tc.port)) {
                if (f) {
                    fprintf(f, "error: unit test case failed (input: '%s', expected port: %u, actual port: %u)\n",
                            tc.input, *tc.port, p ? *p : 0);
                }
                passed = false;
            } else {
                if (f) {
                    fprintf(f, "unit test case passed (input: '%s', output: '%s')\n",
                            tc.input, test.c_str());
                }
            }
        }

        return passed;
    }

};


// class watchlist implements a watchlist of host identifiers,
// including IPv4 and IPv6 addresses and DNS names
//
class watchlist {
    std::unordered_set<uint32_t> ipv4_addrs;
    std::unordered_set<ipv6_array_t> ipv6_addrs;
    std::unordered_set<std::string> dns_names;

    //    std::unordered_set<host_identifier> hosts;

    // TODO: for performance, try using perfect_hash in place of
    // unordered_map
    //
    // TODO: for performance, replace std:string with const char *,
    // using a dynamically allocated buffer holding null-terminated
    // strings

public:

    // watchlist(input) constructs a watchlist by parsing the input
    // text input_stream, each line of which must contain an IPv4
    // address, an IPv6 address, a DNS name, a comment starting with
    // the character '#', or be blank (zero length)
    //
    watchlist(std::istream &input) {

        std::string line;
        while (std::getline(input, line)) {
            datum d = get_datum(line);
            if (process_line(d) == false) {
                throw std::runtime_error{"could not read watchlist file"};
            }
            // d = get_datum(line);
            // host_identifier hid = host_identifier_constructor(d);
            // hosts.insert(hid);
        }
    }

    watchlist() { }

    // contains(x) returns true if this watchlist contains x, and
    // false otherwise.
    //
    bool contains(uint32_t addr) const {
        return ipv4_addrs.find(addr) != ipv4_addrs.end();
    }
    bool contains(std::string &name) const {
        return dns_names.find(name) != dns_names.end();
    }
    bool contains(ipv6_array_t addr) const {
        return ipv6_addrs.find(addr) != ipv6_addrs.end();
    }
    bool contains(host_identifier hid) const {
        return std::visit(*this, hid);
    }

    // contains_addr(a) returns true if this watchlist contains the
    // IPv4 or IPv6 address string a, and false otherwise.
    //
    bool contains_addr(const char *addr) const {
        datum d = get_datum(addr);
        if (lookahead<ipv4_address_string> ipv4{d}) {
            return contains(ipv4.value.get_value());
        } else if (lookahead<ipv6_address_string> ipv6{d}) {
            return contains(ipv6.value.get_value_array());
        }
        return false;
    }

    bool operator()(ipv4_t addr) const {
        return ipv4_addrs.find(addr) != ipv4_addrs.end();
    }
    bool operator()(dns_name_t &name) const {
        return dns_names.find(name) != dns_names.end();
    }
    bool operator()(ipv6_array_t addr) const {
        return ipv6_addrs.find(addr) != ipv6_addrs.end();
    }
    bool operator()(std::monostate) const {
        return false;
    }

    bool process_line(std::string &line, int verbose=0) {
        if (verbose) { printf_err(log_info, "encrypted_dns watchlist entry: %s\n", line.c_str()); }
        datum d = get_datum(line);
        return process_line(d);
    }

    // process_line() parses and processes a single line of a
    // watchlist file, and returns true on success and false on
    // failure
    //
    bool process_line(datum d, int verbose=0) {
        if (d.is_null()) {
            return false;
        }
        if (!d.is_not_empty()) {
            return true;
        }
        if (*d.data == '#') {
            return true;      // comment line
        }
        if (lookahead<ipv4_address_string> ipv4{d}) {
            // fprintf(stdout, "ipv4_address_string:\t");  ipv4.value.print();
            ipv4_addrs.insert(ipv4.value.get_value());
            d = ipv4.advance();

        } else if (lookahead<dns_string> dns{d}) {
            // fprintf(stdout, "dns_string:\t");  dns.value.print();
            dns_names.insert(dns.value.get_string());
            d = dns.advance();

        } else if (lookahead<ipv6_address_string> ipv6{d}) {
            // fprintf(stdout, "ipv6_address_string:\t");  ipv6.value.print();
            ipv6_addrs.insert(ipv6.value.get_value_array());
            d = ipv6.advance();

        } else {
            if (verbose) { printf_err(log_warning, "warning: invalid line in watchlist::process_line\n"); }
            return false;
        }
        return true;
    }

    void print() const {
        for (const auto & dns : dns_names) {
            fprintf(stdout, "%s\n", dns.c_str());
        }
        for (const auto & ipv4 : ipv4_addrs) {
            fprintf(stdout, "%u\n", ipv4);
        }
        for (const auto & ipv6 : ipv6_addrs) {
            fprintf(stdout,
                    "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                    ipv6[0], ipv6[1], ipv6[2], ipv6[3], ipv6[4], ipv6[5], ipv6[6], ipv6[7],
                    ipv6[8], ipv6[9], ipv6[10], ipv6[11], ipv6[12], ipv6[13], ipv6[14], ipv6[15]);
        }
    }

};

#endif // WATCHLIST_HPP
