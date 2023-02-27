// reader.cpp
//
// example file reader for ipv4/ipv6/hostname/subnet files

#include <cstdio>
#include <string>
#include <vector>
#include <unordered_set>
#include <variant>
#include <iostream>
#include <fstream>
#include "libmerc/datum.h"
#include "libmerc/lex.h"

datum get_datum(const std::string &s) {
    uint8_t *data = (uint8_t *)s.c_str();
    return { data, data + s.length() };
}

template <typename T>
T str_to_uint(const digits &d) {
    T tmp = 0;
    for (const auto & c: d) {
        tmp = 10 * tmp + (c - '0');
    }
    // fprintf(stdout, ">> %u\n", tmp);
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

        value = str_to_uint<uint8_t>(w) + 256 * (str_to_uint<uint8_t>(x) + 256 * (str_to_uint<uint8_t>(y) + 256 * str_to_uint<uint8_t>(z)));
    }

    bool is_valid() const { return z.is_not_null(); }

    void print() const {
        if (is_valid()) {

        str_to_uint<uint8_t>(w);
        str_to_uint<uint8_t>(x);
        str_to_uint<uint8_t>(y);
        str_to_uint<uint8_t>(z);

            w.fprint(stdout);
            fputc('.', stdout);
            x.fprint(stdout);
            fputc('.', stdout);
            y.fprint(stdout);
            fputc('.', stdout);
            z.fprint(stdout);
            fprintf(stdout, "\n");
        } else {
            fprintf(stdout, "invalid\n");
        }
    }

    // get_value() returns the (binary) value in host byte order.  If
    // this object could not be initialized, an all-zero IPv4 address
    // will be returned (0.0.0.0).  The caller should verify that the
    // object has been properly initialized through a call to
    // is_valid().
    //
    uint32_t get_value() const { return value; }
};

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

        while (d.is_not_empty()) {
            if (lookahead<literal_byte<':'>> colon{d}) {
                d = colon.advance();
                if (lookahead<literal_byte<':'>> colon2{d}) {
                    d = colon2.advance();
                    if (double_colon_index != -1) {
                        return;   // error; multiple double colons
                    }
                    double_colon_index = pieces.size();
                }
            } else {
                hex_digits piece{d};
                if (piece.is_not_null()) {
                    pieces.push_back(piece);
                } else {
                    return;    // invalid label
                }
            }
        }
        valid = true;
    }

    bool is_valid() const { return valid; }

    void print() const {
        if (!valid) { return; }

        ssize_t index = 0;
        for (const auto &p : pieces) {
            if (index == double_colon_index) {
                fputc(':', stdout);
                fputc(':', stdout);
            } else if (index != 0) {
                fputc(':', stdout);
            }
            index++;
            fprintf(stdout, "%x", hex_str_to_uint<uint16_t>(p));
        }
        if (index == double_colon_index) {
            fputc(':', stdout);
            fputc(':', stdout);
        }
        fputc('\n', stdout);
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

    static bool unit_test() {
        // TODO: create a proper unit test by including input and
        // output values.  This will require having some way to
        // initialize uint128_t literals, which is problematic.
        // Probably we need to refactor the IPv6 address code into
        // something more standard and portable than __uint128_.
        //
        // std::vector<std::pair<std::string, uint128_t>> ipv6_string_and_addr{
        //     { "2001:DB8:0:0:8:800:200C:417A", 0x20010db80000000000080800200c417aLL` },
        //     { "2001:DB8::8:800:200C:417A", 0x20010db80000000000080800200c417aLL },
        //     { "::1", 0x00000000000000000000000000000001LL },
        //     { "1::", 0x00010000000000000000000000000000LL },
        //     { "::",  0x00000000000000000000000000000000LL }
        // };
        std::vector<std::string> ipv6_string_examples{
            "2001:DB8:0:0:8:800:200C:417A",
            "2001:DB8::8:800:200C:417A",
            "::1",
            "1::",
            "::"
        };
        for (const auto & ipv6_string : ipv6_string_examples) {
            fprintf(stdout, "parsing ipv6 string '%s':\t", ipv6_string.c_str());
            datum tmp = get_datum(ipv6_string);
            ipv6_address_string ipv6{tmp};
            if (ipv6.is_valid()) {
                ipv6.print(); fputc('\n', stdout);

                // print uint128_t as a hex integer in network byte order
                //
                uint128_t tmp = ipv6.get_value();
                for (size_t i=0; i<16; i++) {
                    uint8_t byte = tmp >> (8*(15-i));
                    fprintf(stdout, "%02x", byte);
                }
                fputc('\n', stdout);
            } else {
                fprintf(stdout, "warning: ipv6 string is invalid\n");
            }
        }

        return 0;
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
        return (x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z') || (x >= '0' && x <= '9') || x == '-';
    }
};

class dns_string {
    std::vector<dns_label_string> label_vector;
    bool valid = false;

public:

    dns_string(datum &d) {

        while (d.is_not_empty()) {
            dns_label_string label{d};
            if (label.is_not_null()) {
                if (lookahead<literal_byte<'.'>> dot{d}) {
                    label_vector.push_back(label);
                    d = dot.advance();
                } else if (!d.is_not_empty()) {
                    label_vector.push_back(label);
                }
            } else {
                return;    // invalid label
            }
        }

        // a valid top level domain name contains at least one
        // alphabetic character
        //
        dns_label_string tld = label_vector.back();
        bool tld_is_valid = false;
        for (const auto &x : tld ) {
            if ((x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z')) {
                tld_is_valid = true;
                break;
            }
        }
        if (!tld_is_valid) {
            return;   // not a valid tld, possibly an IPv4 dotted quad
        }

        valid = true;
    }

    bool is_valid() const {
        return valid;
    }

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
};

using ipv4_t          = uint32_t;
using ipv6_t          = uint128_t;
using dns_name_t      = std::string;
using host_identifier = std::variant<std::monostate, ipv4_t, ipv6_t, dns_name_t>;

// TODO: consider creating functions and visitors for creating and
// operating on the host_identifer variant

bool set_host_identifier(host_identifier &h, datum d) {
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
        // fprintf(stdout, "ipv4_address_string:\t");
        // ipv4.value.print();
        h = ipv4.value.get_value();
        d = ipv4.advance();

    } else if (lookahead<dns_string> dns{d}) {
        // fprintf(stdout, "dns_string:\t");
        // dns.value.print();
        h = dns.value.get_string();
        d = dns.advance();

    } else if (lookahead<ipv6_address_string> ipv6{d}) {
        // fprintf(stdout, "ipv6_address_string:\t");
        // ipv6.value.print();
        h = ipv6.value.get_value();
        d = ipv6.advance();
    } else {
        fprintf(stderr, "warning: invalid line\n");
        return false;
    }
    return true;
}

// class watchlist implements a watchlist of host identifiers,
// including IPv4 and IPv6 addresses and DNS names
//
class watchlist {
    std::unordered_set<uint32_t> ipv4_addrs;
    std::unordered_set<uint128_t> ipv6_addrs;
    std::unordered_set<std::string> dns_names;

    // TODO: for performance, try using perfect_hash in place of unordered_map
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
        }
    }

    // contains(x) returns true if this watchlist contains x, and
    // false otherwise.
    //
    bool contains(uint32_t addr) const {
        return ipv4_addrs.find(addr) != ipv4_addrs.end();
    }
    bool contains(std::string &name) const {
        return dns_names.find(name) != dns_names.end();
    }
    bool contains(uint128_t addr) const {
        return ipv6_addrs.find(addr) != ipv6_addrs.end();
    }

    // process_line() parses and processes a single line of a
    // watchlist file, and returns true on success and false on
    // failure
    //
    bool process_line(datum d) {
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
            ipv6_addrs.insert(ipv6.value.get_value());

        } else {
            fprintf(stderr, "warning: invalid line\n");
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
    }

};

int main(int argc, char *argv[]) {

    std::ios::sync_with_stdio(false);  // for performance

    // run IPv6 unit test code
    //
    // ipv6_address_string::unit_test();

    std::ifstream doh_file{"doh.txt"};
    watchlist doh{doh_file};
    //    watchlist doh{std::cin};
    //    doh.print();

    // loop over input lines, parsing each line as an ipv4_addr or
    // dns_name and then testing them against the watchlist
    //
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.length() == 0) {
            // break;  // assume no more input
            fprintf(stdout, "warning: empty line\n");
            continue;
        }
        datum d = get_datum(line);

        ipv4_address_string ipv4{d};
        if (ipv4.is_valid()) {
            fprintf(stdout, "got ipv4_address_string:\t");
            ipv4.print();

            if (doh.contains(ipv4.get_value())) {
                fprintf(stdout, "\tHIT\n");
            } else {
                fprintf(stdout, "\tMISS\n");
            }

        } else {
            datum d = get_datum(line);
            dns_string dns{d};
            if (dns.is_valid()) {
                fprintf(stdout, "dns_string:\t");
                dns.print();

                std::string dns_tmp = dns.get_string();
                if (doh.contains(dns_tmp)) {
                    fprintf(stdout, "\tHIT\n");
                } else {
                    fprintf(stdout, "\tMISS\n");
                }

            } else {

                datum d = get_datum(line);
                ipv6_address_string ipv6{d};
                if (ipv6.is_valid()) {
                    fprintf(stdout, "ipv6_address_string:\t");
                    ipv6.print();

                    if (doh.contains(ipv6.get_value())) {
                        fprintf(stdout, "\tHIT\n");
                    } else {
                        fprintf(stdout, "\tMISS\n");
                    }

                } else {
                    fprintf(stdout, "warning: invalid line (%s)\n", line.c_str());
                }
            }
        }
    }

    return 0;
}
