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
#include "ip_address.hpp"



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
    std::string label_str;
    std::string last_label;
    size_t label_count = 0;
    size_t pos = 0;
    bool valid = false;

public:
    dns_string(datum &d) {
        if (d.is_not_readable()) {
            return;
        }

        label_str = d.get_string();

        // the first domain may be a wildcard (*)
        if (lookahead<literal_byte<'*'>> wildcard{d}) {
            d = wildcard.advance();
            pos++;
            if (lookahead<literal_byte<'.'>> dot{d}) {
                d = dot.advance();
                pos++;
            } else {
                d.set_null();
                return;
            }
        }

        while (d.is_not_empty()) {
            if (lookahead<dns_label_string> label{d}) {
                d = label.advance();
                pos += label.value.get_string().length();
                label_count++;
                if (lookahead<literal_byte<'.'>> dot{d}) {
                    d = dot.advance();
                    pos++;
                } else {
                    last_label = label.value.get_string().c_str();
                    break;
                }
            } else {
                label_count = 0;
                d.set_null();
                return;
            }
        }

        // a valid top level domain name contains at least one alphabetic character
        if (!std::any_of(last_label.begin(), last_label.end(), [](unsigned char c){ return std::isalpha(std::tolower(c)); })) {
            label_count = 0;
            d.set_null();
            return;
        }

        label_str = label_str.substr(0, pos);
        valid = true;
    }

    bool is_valid() const {
        return valid;
    }

    size_t get_label_count() const { return label_count; }

    void print() const {
        if (!valid) { return; }
        fputs(label_str.c_str(), stdout);
        fputc('\n', stdout);
    }

    std::string get_string() const { return valid ? label_str : std::string(); }

    const std::string & get_value() const { return label_str; }

    // normalize verifies that the DNS name is valid, and if it is
    // not, appends the string ".invalid.alt"
    //
    void normalize() {
        if (!label_str.empty()) {
            auto tld_start = label_str.find_last_of('.') + 1;
            if (label_str.substr(tld_start) == "alt") {
                label_str.replace(tld_start, std::string::npos, "invalid.alt");
            }
        }
    }
    static constexpr const char *invalid = "invalid";
    static constexpr const char *alt = "alt";

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
    bool empty = false;

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
            empty = true;
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
                label_count = dns.value.get_label_count();
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
            // datum ipv4_string = ipv4.get_parsed_data(d);
            // ipv4_string.fprint(stdout); fputc('\n', stdout);
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

    enum detail { off = 0, on = 1 };

    /// return a `std::string` containing a normalized domain name
    ///
    /// While server identifiers are often Fully Qualified Domain
    /// Names (FQDNs), they can also be addresses or other special
    /// cases.  A normalized domain name maps a server identifier into
    /// the domain name hierarchy by leaving FQDNs unchanged and
    /// otherwise mapping the identifier into the special-use
    /// subdomain `alt` (RFC 9476), as follows:
    ///
    ///    * IPv4 addresses are mapped to `address.alt`,
    ///
    ///    * IPv6 addresses are mapped to `address.alt`,
    ///
    ///    * Unqualified domains are mapped to `unqualified.alt`,
    ///
    ///    * Empty or missing domain names are mapped to `missing.alt`,
    ///
    ///    * Text strings that cannot be parsed as addresses or domain
    ///      names are mapped to `other.alt`.
    ///
    std::string get_normalized_domain_name(detail detailed_output=off) const {

        if (std::holds_alternative<ipv4_t>(host_id)) {
            std::string a;
            if (detailed_output) {
                ipv4_address addr = std::get<uint32_t>(host_id);
                normalize(addr);
                a += addr.get_dns_label();
            }
            a += "address.alt";
            return a;
        }

        if (std::holds_alternative<ipv6_array_t>(host_id)) {
            std::string a;
            if (detailed_output) {
                ipv6_array_t addr = std::get<ipv6_array_t>(host_id);
                ipv6_address tmp = get_ipv6_address(addr);
                // normalize(tmp);
                a += tmp.get_dns_label();
            }
            a += "address.alt";
            return a;
        }

        if (std::holds_alternative<std::monostate>(host_id)) {
            if (empty) {
                return "missing.alt";
            }
            return "other.alt";
        }

        if (std::holds_alternative<dns_name_t>(host_id)) {
            std::string domain_name = std::get<dns_name_t>(host_id);
            if (domain_name == "None") {
                return "missing.alt";
            }
            if (label_count == 1 and domain_name != "localhost") {
                return "unqualified.alt";
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

    /// returns the \ref host_identifier member of this
    /// server_identifier
    ///
    const host_identifier & get_host_identifier() const {
        return host_id;
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
            { "ocsp.digicert.com", "ocsp.digicert.com", {} },                       // FQDN
            { "ookla.mbspeed.net:8080", "ookla.mbspeed.net", 8080 },                // FQDN with port number
            { "10.124.145.64", "address.alt", {} },                                 // IPv4 address
            { "10.237.97.140:8443", "address.alt", 8443 },                          // IPv4 address with port number
            { "192.168.1.91", "address.alt", {} },                                  // IPv4 address in private use range
            { "[240e:390:38:1b00:211:32ff:fe78:d4ab]:10087","address.alt", 10087 }, // IPv6 address with square braces and port number
            { "[2408:862e:ff:ff03:1b::]", "address.alt", {} },                      // IPv6 address with square braces
            { "[2001:b28:f23f:f005::a]:80", "address.alt", 80 },                    // IPv6 address with zero compression, square braces, and port number
            { "::ffff:162.62.97.147", "address.alt", {} },                          // IPv6 addr with embedded IPv6 addr (RFC4291, Section 2.5.5)
            { "[::ffff:91.222.113.90]:5000", "address.alt", 5000 },                 // IPv6 addr with embedded ipv4 addr, square braces, and port number
            { "240d:c000:1010:1200::949b:1928:b134", "address.alt", {} },           // IPv6 addr with zero compression
            { "240d:c000:2010:1a58:0:95fe:d8b7:5a8f", "address.alt", {} },          // IPv6 addr without zero compression
            { "*.tplinkcloud.com", "*.tplinkcloud.com", {} },                       // wildcard subdomain
            { "18.158.72.38.nip.io", "18.158.72.38.nip.io", {} },                   // subdomains look like dotted quad
            { " www.google.com", "www.google.com", {} },                            // leading  whitespace
            { "None", "missing.alt", {} },                                          // "None" means missing
            { "", "missing.alt", {} },                                              // "" means missing
            { "localhost:443", "localhost", 443 },                                  // "localhost" with a port number
            { "www", "unqualified.alt", {} },                                       // unqualified domain name (not an FQDN)
            { "0000", "other.alt", {} },                                            // neither a name or address
            { "@#*%^$!", "other.alt", {} },                                         // neither a name or address
            { "8.8.8.8.alt", "8.8.8.8.alt", {} },                                   // .alt subdomains are left unchanged
            { "abc.def.8888", "other.alt", {} },                                    // TLD needs at least one alphabetic character
            { "*cisco.com", "other.alt", {} },                                      // invalid first label
            { "cisco.*.com", "other.alt", {} },                                     // invalid middle label
            { "cisco.com*", "other.alt", {} },                                      // invalid last label
            { "cisco.com.", "other.alt", {} },                                      // trailing dot is invalid
        };

        bool passed = true;
        auto test = [&passed, f](test_case tc, detail detailed_output) {
            std::string in{tc.input};
            std::string out{tc.output};
            datum d = get_datum(in);
            server_identifier server_id{d};
            std::string test = server_id.get_normalized_domain_name(detailed_output);
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
        };
        for (const auto & tc : test_cases) {
            test(tc, detail::off);
        }

        std::vector<test_case> detailed_test_cases = {
            { "173.37.145.84", "173-37-145-84.address.alt", {} },                   // IPv4 address
            { "172.253.63.106:8443", "172-253-63-106.address.alt", 8443 },          // IPv4 address with port number
            { "192.168.1.91", "10-0-0-1.address.alt", {} },                         // IPv4 address in private use range
            { "[240e:390:38:1b00:211:32ff:fe78:d4ab]:10087","240e-390-38-1b00-211-32ff-fe78-d4ab.address.alt", 10087 }, // IPv6 address with square braces and port number
            { "[2408:862e:ff:ff03:1b::]", "2408-862e-ff-ff03-1b--.address.alt", {} },                      // IPv6 address with square braces
            { "[2001:b28:f23f:f005::a]:80", "2001-b28-f23f-f005--a.address.alt", 80 },                    // IPv6 address with zero compression, square braces, and port number
            { "::ffff:162.62.97.147", "--ffff-a23e-6193.address.alt", {} },                          // IPv6 addr with embedded IPv6 addr (RFC4291, Section 2.5.5)
            { "[::ffff:91.222.113.90]:5000", "--ffff-5bde-715a.address.alt", 5000 },                 // IPv6 addr with embedded ipv4 addr, square braces, and port number
            { "2001:db8::2:1", "2001-db8--2-1.address.alt", {} },                                                        // IPv6 addr with zero compression
            { "240d:c000:2010:1a58:0:95fe:d8b7:5a8f", "240d-c000-2010-1a58-0-95fe-d8b7-5a8f.address.alt", {} },          // IPv6 addr without zero compression
        };
        for (const auto & tc : detailed_test_cases) {
            test(tc, detail::on);
        }

        return passed;
    }

};

/// Given the input string `s` that is a textual representation of an
/// ipv4 or ipv6 address, return the textual representation of the
/// normalized address.  If `s` is not correctly formatted, or has
/// trailing data, then the empty string is returned.
///
inline std::string normalize_ip_address(const std::string &s) {
    datum d{(uint8_t *)s.data(), (uint8_t *)s.data() + s.length()};
    if (lookahead<ipv4_address_string> addr_str{d}) {
        d = addr_str.advance();
        if (d.is_not_empty()) {
            return "";  // error: trailing data after address
        }
        ipv4_address addr = addr_str.value.get_value();
        normalize(addr);
        return addr.get_string();
    }
    if (lookahead<ipv6_address_string> addr_str{d}) {
        d = addr_str.advance();
        if (d.is_not_empty()) {
            return "";  // error: trailing data after address
        }
        ipv6_address addr = get_ipv6_address(addr_str.value.get_value_array());
        normalize(addr);
        return addr.get_string();
    }
    return "";  // error: s is neither an ipv4 nor an ipv6 address
}


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
