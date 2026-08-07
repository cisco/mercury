///
/// \file functional_unit_test.cc
///
/// Unit tests for various protocol parsers and utilities.
///
/// Note: This file does NOT define main(). It is compiled and linked with
/// doctest_main.cc, which provides the main() entry point that runs all tests.
///
/// Copyright (c) 2025 Cisco Systems, Inc. All rights reserved.
/// License at https://github.com/cisco/mercury/blob/master/LICENSE
///

#include "doctest.h"
#include "libmerc_driver_helper.hpp"
#include "bencode.h"
#include "snmp.hpp"
#include "tofsee.hpp"
#include "ip_address.hpp"
#include "utf8.hpp"
#include "tsc_clock.hpp"
#include "json_string.hpp"
#include "ftp.hpp"
#include "mem_utils.hpp"
#include "crypto_engine.h"
#include "http.h"
#include "tls.h"
#include "quic.h"

#include <string>
#include <vector>

/*
 * The unit_test() functions defined in header files
 * can be tested here using CHECK framework.
 * The below tests will be run as part of
 * make test and verified.
 */
TEST_CASE("Testing unit_test() defined in class") {
    CHECK(bencoding::dictionary::unit_test() == true);
    CHECK(snmp::unit_test() == true);
    CHECK(tofsee_initial_message::unit_test() == true);
    CHECK(tls_extensions::unit_test() == true);
    CHECK(ipv6_address_string::unit_test() == true);
    CHECK(utf8_string::unit_test() == true);
    CHECK(utf8_safe_string_unit_test() == true);
    CHECK(tsc_clock::unit_test() == true);
    CHECK(json_string::unit_test() == true);
    CHECK(ftp::unit_test()==true);
    CHECK(fixed_fifo_allocator<uint8_t,4>::unit_test()==true);
    CHECK(crypto_engine::unit_test() == true);
}

// Helper: render `data` as the lowercase hex string that mercury emits for
// a JSON hex value (e.g. "4142..."), matching json_object::print_key_hex.
//
static std::string to_hex_string(const std::string &data) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    for (unsigned char c : data) {
        out.push_back(hex[c >> 4]);
        out.push_back(hex[c & 0x0f]);
    }
    return out;
}

// Build an HTTP request from `headers` + `body`, run fingerprint() (which is
// what sets the body datum in production) followed by write_json(), then
// extract and return only the hex value emitted for the "body" key. Returns an
// empty string when no "body" key is present in the output.
//
static std::string http_request_body_hex(const std::string &headers,
                                          const std::string &body,
                                          size_t body_max) {
    std::string raw = headers + body;
    datum request_data{reinterpret_cast<const uint8_t *>(raw.data()),
                       reinterpret_cast<const uint8_t *>(raw.data()) + raw.size()};

    char json_buf[8192];
    buffer_stream buf_json(json_buf, sizeof(json_buf));
    char fp_buf[8192];
    buffer_stream buf_fp(fp_buf, sizeof(fp_buf));
    json_object record(&buf_json);

    size_t saved_body_max = http_config::output_body_max;
    http_config::set_http_body(body_max);

    http_request request{request_data};
    request.fingerprint(buf_fp);   // sets the body datum, past the header terminator
    request.write_json(record, true);
    record.close();

    http_config::output_body_max = saved_body_max;   // restore global state

    std::string json(buf_json.dstr, buf_json.doff);

    // Extract the value of the "body" key, emitted as "body":"<hex>".
    const std::string key = "\"body\":\"";
    size_t start = json.find(key);
    if (start == std::string::npos) {
        return "";
    }
    start += key.size();
    size_t end = json.find('"', start);
    if (end == std::string::npos) {
        return "";
    }
    return json.substr(start, end - start);
}

// Regression test for --http-body-max.
//
// The body datum is set in fingerprint() *after* the header terminator has
// already been consumed, so write_body() must truncate the body directly. A
// previous implementation re-scanned the body for "\r\n\r\n" before
// truncating, which dropped everything before any "\r\n\r\n" that appeared
// inside the body itself. These tests ensure the first N bytes of the actual
// body are reported.
//
TEST_CASE("http-body-max reports first N bytes of the body") {
    const std::string headers =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: test\r\n"
        "\r\n";

    SUBCASE("body shorter than the limit is reported in full") {
        const std::string body = "hello-body";
        CHECK(http_request_body_hex(headers, body, 2048) == to_hex_string(body));
    }

    SUBCASE("body is truncated to exactly N bytes") {
        const std::string body = "0123456789ABCDEF";
        const size_t n = 8;
        CHECK(http_request_body_hex(headers, body, n) == to_hex_string(body.substr(0, n)));
    }

    SUBCASE("body containing CRLFCRLF is not skipped") {
        // The inner "\r\n\r\n" must NOT cause the leading bytes to be dropped.
        const std::string body = "AB\r\n\r\nCDEFGH";
        CHECK(http_request_body_hex(headers, body, 2048) == to_hex_string(body));
    }

    SUBCASE("body-max of 0 suppresses body output") {
        const std::string body = "should-not-appear";
        CHECK(http_request_body_hex(headers, body, 0).empty());
    }
}

// Render a parsed client hello's write_json output as a string.
//
template <typename hello_t>
static std::string client_hello_write_json(hello_t &hello,
                                           const std::vector<uint8_t> &body,
                                           bool is_dtls) {
    datum d{body.data(), body.data() + body.size()};
    hello.parse(d, is_dtls);

    char json_buf[8192];
    buffer_stream buf_json(json_buf, sizeof(json_buf));
    json_object record(&buf_json);
    hello.write_json(record, true);
    record.close();
    return std::string(buf_json.dstr, buf_json.doff);
}

// The DTLS carrier must be committed by the caller (the record/transport
// layer), never inferred from the legacy_version in the clientHello body --
// which is untrusted for nested carriers such as quic and openvpn. A
// clientHello whose legacy_version is the DTLS value 0xfefd but which is
// carried over a TLS-based transport must be reported under "tls", not
// "dtls", and must parse correctly (no phantom DTLS cookie skip that would
// corrupt the fingerprint).
//
TEST_CASE("nested TLS carrier not mislabeled as dtls") {

    // A well-formed TLS clientHello body (no DTLS cookie on the wire) whose
    // legacy_version is set to the DTLS value 0xfefd, with an SNI of
    // "example.com".
    const std::vector<uint8_t> body = {
        0xfe, 0xfd,                                     // legacy_version 0xfefd (DTLS-looking)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // random (32 bytes)
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x00,                                           // session_id length 0
        0x00, 0x02, 0x13, 0x01,                         // cipher_suites: len 2, TLS_AES_128_GCM_SHA256
        0x01, 0x00,                                     // compression: len 1, null
        0x00, 0x14,                                     // extensions length 20
        0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00,       // server_name extension ...
        0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d // ... "example.com"
    };

    SUBCASE("quic carrier reports tls, not dtls") {
        // quic decrypts its Initial and parses the inner clientHello via
        // quic_client_hello (is_dtls defaults to false); see quic.h.
        quic_client_hello hello;
        std::string json = client_hello_write_json(hello, body, false);

        CHECK(hello.is_not_empty());
        CHECK(json.find("\"tls\":{\"client\"") != std::string::npos);
        CHECK(json.find("\"server_name\":\"example.com\"") != std::string::npos);
        CHECK(json.find("\"dtls\"") == std::string::npos);
    }

    SUBCASE("openvpn carrier reports tls, not dtls") {
        // openvpn_tcp parses the reassembled clientHello via
        // tls_client_hello::parse with the default (is_dtls=false); see
        // openvpn.h.
        tls_client_hello hello;
        std::string json = client_hello_write_json(hello, body, false);

        CHECK(hello.is_not_empty());
        CHECK(json.find("\"tls\":{\"client\"") != std::string::npos);
        CHECK(json.find("\"server_name\":\"example.com\"") != std::string::npos);
        CHECK(json.find("\"dtls\"") == std::string::npos);
    }

    SUBCASE("forcing the dtls carrier on a cookie-less hello mis-parses") {
        // Demonstrates why the carrier must not be guessed: parsing the same
        // TLS-layout bytes as DTLS skips a phantom cookie, shifting the
        // cipher-suite parse so the hello is rejected (previously this path
        // was reachable from a crafted quic legacy_version and corrupted the
        // fingerprint).
        tls_client_hello hello;
        (void)client_hello_write_json(hello, body, true);
        CHECK(hello.is_not_empty() == false);
    }
}
