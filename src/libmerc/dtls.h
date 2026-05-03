/*
 * dtls.h
 *
 * Copyright (c) 2022 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef DTLS_H
#define DTLS_H

#include "protocol.h"
#include "fingerprint.h"
#include "match.h"
#include "json_object.h"
#include "tls.h"

// DTLS (RFC 4347)

struct dtls_record {
    uint8_t  content_type;
    uint16_t protocol_version;
    uint16_t epoch;
    uint64_t sequence_number;  // only 48 bits on wire
    uint16_t length;
    struct datum fragment;

    dtls_record(datum &d) : content_type{0}, protocol_version{0}, epoch{0}, sequence_number{0}, length{0}, fragment{NULL, NULL} {
        parse(d);
    }

    void parse(struct datum &d) {
        if (d.length() < (int)(sizeof(content_type) + sizeof(protocol_version) + sizeof(length))) {
            return;
        }
        d.read_uint8(&content_type);
        d.read_uint16(&protocol_version);
        d.read_uint16(&epoch);
        d.read_uint(&sequence_number, 6);   // 6 bytes == 48 bits
        d.read_uint16(&length);
        fragment.init_from_outer_parser(&d, length);
    }
};

struct dtls_handshake {
    handshake_type msg_type;
    uint32_t length;           // note: only 24 bits on the wire (L_HandshakeLength); full message length
    uint16_t message_seq;      // DTLS-only field
    uint32_t fragment_offset;  // 24 bits on wire; DTLS-only field
    uint32_t fragment_length;  // 24 bits on wire; DTLS-only field
    struct datum body;
    size_t additional_bytes_needed = 0;

    dtls_handshake() : msg_type{handshake_type::unknown}, length{0}, message_seq{0}, fragment_offset{0}, fragment_length{0}, body{NULL, NULL} {}

    dtls_handshake(struct datum &d) : msg_type{handshake_type::unknown}, length{0}, message_seq{0}, fragment_offset{0}, fragment_length{0}, body{NULL, NULL} {
        parse(d);
    }

    void parse(struct datum &d) {
        if (d.length() < (int)(4)) {
            return;
        }
        d.read_uint8((uint8_t *)&msg_type);
        uint64_t tmp;
        d.read_uint(&tmp, L_HandshakeLength);
        length = tmp;
        d.read_uint16(&message_seq);
        d.read_uint(&tmp, 3);  // 24 bits on wire
        fragment_offset = tmp;
        d.read_uint(&tmp, 3);  // 24 bits on wire
        fragment_length = tmp;
        // body contains only the fragment data (fragment_length bytes),
        // not the full message (length bytes)
        body.init_from_outer_parser(&d, fragment_length);
        // Only set additional_bytes_needed when this is the start of the message
        // (fragment_offset == 0).  Fragments that begin mid-message must not
        // trigger reassembly initialisation; they are continuations or will be
        // ignored until the first fragment establishes the flow.
        if (fragment_offset == 0) {
            additional_bytes_needed = length - body.length();
        } else {
            additional_bytes_needed = 0;
        }
    }

    // DTLS handshake records begin with content-type 0x16 (Handshake).
    // The next two bytes are the protocol version:
    //   0xfe 0xfd for DTLS 1.3/DTLS 1.2 legacy version
    //   0xfe 0xff for DTLS 1.0.
    // This matcher is unused and is kept for reference.
    static constexpr mask_and_value<8> dtls_matcher = {
        {
         0xff, 0xff, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        {
         0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00,
        }
    };

};

class dtls_client_hello : public base_protocol {
    dtls_record rec;
    dtls_handshake handshake;
    tls_client_hello hello;
public:
    dtls_client_hello(struct datum &pkt) :
        rec{pkt},
        handshake{rec.fragment},
        hello{handshake.body} {}

    void fingerprint(struct buffer_stream &buf, size_t format_version) const {
        hello.fingerprint(buf, format_version);
    }

    void compute_fingerprint(class fingerprint &fp, size_t format_version) const {
        fp.set_type(fingerprint_type_dtls);
        fp.add(*this, format_version);
        fp.final();
    }

    void write_json(json_object &record, bool output_metadata) const {
        hello.write_json(record, output_metadata);
    }

    void write_l7_metadata(cbor_object &o, bool) {
        cbor_array protocols{o, "protocols"};
        protocols.print_string("dtls");
        protocols.close();
    }

    bool is_not_empty() const {
        return hello.is_not_empty();
    }

    const tls_client_hello &get_tls_client_hello() const { return hello; }

    // Reassembly support: mirrors quic_init interface so that process_udp_data
    // can treat DTLS fragments analogously to QUIC CRYPTO frames.

    /// Returns bytes still needed to complete the full handshake message.
    uint32_t additional_bytes_needed() const {
        return static_cast<uint32_t>(handshake.additional_bytes_needed);
    }

    /// Returns the fragment offset (analogous to QUIC crypto frame offset).
    uint32_t get_fragment_offset() const { return handshake.fragment_offset; }

    /// Returns the number of fragment bytes present in this datagram.
    uint32_t get_fragment_length() const {
        return static_cast<uint32_t>(handshake.body.length());
    }

    /// Returns the full (reassembled) handshake message length.
    uint32_t get_handshake_length() const { return handshake.length; }

    /// Returns a datum over the fragment payload in this datagram.
    datum get_fragment_data() const { return handshake.body; }

    /// Re-parse the TLS ClientHello from a fully reassembled handshake body.
    void reparse_from_buf(datum buf) {
        hello = tls_client_hello{buf};
    }

    bool do_analysis(const struct key &k_, struct analysis_context &analysis_, classifier *c_) {
        return hello.do_analysis(k_, analysis_, c_);
    }

    // DTLS handshake records begin with content-type 0x16 (Handshake).
    // The next two bytes are the protocol version:
    //   0xfe 0xfd for DTLS 1.3/DTLS 1.2 legacy version
    //   0xfe 0xff for DTLS 1.0.
    // The 14th byte of the record payload is the handshake type.
    //   0x01 - ClientHello.
    //   0x02 - ServerHello.
    //   0x03 - HelloVerifyRequest.
    static constexpr mask_and_value<16> dtls_matcher = {
        {
         0xff, 0xff, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00
        },
        {
         0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
        }
    };

};

class dtls_hello_verify_request: public base_protocol {
    dtls_record rec;
    dtls_handshake handshake;
    encoded<uint16_t> protocol_version;
    encoded<uint8_t> cookie_len;
    datum cookie;
    bool valid;

public:
    // set the boolean verbose to `true` for
    // verbose output in `dtls_hello_verify_request::write_json()
    static constexpr bool verbose = false;

    dtls_hello_verify_request(struct datum &p) :
        rec{p},
        handshake{rec.fragment},
        protocol_version{handshake.body},
        cookie_len{handshake.body},
        cookie{handshake.body, cookie_len.value()},
        valid{handshake.body.is_not_null()} {}

    void write_json(json_object &record, bool metadata) const {
        (void)metadata;  // ignore parameter

        if (!verbose || !valid) {
            return;
        }

        json_object dtls{record, "dtls"};
        json_object hello_verify{dtls, "hello_verify_request"};
        hello_verify.print_key_uint16_hex("version", protocol_version);
        hello_verify.print_key_hex("cookie", cookie);
        hello_verify.close();
        dtls.close();
    }

    void write_l7_metadata(cbor_object &o, bool) {
        cbor_array protocols{o, "protocols"};
        protocols.print_string("dtls");
        protocols.close();
    }

    bool is_not_empty() const {
        return valid;
    }

    static constexpr mask_and_value<16> dtls_matcher = {
        {
         0xff, 0xff, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00
        },
        {
         0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00
        }
    };
};

class dtls_server_hello : public base_protocol {
    dtls_record rec;
    dtls_handshake handshake;
    tls_server_hello hello;

public:
    dtls_server_hello(datum &p) :
        rec{p},
        handshake{rec.fragment},
        hello{handshake.body} {}

    void fingerprint(struct buffer_stream &buf) const {
        hello.fingerprint(buf);
    }

    void write_json(json_object &o, bool write_metadata=false) const {
        hello.write_json(o, write_metadata);
    }

    void write_l7_metadata(cbor_object &o, bool) {
        cbor_array protocols{o, "protocols"};
        protocols.print_string("dtls");
        protocols.close();
    }

    void compute_fingerprint(class fingerprint &fp) const {
        fp.set_type(fingerprint_type_dtls_server);
        fp.add(*this);
        fp.final();
    }

    bool is_not_empty() const {
        return hello.is_not_empty();
    }

    const tls_server_hello &get_tls_server_hello() const { return hello; }

    static constexpr mask_and_value<16> dtls_matcher = {
        {
         0xff, 0xff, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00
        },
        {
         0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00
        }
    };
};

[[maybe_unused]] inline int dtls_client_hello_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<dtls_client_hello>(data, size);
}

[[maybe_unused]] inline int dtls_server_hello_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<dtls_server_hello>(data, size);
}

[[maybe_unused]] inline int dtls_hello_verify_request_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<dtls_hello_verify_request>(data, size);
}

#endif /* DTLS_H */
