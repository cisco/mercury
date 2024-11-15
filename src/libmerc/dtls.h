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
#include "util_obj.h"
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
    uint32_t length;  // note: only 24 bits on the wire (L_HandshakeLength)
    uint16_t message_seq;      // DTLS-only field
    uint32_t fragment_offset;  // 24 bits on wire; DTLS-only field
    uint32_t fragment_length;  // 24 bits on wire; DTLS-only field
    struct datum body;

    dtls_handshake() : msg_type{handshake_type::unknown}, length{0}, body{NULL, NULL} {}

    dtls_handshake(struct datum &d) : msg_type{handshake_type::unknown}, length{0}, body{NULL, NULL} {
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
        body.init_from_outer_parser(&d, length);
    }

};

class dtls_client_hello : public base_protocol {
    tls_client_hello hello;
public:
    dtls_client_hello(struct datum &pkt) : hello{pkt} {}

    void fingerprint(struct buffer_stream &buf) const {
        hello.fingerprint(buf);
    }

    void compute_fingerprint(class fingerprint &fp) const {
        fp.set_type(fingerprint_type_dtls);
        fp.add(*this);
        fp.final();
    }

    void write_json(struct json_object &record, bool output_metadata) const {
        hello.write_json(record, output_metadata);
    }

    bool is_not_empty() const {
        return hello.is_not_empty();
    }

    static constexpr mask_and_value<16> dtls_matcher = {
        {
         0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00
        },
        {
         0x16, 0xfe, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
        }
    };

};

class dtls_server_hello : public base_protocol {
    tls_server_hello hello;

public:
    dtls_server_hello(datum &p) : hello{p} {}

    void fingerprint(struct buffer_stream &buf) const {
        hello.fingerprint(buf);
    }

    void write_json(struct json_object &o, bool write_metadata=false) const {
        hello.write_json(o, write_metadata);
    }

    void compute_fingerprint(class fingerprint &fp) const {
        fp.set_type(fingerprint_type_dtls_server);
        fp.add(*this);
        fp.final();
    }

    bool is_not_empty() const {
        return hello.is_not_empty();
    }

    static constexpr mask_and_value<16> dtls_matcher = {
        {
         0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00
        },
        {
         0x16, 0xfe, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00
        }
    };
};
#endif /* DTLS_H */
