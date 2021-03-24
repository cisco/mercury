/*
 * tls.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef TLS_H
#define TLS_H

#include "fingerprint.h"
#include "extractor.h"

struct tls_security_assessment {
    bool weak_version_offered;
    bool weak_ciphersuite_offered;
    bool weak_elliptic_curve_offered;
    bool weak_version_used;
    bool weak_ciphersuite_used;
    bool weak_elliptic_curve_used;
    bool weak_key_size_used;

    tls_security_assessment() :
        weak_version_offered{false},
        weak_ciphersuite_offered{false},
        weak_elliptic_curve_offered{false},
        weak_version_used{false},
        weak_ciphersuite_used{false},
        weak_elliptic_curve_used{false},
        weak_key_size_used{false}
    {  }

    void print(struct json_object &o, const char *key);
};


/*
 *
 * From RFC 8446 (TLSv1.3):
 *
 *     uint16 ProtocolVersion;
 *
 *     enum {
 *         invalid(0),
 *         change_cipher_spec(20),
 *         alert(21),
 *         handshake(22),
 *         application_data(23),
 *         (255)
 *     } ContentType;
 *
 *     struct {
 *         ContentType type;
 *         ProtocolVersion legacy_record_version;
 *         uint16 length;
 *         opaque fragment[TLSPlaintext.length];
 *     } TLSPlaintext;
 *
 *
 *      struct {
 *         opaque content[TLSPlaintext.length];
 *         ContentType type;
 *         uint8 zeros[length_of_padding];
 *     } TLSInnerPlaintext;
 *
 *     struct {
 *         ContentType opaque_type = application_data;     // 23
 *         ProtocolVersion legacy_record_version = 0x0303; // TLS v1.2
 *         uint16 length;
 *         opaque encrypted_record[TLSCiphertext.length];
 *     } TLSCiphertext;
 *
 *     enum {
 *         client_hello(1),
 *         server_hello(2),
 *         new_session_ticket(4),
 *         end_of_early_data(5),
 *         encrypted_extensions(8),
 *         certificate(11),
 *         certificate_request(13),
 *         certificate_verify(15),
 *         finished(20),
 *         key_update(24),
 *         message_hash(254),
 *         (255)
 *     } HandshakeType;
 *
 *     struct {
 *         HandshakeType msg_type;     // handshake type
 *         uint24 length;              // remaining bytes in message
 *         select (Handshake.msg_type) {
 *             case client_hello:          ClientHello;
 *             case server_hello:          ServerHello;
 *             case end_of_early_data:     EndOfEarlyData;
 *             case encrypted_extensions:  EncryptedExtensions;
 *             case certificate_request:   CertificateRequest;
 *             case certificate:           Certificate;
 *             case certificate_verify:    CertificateVerify;
 *             case finished:              Finished;
 *             case new_session_ticket:    NewSessionTicket;
 *             case key_update:            KeyUpdate;
 *         };
 *     } Handshake;
 */

enum class tls_content_type : uint16_t {
    // 0-19 	Unassigned (Requires coordination; see [RFC7983]) 		[RFC5764][RFC7983]
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    heartbeat = 24,
    tls12_cid = 25 // (TEMPORARY - registered 2019-07-02, extension registered 2020-07-28, expires 2021-07-02) 	Y 	[draft-ietf-tls-dtls-connection-id]
    // 26-63 	Unassigned
    // 64-255 	Unassigned (Requires coordination; see [RFC7983]) 		[RFC5764][RFC7983]
};

enum class tls_version : uint16_t {
    sslv3_0 = 0x0300,
    tlsv1_0 = 0x0301,
    tlsv1_1 = 0x0302,
    tlsv1_2 = 0x0303,
};

/*
 * field lengths
 */
#define L_CipherSuite              2
#define L_CompressionMethod        1
#define L_HandshakeLength          3
#define L_CertificateLength        3
#define L_CertificateListLength    3

struct tls_record {
    uint8_t  content_type;
    uint16_t protocol_version;
    uint16_t length;
    struct datum fragment;

    tls_record() : content_type{0}, protocol_version{0}, length{0}, fragment{NULL, NULL} {}

    void parse(struct datum &d) {
        if (d.length() < (int)(sizeof(content_type) + sizeof(protocol_version) + sizeof(length))) {
            return;
        }
        d.read_uint8(&content_type);
        d.read_uint16(&protocol_version);
        d.read_uint16(&length);
        fragment.init_from_outer_parser(&d, length);
    }

    bool is_not_empty() const { return fragment.is_not_empty(); } 

    static bool is_valid(const struct datum &d) {
        struct datum tmp = d;
        struct tls_record record;
        record.parse(tmp);
        return record.is_valid();
    }

    bool is_valid() const {

        switch ((tls_content_type) content_type) {
        case tls_content_type::change_cipher_spec:
        case tls_content_type::alert:
        case tls_content_type::handshake:
        case tls_content_type::application_data:
        case tls_content_type::heartbeat:
        case tls_content_type::tls12_cid:
            break;
        default:
            return false;
        }

        switch((tls_version) protocol_version) {
        case tls_version::sslv3_0:
        case tls_version::tlsv1_0:
        case tls_version::tlsv1_1:
        case tls_version::tlsv1_2:
            break;
        default:
            return false;
        }
        return true;
    }
};

enum class handshake_type : uint8_t {
    unknown      = 0,
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    message_hash = 254
};

struct tls_handshake {
    handshake_type msg_type;
    uint32_t length;  // note: only 24 bits on the wire (L_HandshakeLength)
    struct datum body;
    size_t additional_bytes_needed;

    static const unsigned int max_handshake_len = 32768;

    tls_handshake() : msg_type{handshake_type::unknown}, length{0}, body{NULL, NULL}, additional_bytes_needed{0} {}

    tls_handshake(struct datum &d) : msg_type{handshake_type::unknown}, length{0}, body{NULL, NULL} {
        parse(d);
    }

    void parse(struct datum &d) {
        if (d.length() < (int)(4)) {
            return;
        }
        d.read_uint8((uint8_t *)&msg_type);
        size_t tmp;
        d.read_uint(&tmp, L_HandshakeLength);
        length = tmp;
        if (length > max_handshake_len) {
            return;
        }
        body.init_from_outer_parser(&d, length);
        additional_bytes_needed = length - body.length();
    }
};

/*
 * From RFC 5246 (TLSv1.2)
 *
 *     opaque ASN.1Cert<1..2^24-1>;
 *
 *     struct {
 *         ASN.1Cert certificate_list<0..2^24-1>;
 *     } Certificate;
 *
 */

struct tls_server_certificate {
    uint32_t length; // note: only 24 bits on the wire (L_CertificateListLength)
    struct datum certificate_list;
    size_t additional_bytes_needed;

    static const size_t max_length = 65536;

    tls_server_certificate() : length{0}, certificate_list{NULL, NULL}, additional_bytes_needed{0} {}

    void parse(struct datum &d) {
        size_t tmp = 0;
        if (d.read_uint(&tmp, L_CertificateListLength) == false) {
            return;
        }
        if (tmp > tls_server_certificate::max_length) {
            d.set_null();
            return;  // probably not a real server certificate
        }
        length = tmp;
        certificate_list.init_from_outer_parser(&d, length);
        additional_bytes_needed = length - certificate_list.length();
        if (additional_bytes_needed) {
            // fprintf(stderr, "certificate additional_bytes_needed: %zu\ttotal bytes needed: %u\n", additional_bytes_needed, length);
        }
    }

    bool is_not_empty() const { return certificate_list.is_not_empty(); }

    void write_json(struct json_array &a, bool json_output) const;

};

#define L_ExtensionType            2
#define L_ExtensionLength          2

/*
 * extension types used in normalization
 */
#define type_sni                0x0000
#define type_supported_groups   0x000a
#define type_supported_versions 0x002b

#define SNI_HDR_LEN 9


enum class tls_role { client, server };

struct tls_extensions : public datum {

    tls_extensions() = default;

    tls_extensions(const uint8_t *data, const uint8_t *data_end) : datum{data, data_end} {}

    void print(struct json_object &o, const char *key) const;

    void print_server_name(struct json_object &o, const char *key) const;

    void print_quic_transport_parameters(struct json_object &o, const char *key) const;

    void set_server_name(struct datum &server_name) const;

    void print_session_ticket(struct json_object &o, const char *key) const;

    void fingerprint(struct buffer_stream &b, enum tls_role role) const;
};


struct tls_client_hello {
    struct datum protocol_version;
    struct datum random;
    struct datum session_id;
    struct datum cookie;      // only present for dtls
    struct datum ciphersuite_vector;
    struct datum compression_methods;
    struct tls_extensions extensions;
    bool dtls;
    size_t additional_bytes_needed;

    tls_client_hello() : protocol_version{NULL, NULL}, random{NULL, NULL}, session_id{NULL, NULL}, cookie{NULL, NULL}, ciphersuite_vector{NULL, NULL}, compression_methods{NULL, NULL}, extensions{NULL, NULL}, dtls{false}, additional_bytes_needed{0} {}

    void parse(struct datum &p);

    bool is_not_empty() const { return ciphersuite_vector.is_not_empty(); };

    void operator()(struct buffer_stream &buf) const;

    void write_fingerprint(struct buffer_stream &buf) const;

    void compute_fingerprint(struct fingerprint &fp) const;

    static void write_json(struct datum &data, struct json_object &record, bool output_metadata);

    void write_json(struct json_object &record, bool output_metadata) const;

    struct tls_security_assessment security_assesment();
};

#include "match.h"

struct tls_server_hello {
    struct datum protocol_version;
    struct datum random;
    struct datum ciphersuite_vector;
    struct datum compression_method;
    struct tls_extensions extensions;

    tls_server_hello() = default;

    void parse(struct datum &p);

    bool is_not_empty() const {
        uint16_t tls_version_list[6] = {
            0x0303, 0x0302, 0x0301, 0x0300, 0xfeff, 0xfefd
        };
        struct datum tmp = protocol_version;
        uint16_t version;
        tmp.read_uint16(&version);
        if (!uint16_match(version, tls_version_list, 6)) {
            return false;
        };
        return ciphersuite_vector.is_not_empty();
    };

    void operator()(struct buffer_stream &buf) const;

    enum status parse_tls_server_hello(struct datum &p);

    void write_json(struct json_object &record) const;

    void compute_fingerprint(struct fingerprint &fp) const;

};


// DTLS (RFC 4347)

struct dtls_record {
    uint8_t  content_type;
    uint16_t protocol_version;
    uint16_t epoch;
    uint64_t sequence_number;  // only 48 bits on wire
    uint16_t length;
    struct datum fragment;

    dtls_record() : content_type{0}, protocol_version{0}, epoch{0}, sequence_number{0}, length{0}, fragment{NULL, NULL} {}

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
        size_t tmp;
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


#endif /* TLS_H */
