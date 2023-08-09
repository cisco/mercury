/*
 * tls.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef TLS_H
#define TLS_H

#include "fingerprint.h"
#include "match.h"
#include "analysis.h"
#include "protocol.h"
#include "tcpip.h"


// class xtn represents a TLS extension
//
class xtn {
    encoded<uint16_t> type_;
    encoded<uint16_t> length;
public:
    datum value;

    xtn(datum &d) : type_{d}, length{d}, value{d, length} { }

    uint16_t type() const { return type_; }
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

    tls_record(datum &d) : content_type{0}, protocol_version{0}, length{0}, fragment{NULL, NULL} { parse(d); }

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
        struct tls_record record{tmp};
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

    size_t packet_metadata_length() const {
        if (!is_valid()) {
            return 0;
        }
        switch ((tls_content_type)content_type) {
        case tls_content_type::alert:
        case tls_content_type::handshake:
            return length;
            break;
        default:
            return sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t);
        }
    }

    tls_content_type type() const { return (tls_content_type)content_type; }
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
    size_t additional_bytes_needed = 0;

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
        uint64_t tmp;
        d.read_uint(&tmp, L_HandshakeLength);
        length = tmp;
        if (length > max_handshake_len) {
            return;
        }
        body.init_from_outer_parser(&d, length);
        additional_bytes_needed = length - body.length();
    }

    handshake_type type() const { return msg_type; }
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
    size_t additional_bytes_needed = 0;

    static const size_t max_length = 65536;

    tls_server_certificate() : length{0}, certificate_list{NULL, NULL}, additional_bytes_needed{0} {}

    void parse(struct datum &d) {
        uint64_t tmp = 0;
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

    static constexpr mask_and_value<8> matcher{
        { 0xff, 0xff, 0xfc, 0x00, 0x00, 0xff, 0x00, 0x00 },
        { 0x16, 0x03, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00 }
    };

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

    void print_alpn(struct json_object &o, const char *key) const;

    void print_session_ticket(struct json_object &o, const char *key) const;

    void fingerprint_quic_tls(struct buffer_stream &b, enum tls_role role) const;
    void set_meta_data(datum &server_name,
                       datum &user_agent,
                       datum& alpn) const;

    void fingerprint(struct buffer_stream &b, enum tls_role role) const;

    datum get_supported_groups() const;

};


struct tls_client_hello : public base_protocol {
    struct datum protocol_version;
    struct datum random;
    struct datum session_id;
    struct datum cookie;      // only present for dtls
    struct datum ciphersuite_vector;
    struct datum compression_methods;
    struct tls_extensions extensions;
    bool dtls = false;
    bool is_quic_hello = false;
    size_t additional_bytes_needed = 0;

    tls_client_hello() { }

    tls_client_hello(datum &p) { parse(p); }

    void parse(datum &p);

    bool is_not_empty() const { return compression_methods.is_not_empty(); };

    void fingerprint(struct buffer_stream &buf, size_t format_version=0) const;

    void compute_fingerprint(class fingerprint &fp, size_t format_version=0) const;

    static void write_json(struct datum &data, struct json_object &record, bool output_metadata);

    void write_json(struct json_object &record, bool output_metadata) const;

    bool do_analysis(const struct key &k_, struct analysis_context &analysis_, classifier *c);

    static constexpr mask_and_value<8> matcher{
        { 0xff, 0xff, 0xfc, 0x00, 0x00, 0xff, 0x00, 0x00 },
        { 0x16, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 }
    };

};

#include "match.h"

struct tls_server_hello : public base_protocol {
    struct datum protocol_version;
    struct datum random;
    struct datum ciphersuite_vector;
    struct datum compression_method;
    struct tls_extensions extensions;

    tls_server_hello() {  }

    tls_server_hello(datum &p) { parse(p); }

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

    void fingerprint(struct buffer_stream &buf) const;

    enum status parse_tls_server_hello(struct datum &p);

    void write_json(struct json_object &o, bool write_metadata=false) const {
        if (ciphersuite_vector.is_not_readable()) {
            return;
        }

        if (write_metadata) {
            o.print_key_hex("version", protocol_version);
            o.print_key_hex("random", random);
            o.print_key_hex("selected_cipher_suite", ciphersuite_vector);
            o.print_key_hex("compression_method", compression_method);
            extensions.print_alpn(o, "application_layer_protocol_negotiation");
            extensions.print_session_ticket(o, "session_ticket");
        }
    }

    void compute_fingerprint(class fingerprint &fp) const {
        fp.set_type(fingerprint_type_tls_server);
        fp.add(*this);
        fp.final();
    }

    static constexpr mask_and_value<8> matcher{
        { 0xff, 0xff, 0xfc, 0x00, 0x00, 0xff, 0x00, 0x00 },
        { 0x16, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00 }
    };

};

class tls_server_hello_and_certificate : public base_protocol {
    struct tls_server_hello hello;
    struct tls_server_certificate certificate;

public:
    tls_server_hello_and_certificate(struct datum &pkt, struct tcp_packet *tcp_pkt) : hello{}, certificate{} {
        parse(pkt, tcp_pkt);
    }

    void parse(struct datum &pkt, struct tcp_packet *tcp_pkt) {

        // parse server_hello and/or certificate
        //
        struct tls_record rec{pkt};
        struct tls_handshake handshake{rec.fragment};
        if (handshake.msg_type == handshake_type::server_hello) {
            hello.parse(handshake.body);
            if (rec.is_not_empty()) {
                struct tls_handshake h;
                h.parse(rec.fragment);
                certificate.parse(h.body);
            }

        } else if (handshake.msg_type == handshake_type::certificate) {
            certificate.parse(handshake.body);
        }
        struct tls_record rec2{pkt};
        struct tls_handshake handshake2{rec2.fragment};
        if (handshake2.msg_type == handshake_type::certificate) {
            certificate.parse(handshake2.body);
        }
        if (tcp_pkt && certificate.additional_bytes_needed) {
            tcp_pkt->reassembly_needed(certificate.additional_bytes_needed);
        }
    }

    bool is_not_empty() {
        return hello.is_not_empty() || certificate.is_not_empty();
    }

    void write_json(struct json_object &record, bool metadata_output, bool certs_json_output) {

        bool have_hello = hello.is_not_empty();
        bool have_certificate = certificate.is_not_empty();
        if (have_hello || have_certificate) {

            // output certificate (always) and server_hello (if configured to)
            //
            if ((metadata_output && have_hello) || have_certificate) {
                struct json_object tls{record, "tls"};
                struct json_object tls_server{tls, "server"};
                if (have_certificate) {
                    struct json_array server_certs{tls_server, "certs"};
                    certificate.write_json(server_certs, certs_json_output);
                    server_certs.close();
                }
                if (metadata_output && have_hello) {
                    hello.write_json(tls_server, metadata_output);
                }
                tls_server.close();
                tls.close();
            }
        }
    }

    void compute_fingerprint(fingerprint &fp) const {
        if (hello.is_not_empty()) {
            hello.compute_fingerprint(fp);
        }
    }

    const char *get_name() {
        if (hello.is_not_empty()) {
            return "tls_server";
        }
        return nullptr;
    }

    void fingerprint(buffer_stream &b) {
        if (hello.is_not_empty()) {
            hello.fingerprint(b);
        }
    }

};

static uint16_t degrease_uint16(uint16_t x) {
    switch(x) {
    case 0x0a0a:
    case 0x1a1a:
    case 0x2a2a:
    case 0x3a3a:
    case 0x4a4a:
    case 0x5a5a:
    case 0x6a6a:
    case 0x7a7a:
    case 0x8a8a:
    case 0x9a9a:
    case 0xaaaa:
    case 0xbaba:
    case 0xcaca:
    case 0xdada:
    case 0xeaea:
    case 0xfafa:
        return 0x0a0a;
        break;
    default:
        return x;
    }
    return x;
}

static void raw_as_hex_degrease(struct buffer_stream &buf, const void *data, size_t len) {
    if (len % 2) {
        len--;   // force len to be a multiple of two
    }
    uint16_t *x = (uint16_t *)data;
    uint16_t *x_end = x + (len/2);

    while (x < x_end) {
        uint16_t tmp = degrease_uint16(*x++);
        buf.raw_as_hex((const uint8_t *)&tmp, sizeof(tmp));
    }

}


// struct {
//     public-key-encrypted PreMasterSecret pre_master_secret;
// } EncryptedPreMasterSecret;

class encrypted_premaster_secret {

public:

    encrypted_premaster_secret(datum &)
    {}
};

//       enum { implicit, explicit } PublicValueEncoding;
//
//       implicit
//          If the client has sent a certificate which contains a suitable
//          Diffie-Hellman key (for fixed_dh client authentication), then
//          Yc is implicit and does not need to be sent again.  In this
//          case, the client key exchange message will be sent, but it MUST
//          be empty.
//
//       explicit
//          Yc needs to be sent.
//
//       struct {
//           select (PublicValueEncoding) {
//               case implicit: struct { };
//               case explicit: opaque dh_Yc<1..2^16-1>;
//           } dh_public;
//       } ClientDiffieHellmanPublic;
//
class client_diffie_hellman_public {
public:

    client_diffie_hellman_public(datum &)
    { }
};

// ClientKeyExchange format (following RFC 5246, TLSv1.2)
//
// struct {
//     select (KeyExchangeAlgorithm) {
//         case rsa:
//             EncryptedPreMasterSecret;
//         case dhe_dss:
//         case dhe_rsa:
//         case dh_dss:
//         case dh_rsa:
//         case dh_anon:
//             ClientDiffieHellmanPublic;
//     } exchange_keys;
// } ClientKeyExchange;

class client_key_exchange {
    datum value;

public:

    client_key_exchange(datum &d) : value{d}
    {}
};

namespace {

    [[maybe_unused]] int tls_client_hello_fuzz_test(const uint8_t *data, size_t size) {
        struct datum hello_data{data, data+size};
        char buffer_1[8192];
        struct buffer_stream buf_json(buffer_1, sizeof(buffer_1));
        char buffer_2[8192];
        struct buffer_stream buf_fp(buffer_2, sizeof(buffer_2));
        struct json_object record(&buf_json);
        

        tls_client_hello hello{hello_data};
        if (hello.is_not_empty()) {
            hello.write_json(record, true);
            hello.fingerprint(buf_fp);
        }

        return 0;
    } 

}; //end of namespace

#endif /* TLS_H */
