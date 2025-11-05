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
#include "tls_parameters.hpp"
#include "flow_key.h"
#include "json_object.h"
#include "x509.h"
#include "quic_vli.hpp"
#include "tls_extensions.h"
#include "ech.hpp"
#include "mem_utils.hpp"



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
    server_key_exchange = 12,
    certificate_request = 13,
    certificate_verify = 15,
    client_key_exchange = 16,
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

    static constexpr uint16_t max_repeat_extensions = 3;

    tls_extensions() = default;

    tls_extensions(const uint8_t *data, const uint8_t *data_end) : datum{data, data_end} {}

    void print(struct json_object &o, const char *key) const;

    datum get_server_name() const;

    void print_server_name(struct json_object &o, const char *key) const;

    void print_quic_transport_parameters(struct json_object &o, const char *key) const;

    void print_alpn(struct json_object &o, const char *key) const;

    void print_session_ticket(struct json_object &o, const char *key) const;

    void print_ech_client_hello(struct json_object &o) const;

    void fingerprint_quic_tls(struct buffer_stream &b, enum tls_role role) const;
    void fingerprint_format2(struct buffer_stream &b, enum tls_role role) const;

    void set_meta_data(datum &server_name,
                       datum &user_agent,
                       datum& alpn) const;

    void fingerprint(struct buffer_stream &b, enum tls_role role) const;

    void write_raw_features(writeable &buf) const;

    datum get_supported_groups() const;

    void write_l7_metadata(cbor_object &o) const {
        o.print_key_string("server_name", get_server_name());
    }

#ifndef NDEBUG
    static bool unit_test() {
        uint8_t extensions[] = {
        0x00, 0x3f, 0x00, 0x01, 0x01,   //check if unassigned extension is encoded correctly
        0xff, 0x2b, 0x00, 0x01, 0x01,   //check if private extensions is encoded correctly
        0x1a, 0x1a, 0x00, 0x00,         //Grease extension 1
        0x2a, 0x2a, 0x00, 0x00,         //Grease extension 2
        0xff, 0x2b, 0x00, 0x01, 0x02,   // Private extension repeated second time
        0xff, 0x2b, 0x00, 0x01, 0x02,   // Private extension repeated third time
        0xff, 0x2b, 0x00, 0x01, 0x02    // Private extension repeated fourth time
        };

        /* In Format 1, extensions are degreased and no other encoding happens */
        unsigned char expected_json_format1[] = "[(003f)(0a0a)(0a0a)(ff2b)(ff2b)(ff2b)(ff2b)]";

        unsigned char expected_json_format2[] = "[(003e)(0a0a)(0a0a)(ff00)(ff00)(ff00)]";

        datum exts_data{extensions, extensions + sizeof(extensions)};

        tls_extensions exts{exts_data.data, exts_data.data_end};

        char buffer1[200];
        struct buffer_stream buf1(buffer1, sizeof(buffer1));

        exts.fingerprint_quic_tls(buf1, tls_role::client);

        if (memcmp(expected_json_format1, buf1.dstr, sizeof(expected_json_format1) - 1)) {
            fprintf(stdout, "Test for fingerprint format1 failed\n");
            return false;
        }

        char buffer2[200];
        struct buffer_stream buf2(buffer2, sizeof(buffer2));

        exts.fingerprint_format2(buf2, tls_role::client);
        if (memcmp(expected_json_format2, buf2.dstr, sizeof(expected_json_format2) - 1)) {
            fprintf(stdout, "Test for Fingerprint format 2 failed\n");
            return false;
        }

        return true;

    }
#endif //NDEBUG
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
    static inline bool output_raw_features = false;
    static void set_raw_features(bool value) { output_raw_features = value; }

    tls_client_hello() { }

    tls_client_hello(datum &p) { parse(p); }

    void parse(datum &p);

    bool is_not_empty() const { return compression_methods.is_not_empty(); };

    void fingerprint(struct buffer_stream &buf, size_t format_version=0) const;

    void compute_fingerprint(class fingerprint &fp, size_t format_version=0) const;

    static void write_json(struct datum &data, struct json_object &record, bool output_metadata);

    void write_json(struct json_object &record, bool output_metadata) const;

    void write_raw_features(writeable &buf) const;

    bool is_faketls() const;

    bool do_analysis(const struct key &k_, struct analysis_context &analysis_, classifier *c);

    bool do_network_behavioral_detections(const struct key &k_, struct analysis_context &analysis_, classifier *c, struct common_data &nbd_common);

    static bool check_residential_proxy(const struct key &k_, datum random_nonce);

    static constexpr mask_and_value<8> matcher{
        { 0xff, 0xff, 0xfc, 0x00, 0x00, 0xff, 0x00, 0x00 },
        { 0x16, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 }
    };

    void reset() {
        protocol_version.set_null();
        random.set_null();
        session_id.set_null();
        cookie.set_null();
        ciphersuite_vector.set_null();
        compression_methods.set_null();
        extensions.set_null();
        dtls = false;
        is_quic_hello = false;
        additional_bytes_needed = 0;
    }

    void write_l7_metadata(cbor_object &o, bool metadata) {
        if (metadata) {
            cbor_array protocols{o, "protocols"};
            protocols.print_string("tls");
            protocols.close();
        }

        cbor_object tls{o, "tls"};
        cbor_object tls_client{tls, "client"};
        tls_client.print_key_hex("random", random);
        extensions.write_l7_metadata(tls_client);
        tls_client.close();
        tls.close();
     }

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

    bool is_not_empty() const {
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

    void write_l7_metadata(cbor_object &o, bool) {
        cbor_array protocols{o, "protocols"};
        protocols.print_string("tls");
        protocols.close();
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

    const tls_server_hello & get_server_hello() const { return hello; }
};


//   ClientKeyExchange, following RFC 5246 Section 7.4.7
//
//   struct {
//       select (KeyExchangeAlgorithm) {
//           case rsa:
//               EncryptedPreMasterSecret;
//           case dhe_dss:
//           case dhe_rsa:
//           case dh_dss:
//           case dh_rsa:
//           case dh_anon:
//               ClientDiffieHellmanPublic;
//       } exchange_keys;
//   } ClientKeyExchange;

// enum { dhe_dss, dhe_rsa, dh_anon, rsa, dh_dss, dh_rsa
//     /* may be extended, e.g., for ECDH -- see [TLSECC] */
// } KeyExchangeAlgorithm;


enum role {
    client,
    server,
    undetected
};

class tls_certificate : public base_protocol {
    struct tls_server_certificate certificate;
    role entity;

public:

    tls_certificate(struct datum &pkt, struct tcp_packet *tcp_pkt) : certificate{}, entity{undetected} {
        parse(pkt, tcp_pkt);
    }

    void parse(struct datum &pkt, struct tcp_packet *tcp_pkt) {

        // parse certificate
        //
        struct tls_record rec{pkt};
        struct tls_handshake handshake{rec.fragment};
        if (handshake.msg_type == handshake_type::certificate) {
            certificate.parse(handshake.body);

            if (rec.fragment.is_not_empty()) {
                tls_handshake handshake{rec.fragment};
                if (handshake.msg_type == handshake_type::client_key_exchange) {
                    entity = client;
                } else if (handshake.msg_type == handshake_type::server_key_exchange) {
                    entity = server;
                }
            } else if (pkt.is_not_empty()) {
                tls_record rec2{pkt};
                tls_handshake handshake{rec2.fragment};
                if (handshake.msg_type == handshake_type::client_key_exchange) {
                    entity = client;
                } else if (handshake.msg_type == handshake_type::server_key_exchange) {
                    entity = server;
                }
            }

        }
        if (tcp_pkt && certificate.additional_bytes_needed) {
            tcp_pkt->reassembly_needed(certificate.additional_bytes_needed);
        }
    }

    bool is_not_empty() {
        return certificate.is_not_empty();
    }

    void write_json(struct json_object &record, bool metadata_output, bool certs_json_output) {
        (void)metadata_output;

        bool have_certificate = certificate.is_not_empty();
        if (have_certificate) {

            // output certificate
            //
            const char *role = "undetermined";
            if (entity == client) {
                role = "client";
            } else if (entity == server) {
                role = "server";
            }
            struct json_object tls{record, "tls"};
            json_object client_or_server{tls, role};
            struct json_array certs{client_or_server, "certs"};
            certificate.write_json(certs, certs_json_output);
            certs.close();
            client_or_server.close();
            tls.close();

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

    [[maybe_unused]] int tls_server_hello_and_certificate_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum pkt_data{data1, data1+size1};
        datum tcp_data{data2, data2+size2};
        tcp_packet tcp_pkt{tcp_data};

        char buffer_1[8192];
        struct buffer_stream buf_json(buffer_1, sizeof(buffer_1));
        char buffer_2[8192];
        struct buffer_stream buf_fp(buffer_2, sizeof(buffer_2));
        struct json_object record(&buf_json);

        tls_server_hello_and_certificate hello{pkt_data, &tcp_pkt};
        if (hello.is_not_empty()) {
            hello.write_json(record, true, true);
            hello.fingerprint(buf_fp);
        }

        return 0;
    }

}; //end of namespace


inline bool is_faketls_util(const datum ciphersuite_vector) {
    size_t len = ciphersuite_vector.length();

    if (len % 2) {
        len--;    // forces length to be a multiple of 2
    }

    uint16_t *x = (uint16_t *)ciphersuite_vector.data;
    uint16_t *x_end = x + (len/2);

    size_t invalid_ciphers = 0;

    while (x < x_end) {
        uint16_t tmp = hton(degrease_uint16(*x++));
        if (tls::cipher_suites_list.find(tmp) != tls::cipher_suites_list.end())    // cipher suite found in IANA list
            continue;
        else if (tls::faketls_cipher_suite_exceptions.find(tmp) == tls::faketls_cipher_suite_exceptions.end())    // cipher suite not found in IANA and exception list
            invalid_ciphers++;
    }

    // flag for faketls only when all the cipher suites used are outside of IANA/exception list
    //
    if (invalid_ciphers == len/2) {
        return true;
    }

    return false;
}


/* TLS Constants */

#define L_ContentType              1
#define L_ProtocolVersion          2
#define L_RecordLength             2
#define L_HandshakeType            1
#define L_HandshakeLength          3
#define L_ProtocolVersion          2
#define L_Random                  32
#define L_SessionIDLength          1
#define L_CipherSuiteVectorLength  2
#define L_CompressionMethodsLength 1
#define L_ExtensionsVectorLength   2
#define L_ExtensionType            2
#define L_ExtensionLength          2

#define L_NamedGroupListLen        2
#define L_ProtocolVersionListLen   1

/*
 * field lengths used in serverHello parsing
 */
#define L_CipherSuite              2
#define L_CompressionMethod        1
#define L_CertificateLength        3
#define L_CertificateListLength    3

/*
 * expanded set of static extensions
 */
#define num_static_extension_types 20

/*
 * extension types used in normalization
 */
#define type_sni                             0x0000
#define type_supported_groups                0x000a
#define type_alpn                            0x0010
#define type_supported_versions              0x002b
#define type_session_ticket                  0x0023
#define type_quic_transport_parameters       0x0039
#define type_quic_transport_parameters_draft 0xffa5

#define type_ech_client_hello                0xfe0d

static uint16_t static_extension_types[num_static_extension_types] = {
        1,         /* max fragment length                    */
        5,         /* status_request                         */
        7,         /* client authz                           */
        8,         /* server authz                           */
        9,         /* cert type                              */
        10,        /* supported_groups                       */
        11,        /* ec_point_formats                       */
        13,        /* signature_algorithms                   */
        15,        /* heartbeat                              */
        16,        /* application_layer_protocol_negotiation */
        17,        /* status request v2                      */
        24,        /* token binding                          */
        27,        /* compressed certificate                 */
        28,        /* record size limit                      */
        type_quic_transport_parameters,
        43,        /* supported_versions                     */
        45,        /* psk_key_exchange_modes                 */
        50,        /* signature algorithms cert              */
        21760,     /* token binding (old)                    */
        type_quic_transport_parameters_draft
    };

inline void tls_extensions::print(struct json_object &o, const char *key) const {

    struct datum ext_parser{this->data, this->data_end};

    struct json_array array{o, key};

    while (ext_parser.length() > 0) {
        uint64_t tmp_len = 0;
        uint64_t tmp_type;

        const uint8_t *data = ext_parser.data;
        if (ext_parser.read_uint(&tmp_type, L_ExtensionType) == false) {
            break;
        }
        if (ext_parser.read_uint(&tmp_len, L_ExtensionLength) == false) {
            break;
        }
        if (ext_parser.skip(tmp_len) == false) {
            break;
        }

        struct datum ext{data, ext_parser.data};
        array.print_hex(ext);

    }

    array.close();
}

inline datum tls_extensions::get_server_name() const {

    struct datum ext_parser{this->data, this->data_end};

    while (ext_parser.length() > 0) {
        uint64_t tmp_len = 0;
        uint64_t tmp_type;

        const uint8_t *data = ext_parser.data;
        if (ext_parser.read_uint(&tmp_type, L_ExtensionType) == false) {
            break;
        }
        if (ext_parser.read_uint(&tmp_len, L_ExtensionLength) == false) {
            break;
        }
        if (ext_parser.skip(tmp_len) == false) {
            break;
        }
        const uint8_t *data_end = ext_parser.data;

        if (tmp_type == type_sni) {
            struct datum ext{data, data_end};
            ext.skip(SNI_HDR_LEN);
            return ext;
        }
    }
    return datum{nullptr, nullptr};

}

inline void tls_extensions::print_server_name(struct json_object &o, const char *key) const {
    datum server_name = get_server_name();
    o.print_key_json_string(key, server_name);
}

inline datum tls_extensions::get_supported_groups() const {

    datum ext_parser{this->data, this->data_end};

    while (ext_parser.length() > 0) {
        uint64_t tmp_len = 0;
        uint64_t tmp_type;

        const uint8_t *data = ext_parser.data;
        if (ext_parser.read_uint(&tmp_type, L_ExtensionType) == false) {
            break;
        }
        if (ext_parser.read_uint(&tmp_len, L_ExtensionLength) == false) {
            break;
        }
        if (ext_parser.skip(tmp_len) == false) {
            break;
        }
        const uint8_t *data_end = ext_parser.data;

        if (tmp_type == type_supported_groups) {
            return datum{data, data_end};
        }
    }
    return { nullptr, nullptr };
}


//   Application Layer Protocol Negotiation (following RFC 7301)
//
//   enum {
//       application_layer_protocol_negotiation(16), (65535)
//   } ExtensionType;
//
//   The "extension_data" field of the
//   ("application_layer_protocol_negotiation(16)") extension SHALL
//   contain a "ProtocolNameList" value.
//
//   opaque ProtocolName<1..2^8-1>;
//
//   struct {
//       ProtocolName protocol_name_list<2..2^16-1>
//   } ProtocolNameList;
//
//   "ProtocolNameList" contains the list of protocols advertised by the
//   client, in descending order of preference.  Protocols are named by
//   IANA-registered, opaque, non-empty byte strings, as described further
//   in Section 6 ("IANA Considerations") of this document.  Empty strings
//   MUST NOT be included and byte strings MUST NOT be truncated.
//
//

class protocol_name : public datum {
public:
    protocol_name(datum &d) {
        uint8_t length = 0;
        d.read_uint8(&length);
        parse(d, length);
    }

    bool is_grease() const {
        if (length() != 2) {
            return false;
        }
        if (data[0] == data[1] and (data[0] & 0x0f) == 0x0a) {
            return true;
        }
        return false;
    }

    void write_json(json_array &a) const {
        if (is_grease()) {
            a.print_string("\\n\\n");  // print json-escaped CR
        } else {
            a.print_json_string(*this);
        }
    }

};

class protocol_name_list {
    datum data;

public:

    protocol_name_list(datum &d) {
        uint16_t length;
        d.read_uint16(&length);
        data.parse(d, length);
    }

    datum get_data() const {
        return data;
    }


    // write ALPN strings into an array inside the json_object \param
    // o, normalizing all GREASE values to hexadecimal 0a0a ("\n\n")
    //
    void write_json(json_object &o, const char *key) {
        json_array alpn_array{o, key};
        while (data.is_not_empty()) {
            protocol_name name{data};
            name.write_json(alpn_array);
        }
        alpn_array.close();
    }
};

inline void tls_extensions::print_alpn(struct json_object &o, const char *key) const {

    struct datum ext_parser{this->data, this->data_end};

    while (ext_parser.length() > 0) {
        uint64_t tmp_len = 0;
        uint64_t tmp_type;

        const uint8_t *data = ext_parser.data;
        if (ext_parser.read_uint(&tmp_type, L_ExtensionType) == false) {
            break;
        }
        if (ext_parser.read_uint(&tmp_len, L_ExtensionLength) == false) {
            break;
        }
        if (ext_parser.skip(tmp_len) == false) {
            break;
        }
        const uint8_t *data_end = ext_parser.data;

        if (tmp_type == type_alpn) {
            struct datum ext{data, data_end};
            ext.skip(L_ExtensionType + L_ExtensionLength);
            protocol_name_list pnl{ext};
            pnl.write_json(o, key);
        }
    }
}

#define type_quic_user_agent 0x3129

// quic_transport_parameters are carried in a TLS extension; see
// https://datatracker.ietf.org/doc/html/rfc9000#section-18 and
// https://www.iana.org/assignments/quic/quic.xhtml#quic-transport
//
//   Transport Parameter {
//     Transport Parameter ID (i),
//     Transport Parameter Length (i),
//     Transport Parameter Value (..),
//   }
//
class quic_transport_parameter {
    variable_length_integer_datum _id;
    variable_length_integer _length;
    datum _value;

public:

    quic_transport_parameter(datum &d) : _id{d}, _length{d}, _value{d, (ssize_t)_length.value()} { }

    bool is_not_empty() const {
        return _value.is_not_null(); // note: zero-length value is possible
    }

    void write_id(buffer_stream &b) const {
        if (!_id.is_grease()) {
            _id.write(b);
        } else {
            // write out the smallest GREASE value (0x1b == 27)
            b.write_char('1');
            b.write_char('b');
        }
    }
    variable_length_integer_datum get_id() const { return _id; }
    datum  get_value() const { return _value; }

};

inline void tls_extensions::print_quic_transport_parameters(struct json_object &o, const char *key) const {

    struct datum ext_parser{this->data, this->data_end};

    while (ext_parser.length() > 0) {
        uint64_t tmp_len = 0;
        uint64_t tmp_type;

        const uint8_t *data = ext_parser.data;
        if (ext_parser.read_uint(&tmp_type, L_ExtensionType) == false) {
            break;
        }
        if (ext_parser.read_uint(&tmp_len, L_ExtensionLength) == false) {
            break;
        }
        if (ext_parser.skip(tmp_len) == false) {
            break;
        }
        const uint8_t *data_end = ext_parser.data;

        if (tmp_type == type_quic_transport_parameters) {
            struct datum ext{data, data_end};
            o.print_key_hex(key, ext);

            // print user_agent, if there is one in the quic transport parameters
            //
            ext.skip(4);   // skip extension type and length
            while (ext.length() > 0) {
                quic_transport_parameter qtp(ext);
                if (qtp.get_id().value() == type_quic_user_agent) {
                    o.print_key_json_string("google_user_agent", qtp.get_value());
                }
            }

        } else if (tmp_type == type_quic_transport_parameters_draft) {
            struct datum ext{data, data_end};
            o.print_key_hex("quic_transport_parameters_draft", ext);

            // print user_agent, if there is one in the quic transport parameters
            //
            ext.skip(4);   // skip extension type and length
            while (ext.length() > 0) {
                quic_transport_parameter qtp(ext);
                if (qtp.get_id().value() == type_quic_user_agent) {
                    o.print_key_json_string("google_user_agent", qtp.get_value());
                }
            }
        }
    }

}

inline void tls_extensions::set_meta_data(struct datum &server_name,
                                   struct datum &user_agent,
                                   //std::vector<std::string>& alpn
                                   datum &alpn
                                   ) const {

    struct datum ext_parser{this->data, this->data_end};

    while (ext_parser.length() > 0) {
        uint64_t tmp_len = 0;
        uint64_t tmp_type;

        const uint8_t *data = ext_parser.data;
        if (ext_parser.read_uint(&tmp_type, L_ExtensionType) == false) {
            break;
        }
        if (ext_parser.read_uint(&tmp_len, L_ExtensionLength) == false) {
            break;
        }
        if (ext_parser.skip(tmp_len) == false) {
            break;
        }
        const uint8_t *data_end = ext_parser.data;

        if (tmp_type == type_sni) {
            struct datum ext{data, data_end};
            ext.skip(SNI_HDR_LEN);
            server_name = ext;
        }

        if (tmp_type == type_quic_transport_parameters_draft) {
            struct datum ext{data, data_end};
            ext.skip(4);    // skip extension type and length
            while (ext.length() > 0) {
                quic_transport_parameter qtp(ext);
                if (qtp.get_id().value() == type_quic_user_agent) {
                    user_agent = qtp.get_value();
                }
            }
        }

        if (tmp_type == type_alpn) {
            struct datum ext{data, data_end};
            ext.skip(L_ExtensionType + L_ExtensionLength);
            protocol_name_list pnl{ext};
            alpn = pnl.get_data();
            // datum data = pnl.get_data();
            // while (data.is_not_empty()) {
            //     protocol_name name{data};
            //     alpn.push_back(name.get_string());
            // }
        }

    }
}

struct tls_extension {
    uint16_t type;
    uint16_t length;
    struct datum value;
    const uint8_t *type_ptr;
    const uint8_t *length_ptr;
    uint16_t cnt; //No.of extensions of the same type
    uint16_t encoded_type;

    tls_extension() : type{0}, length{0}, value{NULL, NULL}, type_ptr{NULL}, length_ptr{NULL}, cnt{0} { }

    tls_extension(struct datum &p) : type{0}, length{0}, value{NULL, NULL}, type_ptr{NULL}, length_ptr{NULL}, cnt{0} {

        type_ptr = p.data;
        if (p.read_uint16(&type) == false) { return; }
        length_ptr = p.data;
        if (p.read_uint16(&length) == false) { return; }
        if (length <= p.length()) {
            value.data = p.data;
            value.data_end = value.data + length;
            p.data += length;
        }

        // Initialize with degreased extension
        if (is_grease()) {
            encoded_type = 0x0a0a;
        } else {
            encoded_type = type;
        }
    }

    bool is_not_empty() { return value.is_not_empty(); }

    bool is_grease() const {
        return ((type & 0x0f0f) == 0x0a0a);
    }

    bool is_private_extension() const {
        return((type == 65280) || (type >= 65282));
    }

    bool is_unassigned_extension() const {
        return (type >=62 && type <= 65279 && !is_grease());
    }


    void fingerprint_format1(struct buffer_stream &b, enum tls_role role) {
        if (uint16_match(type, static_extension_types, num_static_extension_types) == true) {
            if (type == type_supported_groups) {
                // fprintf(stderr, "I am degreasing supported groups\n");
                b.write_char('(');
                b.write_hex_uint(encoded_type);
                write_length(b);
                write_degreased_value(b, L_NamedGroupListLen);
                b.write_char(')');

            } else if (type == type_supported_versions) {
                // fprintf(stderr, "I am degreasing supported versions\n");
                b.write_char('(');
                b.write_hex_uint(encoded_type);
                write_length(b);
                if (role == tls_role::client) {
                    write_degreased_value(b, L_ProtocolVersionListLen);
                } else {
                    write_degreased_value(b, 0);
                }
                b.write_char(')');

            } else if (type == type_quic_transport_parameters || type == type_quic_transport_parameters_draft) {
                b.write_char('(');
                b.write_char('(');
                b.write_hex_uint(encoded_type);
                b.write_char(')');

                // sort quic transport parameter ids, then write them
                // into the fingerprint
                //
                std::vector<variable_length_integer_datum> id_vector;
                while (value.is_not_null()) {
                    quic_transport_parameter qtp{value};
                    if (qtp.is_not_empty()) {
                        id_vector.push_back(qtp.get_id());
                    }
                }
                std::sort(id_vector.begin(),
                          id_vector.end(),
                          [](const variable_length_integer_datum &a, const variable_length_integer_datum &b) {
                              if (a.is_grease()) {
                                  if (b.is_grease()) {
                                      return false;
                                  }
                                  return 0x1b < b.value();
                              } else if (b.is_grease()) {
                                  return a.value() < 0x1b;
                              }
                              return a.cmp(b) < 0;
                          }
                          );
                b.write_char('[');
                for (const auto &id : id_vector) {
                    b.write_char('(');
                    if (!id.is_grease()) {
                        id.write(b);
                    } else {
                        // write out the smallest GREASE value (0x1b == 27)
                        b.write_char('1');
                        b.write_char('b');
                    }
                    b.write_char(')');
                }
                b.write_char(']');
                b.write_char(')');


            } else {
                b.write_char('(');
                b.write_hex_uint(encoded_type);
                write_length(b);
                write_value(b);
                b.write_char(')');
            }
        } else {
            b.write_char('(');
            b.write_hex_uint(encoded_type);
            b.write_char(')');
        }

    }

    void write_degreased_type(struct buffer_stream &b) const {
        if (type_ptr) {
            raw_as_hex_degrease(b, type_ptr, sizeof(uint16_t));
        }
    }

    void write_length(struct buffer_stream &b) const {
        if (length_ptr) {
            raw_as_hex_degrease(b, length_ptr, sizeof(uint16_t));
        }
    }
    void write_degreased_value(struct buffer_stream &b, ssize_t ungreased_len) const {
        if (value.is_not_empty()) {
            size_t skip_len;
            size_t greased_len;
            if (ungreased_len < value.length()) {
                skip_len = ungreased_len;
                greased_len = value.length() - ungreased_len;
            } else {
                skip_len = value.length();
                greased_len = 0;
            }
            b.raw_as_hex(value.data, skip_len);
            raw_as_hex_degrease(b, value.data + skip_len, greased_len);
        }
    }
    void write_value(struct buffer_stream &b) const {
        if (value.is_not_empty()) {
            b.raw_as_hex(value.data, value.length());
        }
    }

    void write_raw_features(writeable &buf, bool &first) const {
        if (!first) {
            buf.copy(',');
        } else {
            first = false;
        }

        buf.copy('[');
        buf.write_quote_enclosed_hex(type_ptr, sizeof(type));
        buf.copy(',');
        buf.write_quote_enclosed_hex(value);
        buf.copy(']');
    }

};

inline void tls_extensions::fingerprint(struct buffer_stream &b, enum tls_role role) const {

    struct datum ext_parser{this->data, this->data_end};
    b.write_char('(');
    while (ext_parser.length() > 0) {

        tls_extension x{ext_parser};
        if (x.value.data == NULL) {
            break;
        }
        if (uint16_match(x.type, static_extension_types, num_static_extension_types) == true) {
            if (x.type == type_supported_groups) {
                // fprintf(stderr, "I am degreasing supported groups\n");
                b.write_char('(');
                x.write_degreased_type(b);
                x.write_length(b);
                x.write_degreased_value(b, L_NamedGroupListLen);
                b.write_char(')');

            } else if (x.type == type_supported_versions) {
                // fprintf(stderr, "I am degreasing supported versions\n");
                b.write_char('(');
                x.write_degreased_type(b);
                x.write_length(b);
                if (role == tls_role::client) {
                    x.write_degreased_value(b, L_ProtocolVersionListLen);
                } else {
                    x.write_degreased_value(b, 0);
                }
                b.write_char(')');

            } else if (x.type == type_quic_transport_parameters || x.type == type_quic_transport_parameters_draft) {
                b.write_char('(');
                b.write_char('(');
                x.write_degreased_type(b);
                b.write_char(')');

                // loop over quic transport parameters, write each type code
                //
                b.write_char('(');
                while (x.value.is_not_null()) {
                    quic_transport_parameter qtp{x.value};
                    if (qtp.is_not_empty()) {
                        b.write_char('(');
                        qtp.write_id(b);
                        b.write_char(')');
                    }
                }
                b.write_char(')');
                b.write_char(')');

            } else {
                b.write_char('(');
                x.write_degreased_type(b);
                x.write_length(b);
                x.write_value(b);
                b.write_char(')');
            }
        } else {
            b.write_char('(');
            x.write_degreased_type(b);
            b.write_char(')');
        }

    }
    b.write_char(')');

}

inline void tls_extensions::fingerprint_quic_tls(struct buffer_stream &b, enum tls_role role) const {

    struct datum ext_parser{this->data, this->data_end};

    std::vector<tls_extension> tls_ext_vec;

    // push all extensions for sorting
    //
    while (ext_parser.length() > 0) {

        tls_extension x{ext_parser};
        if (x.value.data == NULL) {
            break;
        }

        tls_ext_vec.push_back(x);
    }

    //sort extensions based on type and memcmp in case of same type
    std::sort(tls_ext_vec.begin(),tls_ext_vec.end(),
              [](const tls_extension &a, const tls_extension &b) {
                  if (a.is_grease()) {
                      if (b.is_grease()) {
                          return false;
                      }
                      return 0x0a0a < b.type;
                      } else if (b.is_grease()) {
                          return a.type < 0x0a0a;
                      }
                  if (a.type != b.type) {
                      return a.type < b.type;
                  }
                  if (a.length != b.length) {
                      return a.length < b.length;
                  }
                  return a.value.cmp(b.value) < 0;
              }
              );

    b.write_char('[');
    for (auto &x : tls_ext_vec) {
        x.fingerprint_format1(b, role);
    }
    b.write_char(']');
}

inline void tls_extensions::fingerprint_format2(struct buffer_stream &b, enum tls_role role) const {

    struct datum ext_parser{this->data, this->data_end};
    std::array<std::array<tls_extension, tls_extensions::max_repeat_extensions>, tls_extensions_assign::include_list_len> extensions_list;

    int32_t index = -1;

    // Store the sorted index of all extensions

    while (ext_parser.length() > 0) {

        tls_extension x{ext_parser};
        if (x.value.data == NULL) {
            break;
        }

        index = tls_extensions_assign::get_index(x.type);

        if (index == -1) {
            if (x.is_private_extension()) {
                // Unknown private extensions will be encoded as the
                // smallest extension in private extension range
                x.encoded_type = tls_extensions_assign::smallest_private_extn;
            } else if (x.is_unassigned_extension()) {
                // Unknown unassigned extensions will be encoded as the
                // smallest extension in the unassigned range
                x.encoded_type = tls_extensions_assign::smallest_unassigned_extn;
            }
            index = tls_extensions_assign::get_index(x.encoded_type);
        }

        if (index >= 0) {
            int cnt = extensions_list[index][0].cnt;

            if (cnt < tls_extensions::max_repeat_extensions) {
                extensions_list[index][cnt] = x;
                extensions_list[index][0].cnt++;
            }
        }
    }

    b.write_char('[');
    for (int extn = 0; extn < tls_extensions_assign::include_list_len; extn++) {
        uint8_t extn_cnt = extensions_list[extn][0].cnt;
        if (extn_cnt > 1) {
            std::sort(extensions_list[extn].begin(), extensions_list[extn].begin() + extensions_list[extn][0].cnt,
              [](const tls_extension &a, const tls_extension &b) {
                if (a.is_grease()) {
                    if (b.is_grease()) {
                        return false;
                    }
                    return 0x0a0a < b.type;
                } else if (b.is_grease()) {
                    return a.type < 0x0a0a;
                }
                if (a.length != b.length) {
                    return a.length < b.length;
                }
                return a.value.cmp(b.value) < 0;
            }
            );
        }
        for (int count = 0; count < extn_cnt; count++) {
            tls_extension &x = extensions_list[extn][count];
            x.fingerprint_format1(b, role);
        }
    }
   b.write_char(']');
}

inline void tls_extensions::write_raw_features(writeable &buf) const {
    buf.copy('[');
    struct datum ext_parser{this->data, this->data_end};
    bool first_extension = true;
    while (ext_parser.length() > 0) {
        tls_extension x{ext_parser};
        x.write_raw_features(buf, first_extension);
    }
    buf.copy(']');
}

inline void tls_extensions::print_session_ticket(struct json_object &o, const char *key) const {

    struct datum ext_parser{this->data, this->data_end};

    while (ext_parser.length() > 0) {
        uint64_t tmp_len = 0;
        uint64_t tmp_type;

        const uint8_t *data = ext_parser.data;
        if (ext_parser.read_uint(&tmp_type, L_ExtensionType) == false) {
            break;
        }
        if (ext_parser.read_uint(&tmp_len, L_ExtensionLength) == false) {
            break;
        }
        if (ext_parser.skip(tmp_len) == false) {
            break;
        }

        if (tmp_type == type_session_ticket) {

            // possible format, as per https://tools.ietf.org/html/rfc5077#section-4
            //
            // struct {
            //    opaque key_name[16];
            //    opaque iv[16];
            //    opaque encrypted_state<0..2^16-1>;
            //    opaque mac[32];
            // } ticket;

            struct datum ext{data + L_ExtensionType + L_ExtensionLength, ext_parser.data};
            o.print_key_hex(key, ext);
        }
    }

}

inline void tls_extensions::print_ech_client_hello(struct json_object &o) const {

    struct datum ext_parser{this->data, this->data_end};

    while (ext_parser.length() > 0) {
        uint64_t tmp_len = 0;
        uint64_t tmp_type;

        const uint8_t *data = ext_parser.data;
        if (ext_parser.read_uint(&tmp_type, L_ExtensionType) == false) {
            break;
        }
        if (ext_parser.read_uint(&tmp_len, L_ExtensionLength) == false) {
            break;
        }
        if (ext_parser.skip(tmp_len) == false) {
            break;
        }

        if (tmp_type == type_ech_client_hello) {
            struct datum ext{data + L_ExtensionType + L_ExtensionLength, ext_parser.data};
            ech_client_hello{ext}.write_json(o);
        }
    }

}

#define L_DTLSCookieLength             1

inline void tls_client_hello::parse(struct datum &p) {
    uint64_t tmp_len;

    mercury_debug("%s: processing packet\n", __func__);

    // parse clientHello.ProtocolVersion
    protocol_version.parse(p, L_ProtocolVersion);
    if (protocol_version.is_not_readable()) {
        return;
    }

    // determine if this is DTLS or plain old TLS
    if (protocol_version.data[0] == 0xfe) {
        dtls = true;
    }

    // parse clientHello.Random
    random.parse(p, L_Random);

    // parse SessionID
    if (p.read_uint(&tmp_len, L_SessionIDLength) == false) {
        return;
    }
    session_id.parse(p, tmp_len);

    if (dtls) {
        // skip over Cookie and CookieLen
        if (p.lookahead_uint(L_DTLSCookieLength, &tmp_len) == false) {
            return;
        }
        if (p.skip(tmp_len + L_DTLSCookieLength) == false) {
            return;
        }
    }

    // parse clientHello.Ciphersuites
    if (p.read_uint(&tmp_len, L_CipherSuiteVectorLength) == false) {
        return;
    }
    if (tmp_len & 1) {
        return;  // not a valid ciphersuite vector length
    }
    ciphersuite_vector.parse(p, tmp_len);

    // parse compression methods
    if (p.read_uint(&tmp_len, L_CompressionMethodsLength) == false) {
        return;
    }
    compression_methods.parse(p, tmp_len);

    // parse extensions vector
    if (p.read_uint(&tmp_len, L_ExtensionsVectorLength) == false) {
        return;
    }
    extensions.parse_soft_fail(p, tmp_len);

    return;

}

inline void tls_client_hello::write_raw_features(writeable &buf) const {
    buf.copy('[');
    buf.write_quote_enclosed_hex(protocol_version);
    buf.copy(',');
    buf.write_quote_enclosed_hex(ciphersuite_vector);
    buf.copy(',');
    extensions.write_raw_features(buf);
    buf.copy(']');
}


inline void tls_client_hello::write_json(struct json_object &record, bool output_metadata) const {
    if (ciphersuite_vector.is_not_readable()) {
        return;
    }
    const char *label = "tls";
    if (dtls) {
        label = "dtls";
    }
    struct json_object tls{record, label};
    struct json_object tls_client{tls, "client"};
    if (output_metadata) {
        tls_client.print_key_hex("version", protocol_version);
        tls_client.print_key_hex("random", random);
        tls_client.print_key_hex("session_id", session_id);
        tls_client.print_key_hex("cipher_suites", ciphersuite_vector);
        tls_client.print_key_hex("compression_methods", compression_methods);
        //tls.print_key_hex("extensions", hello.extensions);
        //hello.extensions.print(tls, "extensions");
    }
    extensions.print_server_name(tls_client, "server_name");
    extensions.print_quic_transport_parameters(tls_client, "quic_transport_parameters");
    if (output_metadata) {
        extensions.print_alpn(tls_client, "application_layer_protocol_negotiation");
        extensions.print_session_ticket(tls_client, "session_ticket");
        extensions.print_ech_client_hello(tls_client);
    }

    if (output_raw_features) {
        data_buffer<4096> buf;
        write_raw_features(buf);
        tls_client.print_key_json_string("features", buf.contents());
    }

    tls_client.close();
    tls.close();
}

// static function
//
inline void tls_client_hello::write_json(struct datum &data, struct json_object &record, bool output_metadata) {
    struct tls_record rec{data};
    struct tls_handshake handshake{rec.fragment};
    struct tls_client_hello hello{handshake.body};
    hello.write_json(record, output_metadata);
}

inline void tls_client_hello::fingerprint(struct buffer_stream &buf, size_t format_version) const {
    if (is_not_empty() == false) {
        return;
    }
    if (format_version == 0) {
        ;
    } else if (format_version >= 1 && format_version <= 2) {
        buf.write_uint8(format_version);
        buf.write_char('/');
    } else {
        return; // unsupported format version
    }

    /*
     * copy clientHello.ProtocolVersion
     */
    buf.write_char('(');
    buf.raw_as_hex(protocol_version.data, protocol_version.length());
    buf.write_char(')');

    /* copy ciphersuite offer vector */
    buf.write_char('(');
    raw_as_hex_degrease(buf, ciphersuite_vector.data, ciphersuite_vector.length());
    buf.write_char(')');

    /*
     * copy extensions vector
     */
    if (format_version == 0) {
        extensions.fingerprint(buf, tls_role::client);
    } else if (format_version == 1) {
        extensions.fingerprint_quic_tls(buf, tls_role::client);
    } else if (format_version == 2) {
        assert(tls_extensions::unit_test() == true);
        extensions.fingerprint_format2(buf, tls_role::client);
    }
}

inline void tls_client_hello::compute_fingerprint(class fingerprint &fp, size_t format_version) const {
    fp.set_type(fingerprint_type_tls);
    fp.add(*this, format_version);
    fp.final();
}

inline bool tls_client_hello::is_faketls() const {
    return is_faketls_util(ciphersuite_vector);
}


inline bool tls_client_hello::do_analysis(const struct key &k_, struct analysis_context &analysis_, classifier *c_) {
    datum sn;
    datum ua;
    datum alpn;

    extensions.set_meta_data(sn, ua, alpn);

    analysis_.destination.init(sn, ua, alpn, k_);
    if (c_ == nullptr) {
            return false;
    }

    bool ret = c_->analyze_fingerprint_and_destination_context(analysis_.fp, analysis_.destination, analysis_.result);

    if (analysis_.result.status == fingerprint_status_randomized) {    // check for faketls on randomized connections only
        if (!analysis_.result.attr.is_initialized() && c_) {
            analysis_.result.attr.initialize(&(c_->get_common_data().attr_name.value()),c_->get_common_data().attr_name.get_names_char());
        }
        if (is_faketls()) {
            analysis_.result.attr.set_attr(c_->get_common_data().faketls_idx, 1.0);
        }
    }

    return ret;
}


inline bool tls_client_hello::do_network_behavioral_detections(const struct key &k_, struct analysis_context &analysis_,
                                                               classifier *c_, struct common_data &nbd_common) {
    if (check_residential_proxy(k_, random)) {
        if (c_) {
            analysis_.result.attr.set_attr(c_->common.res_proxy_idx, 1.0);
            return true;
        } else if (nbd_common.res_proxy_idx != -1) {
            analysis_.result.attr.set_attr(nbd_common.res_proxy_idx, 1.0);
            return true;
        }
    }
    return false;
}


inline bool tls_client_hello::check_residential_proxy(const struct key &k_, datum random) {
    constexpr uint16_t max_nonce_entries = 1024;
    static uint16_t nonce_index = 0;
    static std::mutex res_proxy_mutex;
    static std::vector<std::array<uint8_t,L_Random>> current_nonces(max_nonce_entries);

    // Use a custom allocator for the unordered_map
    using nonce_map_allocator = fixed_fifo_allocator<std::pair<const std::array<uint8_t, L_Random>, uint32_t>, max_nonce_entries>;
    static std::unordered_map<
        std::array<uint8_t, L_Random>,
        uint32_t,
        std::hash<std::array<uint8_t, L_Random>>,
        std::equal_to<std::array<uint8_t, L_Random>>,
        nonce_map_allocator> nonce_ip_map(max_nonce_entries);
    std::array<uint8_t,L_Random> random_nonce;

    if (k_.ip_vers != 4) {
        return false; // only support ipv4 for now, need to update nonce_ip_map to support ipv6
    }

    // determine if IP addresses are internal/external
    bool is_src_ip_global = k_.src_is_global();
    bool is_dst_ip_global = k_.dst_is_global();

    //
    // check if src_ip is external and dst_ip is internal,
    //   and if so, start tracking random nonce
    if ((is_src_ip_global == true) && (is_dst_ip_global == false)) {
        if (random.length() != L_Random) {
            return false;
        }

        std::memcpy(random_nonce.data(), random.data, L_Random);
        std::lock_guard lock(res_proxy_mutex);

        auto nonce_iter = nonce_ip_map.find(random_nonce);
        if (nonce_iter != nonce_ip_map.end()) { // nonce collision
            return false;
        }


        if (nonce_ip_map.size() == max_nonce_entries) { // cache is full, delete oldest entry
            nonce_ip_map.erase(current_nonces[nonce_index]);
        }

        current_nonces[nonce_index] = random_nonce;
        nonce_index = (nonce_index + 1) % max_nonce_entries;
        nonce_ip_map.insert(nonce_iter, {random_nonce, (uint32_t)k_.addr.ipv4.dst});

        return false;
    }

    //
    // check if we have seen the random nonce before,
    //   and if so, check if the src_ip is internal and
    //   the dst_ip is external
    //
    if ((is_src_ip_global == false) && (is_dst_ip_global == true)) {
        if (random.length() != L_Random) {
            return false;
        }
        std::memcpy(random_nonce.data(), random.data, L_Random);
        std::lock_guard lock(res_proxy_mutex);

        auto nonce_iter = nonce_ip_map.find(random_nonce);
        if (nonce_iter == nonce_ip_map.end()) { // nonce not found
            return false;
        }
        if (nonce_iter->second == (uint32_t)k_.addr.ipv4.src) {
            return true;
        }
        return false;
    }

    return false;
}

inline void tls_server_hello::parse(struct datum &p) {
    mercury_debug("%s: processing packet with %td bytes\n", __func__, p.data_end - p.data);

    parse_tls_server_hello(p);

    return;

}

inline enum status tls_server_hello::parse_tls_server_hello(struct datum &record) {
    uint64_t tmp_len;

    mercury_debug("%s: processing server_hello with %td bytes\n", __func__, record.data_end - record.data);

    protocol_version.parse(record, L_ProtocolVersion);
    random.parse(record, L_Random);

    /* skip over SessionID and SessionIDLen */
    if (record.lookahead_uint(L_SessionIDLength, &tmp_len) == false) {
	    goto bail;
    }
    if (record.skip(tmp_len + L_SessionIDLength) == false) {
	    goto bail;
    }

    ciphersuite_vector.parse(record, L_CipherSuite);

    compression_method.parse(record, L_CompressionMethod);

    // parse extensions vector
    if (record.read_uint(&tmp_len, L_ExtensionsVectorLength) == false) {
        return status_ok;  // could differentiate between err/ok
    }
    extensions.parse(record, tmp_len);

    return status_ok;

 bail:
    return status_err;
}

inline void tls_server_hello::fingerprint(struct buffer_stream &buf) const {
    if (is_not_empty()) {

        /*
         * copy serverHello.ProtocolVersion
         */
        buf.write_char('(');
        buf.raw_as_hex(protocol_version.data, protocol_version.length());
        buf.write_char(')');

        /* copy ciphersuite offer vector */
        buf.write_char('(');
        buf.raw_as_hex(ciphersuite_vector.data, ciphersuite_vector.length());
        buf.write_char(')');

        /*
         * copy extensions vector
         */
        extensions.fingerprint(buf, tls_role::server);
    }
}

inline void tls_server_certificate::write_json(struct json_array &a, bool json_output) const {

    struct datum tmp_cert_list = certificate_list;
    while (tmp_cert_list.length() > 0) {

        /* get certificate length */
        uint64_t tmp_len;
        if (tmp_cert_list.read_uint(&tmp_len, L_CertificateLength) == false) {
            return;
        }

        if (tmp_len > (unsigned)tmp_cert_list.length()) {
            tmp_len = tmp_cert_list.length(); /* truncate */
        }

        if (tmp_len == 0) {
            return; /* don't bother printing out a partial cert if it has a length of zero */
        }

        struct json_object o{a};
        if (json_output) {
            struct json_object cert{o, "cert"};
            struct x509_cert c;
            c.parse(tmp_cert_list.data, tmp_len);
            c.print_as_json(cert, {}, NULL);
            cert.close();
        } else {
            struct datum cert_parser{tmp_cert_list.data, tmp_cert_list.data + tmp_len};
            o.print_key_base64("base64", cert_parser);
        }
        o.close();

        /*
         * advance parser over certificate data
         */
        if (tmp_cert_list.skip(tmp_len) == false) {
            return;
        }
    }
}


#endif /* TLS_H */
