/*
 * tls.c
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include "json_object.h"
#include "tls.h"
#include "match.h"
#include "x509.h"
#include "quic.h"
#include "fingerprint.h"
#include "tls_extensions.h"

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

void tls_extensions::print(struct json_object &o, const char *key) const {

    struct datum ext_parser{this->data, this->data_end};

    struct json_array array{o, key};

    while (ext_parser.length() > 0) {
        size_t tmp_len = 0;
        size_t tmp_type;

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

void tls_extensions::print_server_name(struct json_object &o, const char *key) const {

    struct datum ext_parser{this->data, this->data_end};

    while (ext_parser.length() > 0) {
        size_t tmp_len = 0;
        size_t tmp_type;

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
            //            tls.print_key_json_string("server_name", pf.x.packet_data.value + SNI_HDR_LEN, pf.x.packet_data.length - SNI_HDR_LEN);
            // o.print_key_json_string(key, ext.data + SNI_HDR_LEN, ext.length() - SNI_HDR_LEN);
            ext.skip(SNI_HDR_LEN);
            o.print_key_json_string(key, ext);
        }
    }

}

datum tls_extensions::get_supported_groups() const {

    datum ext_parser{this->data, this->data_end};

    while (ext_parser.length() > 0) {
        size_t tmp_len = 0;
        size_t tmp_type;

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

    void write_json(json_object &o, const char *key) {
        json_array alpn_array{o, key};
        while (data.is_not_empty()) {
            protocol_name name{data};
            alpn_array.print_json_string(name);
        }
        alpn_array.close();
    }
};

void tls_extensions::print_alpn(struct json_object &o, const char *key) const {

    struct datum ext_parser{this->data, this->data_end};

    while (ext_parser.length() > 0) {
        size_t tmp_len = 0;
        size_t tmp_type;

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

void tls_extensions::print_quic_transport_parameters(struct json_object &o, const char *key) const {

    struct datum ext_parser{this->data, this->data_end};

    while (ext_parser.length() > 0) {
        size_t tmp_len = 0;
        size_t tmp_type;

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

void tls_extensions::set_meta_data(struct datum &server_name,
                                   struct datum &user_agent,
                                   //std::vector<std::string>& alpn
                                   datum &alpn
                                   ) const {

    struct datum ext_parser{this->data, this->data_end};

    while (ext_parser.length() > 0) {
        size_t tmp_len = 0;
        size_t tmp_type;

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

        encoded_type = type;
    }

    bool is_not_empty() { return value.is_not_empty(); }

    bool is_grease() const { return degrease_uint16(type) == 0x0a0a;}

    void fingerprint_format1(struct buffer_stream &b, enum tls_role role, bool use_encoded_type = false) {
        uint16_t extension_type = type;
        if (use_encoded_type) {
            extension_type = encoded_type;
        }
        if (uint16_match(extension_type, static_extension_types, num_static_extension_types) == true) {
            if (extension_type == type_supported_groups) {
                // fprintf(stderr, "I am degreasing supported groups\n");
                b.write_char('(');
                b.write_hex_uint(extension_type);
                write_length(b);
                write_degreased_value(b, L_NamedGroupListLen);
                b.write_char(')');

            } else if (type == type_supported_versions) {
                // fprintf(stderr, "I am degreasing supported versions\n");
                b.write_char('(');
                b.write_hex_uint(extension_type);
                //write_degreased_type(b);
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
                b.write_hex_uint(extension_type);
                //write_degreased_type(b);
                b.write_char(')');

                // sort quic transport parameter ids, then write them
                // into the fingerprint
                //
                std::vector<variable_length_integer_datum> id_vector;
                while (value.is_not_null()) {
                    quic_transport_parameter qtp{value};
                    if (qtp.is_not_empty()) {
                        //b.write_char('(');
                        //qtp.write_id(b);
                        //b.write_char(')');
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
                b.write_hex_uint(extension_type);
                //write_degreased_type(b);
                write_length(b);
                write_value(b);
                b.write_char(')');
            }
        } else {
            b.write_char('(');
            b.write_hex_uint(extension_type);
            //write_degreased_type(b);
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

    void write_raw_features(writeable &buf) const {
        buf.copy('[');
        buf.write_quote_enclosed_hex(type_ptr, sizeof(type));
        buf.copy(',');
        buf.write_quote_enclosed_hex(value);
        buf.copy(']');
    }

};

void tls_extensions::fingerprint(struct buffer_stream &b, enum tls_role role) const {

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

void tls_extensions::fingerprint_quic_tls(struct buffer_stream &b, enum tls_role role) const {

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

void tls_extensions::fingerprint_format2(struct buffer_stream &b, enum tls_role role) const {

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
            if (x.is_grease()) {
                x.encoded_type = 0x0a0a;
            } else if (tls_extensions_assign::is_private_extension(x.type)) {
                // Unknown private extensions will be encoded as 65280,
                // which is the smallest extension in private extension range
                x.encoded_type = 65280;
            } else if (tls_extensions_assign::is_unassigned_extension(x.type)) {
                // Unknown unassigned extensions will be encoded as 61,
                // which is the smallest extension in the unassigned range
                x.encoded_type = 62;
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
            x.fingerprint_format1(b, role, true); 
        }
    }
   b.write_char(']'); 
}

void tls_extensions::write_raw_features(writeable &buf) const {
    buf.copy('[');
    struct datum ext_parser{this->data, this->data_end};
    bool first_extension = true;
    while (ext_parser.length() > 0) {
        if (!first_extension) {
            buf.copy(',');
        } else {
            first_extension = false;
        }
        tls_extension x{ext_parser};
        x.write_raw_features(buf);
    }
    buf.copy(']');
}

void tls_extensions::print_session_ticket(struct json_object &o, const char *key) const {

    struct datum ext_parser{this->data, this->data_end};

    while (ext_parser.length() > 0) {
        size_t tmp_len = 0;
        size_t tmp_type;

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

#define L_DTLSCookieLength             1

void tls_client_hello::parse(struct datum &p) {
    size_t tmp_len;

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
void tls_client_hello::write_raw_features(writeable &buf) const {
    buf.copy('[');
    buf.write_quote_enclosed_hex(protocol_version);
    buf.copy(',');
    buf.write_quote_enclosed_hex(ciphersuite_vector);
    buf.copy(',');
    extensions.write_raw_features(buf);
    buf.copy(']');
}
    

void tls_client_hello::write_json(struct json_object &record, bool output_metadata) const {
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
    }
    data_buffer<2048> buf;
    write_raw_features(buf);
    tls_client.print_key_json_string("features", buf.contents());
    tls_client.close();
    tls.close();
}

// static function
//
void tls_client_hello::write_json(struct datum &data, struct json_object &record, bool output_metadata) {
    struct tls_record rec{data};
    struct tls_handshake handshake{rec.fragment};
    struct tls_client_hello hello{handshake.body};
    hello.write_json(record, output_metadata);
}

void tls_client_hello::fingerprint(struct buffer_stream &buf, size_t format_version) const {
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

void tls_client_hello::compute_fingerprint(class fingerprint &fp, size_t format_version) const {
    fp.set_type(fingerprint_type_tls);
    fp.add(*this, format_version);
    fp.final();
}

bool tls_client_hello::do_analysis(const struct key &k_, struct analysis_context &analysis_, classifier *c_) {
    datum sn;
    datum ua;
    datum alpn;

    extensions.set_meta_data(sn, ua, alpn);

    analysis_.destination.init(sn, ua, alpn, k_);

    return c_->analyze_fingerprint_and_destination_context(analysis_.fp, analysis_.destination, analysis_.result);
}

void tls_server_hello::parse(struct datum &p) {
    mercury_debug("%s: processing packet with %td bytes\n", __func__, p.data_end - p.data);

    parse_tls_server_hello(p);

    return;

}

enum status tls_server_hello::parse_tls_server_hello(struct datum &record) {
    size_t tmp_len;

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

void tls_server_hello::fingerprint(struct buffer_stream &buf) const {
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

void tls_server_certificate::write_json(struct json_array &a, bool json_output) const {

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
            struct json_object_asn1 cert{o, "cert"};
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

