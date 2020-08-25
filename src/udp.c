/*
 * udp.c
 *
 * UDP protocol processing
 */


#include "extractor.h"
#include "proto_identify.h"
#include "ept.h"

#define VXLAN_PORT 4789
/*
 *  VXLAN Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |R|R|R|R|I|R|R|R|            Reserved                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                VXLAN Network Identifier (VNI) |   Reserved    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define VXLAN_HDR_LEN 8

unsigned int packet_filter_process_vxlan(struct packet_filter *pf, struct key *k) {
    struct parser *p = &pf->p;
    if (parser_skip(p, VXLAN_HDR_LEN) != status_ok) {
        return 0;
    }
    /*
     * note: we ignore the VXLAN Network Identifier for now, which
     * makes little difference as long as they are all identical
     */
    return packet_filter_process_packet(pf, k);
}


/* DTLS Client */
unsigned char dtls_client_hello_mask[] = {
    0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00
};

unsigned char dtls_client_hello_value[] = {
    0x16, 0xfe, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
};

struct pi_container dtls_client = {
    DIR_CLIENT,
    DTLS_PORT
};


/* DTLS Server */
unsigned char dtls_server_hello_mask[] = {
    0xff, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00
};

unsigned char dtls_server_hello_value[] = {
    0x16, 0xfe, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00
};

struct pi_container dtls_server = {
    DIR_SERVER,
    DTLS_PORT
};


/* dhcp client */
unsigned char dhcp_client_value[] = {
    0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00
};

unsigned char dhcp_client_mask[] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00
};

struct pi_container dhcp_client = {
    DIR_CLIENT,
    DHCP_CLIENT_PORT
};

/*
 * dns server
 */
unsigned char dns_server_mask[] = {
    0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff, 0x00
};
unsigned char dns_server_value[] = {
    0x00, 0x00, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00
};
struct pi_container dns_server = {
    DIR_SERVER,
    DNS_PORT
};

/*
 * wireguard
 */
unsigned char wireguard_mask[] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00
};
unsigned char wireguard_value[] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
struct pi_container wireguard = {
    DIR_CLIENT,
    WIREGUARD_PORT
};


const struct pi_container *proto_identify_udp(const uint8_t *udp_data,
                                              unsigned int len) {

    extractor_debug("%s: with length %u\n", __func__, len);

    if (len < sizeof(dhcp_client_mask)) {
        return NULL;
    }

    /* note: udp_data will be 32-bit aligned as per the standard */

    extractor_debug("%s: udp data: %02x%02x%02x%02x%02x%02x%02x%02x\n", __func__,
                    udp_data[0], udp_data[1], udp_data[2], udp_data[3], udp_data[4], udp_data[5], udp_data[6], udp_data[7]);

    if (u32_compare_masked_data_to_value(udp_data,
                                         dhcp_client_mask,
                                         dhcp_client_value)) {
        return &dhcp_client;
    }


    if (len < sizeof(dtls_client_hello_mask)) {
        return NULL;
    }

    if (u64_compare_masked_data_to_value(udp_data,
                                         dtls_client_hello_mask,
                                         dtls_client_hello_value)) {
        return &dtls_client;
    }
    if (u64_compare_masked_data_to_value(udp_data,
                                         dtls_server_hello_mask,
                                         dtls_server_hello_value)) {
        return &dtls_server;
    }
    if (u64_compare_masked_data_to_value(udp_data,
                                         dns_server_mask,
                                         dns_server_value)) {
        return &dns_server;
    }
    if (u64_compare_masked_data_to_value(udp_data,
                                         wireguard_mask,
                                         wireguard_value)) {
        return &wireguard;
    }

    return NULL;
}

/*
 * UDP header (from RFC 768)
 *
 *                0      7 8     15 16    23 24    31
 *               +--------+--------+--------+--------+
 *               |     Source      |   Destination   |
 *               |      Port       |      Port       |
 *               +--------+--------+--------+--------+
 *               |                 |                 |
 *               |     Length      |    Checksum     |
 *               +--------+--------+--------+--------+
 *               |
 *               |          data octets ...
 *               +---------------- ...
 *
 * Length is the length in octets of this user datagram including this
 * header and the data.  (This means the minimum value of the length
 * is eight.)
 *
 * Checksum is the 16-bit one's complement of the one's complement sum
 * of a pseudo header of information from the IP header, the UDP
 * header, and the data, padded with zero octets at the end (if
 * necessary) to make a multiple of two octets.
 *
 * If the computed checksum is zero, it is transmitted as all ones
 * (the equivalent in one's complement arithmetic).  An all zero
 * transmitted checksum value means that the transmitter generated no
 * checksum (for debugging or for higher level protocols that don't
 * care).
 *
 */

#define L_udp_src_port 2
#define L_udp_dst_port 2
#define L_udp_length   2
#define L_udp_checksum 2

unsigned int parser_extractor_process_udp_data(struct parser *p, struct extractor *x);

unsigned int packet_filter_process_udp(struct packet_filter *pf, struct key *k) {
    struct parser *p = &pf->p;
    struct extractor *x = &pf->x;

    extractor_debug("%s: processing packet (len %td)\n", __func__, parser_get_data_length(p));
#ifdef DEBUG
    const unsigned char *d = p->data;
#endif

    size_t src_port;
    if (parser_read_and_skip_uint(p, L_udp_src_port, &src_port) == status_err) {
        return 0;
    }
    size_t dst_port;
    if (parser_read_and_skip_uint(p, L_udp_dst_port, &dst_port) == status_err) {
        return 0;
    }
    size_t udp_length;
    if (parser_read_and_skip_uint(p, L_udp_length, &udp_length) == status_err) {
        return 0;
    }
    if (parser_skip(p, L_udp_checksum) == status_err) {
        return 0;
    }

    extractor_debug("%s: udp header: %02x%02x%02x%02x%02x%02x%02x%02x\n", __func__,
                    d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);

    k->dst_port = dst_port;
    k->src_port = src_port;
    k->protocol = 17;

    /* handle the udp length field */
    if (udp_length < 8) {
      return 0; /* error: header claims that packet is shorter than header */
    }
    if ((unsigned int)parser_get_data_length(p) != udp_length - 8) {
      parser_set_data_length(p, udp_length - 8);
    }

    if (dst_port == VXLAN_PORT) {
        return packet_filter_process_vxlan(pf, k);
    }
    /*
     * process the UDP Data payload
     */
    return parser_extractor_process_udp_data(p, x);

}


unsigned int parser_extractor_process_dtls(struct parser *p, struct extractor *x);
unsigned int parser_extractor_process_dtls_server(struct parser *p, struct extractor *x);
unsigned int parser_extractor_process_dhcp(struct parser *p, struct extractor *x);
unsigned int parser_extractor_process_dns(struct parser *p, struct extractor *x);
unsigned int parser_extractor_process_wireguard(struct parser *p, struct extractor *x);

unsigned int parser_extractor_process_udp_data(struct parser *p, struct extractor *x) {
    const struct pi_container *pi;
    struct pi_container dummy = { 0, 0 };

    extractor_debug("%s: parser has %td bytes\n", __func__, p->data_end - p->data);

    pi = proto_identify_udp(p->data, parser_get_data_length(p));

    if (pi == NULL) {
        pi = &dummy;
    }

    extractor_debug("%s: found udp protocol %u\n", __func__, pi->app);

    switch(pi->app) {
    case DHCP_CLIENT_PORT:
        return parser_extractor_process_dhcp(p, x);
        break;
    case DTLS_PORT:
        if (pi->dir == DIR_CLIENT) {
            return parser_extractor_process_dtls(p, x);
        } else {
            return parser_extractor_process_dtls_server(p, x);
        }
        break;
    case SSH_PORT:
        return parser_extractor_process_ssh(p, x);
        break;
    case DNS_PORT:
        return parser_extractor_process_dns(p, x);
        break;
    case WIREGUARD_PORT:
        return parser_extractor_process_wireguard(p, x);
        break;
    default:
        ;
    }

    return 0; /* if we get here, we have nothing to report */
}


/*
 * DHCP protocol processing
 */


/*
 *
 * Format of a DHCP message (from RFC 2131)
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
 *  +---------------+---------------+---------------+---------------+
 *  |                            xid (4)                            |
 *  +-------------------------------+-------------------------------+
 *  |           secs (2)            |           flags (2)           |
 *  +-------------------------------+-------------------------------+
 *  |                          ciaddr  (4)                          |
 *  +---------------------------------------------------------------+
 *  |                          yiaddr  (4)                          |
 *  +---------------------------------------------------------------+
 *  |                          siaddr  (4)                          |
 *  +---------------------------------------------------------------+
 *  |                          giaddr  (4)                          |
 *  +---------------------------------------------------------------+
 *  |                                                               |
 *  |                          chaddr  (16)                         |
 *  |                                                               |
 *  |                                                               |
 *  +---------------------------------------------------------------+
 *  |                                                               |
 *  |                          sname   (64)                         |
 *  +---------------------------------------------------------------+
 *  |                                                               |
 *  |                          file    (128)                        |
 *  +---------------------------------------------------------------+
 *  |                                                               |
 *  |                          options (variable)                   |
 *  +---------------------------------------------------------------+
 *
 *  DHCP Options Overview (from RFC 2132)
 *
 *  DHCP options have the same format as the BOOTP 'vendor extensions'
 *  defined in RFC 1497.  Options may be fixed length or variable
 *  length.  All options begin with a tag octet, which uniquely
 *  identifies the option.  Fixed-length options without data consist
 *  of only a tag octet.  Only options 0 and 255 are fixed length.
 *  All other options are variable-length with a length octet
 *  following the tag octet.  The value of the length octet does not
 *  include the two octets specifying the tag and length.  The length
 *  octet is followed by "length" octets of data.  Options containing
 *  NVT ASCII data SHOULD NOT include a trailing NULL; however, the
 *  receiver of such options MUST be prepared to delete trailing nulls
 *  if they exist.  The receiver MUST NOT require that a trailing null
 *  be included in the data.  In the case of some variable-length
 *  options the length field is a constant but must still be
 *  specified.
 *
 *  Pseudo-BNF for option format:
 *     option     := fixed-code | code length data
 *     fixed-code := 0x00 | 0xff
 *     code       := 0x01 | 0x02 | ... | 0xfe
 *     length     := 0x00 | 0x01 | ... | 0xff
 *     data       := [0x00 | 0x01 | ... | 0xff]^length
 *
 *  When used with BOOTP, the first four octets of the vendor
 *  information field have been assigned to the "magic cookie" (as
 *  suggested in RFC 951).  This field identifies the mode in which
 *  the succeeding data is to be interpreted.  The value of the magic
 *  cookie is the 4 octet dotted decimal 99.130.83.99 (or hexadecimal
 *  number 63.82.53.63) in network byte order.
 */

#define L_dhcp_fixed_header 236
#define L_dhcp_magic_cookie   4
#define L_dhcp_option_tag     1
#define L_dhcp_option_length  1

#define DHCP_OPT_PAD 0x00
#define DHCP_OPT_END 0xff
#define DHCP_OPT_MESSAGE_TYPE   0x35
#define DHCP_OPT_PARAMETER_LIST 0x37
#define DHCP_OPT_VENDOR_CLASS   0x7C

unsigned int parser_extractor_process_dhcp(struct parser *p, struct extractor *x) {

    extractor_debug("%s: processing packet\n", __func__);

    // uint16_t dhcp_proto_number = htons(DHCP_CLIENT_PORT);
    // if (extractor_write_to_output(x, (unsigned char *)&dhcp_proto_number, sizeof(dhcp_proto_number)) == status_err) {
    //    return 0;
    //}

    if (parser_skip(p, L_dhcp_fixed_header) == status_err) {
        return 0;
    }

    /*
     * process option list (see above and RFC 2132)
     */
    if (parser_skip(p, L_dhcp_magic_cookie) == status_err) {
        return 0;
    }
    while (parser_get_data_length(p) > 0) {
        size_t option_tag, option_length;

        extractor_debug("%s: processing option\n", __func__);

        if (parser_read_uint(p, L_dhcp_option_tag, &option_tag) == status_err) {
            return 0;
        }
        if (option_tag == DHCP_OPT_PAD) {
	    break;                	    	    /* we omit padding from the characteristic string */
	}
        if (parser_extractor_copy(p, x, L_dhcp_option_tag) == status_err) {
            return 0;
        }
        if (option_tag == DHCP_OPT_END) {

            /* note: no option_length field is present for this tags */
            ;

        } else {
            if (parser_read_uint(p, L_dhcp_option_length, &option_length) == status_err) {
                break;
            }
            /*
             * TBD: what tags should be copied? not many probably; see
             * https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
             */
            if (option_tag == DHCP_OPT_PARAMETER_LIST || option_tag == DHCP_OPT_VENDOR_CLASS || option_tag == DHCP_OPT_MESSAGE_TYPE) {

                if (parser_extractor_copy_append(p, x, option_length + L_dhcp_option_tag) == status_err) {
                    break;
                }
            } else {

                if (parser_skip(p, option_length + L_dhcp_option_tag) == status_err) {
                    break;
                }
            }
        }
    }

    x->fingerprint_type = fingerprint_type_dhcp_client;
    return extractor_get_output_length(x);
}


/*
 * DTLS packet formats(from RFC 6347)
 *
 *  struct {
 *     ContentType type;
 *     ProtocolVersion version;
 *     uint16 epoch = 0                                 // DTLS field
 *     uint48 sequence_number;                          // DTLS field
 *     uint16 length;
 *     opaque fragment[DTLSPlaintext.length];
 * } DTLSPlaintext;
 *
 * struct {
 *      opaque content[DTLSPlaintext.length];
 *     ContentType type;
 *      uint8 zeros[length_of_padding];
 * } DTLSInnerPlaintext;
 *
 * struct {
 *     ContentType opaque_type = 23;    // application_data
 *     uint32 epoch_and_sequence;
 *     uint16 length;
 *     opaque encrypted_record[length];
 * } DTLSCiphertext;
 *
 *   uint16 ProtocolVersion;
 *   opaque Random[32];
 *
 *  uint8 CipherSuite[2];    // Cryptographic suite selector
 *
 *  struct {
 *      ProtocolVersion legacy_version = { 254,253 }; // DTLSv1.2
 *      Random random;
 *      opaque legacy_session_id<0..32>;
 *      opaque legacy_cookie<0..2^8-1>;                  // DTLS
 *      CipherSuite cipher_suites<2..2^16-2>;
 *      opaque legacy_compression_methods<1..2^8-1>;
 *      Extension extensions<0..2^16-1>;
 *  } ClientHello;
 */

/*
 * TLS fingerprint extraction
 */

#define L_DTLSContentType              1
#define L_DTLSProtocolVersion          2
#define L_DTLSEpoch                    2
#define L_DTLSSequence                 6
#define L_DTLSRecordLength             2
#define L_DTLSHandshakeType            1
#define L_DTLSHandshakeLength          3
#define L_DTLSMessageSequence          2
#define L_DTLSFragmentOffset           3
#define L_DTLSFragmentLength           3
#define L_DTLSProtocolVersion          2
#define L_DTLSRandom                  32
#define L_DTLSSessionIDLength          1
#define L_DTLSCookieLength             1
#define L_DTLSCipherSuiteVectorLength  2
#define L_DTLSCompressionMethodsLength 1
#define L_DTLSExtensionsVectorLength   2
#define L_DTLSExtensionType            2
#define L_DTLSExtensionLength          2

#define L_DTLSNamedGroupListLen        2
#define L_DTLSProtocolVersionListLen   1

/*
 * expanded set of static extensions
 */
#define dtls_num_static_extension_types 34

/*
 * extension types used in normalization
 */
#define dtls_type_sni                0x0000
#define dtls_type_supported_groups   0x000a
#define dtls_type_supported_versions 0x002b

uint16_t dtls_static_extension_types[dtls_num_static_extension_types] = {
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
        43,        /* supported_versions                     */
        45,        /* psk_key_exchange_modes                 */
        50,        /* signature algorithms cert              */
        2570,      /* GREASE                                 */
        6682,      /* GREASE                                 */
        10794,     /* GREASE                                 */
        14906,     /* GREASE                                 */
        19018,     /* GREASE                                 */
        21760,     /* token binding (old)                    */
        23130,     /* GREASE                                 */
        27242,     /* GREASE                                 */
        31354,     /* GREASE                                 */
        35466,     /* GREASE                                 */
        39578,     /* GREASE                                 */
        43690,     /* GREASE                                 */
        47802,     /* GREASE                                 */
        51914,     /* GREASE                                 */
        56026,     /* GREASE                                 */
        60138,     /* GREASE                                 */
        64250      /* GREASE                                 */
    };


/*
 * The function extractor_process_tls processes a DTLS packet.  The
 * extractor MUST have previously been initialized with its data
 * pointer set to the initial octet of the TCP header of the DTLS
 * packet.
 */
unsigned int parser_extractor_process_dtls(struct parser *p, struct extractor *x) {
    size_t tmp_len;
    //struct extractor y;
    struct parser ext_parser;
    const uint8_t *sni_data = NULL;
    size_t sni_length = 0;

    extractor_debug("%s: processing packet\n", __func__);

    /*
     * verify that we are looking at a DTLS ClientHello
     */
    if (parser_match(p,
                     dtls_client_hello_value,
                     L_DTLSContentType + L_DTLSProtocolVersion + L_DTLSEpoch + L_DTLSSequence + L_DTLSRecordLength + L_DTLSHandshakeType,
                     dtls_client_hello_mask) == status_err) {
        return 0; /* not a clientHello */
    }

    x->fingerprint_type = fingerprint_type_dtls;

    /*
     * skip over initial fields
     */
    if (parser_skip(p, L_DTLSHandshakeLength + L_DTLSMessageSequence + L_DTLSFragmentOffset + L_DTLSFragmentLength) == status_err) {
        return 0;
    }

    /*
     * copy clientHello.ProtocolVersion
     */
    if (parser_extractor_copy(p, x, L_DTLSProtocolVersion) == status_err) {
        goto bail;
    }

    /*
     * skip over Random
     */
    if (parser_skip(p, L_DTLSRandom) == status_err) {
        goto bail;
    }

    /* skip over SessionID and SessionIDLen */
    if (parser_read_uint(p, L_DTLSSessionIDLength, &tmp_len) == status_err) {
        goto bail;
    }
    if (parser_skip(p, tmp_len + L_DTLSSessionIDLength) == status_err) {
        goto bail;
    }

    /* skip over Cookie and CookieLen */
    if (parser_read_uint(p, L_DTLSCookieLength, &tmp_len) == status_err) {
        goto bail;
    }
    if (parser_skip(p, tmp_len + L_DTLSCookieLength) == status_err) {
        goto bail;
    }

    /* copy ciphersuite offer vector */
    if (parser_read_uint(p, L_DTLSCipherSuiteVectorLength, &tmp_len) == status_err) {
        goto bail;
    }
    if (parser_skip(p, L_DTLSCipherSuiteVectorLength) == status_err) {
        goto bail;
    }
    if (parser_extractor_copy(p, x, tmp_len) == status_err) {
        goto bail;
    }
    degrease_octet_string(x->last_capture + 2, tmp_len);

    /* skip over compression methods */
    if (parser_read_uint(p, L_DTLSCompressionMethodsLength, &tmp_len) == status_err) {
        goto bail;
    }
    if (parser_skip(p, tmp_len + L_DTLSCompressionMethodsLength) == status_err) {
        goto bail;
    }

    /*
     * parse extensions vector
     */
    /*
     * reserve slot in output for length of extracted extensions
     */
    unsigned char *ext_len_slot;
    if (extractor_reserve(x, &ext_len_slot, sizeof(uint16_t))) {
        goto bail;
    }

    /*  extensions length */
    if (parser_read_and_skip_uint(p, L_DTLSExtensionsVectorLength, &tmp_len)) {
        goto bail;
    }
    parser_init_from_outer_parser(&ext_parser, p, tmp_len);
    while (parser_get_data_length(&ext_parser) > 0) {
        size_t tmp_type;

        if (parser_read_uint(&ext_parser, L_DTLSExtensionType, &tmp_type) == status_err) {
            break;
        }
        if (tmp_type == dtls_type_sni) {
            /*
             * grab Server Name Indication so that we can report it separately
             */
            sni_data = ext_parser.data;
        }

        if (parser_extractor_copy(&ext_parser, x, L_DTLSExtensionType) == status_err) {
            break;
        }
        /* degrease extracted type code */
        degrease_octet_string(x->last_capture + 2, L_DTLSExtensionType);

        if (parser_read_uint(&ext_parser, L_DTLSExtensionLength, &tmp_len) == status_err) {
            break;
        }
        if (tmp_type == dtls_type_sni) {
            /*
             * grab Server Name Indication length
             */
            sni_length = tmp_len + L_DTLSExtensionLength + L_DTLSExtensionType;
            if (sni_data + sni_length > p->data_end) {
                sni_length = p->data_end - sni_data;   /* trim to fit in packet */
            }
        }

        if (uint16_match(tmp_type, dtls_static_extension_types, dtls_num_static_extension_types) == status_err) {
            if (parser_extractor_copy_append(&ext_parser, x, tmp_len + L_DTLSExtensionLength) == status_err) {
                break;
            }
            if (tmp_type == dtls_type_supported_groups) {
                degrease_octet_string(x->last_capture + 2 + L_DTLSExtensionLength + L_DTLSExtensionType + L_DTLSNamedGroupListLen,
                                      tmp_len - L_DTLSNamedGroupListLen);
            }
            if (tmp_type == dtls_type_supported_versions) {
                degrease_octet_string(x->last_capture + 2 + L_DTLSExtensionLength + L_DTLSExtensionType + L_DTLSProtocolVersionListLen,
                                      tmp_len - L_DTLSProtocolVersionListLen);
            }

        } else {

            if (parser_skip(&ext_parser, tmp_len + L_DTLSExtensionLength) == status_err) {
                break;
            }
        }
    }

    /*
     * write the length of the extracted extensions into the reserved slot
     */
    //size_t ext_len_value = (x->output - ext_len_slot) | PARENT_NODE_INDICATOR;
    encode_uint16(ext_len_slot, (x->output - ext_len_slot - sizeof(uint16_t)) | PARENT_NODE_INDICATOR);

    if (sni_data) {
        packet_data_set(&x->packet_data, packet_data_type_dtls_sni, sni_length, sni_data);
    }

    x->proto_state.state = state_done;

    return extractor_get_output_length(x);

 bail:
    /*
     * handle possible packet parsing errors
     */
    extractor_debug("%s: warning: TLS clientHello processing did not fully complete\n", __func__);
    return extractor_get_output_length(x);

}


/*
 * field lengths used in serverHello parsing
 */
#define L_DTLSCipherSuite              2
#define L_DTLSCompressionMethod        1

/*
 * The function parser_process_tls_server processes a TLS
 * serverHello packet.  The parser MUST have previously been
 * initialized with its data pointer set to the initial octet of the
 * TCP header of the TLS packet.
 */
unsigned int parser_extractor_process_dtls_server(struct parser *p, struct extractor *x) {
    size_t tmp_len;

    extractor_debug("%s: processing packet\n", __func__);

    /*
     * verify that we are looking at a DTLS ClientHello
     */
    if (parser_match(p,
                     dtls_server_hello_value,
                     L_DTLSContentType + L_DTLSProtocolVersion + L_DTLSEpoch + L_DTLSSequence + L_DTLSRecordLength + L_DTLSHandshakeType,
                     dtls_server_hello_mask) == status_err) {
        return 0; /* not a clientHello */
    }

    /* set fingerprint type */
    x->fingerprint_type = fingerprint_type_dtls_server;

    /*
     * skip over initial fields
     */
    if (parser_skip(p, L_DTLSHandshakeLength + L_DTLSMessageSequence + L_DTLSFragmentOffset + L_DTLSFragmentLength) == status_err) {
        return 0;
    }

    /*
     * copy serverHello.ProtocolVersion
     */
    if (parser_extractor_copy(p, x, L_DTLSProtocolVersion) == status_err) {
	    goto bail;
    }

    /*
     * skip over Random
     */
    if (parser_skip(p, L_DTLSRandom) == status_err) {
	    goto bail;
    }

    /* skip over SessionID and SessionIDLen */
    if (parser_read_uint(p, L_DTLSSessionIDLength, &tmp_len) == status_err) {
	    goto bail;
    }
    if (parser_skip(p, tmp_len + L_DTLSSessionIDLength) == status_err) {
	    goto bail;
    }

    if (parser_extractor_copy(p, x, L_DTLSCipherSuite) == status_err) {
	    goto bail;
    }

    /* skip over compression methods */
    if (parser_read_uint(p, L_DTLSCompressionMethodsLength, &tmp_len) == status_err) {
	    goto bail;
    }
    if (parser_skip(p, tmp_len + L_DTLSCompressionMethod) == status_err) {
	    goto bail;
    }

    /*
     * parse extensions vector if present
     */
    if (parser_get_data_length(p) > 0) {
        /*
         * reserve slot in output for length of extracted extensions
         */
        unsigned char *ext_len_slot;
        if (extractor_reserve(x, &ext_len_slot, sizeof(uint16_t))) {
	        goto bail;
        }

        /*  extensions length */
        if (parser_read_and_skip_uint(p, L_DTLSExtensionsVectorLength, &tmp_len)) {
	        goto bail;
        }

        struct parser ext_parser;
        parser_init_from_outer_parser(&ext_parser, p, tmp_len);
        while (parser_get_data_length(&ext_parser) > 0)
        {
            size_t tmp_type;
            if (parser_read_uint(&ext_parser, L_DTLSExtensionType, &tmp_type) == status_err)
            {
                break;
            }
            if (parser_extractor_copy(&ext_parser, x, L_DTLSExtensionType) == status_err)
            {
                break;
            }

            if (parser_read_uint(&ext_parser, L_DTLSExtensionLength, &tmp_len) == status_err)
            {
                break;
            }

            if (uint16_match(tmp_type, dtls_static_extension_types, dtls_num_static_extension_types) == status_err)
            {
                if (parser_extractor_copy_append(&ext_parser, x, tmp_len + L_DTLSExtensionLength) == status_err)
                {
                    break;
                }
            }
            else
            {
                if (parser_skip(&ext_parser, tmp_len + L_DTLSExtensionLength) == status_err)
                {
                    break;
                }
            }
        }

        /*
         * write the length of the extracted extensions into the reserved slot
         */
        encode_uint16(ext_len_slot, (x->output - ext_len_slot - sizeof(uint16_t)) | PARENT_NODE_INDICATOR);
    }

    x->proto_state.state = state_done;

    return extractor_get_output_length(x);

 bail:
    /*
     * handle possible packet parsing errors
     */
    extractor_debug("%s: warning: TLS serverHello processing did not fully complete\n", __func__);
    return 0;

}


/*
 * dns parser_extractor_process function
 */

unsigned int parser_extractor_process_dns(struct parser *p, struct extractor *x) {

    extractor_debug("%s: processing packet\n", __func__);

    // set entire DNS packet as packet_data
    packet_data_set(&x->packet_data, packet_data_type_dns_server, p->length(), p->data);

    return 0;
}


