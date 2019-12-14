/*
 * udp.c
 *
 * UDP protocol processing
 */


#include "extractor.h"
#include "proto_identify.h"


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

unsigned char dtls_client_hello_mask[] = {
    0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00
};

unsigned char dtls_client_hello_value[] = {
    0x16, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

struct pi_container dtls_client = {
    DIR_CLIENT,
    DTLS_PORT
};

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

const struct pi_container *proto_identify_udp(const uint8_t *udp_data,
                                              unsigned int len) {

    extractor_debug("%s: with length %u\n", __func__, len);

    if (len < sizeof(dhcp_client_mask)) {
        return NULL;
    }

    extractor_debug("%s: udp data: %02x%02x%02x%02x%02x%02x%02x%02x\n", __func__,
                    udp_data[0], udp_data[1], udp_data[2], udp_data[3], udp_data[4], udp_data[5], udp_data[6], udp_data[7]);

    // debug_print_u8_array(udp_data);

    /* note: udp_data will be 32-bit aligned as per the standard */

    if (u32_compare_masked_data_to_value(udp_data,
                                         dtls_client_hello_mask,
                                         dtls_client_hello_value)) {
        return &dtls_client;
    }
    if (u32_compare_masked_data_to_value(udp_data,
                                         dhcp_client_mask,
                                         dhcp_client_value)) {
        return &dhcp_client;
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
    (void)k;    // ignore flow key for now
    struct parser *p = &pf->p;
    struct extractor *x = &pf->x;

    extractor_debug("%s: processing packet (len %td)\n", __func__, parser_get_data_length(p));
#ifdef DEBUG
    const unsigned char *d = p->data;
#endif

    if (parser_skip(p, L_udp_src_port + L_udp_dst_port) == status_err) {
        return 0;
    }
    size_t udp_length;
    if (parser_read_and_skip_uint(p, L_udp_length, &udp_length) == status_err) {
        return 0;
    }
    /*
     * TBD: should shorten parser data buffer based on udp_length, if needed
     */
    if (parser_skip(p, L_udp_checksum) == status_err) {
        return 0;
    }

    extractor_debug("%s: udp header: %02x%02x%02x%02x%02x%02x%02x%02x\n", __func__,
                    d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);

    /*
	 * process the UDP Data payload
	 */
	return parser_extractor_process_udp_data(p, x);

}


unsigned int parser_extractor_process_dhcp(struct parser *p, struct extractor *x);

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
        fprintf(stderr, "warning: dtls processing is incomplete\n");
        break;
    case SSH_PORT:
        return parser_extractor_process_ssh(p, x);
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
        if (parser_extractor_copy(p, x, L_dhcp_option_tag) == status_err) {
            return 0;
        }
        if (option_tag == DHCP_OPT_PAD || option_tag == DHCP_OPT_END) {

            /* note: no option_length field is present for these tags */
            ;

        } else {
            if (parser_read_uint(p, L_dhcp_option_length, &option_length) == status_err) {
                break;
            }
            /*
             * TBD: what tags should be copied? not many probably; see
             * https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
             */
            if (option_tag == 0xfe) {

                if (parser_extractor_copy_append(p, x, option_length - L_dhcp_option_tag) == status_err) {
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

