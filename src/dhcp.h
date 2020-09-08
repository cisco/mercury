/*
 * dhcp.h
 */

#ifndef DHCP_H
#define DHCP_H

#include <stdint.h>
#include <stdlib.h>
#include "mercury.h"
#include "parser.h"
#include "json_object.h"

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

struct dhcp_option : public parser {
    uint8_t tag;
    uint8_t length;

    dhcp_option() : parser{NULL, NULL}, tag{0}, length{0} {};

    void parse(struct parser &p) {
        p.read_uint8(&tag);
        if (tag == 0 || tag == 255) {
            return;
        }
        p.read_uint8(&length);
        parser::parse(p, length);
    }
};

struct dhcp_discover {
    struct parser options;

    dhcp_discover() = default;

    void parse(struct parser &p) {
        p.skip(L_dhcp_fixed_header);
        p.skip(L_dhcp_magic_cookie);
        options = p;
    }

    void write_json(struct json_object &o) {
        struct json_object json_dhcp{o, "dhcp"};
        json_dhcp.print_key_hex("options_hex", options);
        json_dhcp.print_key_datum("options", options);

        struct json_array option_array{json_dhcp, "options"};
        struct parser tmp = options;
        while (tmp.is_not_empty()) {
            struct dhcp_option opt;
            opt.parse(tmp);
            struct json_object json_opt{option_array};
            json_opt.print_key_uint("type", opt.tag);
            json_opt.print_key_uint("length", opt.length);
            json_opt.print_key_hex("value", opt);
            json_opt.close();
        }
        option_array.close();
        fingerprint(json_dhcp, "fingerprint");
        json_dhcp.close();
    }

    void fingerprint(json_object &o, const char *key) const {

        char fp_buffer[4096];
        struct buffer_stream buf(fp_buffer, sizeof(fp_buffer));

        struct parser tmp = options;
        while (tmp.is_not_empty()) {
            struct dhcp_option opt;
            opt.parse(tmp);
            if (opt.tag == DHCP_OPT_PARAMETER_LIST || opt.tag == DHCP_OPT_VENDOR_CLASS || opt.tag == DHCP_OPT_MESSAGE_TYPE) {
                // copy entire option into fingerprint string
                buf.write_char('(');
                buf.raw_as_hex(&opt.tag, sizeof(opt.tag));
                buf.raw_as_hex(&opt.length, sizeof(opt.length));
                buf.raw_as_hex(opt.data, opt.data_end - opt.data);
                //                buf.raw_as_hex(opt_data, opt_data_end - opt_data);
                buf.write_char(')');

            } else if (opt.tag != DHCP_OPT_PAD) {
                // copy only option tag into fingerprint string
                buf.write_char('(');
                buf.raw_as_hex(&opt.tag, sizeof(opt.tag));
                buf.write_char(')');
            }
        }

        o.print_key_string(key, fp_buffer);
    }

};

#endif /* DHCP_H */
