/*
 * dns.cc
 *
 * Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "dns.h"
#include "buffer_stream.h"
#include "datum.h"



typedef struct {
    uint16_t qtype;
    uint16_t qclass;
} __attribute__((__packed__)) dns_question;

typedef struct {
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    uint16_t rdlength;
} __attribute__((__packed__)) dns_rr;


/** DNS Type */
enum dns_type {
    type_A     = 1, /*!< a host address */
    type_NS    = 2, /*!< an authoritative name server */
    type_MD    = 3, /*!< a mail destination (Obsolete - use MX) */
    type_MF    = 4, /*!< a mail forwarder (Obsolete - use MX) */
    type_CNAME = 5, /*!< the canonical name for an alias */
    type_SOA   = 6, /*!< marks the start of a zone of authority */
    type_MB    = 7, /*!< a mailbox domain name (EXPERIMENTAL) */
    type_MG    = 8, /*!< a mail group member (EXPERIMENTAL) */
    type_MR    = 9, /*!< a mail rename domain name (EXPERIMENTAL) */
    type_NULL  = 10, /*!< a null RR (EXPERIMENTAL) */
    type_WKS   = 11, /*!< a well known service description */
    type_PTR   = 12, /*!< a domain name pointer */
    type_HINFO = 13, /*!< host information */
    type_MINFO = 14, /*!< mailbox or mail list information */
    type_MX    = 15, /*!< mail exchange */
    type_TXT   = 16, /*!< text strings */
    type_AAAA  = 28  /*!< a IPv6 host address */
};

/** DNS classes */
enum dns_class {
    class_IN = 1, /*!< the Internet */
    class_CS = 2, /*!< the CSNET class (Obsolete) */
    class_CH = 3, /*!< the CHAOS class */
    class_HS = 4  /*!< Hesiod [Dyer 87] */
};

/** determine if its a label */
#define char_is_label(c)  (((c) & 0xC0) == 0)

/** determine if its an offset */
#define char_is_offset(c) (((c) & 0xC0) == 0xC0)

/** DNS Output Name Length */
#define DNS_OUTNAME_LEN 256

/** DNS Max Recursion processing depth */
#define DNS_MAX_RECURSION_DEPTH 20

/** DNS error codes */
enum dns_err {
    dns_ok                  = 0,
    dns_err                 = 1,
    dns_err_label_too_long  = 2,
    dns_err_offset_too_long = 3,
    dns_err_malformed       = 4,
    dns_err_label_malformed = 5,
    dns_err_bad_rdlength    = 6,
    dns_err_unprintable     = 7,
    dns_err_too_many        = 8,
    dns_err_unterminated    = 9,
    dns_err_rdata_too_long  = 10
};

/* advance the data position */
static enum dns_err data_advance (const char **data, ssize_t *len, unsigned int size) {
    unsigned int tlen = (unsigned int)*len;

    if (tlen < size) {
        return dns_err_malformed;
    }
    *data += size;
    *len -= size;
    return dns_ok;
}

/* parse DNS question */
static enum dns_err dns_question_parse (const dns_question **q, const char **data, ssize_t *len) {
    if (*len < (int)sizeof(dns_question)) {
        return dns_err_malformed;
    }
    *q = (const dns_question*)*data;
    *data += sizeof(dns_question);
    *len -= sizeof(dns_question);
    return dns_ok;
}

/* parse DNS rr */
static enum dns_err dns_rr_parse (const dns_rr **r, const char **data, ssize_t *len, ssize_t *rdlength) {

    if (*len < (int)sizeof(dns_rr)) {
        return dns_err_malformed;
    }

    *r = (const dns_rr*)*data;
    if (*len < ntohs((*r)->rdlength)) {
        return dns_err_rdata_too_long;
    }

    *rdlength = ntohs((*r)->rdlength);
    *data += sizeof(dns_rr);
    *len -= sizeof(dns_rr);
    return dns_ok;
}

/* parse DNS address */
static enum dns_err dns_addr_parse (const struct in_addr **a, const char **data, ssize_t *len, unsigned short int rdlength) {
    if (*len < (int)sizeof(struct in_addr)) {
        return dns_err_malformed;
    }
    if (rdlength != sizeof(struct in_addr)) {
        return dns_err_bad_rdlength;
    }
    *a = (const struct in_addr*)*data;
    *data += sizeof(struct in_addr);
    *len -= sizeof(struct in_addr);
    return dns_ok;
}

/* parse DNS IPV6 address */
static enum dns_err dns_ipv6_addr_parse (const struct in6_addr **a, const char **data, ssize_t *len, unsigned short int rdlength) {
    if (*len < (int)sizeof(struct in6_addr)) {
        return dns_err_malformed;
    }
    if (rdlength != sizeof(struct in6_addr)) {
        return dns_err_bad_rdlength;
    }
    *a = (const struct in6_addr*)*data;
    *data += sizeof(struct in6_addr);
    *len -= sizeof(struct in6_addr);
    return dns_ok;
}

/* parse 16 bit value */
static enum dns_err uint16_parse (uint16_t **x, const char **data, ssize_t *len) {
    if (*len < (int)sizeof(uint16_t)) {
        return dns_err_malformed;
    }
    *x = (uint16_t*)*data;
    *data += sizeof(uint16_t);
    *len -= sizeof(uint16_t);
    return dns_ok;
}

static inline char printable(char c) {
    if (isprint(c)) {
        return c;
    }
    return '*';
}

static enum dns_err dns_header_parse_name (const dns_hdr *hdr, const char **name, ssize_t *len,
                                           char *outname, unsigned int outname_len,
                                           unsigned int recursion_depth) {
    char *terminus = outname + outname_len;
    const char *c = *name;
    unsigned char jump;
    int i;
    ssize_t offsetlen = (*name - (const char *)hdr) + *len; /* num bytes available after offset pointer */
    const char *offsetname;
    enum dns_err err;

    /*
     * A DNS name is a sequence of zero or more labels, possibly
     * followed by an offset.  A label consists of an 8-bit number L
     * that is less than 64 followed by L characters.  An offset is
     * 16-bit number, with the first two bits set to one.  A name is
     * either a sequence of two or more labels, with the last label
     * being NULL (L=0), or a sequence of one or more labels followed by
     * an offset, or just an offset.
     *
     * An offset is a pointer to (part of) a second name in another
     * location of the same DNS packet.  Importantly, note that there
     * may be an offset in the second name; this function must follow
     * each offset that appears and copy the names to outputname.
     */

    /* robustness check */
    if (*len <= 0 || outname > terminus || outname_len < 2) {
      return dns_err_unterminated;
    }
    outname[1] = 0;         /* set output to "", in case of error */
    while (*len > 0 && outname < terminus) {
        if (char_is_label(*c)) {
            if (*c < 64 && *len > *c) {
                if (*c == 0) {
                    *name = c+1;
                    *outname = 0;
                    return dns_ok;  /* got NULL label       */
                }
                jump = *c + 1;
                /*
                 * make (printable) copy of string
                 */
                *outname++ = '.';
                for (i=1; i<jump; i++) {
                    *outname++ = printable(c[i]);
                }
                /* advance pointers, decrease lengths */
                outname_len -= jump;
                *len -= jump;
                c += jump;
                *name += jump;
            } else {
                return dns_err_label_too_long;
            }
        } else if (char_is_offset(*c)) {
            uint16_t *offset;

            err = uint16_parse(&offset, name, len);
            if (err != dns_ok) {
                return dns_err_offset_too_long;
            }
            offsetname = (const char *)((char *)hdr + (ntohs(*offset) & 0x3FFF));
            offsetlen -= (ntohs(*offset) & 0x3FFF);
            if (recursion_depth >= DNS_MAX_RECURSION_DEPTH) {
                return dns_err_offset_too_long;
            }
            return dns_header_parse_name(hdr, &offsetname, &offsetlen, outname, outname_len, recursion_depth + 1);
        } else {
            return dns_err_label_malformed;
        }
    }
    return dns_err_unterminated;
}

static enum dns_err dns_header_parse_mxname (const dns_hdr *hdr, const char **name, ssize_t *len,
                                             char *outname, unsigned int outname_len,
                                             unsigned int recursion_depth) {
    char *terminus = outname + outname_len;
    const char *c = *name;
    unsigned char jump;
    int i;
    int processed_preference = 0;
    ssize_t offsetlen = (*name - (const char *)hdr) + *len; /* num bytes available after offset pointer */
    const char *offsetname;
    enum dns_err err;

    /*
     * A DNS name is a sequence of zero or more labels, possibly
     * followed by an offset.  A label consists of an 8-bit number L
     * that is less than 64 followed by L characters.  An offset is
     * 16-bit number, with the first two bits set to one.  A name is
     * either a sequence of two or more labels, with the last label
     * being NULL (L=0), or a sequence of one or more labels followed by
     * an offset, or just an offset.
     *
     * An offset is a pointer to (part of) a second name in another
     * location of the same DNS packet.  Importantly, note that there
     * may be an offset in the second name; this function must follow
     * each offset that appears and copy the names to outputname.
     */

    /* robustness check */
    if (*len <= 0 || outname > terminus || outname_len < 2) {
      return dns_err_unterminated;
    }
    outname[1] = 0;         /* set output to "", in case of error */
    while (*len > 0 && outname < terminus) {
        if (char_is_label(*c)) {
            /* first 2 bytes of the MX label is the preference */
            if (!processed_preference) {
                c += 2;
                *len -= 2;
                processed_preference = 1;
            }
            if (*c < 64 && *len > *c) {
                if (*c == 0) {
                    *name = c+1;
                    *outname = 0;
                    return dns_ok;  /* got NULL label       */
                }
                jump = *c + 1;
                /*
                 * make (printable) copy of string
                 */
                *outname++ = '.';
                for (i=1; i<jump; i++) {
                    *outname++ = printable(c[i]);
                }
                /* advance pointers, decrease lengths */
                outname_len -= jump;
                *len -= jump;
                c += jump;
                *name += jump;
            } else {
                return dns_err_label_too_long;
            }
        } else if (char_is_offset(*c)) {
            uint16_t *offset;

            err = uint16_parse(&offset, name, len);
            if (err != dns_ok) {
                return dns_err_offset_too_long;
            }
            offsetname = ((char *)hdr + (ntohs(*offset) & 0x3FFF));
            offsetlen -= (ntohs(*offset) & 0x3FFF);
            if (recursion_depth >= DNS_MAX_RECURSION_DEPTH) {
                return dns_err_offset_too_long;
            }
            return dns_header_parse_mxname(hdr, &offsetname, &offsetlen, outname, outname_len, recursion_depth + 1);
        } else {
            return dns_err_label_malformed;
        }
    }
    return dns_err_unterminated;
}

/*
 * dns_rdata_print(rh, rr, r, len, output) prints the RDATA field at
 * location *r
 */
static enum dns_err
dns_rdata_print (const dns_hdr *rh, const dns_rr *rr, const char **r, ssize_t *len, struct json_object &o) {
    enum dns_err err;
    uint16_t rclass = ntohs(rr->rclass);
    uint16_t type = ntohs(rr->type);

    if (rclass == class_IN) {
        if (type == type_A) {
            const struct in_addr *addr;

            err = dns_addr_parse(&addr, r, len, ntohs(rr->rdlength));
            if (err != dns_ok) {
                return err;
            }
            char ipv4_addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, addr, ipv4_addr, INET_ADDRSTRLEN);
            o.print_key_string("rrtype", "A");
            o.print_key_string("rdata", ipv4_addr);

        } else if (type == type_AAAA) {
            const struct in6_addr *addr;

            err = dns_ipv6_addr_parse(&addr, r, len, ntohs(rr->rdlength));
            if (err != dns_ok) {
                return err;
            }
            char ipv6_addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, addr, ipv6_addr, INET6_ADDRSTRLEN);
            o.print_key_string("rrtype", "AAAA");
            o.print_key_string("rdata", ipv6_addr);

        } else if (type == type_SOA  || type == type_PTR || type == type_CNAME || type == type_NS || type == type_MX) {
            const char *tname;
            char name[DNS_OUTNAME_LEN];

            /* mail exchange has a 2-byte preference before the name */
            if (type == type_MX) {
                err = dns_header_parse_mxname(rh, r, len, name, (DNS_OUTNAME_LEN-1), 0); /* note: does not check rdlength */
            } else {
                err = dns_header_parse_name(rh, r, len, name, (DNS_OUTNAME_LEN-1), 0); /* note: does not check rdlength */
            }
            if (err != dns_ok) {
                return err;
            }

            /* get the typename */
            if (type == type_SOA) {
                tname = "SOA";
            } else if (type == type_PTR) {
                tname = "PTR";
            } else if (type == type_NS) {
                tname = "NS";
            } else if (type == type_MX) {
                tname = "MX";
            } else {
                tname = "CNAME";
            }
            o.print_key_string("rrtype", tname);
            o.print_key_string("rrname", name + 1);

            /* advance to end of the resource record */
            if (*len-1 > 0) {
                err = data_advance(r, len, *len-1);
                if (err != dns_ok) {
                    return err;
                }
            }

        } else if (type == type_TXT) {

            o.print_key_string("rrtype", "txt");
            const uint8_t *txt_rdata = (const uint8_t *)*r;
            o.print_key_json_string("rdata", txt_rdata, ntohs(rr->rdlength));

            err = data_advance(r, len, ntohs(rr->rdlength));
            if (err != dns_ok) {
                return err;
            }

        } else {
            err = data_advance(r, len, ntohs(rr->rdlength));
            if (err != dns_ok) {
                return err;
            }
            o.print_key_uint("type", type);
            o.print_key_uint("class", rclass);
            o.print_key_uint("rdlength", ntohs(rr->rdlength));

            /*
             * several DNS types are not explicitly supported here, and more
             * types may be added in the future, if deemed important.  see
             * http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
             */
        }
    } else {
        err = data_advance(r, len, ntohs(rr->rdlength));
        if (err != dns_ok) {
            return err;
        }
        o.print_key_uint("type", type);
        o.print_key_uint("class", rclass);
        o.print_key_uint("rdlength", ntohs(rr->rdlength));

    }
    return dns_ok;
}

void dns_print_packet (const char *dns_pkt, ssize_t pkt_len, struct json_object &outer) {
    enum dns_err err = dns_ok;
    const dns_hdr *rh = NULL;
    const dns_question *question = NULL;
    const dns_rr *rr;
    uint8_t flags_rcode = 0;
    uint16_t qdcount = 0, ancount = 0, nscount = 0, arcount = 0;
    ssize_t rdlength = 0;
    char name[DNS_OUTNAME_LEN];

    /*
     * DNS packet format:
     *
     *   one struct dns_hdr
     *   one (question) name
     *   one struct dns_question
     *   zero or more (resource record) name
     *                struct dns_rr
     *                rr_data
     */
    struct json_object o{outer, "response"};

    if (pkt_len < (ssize_t) sizeof(dns_hdr)) {
        o.print_key_uint("malformed", pkt_len);
        o.close();
      return;
    }

    ssize_t len = pkt_len;
    const char *r = dns_pkt;
    rh = (const dns_hdr*)r;
    uint16_t flags = ntohs(rh->flags);
    flags_rcode = ntohs(rh->flags) & 0x000f;
    // uint8_t flags_qr = ntohs(rh->flags) >> 15;
    uint16_t opcode = (ntohs(rh->flags) >> 11) & 0xf;
    len -= 12;
    r += 12;

    qdcount = ntohs(rh->qdcount);
    if (qdcount > 1) {
        err = dns_err_too_many;
        o.print_key_uint("malformed", len);
        o.close();
        return;
    }

    memset(name, 0x00, DNS_OUTNAME_LEN);
    while (qdcount-- > 0) {
        /* parse question name and struct */
        err = dns_header_parse_name(rh, &r, &len, name, (DNS_OUTNAME_LEN-1), 0);
        if (err != dns_ok) {
            o.print_key_uint("malformed", len);
            o.close();
            return;
        }
        err = dns_question_parse(&question, &r, &len);
        if (err != dns_ok) {
            o.print_key_uint("malformed", len);
            o.close();
            return;
        }
        o.print_key_string("qname", name+1);
    }
    o.print_key_uint("opcode", opcode);
    o.print_key_uint("rcode", flags_rcode);
    o.print_key_uint("flags", flags);

    struct json_array rarray{o, "answer"};

    ancount = ntohs(rh->ancount);
    memset(name, 0x00, DNS_OUTNAME_LEN);
    while (ancount-- > 0) {
        struct json_object robj{rarray};

        /* parse rr name, struct, and rdata */
        err = dns_header_parse_name(rh, &r, &len, name, (DNS_OUTNAME_LEN-1), 0);
        if (err != dns_ok) {
            robj.print_key_uint("malformed", len);
            robj.close();
            rarray.close();
            o.close();
            return;
        }
        err = dns_rr_parse(&rr, &r, &len, &rdlength);
        if (err) {
            robj.print_key_uint("malformed", len);
            robj.close();
            rarray.close();
            o.close();
            return;
        }
        err = dns_rdata_print(rh, rr, &r, &rdlength, robj);
        if (err) {
            robj.print_key_uint("malformed", len);
            robj.close();
            rarray.close();
            o.close();
            return;
        }
        len -= rdlength;
        if (rdlength > 1) {
            r += (rdlength - 1);
            rdlength = 1;
        }
        robj.print_key_uint("ttl", ntohl(rr->ttl));
        robj.close();
    }

    rarray.close();

    struct json_array authority{o, "authority"};
    nscount = ntohs(rh->nscount);
    if (rdlength > 1) {
        r += (rdlength - 1);
    }
    memset(name, 0x00, DNS_OUTNAME_LEN);
    while (nscount-- > 0) {
        struct json_object robj{authority};

        /* parse rr name, struct, and rdata */
        err = dns_header_parse_name(rh, &r, &len, name, (DNS_OUTNAME_LEN-1), 0);
        if (err != dns_ok) {
            robj.print_key_uint("malformed", len);
            robj.close();
            authority.close();
            o.close();
            return;
        }
        err = dns_rr_parse(&rr, &r, &len, &rdlength);
        if (err) {
            robj.print_key_uint("malformed", len);
            robj.close();
            authority.close();
            o.close();
            return;
        }
        err = dns_rdata_print(rh, rr, &r, &rdlength, robj);
        if (err) {
            robj.print_key_uint("malformed", len);
            robj.close();
            authority.close();
            o.close();
            return;
        }
        len -= rdlength;
        if (rdlength > 1) {
            r += (rdlength - 1);
            rdlength = 1;
        }
        robj.print_key_uint("ttl", ntohl(rr->ttl));
        robj.close();
    }

    authority.close();

    struct json_array additional{o, "additional"};
    arcount = ntohs(rh->arcount);
    if (rdlength > 1) {
        r += (rdlength - 1);
    }
    memset(name, 0x00, DNS_OUTNAME_LEN);
    while (arcount-- > 0) {
        struct json_object robj{additional};

        /* parse rr name, struct, and rdata */
        err = dns_header_parse_name(rh, &r, &len, name, (DNS_OUTNAME_LEN-1), 0);
        if (err != dns_ok) {
            robj.print_key_uint("malformed", len);
            robj.close();
            additional.close();
            o.close();
            return;
        }
        err = dns_rr_parse(&rr, &r, &len, &rdlength);
        if (err) {
            robj.print_key_uint("malformed", len);
            robj.close();
            additional.close();
            o.close();
            return;
        }
        err = dns_rdata_print(rh, rr, &r, &rdlength, robj);
        if (err) {
            robj.print_key_uint("malformed", len);
            robj.close();
            additional.close();
            o.close();
            return;
        }
        len -= rdlength;
        if (rdlength > 1) {
            r += (rdlength - 1);
            rdlength = 1;
        }
        robj.print_key_uint("ttl", ntohl(rr->ttl));
        robj.close();
    }
    additional.close();
    o.close();

    return;
}

// START NEW CODE

// END NEW CODE

// dns_get_json_string() is used by the cython library
//
std::string dns_get_json_string(const char *dns_pkt, ssize_t pkt_len) {
    char buffer[8192*8];
    struct buffer_stream buf(buffer, sizeof(buffer));
    struct json_object dns{&buf};
    dns_print_packet(dns_pkt, pkt_len, dns);
    dns.close();
    std::string tmp_str(buffer, buf.length());
    return tmp_str;
}

void write_dns_server_data(const uint8_t *data, size_t length, struct json_object &dns_object, bool output_base64) {
    if (output_base64) {
        struct datum p{data, data+length};
        dns_object.print_key_base64("base64", p);
    } else {
        dns_print_packet((const char *)data, length, dns_object);
        struct datum p{data, data+length};
        struct dns_packet dns_packet;
        dns_packet.parse(p);
    }
    return;
}
