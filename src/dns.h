/*
 * dns.h
 *
 * Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

/**
 * \file dns.h
 *
 * \brief interface file for DNS code
 */
#ifndef DNS_H
#define DNS_H

#include <string>
#include "json_object.h"
#include "util_obj.h"

/**
 * \file dns.h
 *
 * \brief Domain Name System (DNS) protocol support
 *
 * \remarks
 * \verbatim
 *
 * DNS packet formats (from RFC 1035)
 *
 *                      DNS Header
 *
 *                                   1  1  1  1  1  1
 *     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                      ID                       |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    QDCOUNT                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    ANCOUNT                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    NSCOUNT                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    ARCOUNT                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 *
 *                    Resource Records
 *
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                                               |
 *   |                                               |
 *   |                      NAME                     |
 *   |                                               |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                      TYPE                     |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                     CLASS                     |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                      TTL                      |
 *   |                                               |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                   RDLENGTH                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 *   |                     RDATA                     |
 *   |                                               |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * \endverbatim
 */

/**
 * \remarks
 * \verbatim
 * RCODE        Response code - this 4 bit field is set as part of
 *              responses.  The values have the following
 *              interpretation:
 *
 *              0               No error condition
 *
 *              1               Format error - The name server was
 *                              unable to interpret the query.
 *
 *              2               Server failure - The name server was
 *                              unable to process this query due to a
 *                              problem with the name server.
 *
 *              3               Name Error - Meaningful only for
 *                              responses from an authoritative name
 *                              server, this code signifies that the
 *                              domain name referenced in the query does
 *                              not exist.
 *
 *              4               Not Implemented - The name server does
 *                              not support the requested kind of query.
 *
 *              5               Refused - The name server refuses to
 *                              perform the specified operation for
 *                              policy reasons.  For example, a name
 *                              server may not wish to provide the
 *                              information to the particular requester,
 *                              or a name server may not wish to perform
 *                              a particular operation (e.g., zone
 * \endverbatim
 */

#if CPU_IS_BIG_ENDIAN

/** DNS header structure */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((__packed__)) dns_hdr;

#else

/** DNS header structure */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((__packed__)) dns_hdr;

#endif

enum class dns_rr_type : uint16_t {
    unknown  = 0,
    A        = 1, /*!< a host address */
    NS       = 2, /*!< an authoritative name server */
    MD       = 3, /*!< a mail destination (Obsolete - use MX) */
    MF       = 4, /*!< a mail forwarder (Obsolete - use MX) */
    CNAME    = 5, /*!< the canonical name for an alias */
    SOA      = 6, /*!< marks the start of a zone of authority */
    MB       = 7, /*!< a mailbox domain name (EXPERIMENTAL) */
    MG       = 8, /*!< a mail group member (EXPERIMENTAL) */
    MR       = 9, /*!< a mail rename domain name (EXPERIMENTAL) */
    NULL_RR  = 10, /*!< a null RR (EXPERIMENTAL) */
    WKS      = 11, /*!< a well known service description */
    PTR      = 12, /*!< a domain name pointer */
    HINFO    = 13, /*!< host information */
    MINFO    = 14, /*!< mailbox or mail list information */
    MX       = 15, /*!< mail exchange */
    TXT      = 16, /*!< text strings */
    X25      = 19,
    AAAA     = 28, /*!< a IPv6 host address */
    SRV      = 33,
    NAPTR    = 35,
    DS       = 43,
    NSEC	 = 47,
    DNSKEY   = 48,
    HTTPS    = 65,
    WILDCARD = 255,
    DLV      = 32769
};

char UNKNOWN[] = "UNKNOWN";

const char *dns_rr_type_name(dns_rr_type t) {
    switch(t) {
    case dns_rr_type::A:       return "A";
    case dns_rr_type::NS:      return "NS";
    case dns_rr_type::MD:      return "MD";
    case dns_rr_type::MF:      return "MF";
    case dns_rr_type::CNAME:   return "CNAME";
    case dns_rr_type::SOA:     return "SOA";
    case dns_rr_type::MB:      return "MB";
    case dns_rr_type::MG:      return "MG";
    case dns_rr_type::MR:      return "MR";
    case dns_rr_type::NULL_RR: return "NULL";
    case dns_rr_type::WKS:     return "WKS";
    case dns_rr_type::PTR:     return "PTR";
    case dns_rr_type::HINFO:   return "HINFO";
    case dns_rr_type::MINFO:   return "MINFO";
    case dns_rr_type::MX:      return "MX";
    case dns_rr_type::TXT:     return "TXT";
    case dns_rr_type::X25:     return "X25";
    case dns_rr_type::AAAA:    return "AAAA";
    case dns_rr_type::SRV:     return "SRV";
    case dns_rr_type::NAPTR:   return "NAPTR";
    case dns_rr_type::DS:      return "DS";
    case dns_rr_type::NSEC:    return "NSEC";
    case dns_rr_type::DNSKEY:  return "DNSKEY";
    case dns_rr_type::HTTPS:   return "HTTPS";
    case dns_rr_type::WILDCARD: return "WILDCARD";
    case dns_rr_type::DLV:     return "DLV";
    default:
        break;
    }
    return UNKNOWN;
}

enum dns_rr_class : uint16_t {
    IN = 1, /*!< the Internet */
    CS = 2, /*!< the CSNET class (Obsolete) */
    CH = 3, /*!< the CHAOS class */
    HS = 4  /*!< Hesiod [Dyer 87] */
};

const char *dns_rr_class_name(dns_rr_class c) {
    switch (c) {
    case dns_rr_class::IN: return "IN";
    case dns_rr_class::CS: return "CS";
    case dns_rr_class::CH: return "CH";
    case dns_rr_class::HS: return "HS";
    default:
        break;
    }
    return UNKNOWN;
}

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

enum class dns_label_type { null, char_string, offset };

struct dns_label_header {
    uint8_t L;

    dns_label_header() : L{0} {  }
    dns_label_header(struct datum &d) {
        d.read_uint8(&L);
    }

    bool is_NULL() { return L == 0; }

    dns_label_type type() {
        if (L == 0) {
            return dns_label_type::null;
        }
        if (L & 0xC0) {
            return dns_label_type::offset;
        }
        return dns_label_type::char_string;
    }

    uint8_t char_string_length() {
        return L & 0x3F;
    }
    uint8_t offset() {
        return L & 0x3F;
    }
};

struct dns_name : public data_buffer<256> {

    static const unsigned int recursion_threshold = 16;  // prevents stack overflow

    dns_name() : data_buffer{} {}

    void parse(struct datum &d, const struct datum &dns_body, unsigned int recursion_count=0) {

        if (recursion_count++ > recursion_threshold) {
            d.set_empty();
            return;
        }

        while (d.is_not_empty()) {

            struct dns_label_header h{d};
            dns_label_type type = h.type();
            if (type == dns_label_type::null) {
                break;
            }
            if (type == dns_label_type::char_string) {
                copy(d, h.char_string_length());
                copy('.');
            }
            if (type == dns_label_type::offset) {
                uint8_t tmp;
                d.read_uint8(&tmp);
                uint16_t offset = (((uint16_t)h.offset()) << 8) + tmp;

                if (offset < sizeof(dns_hdr)) {
                    d.set_empty();  // error: offset too small
                    return;
                } else if ((ssize_t)offset >= dns_body.length()) {
                    d.set_empty();
                    return;         // error: offset points to itself, or a following label
                }

                // parse the label at hdr + offset
                struct datum tmp_dns_body = dns_body;
                tmp_dns_body.skip(offset - sizeof(dns_hdr));
                parse(tmp_dns_body, dns_body, recursion_count);
                break;
            }
        }
    }
};

struct dns_question_record {
    struct dns_name name;
    uint16_t rr_type;
    uint16_t rr_class;
    bool cache;

    dns_question_record() : name{}, rr_type{0}, rr_class{0} {}

    void parse(struct datum &d, const struct datum &dns_body) {
        name.parse(d, dns_body);
        d.read_uint16(&rr_type);
        d.read_uint16(&rr_class);
        cache = rr_class & 0x8000;  // mDNS cache bit
        rr_class &= 0x7fff;         // mask away mDNS cache bit
        if (d.is_null()) {
            name.set_empty();
        }
    }

    void write_json(struct json_object &o, const char *key) const {
        if (name.is_not_empty()) {
            struct json_object rr{o, key};
            rr.print_key_json_string("name", name.buffer, name.length());
            rr.print_key_uint("type", rr_type);
            rr.print_key_uint("class", rr_class);
            rr.close();
        }
    }
    void write_json(struct json_object &o) const {
        if (name.is_not_empty()) {
            o.print_key_json_string("name", name.buffer, name.length());
            const char *type_name = dns_rr_type_name((dns_rr_type)rr_type);
            o.print_key_string("type", type_name);
            if (type_name == UNKNOWN) {
                o.print_key_uint("type_code", rr_type);
            }
            const char *class_name = dns_rr_class_name((dns_rr_class)rr_class);
            o.print_key_string("class", class_name);
            if (class_name == UNKNOWN) {
                o.print_key_uint("class_code", rr_class);
            }
        }
    }
    bool is_not_empty() const { return name.is_not_empty(); }

};

struct dns_resource_record {
    dns_question_record question_record;
    uint32_t ttl;
    uint16_t rd_length;
    struct datum rdata;
    struct datum body;

    dns_resource_record() : question_record{}, ttl{0}, rd_length{0}, rdata{NULL, NULL}, body{NULL, NULL} {}

    void parse(struct datum &d, const struct datum &dns_body) {
        body = dns_body;
        question_record.parse(d, dns_body);
        d.read_uint32(&ttl);
        d.read_uint16(&rd_length);
        rdata.parse(d, rd_length);
    }

    void write_json(struct json_array &a) const {
        if (question_record.is_not_empty()) {
            struct json_object rr{a};
            question_record.write_json(rr);
            rr.print_key_uint("ttl", ttl);

            struct datum tmp_rdata = rdata;
            if ((dns_rr_class)(question_record.rr_class) == dns_rr_class::IN) {
                if ((dns_rr_type)question_record.rr_type == dns_rr_type::A) {
                    struct ipv4_addr addr;
                    addr.parse(tmp_rdata);
                    rr.print_key_value("ipv4_addr", addr);

                } else if ((dns_rr_type)question_record.rr_type == dns_rr_type::AAAA) {
                    struct ipv6_addr addr;
                    addr.parse(tmp_rdata);
                    rr.print_key_value("ip6_addr", addr);

                } else if ((dns_rr_type)question_record.rr_type == dns_rr_type::TXT) {
                    struct json_array txt{rr, "txt"};
                    while (tmp_rdata.is_not_empty()) {
                        uint8_t length;
                        tmp_rdata.read_uint8(&length);
                        struct datum tmp;
                        tmp.parse(tmp_rdata, length);
                        txt.print_json_string(tmp);
                    }
                    txt.close();

                } else if ((dns_rr_type)question_record.rr_type == dns_rr_type::SRV) {
                    struct json_object srv{rr, "srv"};

                    uint16_t priority;
                    tmp_rdata.read_uint16(&priority);
                    srv.print_key_uint("priority", priority);

                    uint16_t weight;
                    tmp_rdata.read_uint16(&weight);
                    srv.print_key_uint("weight", weight);

                    uint16_t port;
                    tmp_rdata.read_uint16(&port);
                    srv.print_key_uint("port", port);

                    struct dns_name target;
                    target.parse(tmp_rdata, body);
                    srv.print_key_json_string("target", target.buffer, target.length());

                    srv.close();

                } else if ((dns_rr_type)question_record.rr_type == dns_rr_type::NSEC) {

                    struct json_object nsec{rr, "nsec"};

                    struct dns_name next_name;
                    next_name.parse(tmp_rdata, body);
                    nsec.print_key_json_string("next_domain_name", next_name.buffer, next_name.length());

                    nsec.print_key_hex("type_bit_maps", tmp_rdata);
                    nsec.close();
                }

            } else {
                rr.print_key_hex("rdata", tmp_rdata);
            }
            rr.close();
        }
    }
};

struct dns_packet {
    dns_hdr *header;
    struct datum records;
    uint16_t qdcount, ancount, nscount, arcount;

    static const uint16_t max_count = 32;

    dns_packet() : header{NULL}, records{NULL, NULL} {  }

    dns_packet(struct datum &d) : header{NULL}, records{NULL, NULL} {
        parse(d);
    }

    void parse(struct datum &d) {
        if (d.length() < (int)sizeof(dns_hdr)) {
            return;  // too short
        }
        header = (dns_hdr *)d.data;
        d.skip(sizeof(dns_hdr));
        qdcount = ntohs(header->qdcount);
        ancount = ntohs(header->ancount);
        nscount = ntohs(header->nscount);
        arcount = ntohs(header->arcount);
        if (qdcount > dns_packet::max_count
            || ancount > dns_packet::max_count
            || nscount > dns_packet::max_count
            || arcount > dns_packet::max_count) {

            header = NULL;  // invalid format, not a DNS packet
            return;
        }
        records = d;

        // trial parsing, just to verify dns packet formatting
        dns_question_record question_record;
        question_record.parse(d, records);
        if (question_record.is_not_empty() == false) {
            records.set_null();
            //fprintf(stderr, "notice: setting dns packet to null\n");
        }
    }

    bool is_not_empty() {
        return (header != NULL);
    }
    void write_json(struct json_object &o) const {
        if (header == NULL) {
            return;
        }
        const char *key = (header->flags & 0x8000) ?  "response" : "query";
        struct json_object dns_json{o, key};
        //dns_json.print_key_uint("qdcount", qdcount);
        //dns_json.print_key_uint("ancount", ancount);
        //dns_json.print_key_uint("nscount", nscount);
        //dns_json.print_key_uint("arcount", arcount);

        struct datum record_list = records; // leave records element unchanged (const)
        if (qdcount) {
            struct json_array q{dns_json, "question"};
            for (unsigned int count = 0; count < qdcount; count++) {
                dns_question_record question_record;
                question_record.parse(record_list, records);
                struct json_object o{q};
                question_record.write_json(o);
                o.close();
            }
            q.close();
        }

        if (ancount) {
            struct json_array a{dns_json, "answer"};
            for (unsigned int count = 0; count < ancount; count++) {
                dns_resource_record resource_record;
                resource_record.parse(record_list, records);
                resource_record.write_json(a);
            }
            a.close();
        }

        if (nscount) {
            struct json_array a{dns_json, "authority"};
            for (unsigned int count = 0; count < nscount; count++) {
                dns_resource_record resource_record;
                resource_record.parse(record_list, records);
                resource_record.write_json(a);
            }
            a.close();
        }

        if (arcount) {
            struct json_array a{dns_json, "additional"};
            for (unsigned int count = 0; count < arcount; count++) {
                dns_resource_record resource_record;
                resource_record.parse(record_list, records);
                resource_record.write_json(a);
            }
            a.close();
        }

        dns_json.close();
    }
};


std::string dns_get_json_string(const char *dns_pkt, ssize_t pkt_len);

#endif /* DNS_H */
