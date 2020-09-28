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
    AAAA     = 28  /*!< a IPv6 host address */
};

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
    case dns_rr_type::AAAA:    return "AAAA";
    default:
        break;
    }
    return "uknown";
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
    return "unknown";
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

    dns_name() : data_buffer{} {}

    void parse(struct datum &d, const struct datum &dns_body) {
        bool first = true;
        while (d.is_not_empty()) {
            struct dns_label_header h{d};
            dns_label_type type = h.type();
            if (type == dns_label_type::null) {
                break;
            }
            if (type == dns_label_type::char_string) {
                if (first) {
                    first = false;
                } else {
                    copy('.');
                }
                copy(d, h.char_string_length());
            }
            if (type == dns_label_type::offset) {
                uint8_t tmp;
                d.read_uint8(&tmp);
                uint16_t offset = (((uint16_t)h.offset()) << 8) + tmp;

                // parse the label at hdr + offset
                if (offset < sizeof(dns_hdr)) {
                    d.set_empty();  // error: offset too small
                }
                struct datum tmp_dns_body = dns_body;
                tmp_dns_body.skip(offset - sizeof(dns_hdr));
                parse(tmp_dns_body, dns_body);
                break;
            }
        }
    }
};

struct dns_question_record {
    struct dns_name name;
    uint16_t rr_type;
    uint16_t rr_class;

    dns_question_record() : name{}, rr_type{0}, rr_class{0} {}

    void parse(struct datum &d, const struct datum &dns_body) {
        name.parse(d, dns_body);
        d.read_uint16(&rr_type);
        d.read_uint16(&rr_class);
    }

    void write_json(struct json_object &o, const char *key) {
        if (name.is_not_empty()) {
            struct json_object rr{o, key};
            rr.print_key_json_string("name", name.buffer, name.length());
            rr.print_key_uint("type", rr_type);
            rr.print_key_uint("class", rr_class);
            rr.close();
        }
    }
    void write_json(struct json_object &o) {
        if (name.is_not_empty()) {
            o.print_key_json_string("name", name.buffer, name.length());
            o.print_key_string("type", dns_rr_type_name((dns_rr_type)rr_type));
            o.print_key_string("class", dns_rr_class_name((dns_rr_class)rr_class));
        }
    }
    bool is_not_empty() { return name.is_not_empty(); }

};

struct dns_resource_record {
    dns_question_record question_record;
    uint32_t ttl;
    uint16_t rd_length;
    struct datum rdata;

    dns_resource_record() : question_record{}, ttl{0}, rd_length{0}, rdata{NULL, NULL} {}

    void parse(struct datum &d, const struct datum &dns_body) {
        question_record.parse(d, dns_body);
        d.read_uint32(&ttl);
        d.read_uint16(&rd_length);
        rdata.parse(d, rd_length);
    }

    void write_json(struct json_array &a) {
        if (question_record.is_not_empty()) {
            struct json_object rr{a};
            question_record.write_json(rr);
            rr.print_key_uint("ttl", ttl);
            // rr.print_key_uint("length", rd_length);
            if ((dns_rr_class)question_record.rr_class == dns_rr_class::IN) {
                if ((dns_rr_type)question_record.rr_type == dns_rr_type::A) {
                    struct ipv4_addr addr;
                    addr.parse(rdata);
                    rr.print_key_value("ipv4_addr", addr);

                } else if ((dns_rr_type)question_record.rr_type == dns_rr_type::AAAA) {
                    struct ipv6_addr addr;
                    addr.parse(rdata);
                    rr.print_key_value("ip6_addr", addr);
                }

            } else {
                rr.print_key_json_string("rdata", rdata);
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
