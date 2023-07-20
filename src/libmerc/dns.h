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

#include "protocol.h"
#include "json_object.h"
#include "util_obj.h"
#include "match.h"

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

enum class netbios_rr_type : uint16_t {
    NB     = 32,   /* NetBIOS general Name Service Resource Record */
    NBSTAT = 33    /* NetBIOS NODE STATUS Resource Record */
};

static const char UNKNOWN[] = "UNKNOWN";

inline const char *dns_rr_type_name(dns_rr_type t) {
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

inline const char *netbios_rr_type_name(netbios_rr_type t) {
    switch(t) {
    case netbios_rr_type::NB:        return "NB";
    case netbios_rr_type::NBSTAT:    return "NBSTAT";
    default:
        break;
    }
    return UNKNOWN;
}

inline const char* get_rr_type_name(uint16_t type, bool is_netbios) {
    if(is_netbios) {
        return(netbios_rr_type_name((netbios_rr_type) type));
    }
    return (dns_rr_type_name((dns_rr_type) type));
}

enum dns_rr_class : uint16_t {
    IN = 1, /*!< the Internet */
    CS = 2, /*!< the CSNET class (Obsolete) */
    CH = 3, /*!< the CHAOS class */
    HS = 4  /*!< Hesiod [Dyer 87] */
};

inline const char *dns_rr_class_name(dns_rr_class c) {
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

#define MAX_NETBIOS_NAME 16
struct dns_name : public data_buffer<256> {

    static const unsigned int recursion_threshold = 16;  // prevents stack overflow
    bool is_netbios_name;

    dns_name() : data_buffer{}, is_netbios_name{false} {}

    dns_name(datum &d, const datum &dns_body, unsigned int recursion_count=0) :
        data_buffer{},
        is_netbios_name{false}
    {
        parse(d, dns_body, recursion_count);
    }

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
                data_buffer<256>::parse(d, h.char_string_length());
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

        if (check_netbios()) {
            is_netbios_name = true;
        }
    }

    void get_netbios_name (data_buffer<MAX_NETBIOS_NAME> &netbios_name) const {
        uint8_t c;
        /*
         * NetBIOS names are 16 bytes long, but they are mapped to a 32-byte
         * wide string of alphabet (A,B...O,P) using a
         * reversible, half-ASCII, biased encoding.
         *
         * Encoding algorithm:
         * Each 4-bit, half-octet of the NetBIOS name is treated as an 8-bit,
         * right-adjusted, zero-filled binary number.  This number is added to 
         * value of the ASCII character 'A' (hexidecimal 41).  The resulting
         * 8-bit number is stored in the appropriate byte.
         *
         * Decoding is the reverse of the encoding process.
         * Reference:
         * https://datatracker.ietf.org/doc/html/rfc1001#section-14.1
         */
         for (int i = 0; i < MAX_NETBIOS_NAME; i++) {
             c = (((uint8_t)buffer[2 * i] - int('A')) << 4) |
                     (((uint8_t)buffer[2 * i + 1] - int('A')) & 0x0f);
            netbios_name.copy(c);
         }
    }
 
    bool is_netbios() const {
        return is_netbios_name;
    }

    // check_netbios() returns true if and only if this name is a NetBIOS
    // name, as defined in RFC 1001.
    //

    bool check_netbios() const {
        if (readable_length() == 33) {
            for (const uint8_t *b=buffer; b < data - 1; b++) {
                if (is_netbios_char(*b) == false) {
                    return false;
                }
            }
        }
        else {
            return false;
        }
        return true;
    }

    bool is_netbios_char(uint8_t c) const {
        if (c < 'A' || c > 'P') {
            return false;
        }
        return true;
    }

};

// The SOA RDATA format consists of these ordered fields:
//
// MNAME:   The <domain-name> of the name server that was the original or
//          primary source of data for this zone.
//
// RNAME:   A <domain-name> which specifies the mailbox of the
//          person responsible for this zone.
//
// SERIAL:  The unsigned 32 bit version number of the original copy
//          of the zone.
//
// REFRESH: A 32 bit time interval before the zone should be
//          refreshed.
//
// RETRY:   A 32 bit time interval that should elapse before a
//          failed refresh should be retried.
//
// EXPIRE:  A 32 bit time value that specifies the upper limit on
//          the time interval that can elapse before the zone is no
//          longer authoritative.
//
// MINIMUM: The unsigned 32 bit minimum TTL field that should be
//          exported with any RR from this zone.
//
class soa_rdata {
    dns_name mname;
    dns_name rname;
    encoded<uint32_t> serial;
    encoded<uint32_t> refresh;
    encoded<uint32_t> retry;
    encoded<uint32_t> expire;
    encoded<uint32_t> minimum;
    bool valid;

public:
    soa_rdata(datum &d, const datum &dns_body) :
        mname{d, dns_body},
        rname{d, dns_body},
        serial{d},
        refresh{d},
        retry{d},
        expire{d},
        minimum{d},
        valid{d.is_not_null() && !mname.is_null() && !rname.is_null()}
    {}

    void write_json(json_object &o) const {
        if (valid) {
            o.print_key_json_string("mname", mname.buffer, mname.readable_length());
            o.print_key_json_string("rname", rname.buffer, rname.readable_length());
            o.print_key_uint("serial", serial);
            o.print_key_uint("refresh", refresh);
            o.print_key_uint("retry", retry);
            o.print_key_uint("expire", expire);
            o.print_key_uint("minimum", minimum);
        }
    }
};

struct dns_question_record {
    struct dns_name name;
    uint16_t rr_type;
    uint16_t rr_class;
    bool cache;

    dns_question_record() : name{}, rr_type{0}, rr_class{0}, cache{false} {}

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
            if (name.is_netbios()) {
                data_buffer<MAX_NETBIOS_NAME> netbios_name;
                name.get_netbios_name(netbios_name);
                rr.print_key_json_string("name", netbios_name.buffer, netbios_name.readable_length());
            }
            else {
                rr.print_key_json_string("name", name.buffer, name.readable_length());
            }
            rr.print_key_uint("type", rr_type);
            rr.print_key_uint("class", rr_class);
            rr.close();
        }
    }
    void write_json(struct json_object &o) const {
        bool is_netbios = false;
        if (name.is_not_empty()) {
            if (name.is_netbios()) {
                is_netbios = true;
                data_buffer<MAX_NETBIOS_NAME> netbios_name;
                name.get_netbios_name(netbios_name);
                o.print_key_json_string("name", netbios_name.buffer, netbios_name.readable_length());
            } else {
                o.print_key_json_string("name", name.buffer, name.readable_length());
            }
            const char *type_name = get_rr_type_name(rr_type, is_netbios);
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

                /*
                 * The type code 32 or 0x20 has different meaning in netbios.
                 * In netbios, 
                 * NBSTAT uses code 32
                 * In DNS, mDNS,
                 * SRV uses code 32
                 */
                } else if (!question_record.name.is_netbios() and
                           (dns_rr_type)question_record.rr_type == dns_rr_type::SRV) {
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
                    if (!target.is_null()) {
                        srv.print_key_json_string("target", target.buffer, target.readable_length());
                    }

                    srv.close();

                } else if (question_record.name.is_netbios() and
                           (netbios_rr_type)question_record.rr_type == netbios_rr_type::NBSTAT) {

                    struct json_object nbstat{rr, "nbstat"};
                    uint8_t num_names;
                    tmp_rdata.read_uint8(&num_names);
                    datum nb_name; /* 16 byte fixed length netbios name - reference from rfc1002*/
                    datum name_flags; /* 2 byte name flags */
                    struct json_array names{nbstat, "names"};
                    for (int i = 0; i < num_names; i++) {
                        struct json_object name{names};
                        nb_name.parse(tmp_rdata, 16);
                        name.print_key_json_string("name", nb_name);
                        name_flags.parse(tmp_rdata, 2);
                        name.print_key_hex("name_flags", name_flags);
                        name.close();
                    }
                    names.close();

                    eth_addr unit_id{tmp_rdata};
                    nbstat.print_key_value("unit_id", unit_id);

                    encoded<uint8_t> jumpers(tmp_rdata);
                    nbstat.print_key_uint8("jumpers", jumpers.value());

                    encoded<uint8_t> test_result(tmp_rdata);
                    nbstat.print_key_uint8("test_result", test_result.value());

                    encoded<uint16_t> version_number(tmp_rdata);
                    nbstat.print_key_uint16("version_number", version_number.value());

                    encoded<uint16_t> period_of_stats(tmp_rdata);
                    nbstat.print_key_uint16("period_of_statistics", period_of_stats.value());

                    encoded<uint16_t> number_of_crcs(tmp_rdata);
                    nbstat.print_key_uint16("number_of_crcs", number_of_crcs.value());

                    encoded<uint16_t> align_errors(tmp_rdata);
                    nbstat.print_key_uint16("number_of_alignment_errors", align_errors.value());

                    encoded<uint16_t> collisions(tmp_rdata);
                    nbstat.print_key_uint16("number_of_collisions", collisions.value());

                    encoded<uint16_t> send_aborts(tmp_rdata);
                    nbstat.print_key_uint16("number_of_send_aborts", send_aborts.value());

                    encoded<uint32_t> good_sends(tmp_rdata);
                    nbstat.print_key_uint("number_of_good_sends", good_sends.value());

                    encoded<uint32_t> good_receives(tmp_rdata);
                    nbstat.print_key_uint("number_of_good_receives", good_receives.value());

                    encoded<uint16_t> retransmits(tmp_rdata);
                    nbstat.print_key_uint16("number_of_retransmits", retransmits.value());

                    encoded<uint16_t> no_res_cond(tmp_rdata);
                    nbstat.print_key_uint16("number_of_no_resource_conditions", no_res_cond.value());

                    encoded<uint16_t> cmd_blocks(tmp_rdata);
                    nbstat.print_key_uint16("number_of_command_blocks", cmd_blocks.value());

                    encoded<uint16_t> pending_session(tmp_rdata);
                    nbstat.print_key_uint16("number_of_pending_sessions", pending_session.value());

                    encoded<uint16_t> max_pending_session(tmp_rdata);
                    nbstat.print_key_uint16("max_pending_sessions", max_pending_session.value());

                    encoded<uint16_t> max_session(tmp_rdata);
                    nbstat.print_key_uint16("max_total_sessions_possible", max_session.value());

                    encoded<uint16_t> packet_size(tmp_rdata);
                    nbstat.print_key_uint16("session_data_packet_size", packet_size.value());

                    nbstat.close();
                } else if ((dns_rr_type)question_record.rr_type == dns_rr_type::NSEC) {

                    struct json_object nsec{rr, "nsec"};

                    struct dns_name next_name;
                    next_name.parse(tmp_rdata, body);
                    if (!next_name.is_null()) {
                        nsec.print_key_json_string("next_domain_name", next_name.buffer, next_name.readable_length());
                    }

                    nsec.print_key_hex("type_bit_maps", tmp_rdata);
                    nsec.close();
                } else if ((dns_rr_type)question_record.rr_type == dns_rr_type::PTR) {

                    struct dns_name domain_name;
                    domain_name.parse(tmp_rdata, body);
                    if (!domain_name.is_null()) {
                        rr.print_key_json_string("domain_name", domain_name.buffer, domain_name.readable_length());
                    }
                } else if ((netbios_rr_type)question_record.rr_type == netbios_rr_type::NB) {

                    struct json_object nb{rr, "nb"};
                    encoded<uint16_t> nb_flags(tmp_rdata);

                    nb.print_key_uint8("group_name_flag", nb_flags.slice<0,1>());
                    nb.print_key_uint8("owner_node_type", nb_flags.slice<1,3>());
                    
                    struct ipv4_addr addr;
                    addr.parse(tmp_rdata);
                    nb.print_key_value("ipv4_addr", addr);
                    nb.close();
                } else if ((dns_rr_type)question_record.rr_type == dns_rr_type::NS) {

                    struct dns_name domain_name;
                    domain_name.parse(tmp_rdata, body);
                    if (!domain_name.is_null()) {
                        rr.print_key_json_string("ns_domain_name", domain_name.buffer, domain_name.readable_length());
                    }

                } else if ((dns_rr_type)question_record.rr_type == dns_rr_type::SOA) {
                    soa_rdata soa{tmp_rdata, body};
                    soa.write_json(rr);
                }
            } else {
                rr.print_key_hex("rdata", tmp_rdata);
            }
            rr.close();
        }
    }

    bool is_not_empty() const { return question_record.is_not_empty(); }
};

struct dns_packet : public base_protocol {
    dns_hdr *header;
    struct datum records;
    size_t length;
    uint16_t qdcount, ancount, nscount, arcount;
    static const uint16_t max_count = 256;
    bool is_netbios;

    dns_packet(struct datum &d) : header{NULL}, records{NULL, NULL}, length{0}, is_netbios{false} {
        parse(d);
    }

    void parse(struct datum &d) {
        length = d.length();
        header = d.get_pointer<dns_hdr>();
        if (header == nullptr) {
            return;         // too short
        }
        qdcount = ntoh(header->qdcount);
        ancount = ntoh(header->ancount);
        nscount = ntoh(header->nscount);
        arcount = ntoh(header->arcount);
        if ((qdcount == 0 && ancount == 0)
            || qdcount > dns_packet::max_count
            || ancount > dns_packet::max_count
            || nscount > dns_packet::max_count
            || arcount > dns_packet::max_count) {

            header = NULL;  // invalid format, not a DNS packet
            return;
        }
        records = d;

        // format check
        //fprintf(stderr, "qd: %u\tan: %u\tns: %u\tar: %u\tlength: %zu\tweighted sum: %zu\n", qdcount, ancount, nscount, arcount, length, qdcount * 5 + (ancount + nscount + arcount) * 15 - sizeof(dns_hdr));

        // trial parsing, just to verify dns packet formatting
        struct datum record_list = records; // leave records element unchanged (const)
        for (unsigned int count = 0; count < qdcount; count++) {
            dns_question_record question_record;
            question_record.parse(record_list, records);
            if (question_record.is_not_empty() == false) {
                records.set_null();
                header = NULL;
                // fprintf(stderr, "notice: trial parsing setting dns packet to null on question_record %u\n", count);
                return;
            }

            // check for NetBIOS
            if (question_record.name.is_netbios()) {
                is_netbios = true;
            }
        }
        // If qdcount == 0, which can happen in mDNS, then
        // attempt a parse of a resource record
        if (qdcount == 0) {
            for (unsigned int count = 0; count < ancount; count++) {
                dns_resource_record resource_record;
                resource_record.parse(record_list, records);
                if (resource_record.is_not_empty() == false) {
                    records.set_null();
                    header = NULL;
                    return;
                }

                if (resource_record.question_record.name.is_netbios()) {
                    is_netbios = true;
                }
            }
        }
    }

    struct datum get_datum() const {
        if (header == nullptr) {
            return {nullptr, nullptr};
        }
        uint8_t *pkt = (uint8_t *)header;
        return {pkt, pkt + length};
    }

    bool is_not_empty() {
        return (header != NULL);
    }

    bool netbios() {
        return is_netbios;
    }

    void write_json(struct json_object &o) const {
        if (header == NULL) {
            return;
        }
        const char *key = encoded<uint16_t>{header->flags}.bit<0>() ?  "response" : "query";
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

    // mask:   0040fe8eff00ff00fee0
    // value:  00000000000000000000

    static constexpr mask_and_value<16> matcher_new {
        { 0x00, 0x00, // ID
          0x00, 0x00, // Flags
          0xff, 0x00, // QDCOUNT
          0xff, 0x00, // ANCOUNT
          0xff, 0x00, // NSCOUNT
          0xff, 0x00, // ARCOUNT
          0x00, 0x00,
          0x00, 0x00
        },
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
    };

    static constexpr mask_and_value<8> matcher {
        { 0x00, 0x00, 0x10, 0x48, 0xff, 0x00, 0xff, 0x80 },
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
    };

    /*
     * In dns over tcp, the message is prefixed with a two byte length field
     * which gives the message length excluding the two byte length field.
     * This length field allows the low-level processing to assemble a
     * complete message before beginning to parse it.
     */
    static constexpr mask_and_value<8> tcp_matcher {
        { 0x00, 0x00, 0x00, 0x00, 0x10, 0x48, 0xff, 0x00 },
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
    };

    // server_matcher and client_matcher are obsolete
    //
    static constexpr mask_and_value<8> server_matcher {
        { 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff, 0x00 },
        { 0x00, 0x00, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00 }
    };
    static constexpr mask_and_value<8> client_matcher {
        { 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff, 0x00 },
        { 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 }
    };

};

std::string dns_get_json_string(const char *dns_pkt, ssize_t pkt_len);

namespace {

    [[maybe_unused]] int dns_fuzz_test(const uint8_t *data, size_t size) {
        struct datum request_data{data, data+size};
        char buffer[8192];
        struct buffer_stream buf_json(buffer, sizeof(buffer));
        struct json_object record(&buf_json);
        

        dns_packet request{request_data};
        if (request.is_not_empty()) {
            request.write_json(record);            
        }

        return 0;
    }

};

#endif /* DNS_H */
