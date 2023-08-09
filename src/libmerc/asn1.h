/*
 * asn1.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef ASN1_H
#define ASN1_H

#include <stdexcept>

#include "datum.h"
#include "json_object.h"
#include "utils.h"
#include "asn1/oid.h"

namespace std {
    template <>  struct hash<struct datum>  {
        std::size_t operator()(const struct datum& p) const {
            size_t x = 5381;
            const uint8_t *tmp = p.data;
            while (tmp < p.data_end) {
                x = (33 * x) + *tmp;
            }
            return x;
        }
    };
}

/*
 * utility functions
 */

static void utc_to_generalized_time(uint8_t gt[15], const uint8_t utc[13]) {
    if (utc[0] < '5') {
        gt[0] = '2';
        gt[1] = '0';
    } else {
        gt[0] = '1';
        gt[1] = '9';
    }
    memcpy(gt + 2, utc, 13);
}

void fprintf_json_string_escaped(struct buffer_stream &buf, const char *key, const uint8_t *data, unsigned int len);
void fprintf_json_char_escaped(FILE *f, unsigned char x);
void fprintf_json_char_escaped(struct buffer_stream &buf, unsigned char x);
void fprintf_ip_address(FILE *f, const uint8_t *buffer, size_t length);
void fprintf_ip_address(struct buffer_stream &buf, const uint8_t *buffer, size_t length);
void fprintf_json_utctime(FILE *f, const char *key, const uint8_t *data, unsigned int len);
void fprintf_json_generalized_time(FILE *f, const char *key, const uint8_t *data, unsigned int len);
void fprintf_json_utctime(struct buffer_stream &buf, const char *key, const uint8_t *data, unsigned int len);
void fprintf_json_generalized_time(struct buffer_stream &buf, const char *key, const uint8_t *data, unsigned int len);
int generalized_time_gt(const uint8_t *d1, unsigned int l1, const uint8_t *d2, unsigned int l2);
int utctime_to_generalized_time(uint8_t *gt, size_t gt_len, const uint8_t *utc_time, size_t utc_len);
inline uint8_t hex_to_raw(const char *hex);
void hex_string_print_as_oid(FILE *f, const char *c, size_t length);
void raw_string_print_as_oid(FILE *f, const uint8_t *raw, size_t length);
void raw_string_print_as_oid(struct buffer_stream &buf, const uint8_t *raw, size_t length);


/*
 * json_object extensions for printing to TLVs
 */

static const char *oid_empty_string = "";

struct json_object_asn1 : public json_object {
    explicit json_object_asn1(struct buffer_stream *buf) : json_object(buf) {}
    json_object_asn1(struct json_object &object, const char *name) : json_object(object, name) {
        //fprintf(stderr, "json_object_asn1 constructor\n");
    }
    explicit json_object_asn1(struct json_object &object) : json_object(object) {
        //fprintf(stderr, "json_object_asn1 constructor\n");
    }
    explicit json_object_asn1(struct json_array &array);

    void print_key_oid(const char *k, const struct datum &value) {
        const char *output = oid::get_string(&value);
        write_comma(comma);
        if (output != oid_empty_string) {
            b->snprintf("\"%s\":\"%s\"", k, output);
        } else {
            b->snprintf("\"%s\":\"", k);
            if (value.data && value.data_end) {
                raw_string_print_as_oid(*b, value.data, value.data_end - value.data);
            }
            b->write_char('\"');
        }
    }

    void print_key_bitstring_flags(const char *name, const struct datum &value, char * const *flags) {
        struct json_array a{*this, name};
        if (value.is_not_empty()) {
            struct datum p = value;
            char *const *tmp = flags;
            uint8_t number_of_unused_bits = 0;
            p.read_uint8(&number_of_unused_bits);
            while (p.data < p.data_end-1) {
                for (uint8_t x = 0x80; x > 0; x=x>>1) {
                    if (x & *p.data) {
                        if (*tmp) {
                            a.print_string(*tmp);
                        }         // note: we don't report excess length
                    }
                    if (*tmp) {
                        tmp++;
                    }
                }
                p.data++;
            }
            if (p.is_not_empty()) {
                uint8_t terminus = 0x80 >> (8-number_of_unused_bits);
                for (uint8_t x = 0x80; x > terminus; x=x>>1) {
                    if (x & *p.data) {
                        if (*tmp) {
                            a.print_string(*tmp);
                        }         // note: we don't report excess length
                    }
                    if (*tmp) {
                        tmp++;
                    }
                }
            }
        }
        a.close();
        comma = true;
    }

    void print_key_escaped_string(const char *k, const struct datum &value) {
        write_comma(comma);
        fprintf_json_string_escaped(*b, k, value.data, value.data_end - value.data);
    }

    /*
     * UTCTime (Coordinated Universal Time) consists of 13 bytes that
     * encode the Greenwich Mean Time in the format YYMMDDhhmmssZ.  For
     * instance, the bytes 17 0d 31 35 31 30 32 38 31 38 35 32 31 32 5a
     * encode the string "151028185212Z", which represents the time
     * "2015-10-28 18:52:12"
     */
    void print_key_utctime(const char *key, const uint8_t *data, unsigned int len) {
        write_comma(comma);
        b->snprintf("\"%s\":\"", key);
        if (len != 13) {
            b->snprintf("malformed\"");
            return;
        }
        if (data[0] < '5') {
            b->snprintf("20");
        } else {
            b->snprintf("19");
        }
        fprintf_json_char_escaped(*b, data[0]);
        fprintf_json_char_escaped(*b, data[1]);
        b->write_char('-');
        fprintf_json_char_escaped(*b, data[2]);
        fprintf_json_char_escaped(*b, data[3]);
        b->write_char('-');
        fprintf_json_char_escaped(*b, data[4]);
        fprintf_json_char_escaped(*b, data[5]);
        b->write_char(' ');
        fprintf_json_char_escaped(*b, data[6]);
        fprintf_json_char_escaped(*b, data[7]);
        b->write_char(':');
        fprintf_json_char_escaped(*b, data[8]);
        fprintf_json_char_escaped(*b, data[9]);
        b->write_char(':');
        fprintf_json_char_escaped(*b, data[10]);
        fprintf_json_char_escaped(*b, data[11]);
        fprintf_json_char_escaped(*b, data[12]);
        b->write_char('\"');
    }

    /*
     *  For the purposes of [RFC 5280], GeneralizedTime values MUST be
     *  expressed in Greenwich Mean Time (Zulu) and MUST include seconds
     *  (i.e., times are YYYYMMDDHHMMSSZ), even where the number of
     *  seconds is zero.
     */
    void print_key_generalized_time(const char *key, const uint8_t *data, unsigned int len) {
        write_comma(comma);
        b->snprintf("\"%s\":\"", key);
        if (len != 15) {
            b->snprintf("malformed (length %u)\"", len);
            return;
        }
        fprintf_json_char_escaped(*b, data[0]);
        fprintf_json_char_escaped(*b, data[1]);
        fprintf_json_char_escaped(*b, data[2]);
        fprintf_json_char_escaped(*b, data[3]);
        b->write_char('-');
        fprintf_json_char_escaped(*b, data[4]);
        fprintf_json_char_escaped(*b, data[5]);
        b->write_char('-');
        fprintf_json_char_escaped(*b, data[6]);
        fprintf_json_char_escaped(*b, data[7]);
        b->write_char(' ');
        fprintf_json_char_escaped(*b, data[8]);
        fprintf_json_char_escaped(*b, data[9]);
        b->write_char(':');
        fprintf_json_char_escaped(*b, data[10]);
        fprintf_json_char_escaped(*b, data[11]);
        b->write_char(':');
        fprintf_json_char_escaped(*b, data[12]);
        fprintf_json_char_escaped(*b, data[13]);
        fprintf_json_char_escaped(*b, data[14]);
        b->write_char('\"');
    }

    void print_key_ip_address(const char *name, const datum &value) {
        write_comma(comma);
        b->snprintf("\"%s\":\"", name);
        fprintf_ip_address(*b, value.data, value.data_end - value.data);
        b->write_char('\"');
    }

};


struct json_array_asn1 : public json_array {
    explicit json_array_asn1(struct buffer_stream *b) : json_array(b) { }
    explicit json_array_asn1(struct json_object &object, const char *name) : json_array(object, name) { }
    void print_oid(const struct datum &value) {
        const char *output = oid::get_string(&value);
        write_comma(comma);
        if (output != oid_empty_string) {
            b->snprintf("\"%s\"", output);
        } else {
            b->write_char('\"');
            if (value.data && value.data_end) {
                raw_string_print_as_oid(*b, value.data, value.data_end - value.data);
            }
            b->write_char('\"');
        }
    }
};

/*
 * struct tlv holds the tag, length, and (pointers to the beginning
 * and end of the) value.  ASN.1 consists of a sequence of TLV
 * elements, and a struct tlv represents one of these elements.
 *
 * A struct tlv can be initialized to a null value, or initialized
 * with data.  To read data into a struct tlv, call the member
 * function 'parse()'.  The pointers in the 'value' member of a struct
 * tlv are either NULL, or are set to point to a region of memory by
 * the call to parse().
 *
 * WARNING: if that memory is deallocated or changed, the pointers in
 * the struct tlv object will be invalid.  To prevent a struct tlv
 * object from having dangling pointers, its scope MUST be no larger
 * than the scope of the memory buffer it is parsing.
 */

struct tlv {
    unsigned char tag;
    size_t length;
    struct datum value;

    bool operator == (const struct tlv &r) {
        return !is_valid() && tag == r.tag && length == r.length && value.cmp(r.value) == 0;
    }

    constexpr static unsigned char explicit_tag(unsigned char tag) {
        return 0x80 + tag;  // warning: tag must be between 0 and 31 inclusive
    }
    constexpr static unsigned char explicit_tag_constructed(unsigned char tag) {
        return 0xa0 + tag;  // warning: tag must be between 0 and 31 inclusive
    }

    enum tag {
        END_OF_CONTENT	  = 0x00,
        BOOLEAN	          = 0x01,
        INTEGER		      = 0x02,
        BIT_STRING		  = 0x03,
        OCTET_STRING      = 0x04,
        NULL_TAG          = 0x05,
        OBJECT_IDENTIFIER = 0x06,
        OBJECT_DESCRIPTOR = 0x07,
        EXTERNAL          = 0x08,
        REAL  		      = 0x09,
        ENUMERATED	      = 0x0a,
        EMBEDDED_PDV	  = 0x0b,
        UTF8String		  = 0x0c,
        RELATIVE_OID      = 0x0d,
        TIME		      = 0x0e,
        RESERVED	      = 0x0f,
        SEQUENCE          = 0x30,  // also "SEQUENCE OF"
        SET 		      = 0x31,  // also "SET OF"
        NUMERIC_STRING	  = 0x12,
        PRINTABLE_STRING  = 0x13,
        T61String		  = 0x14,
        VIDEOTEX_STRING   = 0x15,
        IA5String		  = 0x16,
        UTCTime		      = 0x17,
        GeneralizedTime	  = 0x18,
        GraphicString	  = 0x19,
        VisibleString	  = 0x1a,
        GeneralString	  = 0x1b,
        UniversalString	  = 0x1c,
        CHARACTER_STRING  = 0x1d,
        BMP_STRING		  = 0x1e
    };

    bool is_not_null() const {
        return (value.data);
    }
    bool is_null() const {
        return (value.data == NULL);
    }
    bool is_valid() const {
        return value.is_not_empty() || length == 0;
    }
    bool is_truncated() const {
        return value.data != NULL && value.length() != (ssize_t) length;
    }
    bool is_complete() const {
        return value.data != NULL && value.length() == (ssize_t) length;
    }
    uint8_t get_little_tag() const { return tag & 0x1f; }
    tlv() {
        // initialize to null/zero
        tag = 0;
        length = 0;
        value.data = NULL;
        value.data_end = NULL;
    }
    tlv(const tlv &r) : tag{0}, length{0}, value{NULL, NULL} {
        tag = r.tag;
        length = r.length;
        value.data = r.value.data;
        value.data_end = r.value.data_end;
    }
    void operator=(const tlv &r) {
        tag = r.tag;
        length = r.length;
        value.data = r.value.data;
        value.data_end = r.value.data_end;
    }
    explicit tlv(struct datum *p, uint8_t expected_tag=0x00, const char *tlv_name=NULL) : tag{0}, length{0}, value{NULL, NULL} {
        parse(p, expected_tag, tlv_name);
    }
    void handle_parse_error(const char *msg, const char *tlv_name) {
#ifdef TLV_ERR_INFO
        printf_err(log_none, "%s in %s\n", msg, tlv_name ? tlv_name : "unknown TLV");
#else
        (void)msg;
        (void)tlv_name;
#endif
#ifdef THROW
        throw std::runtime_error(msg);
#endif
    }
    void parse(struct datum *p, uint8_t expected_tag=0x00, const char *tlv_name=NULL) {

        if (p->data == NULL) {
            handle_parse_error("warning: NULL data", tlv_name ? tlv_name : "unknown TLV");
            return;
        }
        if (p->length() < 2) {
            p->set_empty();  // parser is no longer good for reading
            // fprintf(stderr, "error: incomplete data (only %ld bytes in %s)\n", p->data_end - p->data, tlv_name ? tlv_name : "unknown TLV");
            handle_parse_error("warning: incomplete data", tlv_name);
            return;  // leave tlv uninitialized
        }

        if (expected_tag && p->data[0] != expected_tag) {
            // fprintf(stderr, "note: unexpected type (got %02x, expected %02x)\n", p->data[0], expected_tag);
            // p->set_empty();  // TODO: do we want this?  parser is no longer good for reading

            handle_parse_error("note: unexpected type", tlv_name);
            return;  // unexpected type
        }
        // set tag
        tag = p->data[0];
        length = p->data[1];

        p->skip(2);

        // set length
        if (length >= 128) {
            ssize_t num_octets_in_length = length - 128;  // note: signed to avoid underflow
            if (num_octets_in_length < 0) {
                p->set_empty();  // parser is no longer good for reading
                handle_parse_error("error: invalid length field", tlv_name);
                return;
            }
            if (p->read_uint(&length, num_octets_in_length) == false) {
                p->set_empty();  // parser is no longer good for reading
                // fprintf(stderr, "error: could not read length (want %lu bytes, only %ld bytes remaining)\n", length, p->length());
                handle_parse_error("warning: could not read length", tlv_name);
                return;
            }
        }

        // we could check if value field is truncated here, but we don't for now
        //
        // if (p->length() < (signed)length) {
        //     fprintf(stderr, "warning: value field is truncated (wanted %lu bytes, only %zd bytes remaining)\n", length, p->length());
        // }

        // set value
        value.init_from_outer_parser(p, length);

#ifdef ASN1_DEBUG
        fprint_tlv(stderr, tlv_name);
        // fprintf(stderr, "remainder:\t"); p->fprint_hex(stderr); fprintf(stderr, "\n");
#endif
    }

    // tlv constructor for parsing data from a datum
    //
    tlv(datum &d, uint8_t tag=0x00, const char *name=NULL) {
        parse(&d, tag, name);
    }

    // tlv constructor for parsing data from another tlv value
    //
    tlv(tlv &o, uint8_t tag=0x00, const char *name=NULL) {
        parse(&o.value, tag, name);
    }

    // constructor for writing tlv-encoded data
    //
    explicit tlv(uint8_t tag_, datum value_) :
        tag{tag_},
        length{value_.length()},
        value{value_}
    { }

    void set(uint8_t tag_, datum value_) {
        tag    = tag_;
        length = length_of_length_field(value_.length());
        value  = value_;
    }

    size_t encoded_length() const {
        // fprintf(stderr,
        //         "encoding length: %zu:%u:%zu:\t%zu\n",
        //         sizeof(tag),
        //         length_of_length(length),
        //         length,
        //         sizeof(tag) + length_of_length(length) + length
        //         );
        return sizeof(tag) + length_of_length_field(length) + length;  // note: inapplicable for tlv::SEQUENCE
    }

    static uint8_t length_of_length_field(size_t s) {
        if (s <= 127) {
            //
            // short form: single octet
            //
            return 1;
        }
        // long form: the first octet encodes the number of octets
        // used to encode the length field
        //
        if (s < 0x100) {
            return 2;
        }
        if (s < 0x10000) {
            return 3;
        }
        if (s < 0x1000000) {
            return 4;
        }
        if (s < 0x100000000) {
            return 5;
        }
        if (s < 0x10000000000) {
            return 6;
        }
        if (s < 0x1000000000000) {
            return 7;
        }
        return 8;
    }

    // write_tag_and_length() writes the ASN.1-encoded Tag and Length (but
    // not Value) into a writeable buffer
    //
    void write_tag_and_length(writeable &buf, bool swap_byte_order=false) const {
        (void)swap_byte_order;

        buf << encoded<uint8_t>{tag};

        // Length field format
        //
        // Short form: one octet long. Bit 8 has value "0" and bits
        // 7–1 give the length.
        //
        // Long form: 2 to 127 octets long. Bit 8 of its first octet
        // has value "1" and bits 7–1 give the number of additional
        // length octets. Second and following octets give the length,
        // base 256, most significant digit first.
        //

        size_t total = 0;
        if (length <= 127) {
            buf << encoded<uint8_t>{length};
            total += 1;
        } else {
            buf << encoded<uint8_t>{0x80 | (length_of_length_field(length) - 1)};
            total += 1;
            size_t tmp = length;
            if (tmp >= 0x1000000) {
                buf << encoded<uint8_t>{(length >> 24) & 0xff};
                        total += 1;
            }
            if (tmp >= 0x10000) {
                buf << encoded<uint8_t>{(length >> 16) & 0xff};
                        total += 1;
            }
            if (tmp >= 0x100) {
                buf << encoded<uint8_t>{(length >> 8) & 0xff};
                total += 1;
            }
            buf << encoded<uint8_t>{tmp & 0xff};
            total += 1;
        }
        //        fprintf(stderr, "length encoding used %zu bytes (lol: %u)\n", total, length_of_length(length));
    }

    // write() writes the ASN.1-encoded TLV into a writeable buffer
    //
    void write(writeable &buf, bool swap_byte_order=false) {
        write_tag_and_length(buf, swap_byte_order);
        buf << value;
    }

    void remove_bitstring_encoding() {
        if (!is_valid()) {
            return;
        }
        uint8_t first_octet = 0;
        value.read_uint8(&first_octet);
        if (first_octet) {
            // throw std::runtime_error("error removing bitstring encoding");
            value.set_null();
            return;
        }
        if (length > 0) {
            length = length - 1;
        }
    }
    /*
     * fprintf_tlv(f, name) prints the ASN1 TLV details to f
     *
     * Tag notation: (Tag Class:Constructed:Tag Number)
     *
     *    Tag Class: 0=universal (native to ASN.1), 1=Application
     *    specific, 2=Context-specific, 3=Private
     *
     *    Constructed: 1=yes (value contains zero or more element
     *    encodings), 0=no (primitive)
     *
     *    Tag Number: 0-31
     *
     * End-of-Content (EOC)		0	0
     * BOOLEAN		            1	1
     * INTEGER		            2	2
     * BIT STRING		        3	3
     * OCTET STRING		        4	4
     * NULL		                5	5
     * OBJECT IDENTIFIER		6	6
     * Object Descriptor		7	7
     * EXTERNAL		            8	8
     * REAL (float)		        9	9
     * ENUMERATED		       10	A
     * EMBEDDED PDV		       11	B
     * UTF8String		       12	C
     * RELATIVE-OID		       13	D
     * TIME		               14	E
     * Reserved		           15	F
     * SEQUENCE, SEQUENCE OF   16	10
     * SET and SET OF		   17	11
     * NumericString		   18	12
     * PrintableString		   19	13
     * T61String		       20	14
     * VideotexString		   21	15
     * IA5String		       22	16
     * UTCTime		           23	17
     * GeneralizedTime		   24	18
     * GraphicString		   25	19
     * VisibleString		   26	1A
     * GeneralString		   27	1B
     * UniversalString		   28	1C
     * CHARACTER STRING		   29	1D
     * BMPString		       30	1E
     * DATE		               31	1F *** LONG FORM TAG NUMBER ***
     * TIME-OF-DAY		       32	20 *** LONG FORM TAG NUMBER ***
     * DATE-TIME		       33	21 *** LONG FORM TAG NUMBER ***
     * DURATION		           34	22 *** LONG FORM TAG NUMBER ***
     * OID-IRI		           35	23 *** LONG FORM TAG NUMBER ***
     * RELATIVE-OID-IRI		   36	24 *** LONG FORM TAG NUMBER ***
     */

    void fprint_tlv(FILE *f, const char *tlv_name) const {
        const char *type[32] = {
            "End-of-Content",
            "BOOLEAN",
            "INTEGER",
            "BIT STRING",
            "OCTET STRING",
            "NULL",
            "OBJECT IDENTIFIER",
            "Object Descriptor",
            "EXTERNAL",
            "REAL (float)",
            "ENUMERATED",
            "EMBEDDED PDV",
            "UTF8String",
            "RELATIVE-OID",
            "TIME",
            "Reserved",
            "SEQUENCE, SEQUENCE OF",
            "SET and SET OF",
            "NumericString",
            "PrintableString",
            "T61String",
            "VideotexString",
            "IA5String",
            "UTCTime",
            "GeneralizedTime",
            "GraphicString",
            "VisibleString",
            "GeneralString",
            "UniversalString",
            "CHARACTER STRING",
            "BMPString"
        };
        if (!is_valid()) {
            return;
        }
        if (true || value.data) {
            uint8_t tag_class = tag >> 6;
            uint8_t constructed = (tag >> 5) & 1;
            uint8_t tag_number = tag & 31;
            if (tag_class == 2) {
                // tag is context-specific
                fprintf(f, "T:%02x (%u:%u:%u, explicit tag %u)\tL:%08zu\tV:", tag, tag_class, constructed, tag_number, tag_number, length);
            } else {
                fprintf(f, "T:%02x (%u:%u:%u, %s)\tL:%08zu\tV:", tag, tag_class, constructed, tag_number, type[tag_number], length);
            }
            value.fprint_hex(f);
            if (tlv_name) {
                fprintf(f, "\t(%s)\n", tlv_name);
            } else {
                fprintf(f, "\n");
            }
        } else {
            fprintf(f, "null (%s)\n", tlv_name);
        }
    }

    inline bool is_constructed() const {
        return tag & 0x20;
    }

    // is_der_format(data, length) is a spot-check to provide
    // early detection of malformed input, not a complete check
    //
    static bool is_der_format(const void *data, size_t length) {
        uint8_t *d = (uint8_t *)data;
        struct datum p{d, d + length};
        struct tlv test(&p, tlv::SEQUENCE);
        if (test.is_null() || test.length > (length - 2)) {
            return false;
        }
        return true;
    }

    int time_cmp(const struct tlv &t) const {
        if (!is_valid() || !t.is_valid()) {
            return -1;
        }
        ssize_t l1 = value.data_end - value.data;
        ssize_t l2 = t.value.data_end - t.value.data;
        ssize_t min = l1 < l2 ? l1 : l2;
        if (min == 0 || min > 15) {
            return 0;
        }
        // fprintf(stderr, "comparing %zd bytes of times\nl1: %.*s\nl2: %.*s\n", min, l1, value.data, l2, t.value.data);

        const uint8_t *d1 = value.data;
        const uint8_t *d2 = t.value.data;
        uint8_t gt1[15];
        if (tag == tlv::UTCTime) {
            if (l1 != 13) {
                return 0;
            }
            d1 = gt1;
            utc_to_generalized_time(gt1, value.data);
        } else if ((tag == tlv::GeneralizedTime && l1 != 15) || tag != tlv::GeneralizedTime) {
            return 0; // error; attempt to compare non-time value
        }
        uint8_t gt2[15];
        if (t.tag == tlv::UTCTime) {
            if (l2 != 13) {
                return 0;
            }
            d2 = gt2;
            utc_to_generalized_time(gt2, t.value.data);
        } else if ((t.tag == tlv::GeneralizedTime && l2 != 15) || t.tag != tlv::GeneralizedTime) {
            return 0; // error; attempt to compare non-time value
        }

        if (d1 && d2) {
            return memcmp((const char *)d1, (const char *)d2, min);
        }
        return 0;
    }
    void set(enum tlv::tag type, const void *data, size_t len) {
        tag = type;
        length = len;
        value.data = (const uint8_t *)data;
        value.data_end = (const uint8_t *)data + len;
    }

    /*
     * functions for json_object serialization
     */
    void print_as_json_hex(struct json_object &o, const char *name) const {
        if (!is_valid()) {
            return;
        }
        o.print_key_hex(name, value);
        if ((unsigned)value.length() != length) { o.print_key_string("truncated", name); }
    }

    void print_as_json_oid(struct json_object_asn1 &o, const char *name) const {
        if (!is_valid()) {
            return;
        }
        o.print_key_oid(name, value);
        if ((unsigned)value.length() != length) { o.print_key_string("truncated", name); }
    }

    void print_as_json_escaped_string(struct json_object_asn1 &o, const char *name) const {
        if (!is_valid()) {
            return;
        }
        o.print_key_escaped_string(name, value);
        if ((unsigned)value.length() != length) { o.print_key_string("truncated", name); }
    }

    void print_as_json_utctime(struct json_object_asn1 &o, const char *name) const {
        if (!is_valid()) {
            return;
        }
        o.print_key_utctime(name, value.data, value.data_end - value.data);
        if ((unsigned)value.length() != length) { o.print_key_string("truncated", name); }
    }

    void print_as_json_generalized_time(struct json_object_asn1 &o, const char *name) const {
        if (!is_valid()) {
            return;
        }
        o.print_key_generalized_time(name, value.data, value.data_end - value.data);
        if ((unsigned)value.length() != length) { o.print_key_string("truncated", name); }
    }
    void print_as_json_ip_address(struct json_object_asn1 &o, const char *name) const {
        if (!is_valid()) {
            return;
        }
        o.write_comma(o.comma);
        o.b->snprintf("\"%s\":\"", name);
        fprintf_ip_address(*o.b, value.data, value.data_end - value.data);
        o.b->write_char('\"');
        o.comma = ',';
        if ((unsigned)value.length() != length) { o.print_key_string("truncated", name); }
    }

    void print_as_json_bitstring(struct json_object &o, const char *name, bool comma=false) const {
        if (!is_valid()) {
            return;
        }
        const char *format_string = "\"%s\":[";
        if (comma) {
            format_string = ",\"%s\":[";
        }
        o.b->snprintf(format_string, name);
        if (value.data) {
            struct datum p = value;
            uint8_t number_of_unused_bits = 0;
            p.read_uint8(&number_of_unused_bits);
            const char *comma = "";
            while (p.data < p.data_end-1) {
                for (uint8_t x = 0x80; x > 0; x=x>>1) {
                    o.b->snprintf("%s%c", comma, x & *p.data ? '1' : '0');
                    comma = ",";
                }
                p.data++;
            }
            if (!p.is_not_empty()) {
                return;
            }
            uint8_t terminus = 0x80 >> (8-number_of_unused_bits);
            for (uint8_t x = 0x80; x > terminus; x=x>>1) {
                o.b->snprintf("%s%c", comma, x & *p.data ? '1' : '0');
                comma = ",";
            }

        }
        o.b->write_char(']');
        if ((unsigned)value.length() != length) { o.print_key_string("truncated", name); }
    }

    void print_as_json_bitstring_flags(struct json_object_asn1 &o, const char *name, char * const *flags) const {
        if (!is_valid()) {
            return;
        }
        o.print_key_bitstring_flags(name, value, flags);
        if ((unsigned)value.length() != length) { o.print_key_string("truncated", name); }
    }

    void print_as_json(struct json_object_asn1 &o, const char *name) const {
        if (!is_valid()) {
            return;
        }
        switch(tag) {
        case tlv::UTCTime:
            print_as_json_utctime(o, name);
            break;
        case tlv::GeneralizedTime:
            print_as_json_generalized_time(o, name);
            break;
        case tlv::OBJECT_IDENTIFIER:
            print_as_json_oid(o, name);
            break;
        case tlv::PRINTABLE_STRING:
        case tlv::T61String:
        case tlv::VIDEOTEX_STRING:
        case tlv::IA5String:
        case tlv::GraphicString:
        case tlv::VisibleString:
            print_as_json_escaped_string(o, name);
            break;
        case tlv::BIT_STRING:
            print_as_json_bitstring(o, name);
            break;
        default:
            print_as_json_hex(o, name);  // handle unexpected type
        }
    }

    void print_tag_as_json_hex(struct json_object &o, const char *name) const {
        struct datum p{&tag, &tag+1};
        o.print_key_hex(name, p);
    }


#ifdef TLV_FPRINT
    /*
     * functions for printing to a FILE *
     */
    void print_as_json_hex(FILE *f, const char *name, bool comma=false) const {
        const char *format_string = "\"%s\":\"";
        if (comma) {
            format_string = ",\"%s\":\"";
        }
        fprintf(f, format_string, name);
        if (value.data && value.data_end) {
            fprintf_raw_as_hex(f, value.data, value.data_end - value.data);
        }
        fprintf(f, "\"");
    }
    void print_as_json_oid(FILE *f, const char *name, bool comma=false) const {
        const char *format_string = "\"%s\":";
        if (comma) {
            format_string = ",\"%s\":";
        }
        fprintf(f, format_string, name);

        const char *output = oid::datum_get_oid_string(&value);
        if (output != oid_empty_string) {
            fprintf(f, "\"%s\"", output);
        } else {
            fprintf(f, "\"");
            raw_string_print_as_oid(f, value.data, value.data_end - value.data);
            fprintf(f, "\"");
        }

    }
    void print_as_json_utctime(FILE *f, const char *name) const {
        fprintf_json_utctime(f, name, value.data, value.data_end - value.data);
    }
    void print_as_json_generalized_time(FILE *f, const char *name) const {
        fprintf_json_generalized_time(f, name, value.data, value.data_end - value.data);
    }
    void print_as_json_escaped_string(FILE *f, const char *name) const {
        fprintf_json_string_escaped(f, name, value.data, value.data_end - value.data);
    }
    void print_as_json_ip_address(FILE *f, const char *name) const {
        fprintf(f, "{\"%s\":\"", name);
        fprintf_ip_address(f, value.data, value.data_end - value.data);
        fprintf(f, "\"}");
    }
    void print_as_json_bitstring(FILE *f, const char *name, bool comma=false) const {
        const char *format_string = "\"%s\":[";
        if (comma) {
            format_string = ",\"%s\":[";
        }
        fprintf(f, format_string, name);
        if (value.data) {
            struct datum p = value;
            uint8_t number_of_unused_bits;
            p.read_uint8(&number_of_unused_bits);
            const char *comma = "";
            while (p.data < p.data_end-1) {
                for (uint8_t x = 0x80; x > 0; x=x>>1) {
                    fprintf(f, "%s%c", comma, x & *p.data ? '1' : '0');
                    comma = ",";
                }
                p.data++;
            }
            uint8_t terminus = 0x80 >> (8-number_of_unused_bits);
            for (uint8_t x = 0x80; x > terminus; x=x>>1) {
                fprintf(f, "%s%c", comma, x & *p.data ? '1' : '0');
                comma = ",";
            }

        }
        fprintf(f, "]");
    }
    void print_as_json_bitstring_flags(FILE *f, const char *name, char * const *flags, bool comma=false) const {
        const char *format_string = "\"%s\":[";
        if (comma) {
            format_string = ",\"%s\":[";
        }
        fprintf(f, format_string, name);
        if (value.data) {
            struct datum p = value;
            char *const *tmp = flags;
            uint8_t number_of_unused_bits;
            p.read_uint8(&number_of_unused_bits);
            const char *comma = "";
            while (p.data < p.data_end-1) {
                for (uint8_t x = 0x80; x > 0; x=x>>1) {
                    if (x & *p.data) {
                        fprintf(f, "%s\"%s\"", comma, *tmp);
                        comma = ",";
                    }
                    if (*tmp) {
                        tmp++;
                    }
                }
                p.data++;
            }
            uint8_t terminus = 0x80 >> (8-number_of_unused_bits);
            for (uint8_t x = 0x80; x > terminus; x=x>>1) {
                if (x & *p.data) {
                    fprintf(f, "%s\"%s\"", comma, *tmp);
                    comma = ",";
                }
                if (*tmp) {
                    tmp++;
                }
            }

        }
        fprintf(f, "]");
    }

    void print_as_json(FILE *f, const char *name) const {
        switch(tag) {
        case tlv::UTCTime:
            print_as_json_utctime(f, name);
            break;
        case tlv::GeneralizedTime:
            print_as_json_generalized_time(f, name);
            break;
        case tlv::OBJECT_IDENTIFIER:
            print_as_json_oid(f, name);
            break;
        case tlv::PRINTABLE_STRING:
        case tlv::T61String:
        case tlv::VIDEOTEX_STRING:
        case tlv::IA5String:
        case tlv::GraphicString:
        case tlv::VisibleString:
            print_as_json_escaped_string(f, name);
            break;
        case tlv::BIT_STRING:
            print_as_json_bitstring(f, name);
            break;
        default:
            print_as_json_hex(f, name);  // handle unexpected type
        }
    }

    /*
     * functions for json serialization to a buffer_stream
     */
    void print_as_json_hex(struct buffer_stream &buf, const char *name, bool comma=false) const {
        const char *format_string = "\"%s\":\"";
        if (comma) {
            format_string = ",\"%s\":\"";
        }
        buf.snprintf(format_string, name);
        if (value.data && value.data_end) {
            buf.raw_as_hex(value.data, value.data_end - value.data);
        }
        buf.snprintf("\"");
    }

    void print_as_json_oid(struct buffer_stream &buf, const char *name, bool comma=false) const {
        const char *format_string = "\"%s\":";
        if (comma) {
            format_string = ",\"%s\":";
        }
        buf.snprintf(format_string, name);

        const char *output = oid::datum_get_oid_string(&value);
        if (output != oid_empty_string) {
            buf.snprintf("\"%s\"", output);
        } else {
            buf.snprintf("\"");
            raw_string_print_as_oid(buf, value.data, value.data_end - value.data);
            buf.snprintf("\"");
        }

    }
    void print_as_json_utctime(struct buffer_stream &buf, const char *name) const {
        fprintf_json_utctime(buf, name, value.data, value.data_end - value.data);
    }
    void print_as_json_generalized_time(struct buffer_stream &buf, const char *name) const {
        fprintf_json_generalized_time(buf, name, value.data, value.data_end - value.data);
    }
    void print_as_json_escaped_string(struct buffer_stream &buf, const char *name) const {
        fprintf_json_string_escaped(buf, name, value.data, value.data_end - value.data);
    }

    void print_as_json_ip_address(struct buffer_stream &buf, const char *name) const {
        buf.snprintf("{\"%s\":\"", name);
        fprintf_ip_address(buf, value.data, value.data_end - value.data);
        buf.snprintf("\"}");
    }

    void print_as_json_bitstring(struct buffer_stream &buf, const char *name, bool comma=false) const {
        const char *format_string = "\"%s\":[";
        if (comma) {
            format_string = ",\"%s\":[";
        }
        buf.snprintf(format_string, name);
        if (value.data) {
            struct datum p = value;
            uint8_t number_of_unused_bits;
            p.read_uint8(&number_of_unused_bits);
            const char *comma = "";
            while (p.data < p.data_end-1) {
                for (uint8_t x = 0x80; x > 0; x=x>>1) {
                    buf.snprintf("%s%c", comma, x & *p.data ? '1' : '0');
                    comma = ",";
                }
                p.data++;
            }
            uint8_t terminus = 0x80 >> (8-number_of_unused_bits);
            for (uint8_t x = 0x80; x > terminus; x=x>>1) {
                buf.snprintf("%s%c", comma, x & *p.data ? '1' : '0');
                comma = ",";
            }

        }
        buf.write_char(']');
    }

    void print_as_json_bitstring_flags(struct buffer_stream &buf, const char *name, char * const *flags, bool comma=false) const {
        const char *format_string = "\"%s\":[";
        if (comma) {
            format_string = ",\"%s\":[";
        }
        buf.snprintf(format_string, name);
        if (value.data) {
            struct datum p = value;
            char *const *tmp = flags;
            uint8_t number_of_unused_bits;
            p.read_uint8(&number_of_unused_bits);
            const char *comma = "";
            while (p.data < p.data_end-1) {
                for (uint8_t x = 0x80; x > 0; x=x>>1) {
                    if (x & *p.data) {
                        buf.snprintf("%s\"%s\"", comma, *tmp);
                        comma = ",";
                    }
                    if (*tmp) {
                        tmp++;
                    }
                }
                p.data++;
            }
            uint8_t terminus = 0x80 >> (8-number_of_unused_bits);
            for (uint8_t x = 0x80; x > terminus; x=x>>1) {
                if (x & *p.data) {
                    buf.snprintf("%s\"%s\"", comma, *tmp);
                    comma = ",";
                }
                if (*tmp) {
                    tmp++;
                }
            }

        }
        buf.write_char(']');
    }

    void print_as_json(struct buffer_stream &b, const char *name) const {
        switch(tag) {
        case tlv::UTCTime:
            print_as_json_utctime(b, name);
            break;
        case tlv::GeneralizedTime:
            print_as_json_generalized_time(b, name);
            break;
        case tlv::OBJECT_IDENTIFIER:
            print_as_json_oid(b, name);
            break;
        case tlv::PRINTABLE_STRING:
        case tlv::T61String:
        case tlv::VIDEOTEX_STRING:
        case tlv::IA5String:
        case tlv::GraphicString:
        case tlv::VisibleString:
            print_as_json_escaped_string(b, name);
            break;
        case tlv::BIT_STRING:
            print_as_json_bitstring(b, name);
            break;
        default:
            print_as_json_hex(b, name);  // handle unexpected type
        }
    }
#endif // TLV_FPRINT

};

#endif /* ASN1_H */
