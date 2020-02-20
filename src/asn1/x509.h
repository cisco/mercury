/*
 * x509.h
 *
 */

#ifndef X509_H
#define X509_H

#include <stdio.h>
#include <vector>
#include "oid.h"

#include "../mercury.h"
#include "../parser.h"


const char *parser_get_oid_string(struct parser *p) {
    std::string s = p->get_string();
    const char *tmp = s.c_str();    // TBD: refactor to eliminate string allocation
    auto pair = oid_dict.find(s);
    if (pair == oid_dict.end()) {
        return NULL;
    }
    return pair->second.c_str();;
}

/*
 * utility functions
 */

void fprintf_raw_as_hex(FILE *f, const void *data, unsigned int len) {
    const unsigned char *x = (const unsigned char *)data;
    const unsigned char *end = x + len;

    while (x < end) {
        fprintf(f, "%02x", *x++);
    }
}

void fprintf_json_string_escaped(FILE *f, const char *key, const uint8_t *data, unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

    fprintf(f, "\"%s\":\"", key);
    while (x < end) {
        if (*x < 0x20) {                   /* escape control characters   */
            fprintf(f, "\\u%04x", *x);
        } else if (*x > 0x7f) {            /* escape non-ASCII characters */
            fprintf(f, "\\u%04x", *x);
        } else {
            if (*x == '"' || *x == '\\') { /* escape special characters   */
                fprintf(f, "\\");
            }
            fprintf(f, "%c", *x);
        }
        x++;
    }
    fprintf(f, "\"");

}

void fprintf_json_char_escaped(FILE *f, char x) {
    if (x < 0x20) {                   /* escape control characters   */
        fprintf(f, "\\u%04x", x);
    } else if (x > 0x7f) {            /* escape non-ASCII characters */
        fprintf(f, "\\u%04x", x);
    } else {
        if (x == '"' || x == '\\') { /* escape special characters   */
            fprintf(f, "\\");
        }
        fprintf(f, "%c", x);
    }
}

void fprintf_ip_address(FILE *f, const uint8_t *buffer, size_t length) {
    const uint8_t *b = buffer;
    if (length == 4) {
        fprintf(f, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    } else if (length == 16) {
        fprintf(f, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    } else {
        fprintf(f, "malformed (length: %zu)", length);
    }
}

/*
 * UTCTime (Coordinated Universal Time) consists of 13 bytes that
 * encode the Greenwich Mean Time in the format YYMMDDhhmmssZ.  For
 * instance, the bytes 17 0d 31 35 31 30 32 38 31 38 35 32 31 32 5a
 * encode the string "151028185212Z", which represents the time
 * "2015-10-28 18:52:12"
 */
void fprintf_json_utctime(FILE *f, const char *key, const uint8_t *data, unsigned int len) {

    fprintf(f, "\"%s\":\"", key);
    if (len != 13) {
        fprintf(f, "malformed\"");
        return;
    }
    if (data[0] < '5') {
        fprintf(f, "20");
    } else {
       fprintf(f, "19");
    }
    fprintf_json_char_escaped(f, data[0]);
    fprintf_json_char_escaped(f, data[1]);
    fprintf(f, "-");
    fprintf_json_char_escaped(f, data[2]);
    fprintf_json_char_escaped(f, data[3]);
    fprintf(f, "-");
    fprintf_json_char_escaped(f, data[4]);
    fprintf_json_char_escaped(f, data[5]);
    fprintf(f, " ");
    fprintf_json_char_escaped(f, data[6]);
    fprintf_json_char_escaped(f, data[7]);
    fprintf(f, ":");
    fprintf_json_char_escaped(f, data[8]);
    fprintf_json_char_escaped(f, data[9]);
    fprintf(f, ":");
    fprintf_json_char_escaped(f, data[10]);
    fprintf_json_char_escaped(f, data[11]);

    fprintf(f, "\"");
}


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
    struct parser value;

    static unsigned char explicit_tag(unsigned char tag) {
        if (tag > 31) {
            throw "error: tag too long";
        }
        return 0x80 + tag;
    }
    static unsigned char explicit_tag_constructed(unsigned char tag) {
        if (tag > 31) {
            throw "error: tag too long";
        }
        return 0xa0 + tag;
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

    bool is_not_null() {
        return value.data;
    }
    bool is_null() {
        return (value.data == NULL);
    }
    uint8_t get_tag() { return tag & 0x1f; }
    tlv() {
        // initialize to null/zero 
        tag = 0;
        length = 0;
        value.data = NULL;
        value.data_end = NULL;
    }
    tlv(const tlv &r) {
        tag = r.tag;
        length = r.length;
        value.data = r.value.data;
        value.data_end = r.value.data_end;
    }
    tlv(struct parser *p, uint8_t expected_tag=0x00, const char *tlv_name=NULL) {
        parse(p, expected_tag, tlv_name);
    }
    void parse(struct parser *p, uint8_t expected_tag=0x00, const char *tlv_name=NULL) {

        if (parser_get_data_length(p) < 2) {
            fprintf(stderr, "error: incomplete data (%ld bytes)\n", p->data_end - p->data);
            throw "error initializing tlv";
        }
        // set tag
        tag = p->data[0];
        length = p->data[1];

        if (expected_tag) {
            // fprintf(stderr, "note: looking for tag %02x, got %02x\n", expected_tag, tag);
            if (tag != expected_tag) {
                // fprintf(stderr, "did not get expected tag\n");
                // initialize to zero to indicate we don't match expected type
                tag = 0;
                length = 0;
                value.data = NULL;
                value.data_end = NULL;
                return;
            }
        }

        parser_skip(p, 2);

        // set length
        if (length >= 128) {
            size_t num_octets_in_length = length - 128;
            if (num_octets_in_length < 0) {
                fprintf(stderr, "error: invalid length field\n");
                throw "error initializing tlv";
            }
            if (parser_read_and_skip_uint(p, num_octets_in_length, &length) == status_err) {
                fprintf(stderr, "error: could not read length (want %lu bytes, only %ld bytes remaining)\n", length, parser_get_data_length(p));
                throw "error initializing tlv";
            }
        }

        // set value
        parser_init_from_outer_parser(&value, p, length);
        parser_skip(p, length);

#ifdef ASN1_DEBUG
        fprint(stderr, tlv_name);
#endif
    }

    void remove_bitstring_encoding() {
        size_t first_octet = 0;
        parser_read_and_skip_uint(&value, 1, &first_octet);
        if (first_octet) {
            throw "error removing bitstring encoding";
        }
    }
    /*
     * fprintf(f, name) prints the ASN1 TLV
     *
     * Tag notation: (Tag Class:Constructed:Tag Number)
     *
     *    Tag Class: 0=universal (native to ASN.1), 1=Application
     *    specific, 2=Context-specific, 3=Private
     *
     *    Constructed: 1=yes (value contains zero or more element
     *    encodings.), 0=no 
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

    void fprint(FILE *f, const char *tlv_name) {
        // return;  // return;
        if (value.data) {
            uint8_t tag_class = tag >> 6;
            uint8_t constructed = (tag >> 5) & 1;
            uint8_t tag_number = tag & 31;
            if (tag_class == 2) {
                // tag is context-specific
                fprintf(f, "T:%02x (%u:%u:%u, explicit tag %u)\tL:%08zu\tV:", tag, tag_class, constructed, tag_number, tag_number, length);
            } else {
                fprintf(f, "T:%02x (%u:%u:%u, %s)\tL:%08zu\tV:", tag, tag_class, constructed, tag_number, type[tag_number], length);
            }
            fprintf_raw_as_hex(f, value.data, value.data_end - value.data);
            if (tlv_name) {
                fprintf(f, "\t(%s)\n", tlv_name);
            } else {
                fprintf(f, "\n");
            }
        } else {
            fprintf(f, "null (%s)\n", tlv_name);
        }
    }

    inline bool is_constructed() {
        return tag && 0x20;
        // return (tag >> 5) & 1;
    }

    void print_as_json_hex(FILE *f, const char *name, bool comma=false) {
        const char *format_string = "\"%s\":\"";
        if (comma) {
            format_string = ",\"%s\":\"";
        }
        fprintf(f, format_string, name);
        if (value.data) {
            fprintf_raw_as_hex(f, value.data, value.data_end - value.data);
        }
        fprintf(f, "\"");
    }

    void print_as_json_escaped_string(FILE *f, const char *name) {
        fprintf_json_string_escaped(f, name, value.data, value.data_end - value.data);
    }

};


/*
   Name ::= CHOICE { -- only one possibility for now --
     rdnSequence  RDNSequence }

   RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

   RelativeDistinguishedName ::=
     SET SIZE (1..MAX) OF AttributeTypeAndValue

   AttributeTypeAndValue ::= SEQUENCE {
     type     AttributeType,
     value    AttributeValue }

   AttributeType ::= OBJECT IDENTIFIER

   AttributeValue ::= ANY -- DEFINED BY AttributeType

   DirectoryString ::= CHOICE {
         teletexString           TeletexString (SIZE (1..MAX)),
         printableString         PrintableString (SIZE (1..MAX)),
         universalString         UniversalString (SIZE (1..MAX)),
         utf8String              UTF8String (SIZE (1..MAX)),
         bmpString               BMPString (SIZE (1..MAX)) }

*/

struct attribute {
    struct tlv set;
    struct tlv sequence;
    struct tlv attribute_type;
    struct tlv attribute_value;

    attribute(struct parser *p) : set{p}, sequence{}, attribute_type{}, attribute_value{} { }

    void print_as_json(FILE *f) {
        const char *unknown_oid = "unknown_oid";
        const char *oid_string = unknown_oid;

        if (attribute_type.length == 0 || attribute_value.length == 0) {
            fprintf(f, "{}");  // print empty object to ensure proper JSON formatting
            return;
        }
        oid_string = parser_get_oid_string(&attribute_type.value);
        fprintf(f, "{");
        if (oid_string != unknown_oid) {
            attribute_value.print_as_json_escaped_string(f, oid_string);
        } else {
            attribute_value.print_as_json_hex(f, unknown_oid);
        }
        fprintf(f, "}");

    }
};

struct name {
    struct tlv RDNsequence;
    std::vector<struct attribute> rdn;

    name() : RDNsequence{}, rdn{} {}

    void parse(struct parser *p, const char *label=NULL) {

        RDNsequence.parse(p, tlv::SEQUENCE, "RDNsequence");

        const char *comma = "";
        while (parser_get_data_length(&RDNsequence.value) > 0) {

            if (RDNsequence.is_constructed()) {
                while (parser_get_data_length(&RDNsequence.value) > 0) {
                    rdn.push_back(&RDNsequence.value);

                    struct attribute &r = rdn.back();

                    r.sequence.parse(&r.set.value);

                    if (r.sequence.is_constructed()) {
                        while (parser_get_data_length(&r.sequence.value) > 0) {
                            r.attribute_type.parse(&r.sequence.value, 0, "attribute_type");
                            if (r.attribute_type.tag == 0x06) {
                                const char *unknown_oid = "unknown_oid";
                                const char *oid_string = unknown_oid;

                                oid_string = parser_get_oid_string(&r.attribute_type.value);
                                // get string associated with OID
                                r.attribute_value.parse(&r.sequence.value, 0, "attribute_value");
                            } else {
                                fprintf(stderr, "warning: got unexpected type %02x\n", r.attribute_type.tag);
                            }
                        }
                    }
                }
            }
        }
    }

    void print_as_json(FILE *f, const char *name) {
        if (rdn.size() > 0) {
            fprintf(f, ",\"%s\":[", name);  // open JSON array
            bool first = true;
            for (auto &a : rdn) {
                if (first) {
                    first = false;
                } else {
                    fprintf(f, ",");
                }
                a.print_as_json(f);
            }
            fprintf(f, "]");               //  close JSON array
        }
    }
};

/*
 * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 *
 * Extension  ::=  SEQUENCE  {
 *      extnID      OBJECT IDENTIFIER,
 *      critical    BOOLEAN DEFAULT FALSE,
 *      extnValue   OCTET STRING
 *                  -- contains the DER encoding of an ASN.1 value
 *                  -- corresponding to the extension type identified
 *                  -- by extnID
 *      }
 *
 */

struct extension {
    struct tlv sequence;
    struct tlv extnID;
    struct tlv critical; // boolean default false
    struct tlv extnValue;

    extension(struct parser *p) : sequence{p}, extnID{}, critical{}, extnValue{} {}
};

/*
   BasicConstraints ::= SEQUENCE {
        cA                      BOOLEAN DEFAULT FALSE,
        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
 */
struct basic_constraints {
    struct tlv sequence;
    struct tlv ca;
    struct tlv path_len_constraint;

    //    basic_constraints(struct parser *p) : sequence{p}, ca{&sequence.value}, path_len_constraint{&sequence.value} {}
    basic_constraints(struct parser *p) : sequence{}, ca{}, path_len_constraint{} {
        sequence.parse(p);
        if (parser_get_data_length(&sequence.value) > 0) {
            ca.parse(&sequence.value, 0x01);  // default false boolean
        }
        if (parser_get_data_length(&sequence.value) > 0) {
            path_len_constraint.parse(&sequence.value, 0x02); // integer 0..MAX optional
        }
    }

    void print_as_json(FILE *f) {
        const char *ca_str = "false";  // default
        unsigned int length = 0;   // default
        // TBD: report actual non-default data
        if (ca.length) {  // Check value as well as length!
            ca_str = "true";
        }
        fprintf(f, ",{\"BasicConstraints\":{\"ca\":%s,\"pathLenConstraint\":%u}}", ca_str, length);
    }
};

/*

   id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }

   ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId

   KeyPurposeId ::= OBJECT IDENTIFIER
 */

struct ext_key_usage {
    struct tlv sequence;
    std::vector<struct tlv> key_purpose_id;

    ext_key_usage(struct parser *p) : sequence{} {
        sequence.parse(p, 0, "ext_key_usage.sequence");
        while (parser_get_data_length(&sequence.value) > 0) {
            key_purpose_id.push_back(&sequence.value);
            // sequence.fprint(stdout, "ext_key_usage.key_purpose_id");
        }
    }

    void print_as_json(FILE *f) {
        fprintf(f, ",{\"ext_key_usage\":[");
        bool first = true;
        for (auto &x : key_purpose_id) {
            const char *oid_string = parser_get_oid_string(&x.value);
            if (first) {
                first = false;
            } else {
                fprintf(f, ",");
            }
            fprintf(f, "\"%s\"", oid_string);
        }
        fprintf(f, "]}");
    }
};


/*
   id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }

   SubjectAltName ::= GeneralNames

   GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

   GeneralName ::= CHOICE {
        otherName                       [0]     OtherName,
        rfc822Name                      [1]     IA5String,
        dNSName                         [2]     IA5String,
        x400Address                     [3]     ORAddress,
        directoryName                   [4]     Name,
        ediPartyName                    [5]     EDIPartyName,
        uniformResourceIdentifier       [6]     IA5String,
        iPAddress                       [7]     OCTET STRING,
        registeredID                    [8]     OBJECT IDENTIFIER }

   OtherName ::= SEQUENCE {
        type-id    OBJECT IDENTIFIER,
        value      [0] EXPLICIT ANY DEFINED BY type-id }

   EDIPartyName ::= SEQUENCE {
        nameAssigner            [0]     DirectoryString OPTIONAL,
        partyName               [1]     DirectoryString }

 */

struct general_name {
    struct tlv explicit_tag;
    struct tlv name;

    general_name() : explicit_tag{}, name{} {}
    general_name(struct parser *p) {
        parse(p);
    }
    void parse(struct parser *p, uint8_t expected_tag=0x00) {
        explicit_tag.parse(p, expected_tag);
        if (explicit_tag.is_not_null()) {
            //            fprintf(stdout, "got explicit tag %02x\n", explicit_tag.get_tag());
            // explicit_tag.fprint(stdout, "subject_alt_name.name.explicit_tag");
            if (0 && explicit_tag.is_constructed()) { // HACK
                // fprintf(stdout, "got constructed explicit tag in general_name (%02x)\n", explicit_tag.is_constructed());
                name.parse(&explicit_tag.value, 0, "subject_alt_name.name");
            }
        }
    }

    void print_as_json(FILE *f) {
        if (explicit_tag.get_tag() == 0) {
            struct tlv type_id(&explicit_tag.value, tlv::OBJECT_IDENTIFIER, "other_name.type_id");
            struct tlv value(&explicit_tag.value, 0, "other_name.value");

            fprintf(f, "{\"other_name\":{");
            fprintf(f, "\"type_id\":\"");
            fprintf_raw_as_hex(f, type_id.value.data, (int) (type_id.value.data_end - type_id.value.data));
            fprintf(f, "\",\"value\":\"");
            fprintf_raw_as_hex(f, value.value.data, (int) (value.value.data_end - value.value.data));
            fprintf(f, "\"}}");
        } else if (explicit_tag.get_tag() == 1) {
            fprintf(f, "{");
            fprintf_json_string_escaped(f, "rfc822_name", explicit_tag.value.data, (int) (explicit_tag.value.data_end - explicit_tag.value.data));
            fprintf(f, "}");
        } else if (explicit_tag.get_tag() == 2) {
            fprintf(f, "{");
            fprintf_json_string_escaped(f, "dns_name", explicit_tag.value.data, (int) (explicit_tag.value.data_end - explicit_tag.value.data));
            fprintf(f, "}");
        } else if (explicit_tag.get_tag() == 6) {
            fprintf(f, "{");
            fprintf_json_string_escaped(f, "uri", explicit_tag.value.data, (int) (explicit_tag.value.data_end - explicit_tag.value.data));
            fprintf(f, "}");
        } else if (explicit_tag.get_tag() == 7) {
            fprintf(f, "{\"ip_address\":\"");
            fprintf_ip_address(f, explicit_tag.value.data, (int) (explicit_tag.value.data_end - explicit_tag.value.data));
            fprintf(f, "\"}");
        } else {
            fprintf(f, "{\"SAN explicit tag\":%u}", explicit_tag.get_tag());
            // fprintf_raw_as_hex(f, explicit_tag.value.data, (int) (explicit_tag.value.data_end - explicit_tag.value.data));
        }
    }
};

struct subject_alt_name {
    struct tlv sequence;
    std::vector <struct general_name> names;

    subject_alt_name(struct parser *p) : sequence{p}, names{} {
        // sequence.fprint(stdout, "subject_alt_name.names");
        while (parser_get_data_length(&sequence.value) > 0) {
            names.push_back(&sequence.value);
        }
    }

    void print_as_json(FILE *f) {
        fprintf(f, ",{\"subjectAltName\":[");
        bool first = true;
        for (auto &x : names) {
            if (first) {
                first = false;
            } else {
                fprintf(f, ",");
            }
            x.print_as_json(f);
        }
        fprintf(f, "]}");
    }
};



/*

   id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }

   AuthorityKeyIdentifier ::= SEQUENCE {
      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }

   KeyIdentifier ::= OCTET STRING

 */

struct authority_key_identifier {
    struct tlv sequence;
    struct tlv key_identifier;
    struct general_name cert_issuer;
    struct tlv cert_serial_number;

    authority_key_identifier() : sequence{}, key_identifier{}, cert_issuer{}, cert_serial_number{} {}
    authority_key_identifier(struct parser *p) : sequence{}, key_identifier{}, cert_issuer{}, cert_serial_number{} {
        parse(p);
    }

    void parse(struct parser *p) {
        sequence.parse(p, tlv::SEQUENCE);
        while (parser_get_data_length(&sequence.value) > 0) {
            struct tlv tmp(&sequence.value);

            if (tmp.tag == tlv::explicit_tag(0)) {
                key_identifier = tmp;

            } else if (tmp.tag == tlv::explicit_tag_constructed(1)) {
                cert_issuer.explicit_tag = tmp;

            } else if (tmp.tag == tlv::explicit_tag(2)) {
                cert_serial_number = tmp;
            }
        }
    }

    void print_as_json(FILE *f) {
        fprintf(f, ",{\"authority_key_identifier\":{");
        bool comma = false;
        if (key_identifier.is_not_null()) {
            key_identifier.print_as_json_hex(f, "key_identifier");
            comma = true;
        }
        if (cert_issuer.explicit_tag.is_not_null()) {
            fprintf(f, comma ? ",\"cert_issuer\":" : "\"cert_issuer\":" );
            cert_issuer.print_as_json(f);
            comma = true;
        }
        if (cert_serial_number.is_not_null()) {
            cert_serial_number.print_as_json_hex(f, "cert_serial_number", comma);
        }
        fprintf(f, "}}");
    }
};

/*
  id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 14 }

  SubjectKeyIdentifier ::= KeyIdentifier
*/


/*
 * Validity ::= SEQUENCE {
 *      notBefore      Time,
 *      notAfter       Time  }
 *
 * Time ::= CHOICE {
 *      utcTime        UTCTime,
 *      generalTime    GeneralizedTime }
 */

struct validity {
    struct tlv sequence;
    struct tlv notBefore;
    struct tlv notAfter;

    validity() : sequence{}, notBefore{}, notAfter{} {
        //        parse(p);
    }
    void parse(struct parser *p) {
        sequence.parse(p, tlv::SEQUENCE, "validity.sequence");
        notBefore.parse(&sequence.value, tlv::UTCTime, "validity.notBefore");
        notAfter.parse(&sequence.value, tlv::UTCTime, "validity.notAfter");
    }
    void print_as_json(FILE *f) {
        fprintf(f, ",\"validity\":[");
        fprintf(f, "{");
        fprintf_json_utctime(f, "notBefore", notBefore.value.data, notBefore.value.data_end - notBefore.value.data);
        fprintf(f, "}");
        fprintf(f, ",{");
        fprintf_json_utctime(f, "notAfter", notAfter.value.data, notAfter.value.data_end - notAfter.value.data);
        fprintf(f, "}");
        fprintf(f, "]");  // closing validity
    }

};

/*
 * from RFC 2459
 *
 * RSAPublicKey ::= SEQUENCE {
 *   modulus            INTEGER, -- n
 *    publicExponent     INTEGER  -- e -- }
 */

struct rsa_public_key {
    struct tlv sequence;
    struct tlv modulus;
    struct tlv exponent;

    rsa_public_key() : sequence{}, modulus{}, exponent{} {}
    rsa_public_key(struct parser *p) : sequence{}, modulus{}, exponent{} {
        parse(p);
    }

    void parse(struct parser *p) {
        sequence.parse(p, tlv::SEQUENCE);
        modulus.parse(&sequence.value, tlv::INTEGER);
        exponent.parse(&sequence.value, tlv::INTEGER);
    }

    void print_as_json(FILE *f, const char *name, bool comma) {
        fprintf(f, comma ? ",\"%s\":{" : "\"%s\":{", name);
        if (modulus.is_not_null() && exponent.is_not_null()) {
            modulus.print_as_json_hex(f, "modulus", false);
            exponent.print_as_json_hex(f, "exponent", true);
        }
        fprintf(f, "}");
    }
};

/*
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */

struct algorithm_identifier {
    struct tlv sequence;
    struct tlv algorithm;
    struct tlv parameters;

    algorithm_identifier() : sequence{}, algorithm{}, parameters{} {}
    algorithm_identifier(struct parser *p) : sequence{}, algorithm{}, parameters{} {
        parse(p);
    }
    void parse(struct parser *p) {
        sequence.parse(p, tlv::SEQUENCE);
        algorithm.parse(&sequence.value, tlv::OBJECT_IDENTIFIER);
        if (parser_get_data_length(&sequence.value) > 0) {
            parameters.parse(&sequence.value);
        }
    }
    void print_as_json(FILE *f) {
        fprintf(f, "{");
        fprintf(f, "\"algorithm\":\"%s\"", parser_get_oid_string(&algorithm.value));
        //algorithm.print_as_json_hex(f, "algorithm");
        if (parameters.is_not_null()) {
            fprintf(f, ",");
            parameters.print_as_json_escaped_string(f, "parameters");
        }
        fprintf(f, "}");
    }
    const char *type() {
        if (algorithm.is_not_null()) {
            return parser_get_oid_string(&algorithm.value);
        }
        return NULL;
    }
};

/*
 *
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm            AlgorithmIdentifier,
 *      subjectPublicKey     BIT STRING  }
 */

struct subject_public_key_info {
    struct tlv sequence;
    struct algorithm_identifier algorithm;
    struct tlv subject_public_key;

    subject_public_key_info() : sequence{}, algorithm{}, subject_public_key{} {}
    subject_public_key_info(struct parser *p) : sequence{}, algorithm{}, subject_public_key{} {
        parse(p);
    }
    void parse(struct parser *p) {
        sequence.parse(p);
        algorithm.parse(&sequence.value);
        subject_public_key.parse(&sequence.value, tlv::BIT_STRING);
    }
    void print_as_json(FILE *f) {
        fprintf(f, ",\"subject_public_key_info\":{");
        fprintf(f, "\"algorithm\":");
        algorithm.print_as_json(f);
        if (strcmp(algorithm.type(), "rsaEncryption") == 0) {
            subject_public_key.remove_bitstring_encoding();
            struct rsa_public_key pub_key(&subject_public_key.value);
            pub_key.print_as_json(f, "subject_public_key", true);
        } else {
            subject_public_key.print_as_json_hex(f, "subject_public_key", true);
        }
        fprintf(f, "}");
    }
};

/*
 * TBSCertificate  ::=  SEQUENCE  {
 *      version         [0]  Version DEFAULT v1,
 *      serialNumber         CertificateSerialNumber,
 *      signature            AlgorithmIdentifier,
 *      issuer               Name,
 *      validity             Validity,
 *      subject              Name,
 *      subjectPublicKeyInfo SubjectPublicKeyInfo,
 *      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                           -- If present, version MUST be v2 or v3
 *      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                           -- If present, version MUST be v2 or v3
 *      extensions      [3]  Extensions OPTIONAL
 *                          -- If present, version MUST be v3 --  }
 *
 * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 *
 * CertificateSerialNumber  ::=  INTEGER
 *
 * UniqueIdentifier  ::=  BIT STRING
 *
 */

struct x509_cert {
    struct tlv certificate;
    struct tlv tbs_certificate;
    struct tlv explicitly_tagged_version;
    struct tlv version;
    struct tlv serial_number;
    struct algorithm_identifier algorithm_identifier; // note: confusingly called 'signature' in RFC5280
    struct name issuer;
    struct validity validity;
    struct name subject;
    struct subject_public_key_info subjectPublicKeyInfo;
    struct tlv explicitly_tagged_extensions;
    struct tlv extensions;
    std::vector <struct extension> extension;

    struct algorithm_identifier signature_algorithm;
    struct tlv signature;

    x509_cert()
        : certificate{},
          tbs_certificate{},
          explicitly_tagged_version{},
          version{},
          serial_number{},
          algorithm_identifier{},
          issuer{},
          validity{},
          subject{},
          subjectPublicKeyInfo{},
          extensions{},
          extension{},
          signature_algorithm{},
          signature{} {   }

    void parse(const void *buffer, unsigned int len) {

        struct parser p;
        parser_init(&p, (const unsigned char *)buffer, len);

        certificate.parse(&p, tlv::SEQUENCE, "certificate");

        tbs_certificate.parse(&certificate.value, tlv::SEQUENCE, "tbs_certificate");

        // parse (implicit or explicit) version
        explicitly_tagged_version.parse(&tbs_certificate.value, tlv::explicit_tag_constructed(0), "version_tag");
        if (explicitly_tagged_version.is_not_null()) {
            version.parse(&explicitly_tagged_version.value, tlv::INTEGER, "version");
        } else {

            struct tlv version_or_serial_number(&tbs_certificate.value, tlv::INTEGER, "version_or_serial_number");
            if (version_or_serial_number.length ==1 && version_or_serial_number.value.data[0] < 3) {
                version = version_or_serial_number;
            } else {
                serial_number = version_or_serial_number;
            }
        }

        if (serial_number.is_null()) {
            serial_number.parse(&tbs_certificate.value, tlv::INTEGER, "serial number");
        }

        algorithm_identifier.parse(&tbs_certificate.value); 

        // parse issuer
        issuer.parse(&tbs_certificate.value, "issuer");

        // parse validity
        validity.parse(&tbs_certificate.value);

        // parse subject
        subject.parse(&tbs_certificate.value, "subject");

        // parse subjectPublicKeyInfo
        subjectPublicKeyInfo.parse(&tbs_certificate.value);

        if (parser_get_data_length(&tbs_certificate.value) == 0) {
            return;    // optional extensions are not present
        }

        // parse extensions
        explicitly_tagged_extensions.parse(&tbs_certificate.value, 0xa3);
        if (explicitly_tagged_extensions.is_not_null()) {
            extensions.parse(&explicitly_tagged_extensions.value, 0, "explicitly tagged extensions");
        } else {
            extensions.parse(&tbs_certificate.value, 0, "untagged extensions");
        }
        // fprintf(stderr, "ext.tag class: %u\tnumber: %u\n", extensions.tag & 0xc0, extensions.tag & 0x1f);

        while (parser_get_data_length(&extensions.value) > 0) {
            extension.push_back(&extensions.value);
            struct extension &ext = extension.back();
            //ext.sequence.fprint(stdout, "XXX extension");

            if (ext.sequence.is_constructed()) {
                const char *oid_string = NULL;
                ext.extnID.parse(&ext.sequence.value, 0, "extnID");
                if (ext.extnID.tag == 0x06) {
                    oid_string = parser_get_oid_string(&ext.extnID.value);
                }

                ext.extnValue.parse(&ext.sequence.value, 0, "extnValue");
                if (ext.extnValue.tag == 0x01) {
                    // fprintf(stderr, "found boolean\n");
                    ext.critical = ext.extnValue;
                    ext.extnValue.parse(&ext.sequence.value, 0, "critical");
                }
            }
        }

        // tbs_certificate should be out of data now
        if (parser_get_data_length(&tbs_certificate.value) == 0) {
            // fprintf(stderr, "done parsing tbs_certificate, no remainder\n");
        }

        signature_algorithm.parse(&certificate.value);
        signature.parse(&certificate.value, 0, "signature");

    }

    void print_as_json(FILE *f) {

        fprintf(f, "{");   // open JSON object
        serial_number.print_as_json_hex(f, "serial_number");
        issuer.print_as_json(f, "issuer");
        validity.print_as_json(f);
        subject.print_as_json(f, "subject");
        subjectPublicKeyInfo.print_as_json(f);

        if (extension.size() > 0) {
            fprintf(stdout, ",\"extensions\":[");  // open JSON array for extensions

            const char *comma = "";
            for (auto &xtn : extension) {

                //xtn.sequence.fprint(stdout, "YYY extension");
                if (xtn.sequence.is_constructed()) {
                    const char *true_str = "true";
                    const char *false_str = "false";
                    const char *oid_string = NULL;
                    const char *critical_str = false_str;
                    //xtn.extnID.fprint(stdout, "extnID");
                    if (xtn.extnID.tag == tlv::OBJECT_IDENTIFIER) {
                        oid_string = parser_get_oid_string(&xtn.extnID.value);
                    }
                    if (xtn.critical.tag == tlv::BOOLEAN) {
                        // fprintf(stderr, "found boolean\n");
                        //xtn.critical.fprint(stdout, "critical");
                        critical_str = true_str;
                    }
                    //xtn.extnValue.fprint(stdout, "extnValue");
                    fprintf(stdout, "%s{\"%s\":\"", comma, oid_string);
                    fprintf_raw_as_hex(stdout, xtn.extnValue.value.data, xtn.extnValue.value.data_end - xtn.extnValue.value.data);
                    fprintf(stdout, "\",\"critical\":%s}", critical_str);
                    comma = ",";

                    // new stuff
                    if (oid_string && strcmp("id-ce-basicConstraints", oid_string) == 0) {
                        struct basic_constraints x(&xtn.extnValue.value);
                        x.print_as_json(stdout);
                    }
                    if (oid_string && strcmp("id-ce-extKeyUsage", oid_string) == 0) {
                        struct ext_key_usage x(&xtn.extnValue.value);
                        x.print_as_json(stdout);
                    }
                    if (oid_string && strcmp("id-ce-subjectAltName", oid_string) == 0) {
                        struct subject_alt_name x(&xtn.extnValue.value);
                        x.print_as_json(stdout);
                    }
                    if (oid_string && strcmp("id-ce-authorityKeyIdentifier", oid_string) == 0) {
                        struct authority_key_identifier x(&xtn.extnValue.value);
                        x.print_as_json(stdout);
                    }
                    if (oid_string && strcmp("id-ce-subjectKeyIdentifier", oid_string) == 0) {
                        struct tlv x(&xtn.extnValue.value);
                        fprintf(stdout, ",{");
                        x.print_as_json_hex(stdout, "subject_key_identifier");
                        fprintf(stdout, "}");
                    }
                }
            }
            fprintf(stdout, "]");  // closing extensions JSON array
        }

        fprintf(f, ",\"signature_algorithm\":");
        signature_algorithm.print_as_json(f);
        fprintf(f, ",");
        signature.print_as_json_hex(f, "signature");
        fprintf(f, "}\n"); // close JSON line

    }

};

struct x509_cert_prefix {
    struct tlv serial_number;
    struct tlv issuer;
    const uint8_t *data, *data_end;

    x509_cert_prefix() : serial_number{}, issuer{}, data{}, data_end{} {   }

    x509_cert_prefix(const void *buffer, unsigned int len) : serial_number{}, issuer{}, data{}, data_end{} {
        parse(buffer, len);
    }

    void parse(const void *buffer, unsigned int len) {
        struct tlv certificate;
        struct tlv tbs_certificate;
        struct tlv explicitly_tagged_version;
        struct tlv version;
        struct tlv algorithm_identifier;

        struct parser p;
        data = (const uint8_t *)buffer;

        parser_init(&p, (const unsigned char *)buffer, len);

        certificate.parse(&p, tlv::SEQUENCE, "certificate");

        tbs_certificate.parse(&certificate.value, tlv::SEQUENCE, "tbs_certificate");

        // parse (implicit or explicit) version
        explicitly_tagged_version.parse(&tbs_certificate.value, tlv::explicit_tag_constructed(0), "version_tag");
        if (explicitly_tagged_version.is_not_null()) {
            version.parse(&explicitly_tagged_version.value, tlv::INTEGER, "version");
        } else {

            struct tlv version_or_serial_number(&tbs_certificate.value, tlv::INTEGER, "version_or_serial_number");
            if (version_or_serial_number.length ==1 && version_or_serial_number.value.data[0] < 3) {
                version = version_or_serial_number;
            } else {
                serial_number = version_or_serial_number;
            }
        }

        if (serial_number.is_null()) {
            serial_number.parse(&tbs_certificate.value, tlv::INTEGER, "serial number");
        }

        algorithm_identifier.parse(&tbs_certificate.value);

        // parse issuer
        issuer.parse(&tbs_certificate.value);
        data_end = tbs_certificate.value.data;

    }

    size_t get_length() {
        if (issuer.is_null()) {
            return 0;
        }
        return data_end - data;
    }

    void print_as_json(FILE *f) {
        fprintf(f, "{");   // open JSON object
        serial_number.print_as_json_hex(f, "serial_number");
        fprintf(f, ",");
        issuer.print_as_json_hex(f, "issuer");
        fprintf(f, "}\n"); // close JSON line
    }

    void print_as_json_hex(FILE *f) {
        fprintf(f, "{\"cert_prefix\":\"");   // open JSON object
        fprintf_raw_as_hex(f, data, data_end - data);
        fprintf(f, "\"}\n"); // close JSON line
    }

};


#endif /* X509_H */
