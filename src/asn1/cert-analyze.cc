/*
 * cert-analyze.cc
 *
 * analyze X509 certificates
 */

#include <stdio.h>
#include <string.h>
#include <string>
//#include <vector>
#include <iostream>
#include <unordered_map>


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

/*
UTCTime is encoded with tag 17 and it encoded Coordinated Universal
Time. Its value consists of 13 bytes that encode the Greenwich Mean
Time in the format YYMMDDhhmmssZ, for example bytes

17 0d 31 35 31 30 32 38 31 38 35 32 31 32 5a

encode the string "151028185212Z", which represents the time "2015-10-28 18:52:12"


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
 * START base64
 */

/*
* Base64 encoding/decoding (RFC1341)
* Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
*
* This software may be distributed under the terms of the BSD license.
* See README for more details.
*/

// 2016-12-12 - Gaspard Petit : Slightly modified to return a std::string 
// instead of a buffer allocated with malloc.

#include <string>

static const unsigned char base64_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
* base64_encode - Base64 encode
* @src: Data to be encoded
* @len: Length of the data to be encoded
* @out_len: Pointer to output length variable, or %NULL if not used
* Returns: Allocated buffer of out_len bytes of encoded data,
* or empty string on failure
*/
std::string base64_encode(const unsigned char *src, size_t len)
{
    unsigned char *out, *pos;
    const unsigned char *end, *in;

    size_t olen;

    olen = 4*((len + 2) / 3); /* 3-byte blocks to 4-byte */

    if (olen < len)
        return std::string(); /* integer overflow */

    std::string outStr;
    outStr.resize(olen);
    out = (unsigned char*)&outStr[0];

    end = src + len;
    in = src;
    pos = out;
    while (end - in >= 3) {
        *pos++ = base64_table[in[0] >> 2];
        *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = base64_table[in[2] & 0x3f];
        in += 3;
    }

    if (end - in) {
        *pos++ = base64_table[in[0] >> 2];
        if (end - in == 1) {
            *pos++ = base64_table[(in[0] & 0x03) << 4];
            *pos++ = '=';
        }
        else {
            *pos++ = base64_table[((in[0] & 0x03) << 4) |
                (in[1] >> 4)];
            *pos++ = base64_table[(in[1] & 0x0f) << 2];
        }
        *pos++ = '=';
    }

    return outStr;
}

static const int B64index[256] = { 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62, 63, 62, 62, 63, 52, 53, 54, 55,
56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6,
7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,
0,  0,  0, 63,  0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 };

std::string b64decode(const void* data, const size_t len)
{
    unsigned char* p = (unsigned char*)data;
    int pad = len > 0 && (len % 4 || p[len - 1] == '=');
    const size_t L = ((len + 3) / 4 - pad) * 4;
    std::string str(L / 4 * 3 + pad, '\0');

    for (size_t i = 0, j = 0; i < L; i += 4)
    {
        int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
        str[j++] = n >> 16;
        str[j++] = n >> 8 & 0xFF;
        str[j++] = n & 0xFF;
    }
    if (pad)
    {
        int n = B64index[p[L]] << 18 | B64index[p[L + 1]] << 12;
        str[str.size() - 1] = n >> 16;

        if (len > L + 2 && p[L + 2] != '=')
        {
            n |= B64index[p[L + 2]] << 6;
            str.push_back(n >> 8 & 0xFF);
        }
    }
    return str;
}

#if 0

static const int B64index[256] = {
    0,   0,  0,  0,  0,  0,  0,  0,
    0,   0,  0,  0,  0,  0,  0,  0,
    0,   0,  0,  0,  0,  0,  0,  0,
    0,   0,  0,  0,  0,  0,  0,  0,
    0,   0,  0,  0,  0,  0,  0,  0,
    0,   0,  0, 62, 63, 62, 62, 63,
    52, 53, 54, 55, 56, 57, 58, 59,
    60, 61,  0,  0,  0,  0,  0,  0,
    0,  0,  1,  2,  3,  4,  5,  6,
    7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22,
    23, 24, 25,  0, 0,  0,  0, 63,
    0, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48,
    49, 50, 51
};

size_t base64decode(std::string str, const void* data, const size_t len) {
    unsigned char* p = (unsigned char*)data;
    int pad = len > 0 && (len % 4 || p[len - 1] == '=');
    const size_t L = ((len + 3) / 4 - pad) * 4;
    int length = L / 4 * 3 + pad;

    for (size_t i = 0, j = 0; i < L; i += 4) {
        int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
        str[j++] = n >> 16;
        str[j++] = n >> 8 & 0xFF;
        str[j++] = n & 0xFF;
    }
    if (pad) {
        int n = B64index[p[L]] << 18 | B64index[p[L + 1]] << 12;
        str[str.size() - 1] = n >> 16;

        if (len > L + 2 && p[L + 2] != '=') {
            n |= B64index[p[L + 2]] << 6;
            str.push_back(n >> 8 & 0xFF);
        }
    }
    return length;
}

std::string b64decode(const void* data, const size_t len) {
    unsigned char* p = (unsigned char*)data;
    int pad = len > 0 && (len % 4 || p[len - 1] == '=');
    const size_t L = ((len + 3) / 4 - pad) * 4;
    std::string str(L / 4 * 3 + pad, '\0');

    for (size_t i = 0, j = 0; i < L; i += 4) {
        int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
        str[j++] = n >> 16;
        str[j++] = n >> 8 & 0xFF;
        str[j++] = n & 0xFF;
    }
    if (pad) {
        int n = B64index[p[L]] << 18 | B64index[p[L + 1]] << 12;
        str[str.size() - 1] = n >> 16;

        if (len > L + 2 && p[L + 2] != '=') {
            n |= B64index[p[L + 2]] << 6;
            str.push_back(n >> 8 & 0xFF);
        }
    }
    return str;
}

#endif /* 0 */

void print_as_ascii_with_dots(const void *string, size_t len) {
    const char *s = (const char *)string;
    for (size_t i=0; i < len; i++) {
        if (isprint(s[i])) {
            printf("%c", s[i]);
        } else {
            printf(".");
        }
    }
    printf("\n");
}

/*

python hex-to-oid from Blake
 a = ”551d1f”
 b = ”608648”

def convert(x):
    x =  bytes.fromhex(x)

    y0 = x[0]/40
    y1 = x[0]%40

    y2 = x[1]
    if y2 < 128:
        y3 = x[2]
        print(”%i.%i.%i.%i” % (y0, y1, y2, y3))
    else:
        y3 = x[2]
        odd = False
        if y2/2 != int(y2/2):
            odd = True

        y2 = (y2 >> 1) & 15
        y3 = y3 & 127
        if odd:
            y3 *= 16

        y2 = (y2*256)+y3
        print(”%i.%i.%i” % (y0, y1, y2))



*/

void hex_to_oid(const unsigned char *hex, size_t length, char oid_output[]) {
    oid_output[0] = '1';
    oid_output[1] = '.';
    oid_output[2] = '2';
    oid_output[3] = 0;
}

#include "../mercury.h"
#include "../parser.h"

struct asn1_tlv {
    unsigned char tag;
    size_t length;
    struct parser value;
};

#define asn1_tlv_init() { 0, 0, { NULL, NULL } }

/*
 * fprintf_asn1_tlv(f, x, name) prints the ASN1 TLV
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


const char *type[] = { 
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
   "BMPString",
   "DATE",
   "TIME-OF-DAY,"
   "DATE-TIME",
   "DURATION",
   "OID-IRI",
   "RELATIVE-OID-IRI"
};

void fprintf_asn1_tlv(FILE *f, const struct asn1_tlv *x, const char *name) {
    // return;
    if (x && x->value.data) {
        fprintf(f, "T:%02x (%u:%u:%u, %s)\tL:%08zu\tV:", x->tag, x->tag >> 6, (x->tag >> 5) & 1, x->tag & 31, type[x->tag & 31], x->length);
        fprintf_raw_as_hex(f, x->value.data, x->value.data_end - x->value.data);
        if (name) {
            fprintf(f, "\t(%s)\n", name);
        } else {
            fprintf(f, "\n");
        }
    } else {
        fprintf(f, "null (%s)\n", name);
    }
}

#define ASN1_TAG_CONSTRUCTED 0x20

inline bool asn1_tlv_is_constructed(const struct asn1_tlv *a) {
    return a->tag && ASN1_TAG_CONSTRUCTED;
}

enum status parser_read_asn1_tlv(struct parser *p, struct asn1_tlv *x) {

    if (parser_get_data_length(p) < 2) {
        fprintf(stderr, "error: incomplete data (%ld bytes)\n", p->data_end - p->data);
        return status_err;
    }
    // set tag
    x->tag = p->data[0];
    x->length = p->data[1];
    parser_skip(p, 2);

    // set length
    if (x->length >= 128) {
        size_t num_octets_in_length = x->length - 128;
        if (num_octets_in_length < 0) {
            fprintf(stderr, "error: invalid length field\n");
            return status_err;
        }
        if (parser_read_and_skip_uint(p, num_octets_in_length, &x->length) == status_err) {
            fprintf(stderr, "error: could not read length (want %lu bytes, only %ld bytes remaining)\n", x->length, parser_get_data_length(p));
            return status_err;
        }
    }

    // set value
    parser_init_from_outer_parser(&x->value, p, x->length);
    parser_skip(p, x->length);

    return status_ok;
}

void parser_asn1_tlv_recursive_parse(struct parser *p) {

    while (parser_get_data_length(p) > 0) {
        struct asn1_tlv tmp;

        enum status status = parser_read_asn1_tlv(p, &tmp);
        if (status) {
            fprintf(stderr, "error reading asn1 tlv\n");
            return;
        }
        fprintf_asn1_tlv(stdout, &tmp, "tmp");
        if (asn1_tlv_is_constructed(&tmp)) {

            printf("found constructed type\n");
            parser_asn1_tlv_recursive_parse(&tmp.value);

        }
    }
}

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
 * Validity ::= SEQUENCE {
 *      notBefore      Time,
 *      notAfter       Time  }
 *
 * Time ::= CHOICE {
 *      utcTime        UTCTime,
 *      generalTime    GeneralizedTime }
 *
 * UniqueIdentifier  ::=  BIT STRING
 *
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm            AlgorithmIdentifier,
 *      subjectPublicKey     BIT STRING  }
 *
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
 * id-at-countryName
 */

struct x509_cert {
    struct parser version;
    struct parser serial_number;
    struct parser issuer;
};

void fprintf_parser_as_string(FILE *f, struct parser *p) {
    fprintf(f, "%.*s", (int) (p->data_end - p->data), p->data);
}

/*
 * OIDs 
 *
 */
unsigned char id_at_commonName[3] = { 0x55, 0x04, 0x03 };

unsigned char id_at_surname[3] = { 0x55, 0x04, 0x04 };

unsigned char id_at_serialNumber[3] = { 0x55, 0x04, 0x05 };

unsigned char id_at_countryName[3] = { 0x55, 0x04, 0x06 };

unsigned char id_at_localityName[3] = { 0x55, 0x04, 0x07 };

unsigned char id_at_stateOrProvinceName[3] = { 0x55, 0x04, 0x08 };

unsigned char id_at_organizationName[3] = { 0x55, 0x04, 0x0a };

unsigned char id_at_organizationalUnitName[3] = { 0x55, 0x04, 0x0b };

unsigned char unknown_oid_099226[3] = { 0x09, 0x92, 0x26 };

unsigned char unknown_oid_55040d[3] = { 0x55, 0x04, 0x0d };

unsigned char unknown_oid_550429[3] = { 0x55, 0x04, 0x29 };

unsigned char unknown_oid_551d11[3] = { 0x55, 0x1d, 0x11 };

// question: are repeated OIDs allowed in RDN attribute types?  seems
// really rare

unsigned char id_at_emailaddress[3] = { 0x2a, 0x86, 0x48 };
//pkcs-9 OBJECT IDENTIFIER ::=  { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 }
// id-emailAddress      AttributeType ::= { pkcs-9 1 }
// EmailAddress ::=     IA5String (SIZE (1..ub-emailaddress-length))

unsigned char oid_subjectKeyIdentifier[3] = { 0x55, 0x1d, 0x0e };

unsigned char oid_extKeyUsage[3] = { 0x55, 0x1d, 0x25 };

unsigned char oid_keyUsage[3] = { 0x55, 0x1d, 0x0f };

std::unordered_map<std::string, std::string> extension_oids =
    {
     { { 0x55, 0x1d, 0x0e }, "subject_key_identifier" },
     { { 0x55, 0x1d, 0x25 }, "ext_key_usage" },
     { { 0x55, 0x1d, 0x0f }, "key_usage" }
    };

#include <vector>
#include "oid.h"

const char *parser_get_oid_string(struct parser *p) {
    std::string s = p->get_string();
    const char *tmp = s.c_str();
    // fprintf(stderr, "key: %02x%02x%02x\n", tmp[0], tmp[1], tmp[2]);
    auto pair = oid_dict.find(s);
    if (pair == oid_dict.end()) {
        return NULL; 
    }
    return pair->second.c_str();;
}

unsigned char default_version_value[1] = { 0x00 };
struct asn1_tlv default_version = { 0x02, 0x01, { default_version_value, default_version_value + 1 } };

enum status asn1_tlv_read_x509_name(struct asn1_tlv *tlv, const char *label) {
    enum status status;
    struct asn1_tlv tmp = asn1_tlv_init();

    fprintf(stdout, ",\"%s\":[", label);
    const char *comma = "";
    while (parser_get_data_length(&tlv->value) > 0) {
        status = parser_read_asn1_tlv(&tlv->value, &tmp);
        if (status) {
            fprintf(stderr, "error reading asn1 tlv\n");
            fprintf(stdout, "]}\n"); // close json array and line
            return status_err;
        }
        fprintf_asn1_tlv(stdout, &tmp, "tmp");
        if (asn1_tlv_is_constructed(tlv)) {
            struct asn1_tlv tmp2;
            while (parser_get_data_length(&tmp.value) > 0) {
                status = parser_read_asn1_tlv(&tmp.value, &tmp2);
                if (status) {
                    fprintf(stderr, "error reading asn1 tlv\n");
                    fprintf(stdout, "]}\n"); // close json array and line
                    return status_err;
                }
                fprintf_asn1_tlv(stdout, &tmp2, "tmp2");
                if (asn1_tlv_is_constructed(&tmp2)) {

                    struct asn1_tlv tmp3;
                    while (parser_get_data_length(&tmp2.value) > 0) {
                        status = parser_read_asn1_tlv(&tmp2.value, &tmp3);
                        if (status) {
                            fprintf(stderr, "error reading asn1 tlv\n");
                            fprintf(stdout, "]}\n"); // close json array and line
                            return status_err;
                        }
                        fprintf_asn1_tlv(stdout, &tmp3, "tmp3");
                        if (tmp3.tag == 0x06) {
                            const char *unknown_oid = "unknown_oid";
                            const char *oid_string = unknown_oid;

                            std::cerr << "oid: " << parser_get_oid_string(&tmp3.value) << "\n";

                            if (parser_match(&tmp3.value, id_at_countryName, sizeof(id_at_countryName), NULL) == status_ok) {
                                oid_string = "countryName";
                            } else if (parser_match(&tmp3.value, id_at_surname, sizeof(id_at_surname), NULL) == status_ok) {
                                oid_string = "surname";
                            } else if (parser_match(&tmp3.value, id_at_serialNumber, sizeof(id_at_serialNumber), NULL) == status_ok) {
                                oid_string = "serialNumber";
                            } else if (parser_match(&tmp3.value, id_at_organizationName, sizeof(id_at_organizationName), NULL) == status_ok) {
                                oid_string = "organizationName";
                            } else if (parser_match(&tmp3.value, id_at_organizationalUnitName, sizeof(id_at_organizationalUnitName), NULL) == status_ok) {
                                oid_string = "organizationalUnitName";
                            } else if (parser_match(&tmp3.value, id_at_commonName, sizeof(id_at_commonName), NULL) == status_ok) {
                                oid_string = "commonName";
                            } else if (parser_match(&tmp3.value, id_at_stateOrProvinceName, sizeof(id_at_stateOrProvinceName), NULL) == status_ok) {
                                oid_string = "stateOrProvinceName";
                            } else if (parser_match(&tmp3.value, id_at_localityName, sizeof(id_at_localityName), NULL) == status_ok) {
                                oid_string = "localityName";
                            } else if (parser_match(&tmp3.value, id_at_emailaddress, sizeof(id_at_emailaddress), NULL) == status_ok) {
                                oid_string = "emailaddress";
                            } else if (parser_match(&tmp3.value, unknown_oid_099226, sizeof(unknown_oid_099226), NULL) == status_ok) {
                                oid_string = "unknown_oid_099226";
                            } else if (parser_match(&tmp3.value, unknown_oid_55040d, sizeof(unknown_oid_55040d), NULL) == status_ok) {
                                oid_string = "unknown_oid_55040d";
                            } else if (parser_match(&tmp3.value, unknown_oid_550429, sizeof(unknown_oid_550429), NULL) == status_ok) {
                                oid_string = "unknown_oid_550429";
                            } else if (parser_match(&tmp3.value, unknown_oid_551d11, sizeof(unknown_oid_551d11), NULL) == status_ok) {
                                oid_string = "unknown_oid_551d11";
                            } else {
                                //const unsigned char *oid = tmp3.value.data;
                                //fprintf(stderr, "warning: unknown oid { 0x%02x, 0x%02x, 0x%02x }\n", oid[0], oid[1], oid[2]);
                                fprintf(stderr, "warning: unknown att oid ");
                                fprintf_raw_as_hex(stderr,  tmp3.value.data, tmp3.value.data_end - tmp3.value.data);
                                fprintf(stderr, "\n");

                            }

                            // get string associated with OID
                            status = parser_read_asn1_tlv(&tmp2.value, &tmp3);
                            if (status) {
                                fprintf(stdout, "error reading asn1 tlv (OID value)\n");
                                fprintf(stdout, "]}\n"); // close json array and line
                            }
                            fprintf(stdout, "%s{", comma);
                            if (oid_string != unknown_oid) {
                                fprintf_json_string_escaped(stdout, oid_string, tmp3.value.data, tmp3.value.data_end - tmp3.value.data);
                                // fprintf_parser_as_string(stdout, &tmp3.value);
                            } else {
                                fprintf(stdout, "\"%s\":\"", unknown_oid);
                                fprintf_raw_as_hex(stdout,  tmp3.value.data, tmp3.value.data_end - tmp3.value.data);
                                fprintf(stdout, "\"");
                            }
                            fprintf(stdout, "}");
                            comma = ",";
                        }
                    }
                }
            }
        }
    }
    fprintf(stdout, "]"); // closing "issuer"

    return status_ok;
}

// for debugging, compare to the output of 
//  $ openssl x509 -in first.pem -text -noout
//

void buffer_parse_as_cert(const void *buffer,
                          unsigned int len) {

    struct parser p;
    parser_init(&p, (const unsigned char *)buffer, len);

    // fprintf(stdout, "got cert with length %u\n", len);
    // fprintf_raw_as_hex(stdout, buffer, len);
    // fprintf(stdout, "\n");
    // print_as_ascii_with_dots(buffer, len);

    struct asn1_tlv certificate = asn1_tlv_init();
    enum status status = parser_read_asn1_tlv(&p, &certificate);
    if (status) {
        fprintf(stderr, "error reading asn1 tlv\n");
        return;
    }
    fprintf_asn1_tlv(stdout, &certificate, "certificate");
    struct asn1_tlv tbs_certificate = asn1_tlv_init();
    status = parser_read_asn1_tlv(&certificate.value, &tbs_certificate);
    if (status) {
        fprintf(stderr, "error reading asn1 tlv\n");
        return;
    }
    fprintf_asn1_tlv(stdout, &tbs_certificate, "tbs_certificate");

    // parse (implicit or explicit) version
    struct asn1_tlv tmp = asn1_tlv_init();
    status = parser_read_asn1_tlv(&tbs_certificate.value, &tmp);
    if (status) {
        fprintf(stderr, "error reading asn1 tlv\n");
        return;
    }
    fprintf_asn1_tlv(stdout, &tmp, "OPTIONAL version");
    struct asn1_tlv *version = NULL;
    if (tmp.tag == 0xa0) {
        // fprintf(stdout, "got explicit tag for version\n");
        struct asn1_tlv explicitly_tagged_version = asn1_tlv_init();
        status = parser_read_asn1_tlv(&tmp.value, &explicitly_tagged_version);
        if (status) {
            fprintf(stderr, "error reading asn1 tlv\n");
            return;
        }
        version = &explicitly_tagged_version;
    } else {
        fprintf(stderr, "no explicit tag for version\n");
        if (tmp.tag == 0x02 && tmp.length == 0x01) {
            version = &tmp;               // assume that this TLV is the version field
        } else {
            version = &default_version;   // use the default version
        }
    }
    fprintf_asn1_tlv(stdout, version, "version");
    if (version->length !=1 || version->value.data[0] > 0x02) {
        fprintf(stderr, "error: invalid certificate version - ");
        fprintf_raw_as_hex(stderr, buffer, 16);
        fprintf(stderr, "\n");
        return;
    }

    struct asn1_tlv serial_number = { 0, 0, { NULL, NULL } };
    status = parser_read_asn1_tlv(&tbs_certificate.value, &serial_number);
    if (status) {
        fprintf(stderr, "error reading asn1 tlv\n");
        return;
    }
    fprintf_asn1_tlv(stdout, &serial_number, "serial number");
    fprintf(stdout, "{\"serial_number\":\"");
    fprintf_raw_as_hex(stdout, serial_number.value.data, (serial_number.value.data_end - serial_number.value.data));
    fprintf(stdout, "\"");

    // skip signature
    struct asn1_tlv signature = { 0, 0, { NULL, NULL } };
    status = parser_read_asn1_tlv(&tbs_certificate.value, &signature);
    if (status) {
        fprintf(stderr, "error reading asn1 tlv\n");
        fprintf(stdout, "}\n"); // close json line
        return;
    }
    fprintf_asn1_tlv(stdout, &signature, "signature");

    // parse issuer
    struct asn1_tlv issuer = { 0, 0, { NULL, NULL } };
    status = parser_read_asn1_tlv(&tbs_certificate.value, &issuer);
    if (status) {
        fprintf(stderr, "error reading asn1 tlv\n");
        fprintf(stdout, "}\n"); // close json line
    }
    fprintf_asn1_tlv(stdout, &issuer, "issuer");
    // print_as_ascii_with_dots(issuer.value.data, issuer.value.data_end - issuer.value.data);
    status = asn1_tlv_read_x509_name(&issuer, "issuer");
    if (status) {
        fprintf(stderr, "error reading x509_name\n");
        return;
    }

    // parse validity
    struct asn1_tlv validity = { 0, 0, { NULL, NULL } };
    status = parser_read_asn1_tlv(&tbs_certificate.value, &validity);
    if (status) {
        fprintf(stderr, "error reading asn1 tlv\n");
        fprintf(stdout, "}\n");  // closing JSON line
        return;
    }
    fprintf_asn1_tlv(stdout, &validity, "validity");
    fprintf(stdout, ",\"validity\":[");
    struct asn1_tlv time;
    status = parser_read_asn1_tlv(&validity.value, &time);
    if (status) {
        fprintf(stderr, "error reading asn1 tlv\n");
        fprintf(stdout, "\"}\n");  // closing validity and JSON line
        return;
    }
    if (time.tag == 0x17) {
        fprintf(stdout, "{");
        fprintf_json_utctime(stdout, "notBefore", time.value.data, time.value.data_end - time.value.data);
        fprintf(stdout, "}");
    } else {
        fprintf(stdout, "{");
        fprintf(stdout, "\"unexpected tag\":\"%02x\"", time.tag);
        fprintf(stdout, "}");
    }
    status = parser_read_asn1_tlv(&validity.value, &time);
    if (status) {
        fprintf(stderr, "error reading asn1 tlv\n");
        fprintf(stdout, "\"}\n");  // closing validity and JSON line
        return;
    }
    if (time.tag == 0x17) {
        fprintf(stdout, ",{");
        fprintf_json_utctime(stdout, "notAfter", time.value.data, time.value.data_end - time.value.data);
        fprintf(stdout, "}");
    }
    //fprintf_raw_as_hex(stdout, validity.value.data, (validity.value.data_end - validity.value.data));
    fprintf(stdout, "]");  // closing validity

    // parse subject
    struct asn1_tlv subject = { 0, 0, { NULL, NULL } };
    status = parser_read_asn1_tlv(&tbs_certificate.value, &subject);
    if (status) {
        fprintf(stderr, "error reading asn1 tlv\n");
        return;
    }
    fprintf_asn1_tlv(stdout, &subject, "subject");
    status = asn1_tlv_read_x509_name(&subject, "subject");
    if (status) {
        fprintf(stderr, "error reading x509_name\n");
        return;
    }
    fprintf(stdout, "}\n");  // closing JSON line

    // parse subjectPublicKeyInfo
    struct asn1_tlv subjectPublicKeyInfo = { 0, 0, { NULL, NULL } };
    status = parser_read_asn1_tlv(&tbs_certificate.value, &subjectPublicKeyInfo);
    if (status) {
        fprintf(stderr, "error reading asn1 tlv\n");
        return;
    }
    fprintf_asn1_tlv(stdout, &subjectPublicKeyInfo, "subjectPublicKeyInfo");

    // parse extensions
    struct asn1_tlv ext = asn1_tlv_init();
    status = parser_read_asn1_tlv(&tbs_certificate.value, &ext);
    if (status) {
        fprintf(stderr, "error reading asn1 tlv\n");
        return;
    }
    fprintf_asn1_tlv(stdout, &ext, "ext");
    struct asn1_tlv *extension_sequence = NULL;
    struct asn1_tlv explicitly_tagged_extensions = asn1_tlv_init();
    if (ext.tag == 0xa3) {
        fprintf(stderr, "got explicit tag %u\n", ext.tag & 0x1f);
        status = parser_read_asn1_tlv(&ext.value, &explicitly_tagged_extensions);
        if (status) {
            fprintf(stderr, "error reading asn1 tlv\n");
            return;
        }
        fprintf_asn1_tlv(stdout, &explicitly_tagged_extensions, "explicitly_tagged_extensions");
        extension_sequence = &explicitly_tagged_extensions;
    }
    fprintf_asn1_tlv(stdout, extension_sequence, "extension_sequence");
    while (parser_get_data_length(&extension_sequence->value) > 0) {
        struct asn1_tlv extension = asn1_tlv_init();
        status = parser_read_asn1_tlv(&extension_sequence->value, &extension);
        if (status) {
            fprintf(stderr, "error reading asn1 tlv (extension_sequence)\n");
            return;
        }
        fprintf_asn1_tlv(stdout, &extension, "extension");

        if (asn1_tlv_is_constructed(&extension)) {
            struct asn1_tlv tmp2;
            status = parser_read_asn1_tlv(&extension.value, &tmp2);
            if (status) {
                fprintf(stderr, "error reading asn1 tlv (tmp2)\n");
                return;
            }
            fprintf_asn1_tlv(stdout, &tmp2, "extnID");
            if (tmp2.tag == 0x06) {
                if (parser_match(&tmp2.value, oid_subjectKeyIdentifier, sizeof(oid_subjectKeyIdentifier), NULL) == status_ok) {
                    fprintf(stderr, "found subjectKeyIdentifier\n");
                } else if (parser_match(&tmp2.value, oid_extKeyUsage, sizeof(oid_extKeyUsage), NULL) == status_ok) {
                    fprintf(stderr, "found extKeyUsage\n");
                } else if (parser_match(&tmp2.value, oid_keyUsage, sizeof(oid_keyUsage), NULL) == status_ok) {
                    fprintf(stderr, "found keyUsage\n");
                } else {
                    fprintf(stderr, "warning: unknown ext oid ");
                    fprintf_raw_as_hex(stderr,  tmp2.value.data, tmp2.value.data_end - tmp2.value.data);
                    fprintf(stderr, "\n");
                    // char oid_buf[32];
                    // hex_to_oid(tmp2.value.data, parser_get_data_length(&tmp.value), oid_buf);
                    // fprintf(stderr, "note: unknown oid %s\n", oid_buf);

                }
                // std::string s = extension_oids["abc"];
            }
            status = parser_read_asn1_tlv(&extension.value, &tmp2);
            if (status) {
                fprintf(stderr, "error reading asn1 tlv (tmp2)\n");
                return;
            }
            if (tmp2.tag == 0x01) {
                fprintf(stderr, "found boolean\n");
                fprintf_asn1_tlv(stdout, &tmp2, "critical");
                status = parser_read_asn1_tlv(&extension.value, &tmp2);
                if (status) {
                    fprintf(stderr, "error reading asn1 tlv (tmp2)\n");
                    return;
                }
            }
            fprintf_asn1_tlv(stdout, &tmp2, "extnValue");
        }

    }

    // tbs_certificate should be out of data now
    if (parser_get_data_length(&tbs_certificate.value) == 0) {
        fprintf(stderr, "done parsing tbs_certificate, no remainder\n");
    }

    struct asn1_tlv signatureAlgorithm = asn1_tlv_init();
    status = parser_read_asn1_tlv(&certificate.value, &signatureAlgorithm);
    if (status) {
        fprintf(stderr, "error reading asn1 tlv\n");
        return;
    }
    fprintf_asn1_tlv(stdout, &signatureAlgorithm, "signatureAlgorithm");
    if (signatureAlgorithm.tag == 0x30) {
        struct asn1_tlv algorithm_oid = asn1_tlv_init();
        status = parser_read_asn1_tlv(&signatureAlgorithm.value, &algorithm_oid);
        if (status) {
            fprintf(stderr, "error reading asn1 tlv\n");
        }
        fprintf_asn1_tlv(stdout, &algorithm_oid, "algorithm_oid");

        struct asn1_tlv null = asn1_tlv_init();
        status = parser_read_asn1_tlv(&signatureAlgorithm.value, &null); // this might be optional
        if (status) {
            fprintf(stderr, "error reading asn1 tlv\n");
        }
        fprintf_asn1_tlv(stdout, &null, "null");
    }

    struct asn1_tlv signatureValue = asn1_tlv_init();
    status = parser_read_asn1_tlv(&certificate.value, &signatureValue);
    if (status) {
        fprintf(stderr, "error reading asn1 tlv\n");
        return;
    }
    fprintf_asn1_tlv(stdout, &signatureValue, "signatureValue");

}

#include <mhash.h>
void sha256_hash(const void *buffer,
                 unsigned int len) {
    int i;
    MHASH td;
    unsigned char hash[32]; 

    hashid hash_type = MHASH_SHA1;
    td = mhash_init(hash_type);
    if (td == MHASH_FAILED) {
        return;
    }

    mhash(td, buffer, len);

    mhash_deinit(td, hash);

    printf("%s: ", mhash_get_hash_name(hash_type));
    for (i = 0; i < mhash_get_block_size(hash_type); i++) {
        printf("%.2x", hash[i]);
    }
    printf("\n");

 }

std::unordered_map<std::string, std::string> cert_dict;

int main(int argc, char *argv[]) {
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    stream = fopen(argv[1], "r");
    if (stream == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    //    std::string str(10000, '\0');

    while ((nread = getline(&line, &len, stream)) != -1) {
        //        printf("got line of length %zu:\n", nread);
        // fwrite(line, nread, 1, stdout);

        // advance just past the comma
        int i = 0;
        for (i=0; i<nread; i++) {
            if (line[i] == ',') {
                break;
            }
        }
        char *b64_line = line + (i+1);
        std::string cert = b64decode(b64_line, nread-(i+1));
        //fprintf(stdout, "parsed base64 (len: %zu)\n", cert.length());

        std::string key = cert.substr(0,32);
        //fprintf(stdout, "key:\t");
        //fprintf_raw_as_hex(stdout, key.c_str(), key.length());
        //fprintf(stdout, "\n");

        sha256_hash(cert.c_str(), cert.length());

        // fprintf(stderr, "parsing cert\n");
        buffer_parse_as_cert(cert.c_str(), cert.length());

        // struct tls_information tls_cert = { 0, };
        //        TLSServerCertificate_parse(str.c_str(), cert_len, &tls_cert);

        cert_dict[key] = cert;
    }

    fprintf(stderr, "loaded %lu certs\n", cert_dict.size());

    free(line);
    fclose(stream);

    exit(EXIT_SUCCESS);

}
