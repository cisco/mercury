/*
 * x509.h
 *
 */

#ifndef X509_H
#define X509_H

#include <stdio.h>
#include <unordered_set>
#include "oid.h"    // oid dictionary

#include "../mercury.h"
#include "../parser.h"
#include "asn1.h"

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

    attribute() : set{}, sequence{}, attribute_type{}, attribute_value{} { }
    attribute(struct parser *p) : set{}, sequence{}, attribute_type{}, attribute_value{} {
        parse(p);
    }
    void parse(struct parser *p) {
        set.parse(p);
        sequence.parse(&set.value, tlv::SEQUENCE);
        attribute_type.parse(&sequence.value, tlv::OBJECT_IDENTIFIER, "attribute_type");
        attribute_value.parse(&sequence.value, 0, "attribute_value");
    }

    void print_as_json(FILE *f, const char *comma="") const {
        const char *unknown_oid = "unknown_oid";
        const char *oid_string = unknown_oid;

        if (attribute_type.length == 0 || attribute_value.length == 0) {
            fprintf(f, "%s{}", comma);  // print empty object to ensure proper JSON formatting
            return;
        }
        oid_string = parser_get_oid_string(&attribute_type.value);
        fprintf(f, "%s{", comma);
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

    name() : RDNsequence{} {}
    void parse(struct parser *p, const char *label=NULL) {
        RDNsequence.parse(p, tlv::SEQUENCE, "RDNsequence");
    }
    void print_as_json(FILE *f, const char *name, const char *pre=",") const {

        fprintf(f, "%s\"%s\":[", pre, name);  // open JSON array
        const char *comma = "";
        struct parser tlv_sequence = RDNsequence.value;
        while (tlv_sequence.is_not_empty()) {
            struct attribute attr(&tlv_sequence);
            attr.print_as_json(f, comma);
            comma = ",";
        }
        fprintf(f, "]");               //  close JSON array

    }
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
        if (sequence.value.is_not_empty()) {
            ca.parse(&sequence.value, tlv::BOOLEAN);  // default false boolean
        }
        if (sequence.value.is_not_empty()) {
            path_len_constraint.parse(&sequence.value, tlv::INTEGER); // integer 0..MAX optional
        }
    }

    void print_as_json(FILE *f) const {
        const char *ca_str = "false";  // default
        unsigned int length = 0;   // default
        // TBD: report actual non-default data
        if (ca.length) {  // Check value as well as length!
            ca_str = "true";
        }
        fprintf(f, "\"basic_constraints\":{\"ca\":%s,\"path_len_constraint\":%u}", ca_str, length);
    }
};

/*

   id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }

   ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId

   KeyPurposeId ::= OBJECT IDENTIFIER
 */

struct ext_key_usage {
    struct tlv sequence;

    ext_key_usage(struct parser *p) : sequence{} {
        sequence.parse(p, 0, "ext_key_usage.sequence");
    }

    void print_as_json(FILE *f) const {
        fprintf(f, "\"ext_key_usage\":[");
        bool first = true;
        struct parser p = sequence.value;
        while (p.is_not_empty()) {
            struct tlv key_purpose_id(&p);
            const char *oid_string = parser_get_oid_string(&key_purpose_id.value);
            if (first) {
                first = false;
            } else {
                fprintf(f, ",");
            }
            if (oid_string != oid_empty_string) {
                fprintf(f, "\"%s\"", oid_string);
            } else {
                fprintf(f, "\"");
                raw_string_print_as_oid(f, key_purpose_id.value.data, key_purpose_id.value.data_end - key_purpose_id.value.data);
                fprintf(f, "\"");
            }

        }
        fprintf(f, "]");
    }
};

/*
      id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }

      KeyUsage ::= BIT STRING {
           digitalSignature        (0),
           nonRepudiation          (1), -- recent editions of X.509 have
                                -- renamed this bit to contentCommitment
           keyEncipherment         (2),
           dataEncipherment        (3),
           keyAgreement            (4),
           keyCertSign             (5),
           cRLSign                 (6),
           encipherOnly            (7),
           decipherOnly            (8) }
*/


struct key_usage {
    struct tlv bit_string;

    key_usage() : bit_string{} {}
    key_usage(struct parser *p) : bit_string{} {
        parse(p);
    }
    void parse(struct parser *p) {
        bit_string.parse(p, tlv::BIT_STRING);
    }
    void print_as_json(FILE *f, const char *name) const {
        char *flags[10] = {
            (char *)"digital_signature",
            (char *)"non_repudiation",
            (char *)"key_encipherment",
            (char *)"data_encipherment",
            (char *)"key_agreement",
            (char *)"key_cert_sign",
            (char *)"crl_sign",
            (char *)"encipher_only",
            (char *)"decipher_only",
            NULL
        };
        bit_string.print_as_json_bitstring_flags(f, "key_usage", flags);
    }
};


/*
   from RFC5280

   id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }

   anyPolicy OBJECT IDENTIFIER ::= { id-ce-certificatePolicies 0 }

   certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation

   PolicyInformation ::= SEQUENCE {
        policyIdentifier   CertPolicyId,
        policyQualifiers   SEQUENCE SIZE (1..MAX) OF
                                PolicyQualifierInfo OPTIONAL }

   CertPolicyId ::= OBJECT IDENTIFIER

   PolicyQualifierInfo ::= SEQUENCE {
        policyQualifierId  PolicyQualifierId,
        qualifier          ANY DEFINED BY policyQualifierId }

   -- policyQualifierIds for Internet policy qualifiers

   id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
   id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
   id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }

   PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )

   Qualifier ::= CHOICE {
        cPSuri           CPSuri,
        userNotice       UserNotice }

   CPSuri ::= IA5String

   UserNotice ::= SEQUENCE {
        noticeRef        NoticeReference OPTIONAL,
        explicitText     DisplayText OPTIONAL }

   NoticeReference ::= SEQUENCE {
        organization     DisplayText,
        noticeNumbers    SEQUENCE OF INTEGER }

   DisplayText ::= CHOICE {
        ia5String        IA5String      (SIZE (1..200)),
        visibleString    VisibleString  (SIZE (1..200)),
        bmpString        BMPString      (SIZE (1..200)),
        utf8String       UTF8String     (SIZE (1..200)) }
 */


struct policy_qualifier_info {
    struct tlv sequence;
    struct tlv qualifier_id;   // id-qt-cps or id-qt-unotice
    struct tlv qualifier;      // cPSuri (IA5String) or userNotice

    policy_qualifier_info() : sequence{}, qualifier_id{}, qualifier{} {}
    policy_qualifier_info(struct parser *p) : sequence{}, qualifier_id{}, qualifier{} {
        parse(p);
    }
    void parse(struct parser *p) {
        sequence.parse(p, tlv::SEQUENCE);
        qualifier_id.parse(&sequence.value); // tlv::OBJECT_IDENTIFIER);
        if (sequence.value.is_not_empty()) {
            qualifier.parse(&sequence.value);
        }
    }
    void print_as_json(FILE *f, const char *name, const char *pre="", const char *post="") const {
        fprintf(f, "%s\"%s\":{", pre, name);
        qualifier_id.print_as_json_oid(f, "qualifier_id");
        fprintf(f, ",");
        qualifier.print_as_json_escaped_string(f, "qualifier");
        fprintf(f, "}%s", post);
    }
    bool is_not_null() { return sequence.is_not_null(); }
};

struct policy_information {
    struct tlv sequence;

    policy_information() : sequence{} {}
    policy_information(struct parser *p) {
        sequence.parse(p, tlv::SEQUENCE);
    }
    void print_as_json(FILE *f, const char *name, const char *pre="", const char *post="") const {
        struct parser tlv_sequence = sequence.value;
        struct tlv policy_identifier(&tlv_sequence, tlv::OBJECT_IDENTIFIER);
        struct tlv policy_qualifiers;
        if (tlv_sequence.is_not_empty()) {
            policy_qualifiers.parse(&tlv_sequence, tlv::SEQUENCE);
        }
        fprintf(f, "%s\"%s\":[", pre, name);
        fprintf(f, "{");
        policy_identifier.print_as_json_oid(f, "policy_identifier");
        if (policy_qualifiers.is_not_null()) {
            struct policy_qualifier_info policy_qualifier_info(&policy_qualifiers.value);
            policy_qualifier_info.print_as_json(f, "policy_qualifier_info", ",");
        }
        fprintf(f, "}");
        fprintf(f, "]%s", post);
    }
};

struct certificate_policies {
    struct tlv sequence;

    certificate_policies(struct parser *p) : sequence{} { //, policy_information{} {
        sequence.parse(p, tlv::SEQUENCE);
    }
    void print_as_json(FILE *f, const char *name, const char *pre="", const char *post="") const {
        fprintf(f, "%s\"%s\":[", pre, name);
        const char *c = "{";
        struct parser tlv_sequence = sequence.value;
        while (tlv_sequence.is_not_empty()) {
            struct policy_information pi(&tlv_sequence);
            pi.print_as_json(f, "policy_information", c, "}");
            c = ",{";
        }
        fprintf(f, "]%s", post);
    }
};

/*
 *  id-ce-privateKeyUsagePeriod OBJECT IDENTIFIER ::=  { id-ce 16 }
 *
 *  PrivateKeyUsagePeriod ::= SEQUENCE {
 *      notBefore       [0]     GeneralizedTime OPTIONAL,
 *      notAfter        [1]     GeneralizedTime OPTIONAL }
 *      -- either notBefore or notAfter MUST be present
 */

struct private_key_usage_period {
    struct tlv sequence;
    struct tlv notBefore;
    struct tlv notAfter;

    private_key_usage_period() : sequence{}, notBefore{}, notAfter{} {   }
    private_key_usage_period(struct parser *p) : sequence{}, notBefore{}, notAfter{} {
        parse(p);
    }
    void parse(struct parser *p) {
        sequence.parse(p, tlv::SEQUENCE);
        while (sequence.value.is_not_empty()) {
            struct tlv tmp(&sequence.value);
            if (tmp.tag == tlv::explicit_tag(0)) {
                notBefore = tmp;
            }
            if (tmp.tag == tlv::explicit_tag(1)) {
                notAfter = tmp;
            }
        }
    }
    void print_as_json(FILE *f, const char *name, bool comma=false) const {
        fprintf(f, comma ? "\"%s\":[" : "\"%s\":[", name);
        const char *c = "";
        if (notBefore.is_not_null()) {
            fprintf(f, "{");
            notBefore.print_as_json_generalized_time(f, "not_before");
            fprintf(f, "}");
            c = ",";
        }
        if (notAfter.is_not_null()) {
            fprintf(f, "%s{", c);
            notAfter.print_as_json_generalized_time(f, "not_after");
            fprintf(f, "}");
        }
        fprintf(f, "]");
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

    general_name() : explicit_tag{} {}
    general_name(struct parser *p) {
        parse(p);
    }
    void parse(struct parser *p, uint8_t expected_tag=0x00) {
        explicit_tag.parse(p, expected_tag);
        //explicit_tag.fprint(stderr, "explicit_tag");
    }
    void print_as_json(FILE *f) const {
        if (explicit_tag.tag == otherName) {
            struct parser tlv_sequence = explicit_tag.value;
            struct tlv type_id(&tlv_sequence, tlv::OBJECT_IDENTIFIER);
            struct tlv value(&tlv_sequence, 0);
            fprintf(f, "{\"other_name\":{");
            type_id.print_as_json_oid(f, "type_id");
            value.print_as_json_hex(f, "value", true);
            fprintf(f, "}}");
        } else if (explicit_tag.tag == rfc822Name) {
            fprintf(f, "{");
            explicit_tag.print_as_json_escaped_string(f, "rfc822_name");
            fprintf(f, "}");
        } else if (explicit_tag.tag == dNSName) {
            fprintf(f, "{");
            explicit_tag.print_as_json_escaped_string(f, "dns_name");
            fprintf(f, "}");
        } else if (explicit_tag.tag == uniformResourceIdentifier) {
            fprintf(f, "{");
            explicit_tag.print_as_json_escaped_string(f, "uri");
            fprintf(f, "}");
        } else if (explicit_tag.tag == iPAddress) {
            explicit_tag.print_as_json_ip_address(f, "ip_address");
        } else if (explicit_tag.tag == directoryName) {
            struct parser tmp = explicit_tag.value;
            struct name n;
            n.parse(&tmp);
            n.print_as_json(f, "directory_name");
        } else {
            fprintf(f, "{\"explicit_tag\": \"%02x\",\"value\":\"", explicit_tag.tag);
            fprintf_raw_as_hex(f, explicit_tag.value.data, (int) (explicit_tag.value.data_end - explicit_tag.value.data));
            fprintf(f, "\"}");
        }
    }
    enum tag {
        otherName                 = tlv::explicit_tag_constructed(0),
        rfc822Name                = tlv::explicit_tag(1),
        dNSName                   = tlv::explicit_tag(2),
        x400Address               = tlv::explicit_tag_constructed(3),
        directoryName             = tlv::explicit_tag_constructed(4),
        ediPartyName              = tlv::explicit_tag_constructed(5),
        uniformResourceIdentifier = tlv::explicit_tag(6),
        iPAddress                 = tlv::explicit_tag(7),
        registeredID              = tlv::explicit_tag(8)
    };

};

struct subject_alt_name {
    struct tlv sequence;

    subject_alt_name(struct parser *p) : sequence{p} {
        // sequence.fprint(stdout, "subject_alt_name.names");
    }

    void print_as_json(FILE *f, const char *name) const {
        fprintf(f, "\"%s\":[", name);
        const char *comma = "";
        struct parser tlv_sequence = sequence.value;
        while (tlv_sequence.is_not_empty()) {
            struct general_name general_name(&tlv_sequence);
            fprintf(f, "%s", comma);
            general_name.print_as_json(f);
            comma = ",";
        }

        fprintf(f, "]");
    }
};

/*

   id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::=  { id-ce 31 }

   CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

   DistributionPoint ::= SEQUENCE {
        distributionPoint       [0]     DistributionPointName OPTIONAL,
        reasons                 [1]     ReasonFlags OPTIONAL,
        cRLIssuer               [2]     GeneralNames OPTIONAL }

   DistributionPointName ::= CHOICE {
        fullName                [0]     GeneralNames,
        nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }

   ReasonFlags ::= BIT STRING {
        unused                  (0),
        keyCompromise           (1),
        cACompromise            (2),
        affiliationChanged      (3),
        superseded              (4),
        cessationOfOperation    (5),
        certificateHold         (6),
        privilegeWithdrawn      (7),
        aACompromise            (8) }
 */

struct distribution_point_name {
    struct tlv explicit_tag;
    struct general_name full_name;
    struct attribute name_relative_to_crl_issuer; // relative distinguished name

    // note: name_relative_to_crl_issuer is untested; no such cert has
    // been found

    distribution_point_name() : explicit_tag{}, full_name{} {}
    distribution_point_name(struct parser *p) {
        parse(p);
    }
    void parse(struct parser *p) {
        struct tlv tmp(p);
        if (tmp.tag == tlv::explicit_tag_constructed(0)) {
            full_name.parse(&tmp.value);
        }
        if (tmp.tag == tlv::explicit_tag_constructed(1)) {
            name_relative_to_crl_issuer.parse(&tmp.value);
        }
    }
    void print_as_json(FILE *f, const char *name, const char *pre="", const char *post="") const {
        if (full_name.explicit_tag.is_not_null()) {
            fprintf(f, "%s\"%s\":{", pre, name);
            fprintf(f, "\"full_name\":");
            full_name.print_as_json(f);
            fprintf(f, "}%s", post);
        } else if (name_relative_to_crl_issuer.set.is_not_null()) {
            fprintf(f, "%s\"%s\":{", pre, name);
            fprintf(f, "\"name_relative_to_crl_issuer\":");
            name_relative_to_crl_issuer.print_as_json(f);
            fprintf(f, "%s}", post);
        }
    }
};

struct distribution_point {
    struct tlv sequence;
    // struct tlv reasons;
    // struct tlv crl_issuer;
    //
    // note: reasons and issuer have not been implemented; no certs
    // for testing are available

    distribution_point(struct parser *p) : sequence{p} { }
    void print_as_json(FILE *f, const char *name, const char *pre="", const char *post="") const {
        fprintf(f, "%s\"%s\":[", pre, name);
        struct parser tlv_sequence = sequence.value;
        while (tlv_sequence.is_not_empty()) {
            struct tlv tmp(&tlv_sequence);
            if (tmp.tag == tlv::explicit_tag_constructed(0)) {
                struct distribution_point_name distribution_point_name(&tmp.value);
                distribution_point_name.print_as_json(f, "distribution_point_name", "{", "}");
            }
        }
        fprintf(f, "]%s", post);
    }
};

struct crl_distribution_points {
    struct tlv sequence;

    crl_distribution_points(struct parser *p) : sequence{p} {  }

    void print_as_json(FILE *f, const char *name, const char *pre="", const char *post="") const {
        fprintf(f, "%s\"%s\":[", pre, name);
        const char *comma = "{";
        struct parser tlv_sequence = sequence.value;
        while (tlv_sequence.is_not_empty()) {
            struct distribution_point dp(&tlv_sequence);
            dp.print_as_json(f, "crl_distribution_point", comma, "}");
            comma = ",{";
        }
        fprintf(f, "]%s", post);
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
    struct tlv cert_issuer;   // sequence of general_name
    struct tlv cert_serial_number;

    authority_key_identifier() : sequence{}, key_identifier{}, cert_issuer{}, cert_serial_number{} {}
    authority_key_identifier(struct parser *p) : sequence{}, key_identifier{}, cert_issuer{}, cert_serial_number{} {
        parse(p);
    }

    void parse(struct parser *p) {
        sequence.parse(p, tlv::SEQUENCE);
        while (sequence.value.is_not_empty()) {
            struct tlv tmp(&sequence.value);

            if (tmp.tag == tlv::explicit_tag(0)) {
                key_identifier = tmp;

            } else if (tmp.tag == tlv::explicit_tag_constructed(1)) {
                cert_issuer.parse(&tmp.value);

            } else if (tmp.tag == tlv::explicit_tag(2)) {
                cert_serial_number = tmp;
            }
        }
    }

    void print_as_json(FILE *f) const {
        fprintf(f, "\"authority_key_identifier\":{");
        bool comma = false;
        if (key_identifier.is_not_null()) {
            key_identifier.print_as_json_hex(f, "key_identifier");
            comma = true;
        }
        if (cert_issuer.is_not_null()) {
            fprintf(f, comma ? "," : "" );
            struct parser tlv_sequence = cert_issuer.value; // avoid modifying cert_issuer
            struct name n;
            n.parse(&tlv_sequence);
            n.print_as_json(f, "cert_issuer", "");
            comma = true;
        }
        if (cert_serial_number.is_not_null()) {
            cert_serial_number.print_as_json_hex(f, "cert_serial_number", comma);
        }
        fprintf(f, "}");
    }
};

/*
      id-ce-nameConstraints OBJECT IDENTIFIER ::=  { id-ce 30 }

      NameConstraints ::= SEQUENCE {
           permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
           excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }

      GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
      GeneralSubtree ::= SEQUENCE {
           base                    GeneralName,
           minimum         [0]     BaseDistance DEFAULT 0,
           maximum         [1]     BaseDistance OPTIONAL }

      BaseDistance ::= INTEGER (0..MAX)
 */


struct general_subtree {
    struct tlv sequence;
    struct general_name base;
    struct tlv minimum;
    struct tlv maximum;

    general_subtree(struct parser *p) {
        sequence.parse(p, tlv::SEQUENCE);
        base.parse(&sequence.value);
        while (sequence.value.is_not_empty()) {
            struct tlv tmp(&sequence.value);
            // tmp.fprint(stderr, "general_subtree.sequence.tmp");
            if (tmp.tag == tag_minimum) {
                minimum = tmp;
            }
            if (tmp.tag == tag_maximum) {
                maximum = tmp;
            }
        }
    }
    void print_as_json(FILE *f, const char *name, const char *pre="", const char *post="") const {
        fprintf(f, "%s\"%s\":", pre, name);
        base.print_as_json(f);
        if (minimum.is_not_null()) {
            // TBD: print out minimum (what about default?)
        } else {
            fprintf(f, ",\"minimum\":0");
        }
        fprintf(f, "%s", post);
    }

    enum tag {
        tag_minimum = tlv::explicit_tag(0),
        tag_maximum = tlv::explicit_tag(1)
    };
};

struct name_constraints {
    struct tlv sequence;
    struct tlv permitted_subtrees; // sequence of general_subtree
    struct tlv excluded_subtrees;  // sequence of general_subtree

    name_constraints(struct parser *p) {
        sequence.parse(p, tlv::SEQUENCE);
        while (sequence.value.is_not_empty()) {
            struct tlv tmp(&sequence.value);
            if (tmp.tag == permittedSubtrees) {
                permitted_subtrees = tmp;
            }
            if (tmp.tag == excludedSubtrees) {
                excluded_subtrees = tmp;
            }
        }
    }

    void print_as_json(FILE *f, const char *name, const char *pre="", const char *post="") const {
        fprintf(f, "%s\"%s\":{", pre, name);
        if (permitted_subtrees.is_not_null()) {
            struct parser tmp = permitted_subtrees.value;  // to avoid modifying permitted_subtrees
            general_subtree subtree(&tmp);
            subtree.print_as_json(f, "permitted_subtree");
        }
        fprintf(f, "}%s", post);
    }

    enum tag {
       permittedSubtrees = tlv::explicit_tag_constructed(0),
       excludedSubtrees  = tlv::explicit_tag_constructed(1)
    };
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
        notBefore.parse(&sequence.value, 0, "validity.notBefore"); // tlv::UTCTime or tlv::GeneralizedTime
        notAfter.parse(&sequence.value, 0, "validity.notAfter");   // tlv::UTCTime or tlv::GeneralizedTime
    }
    void print_as_json(FILE *f) const {
        fprintf(f, ",\"validity\":[");
        fprintf(f, "{");
        notBefore.print_as_json(f, "notBefore");
        fprintf(f, "}");
        fprintf(f, ",{");
        notAfter.print_as_json(f, "notAfter");
        fprintf(f, "}");
        fprintf(f, "]");  // closing validity
    }
    bool contains(const uint8_t gt, size_t len) {
        return false;
    }
};


/*
   id-ce-SignedCertificateTimestampList OBJECT IDENTIFIER ::= { 1 3 6 1 4 1 11129 2 4 2 }

   The contents of the ASN.1 OCTET STRING embedded in an OCSP extension
   or X509v3 certificate extension are as follows:

        opaque SerializedSCT<1..2^16-1>;

        struct {
            SerializedSCT sct_list <1..2^16-1>;
        } SignedCertificateTimestampList;

 */
struct signed_certificate_timestamp_list {
    struct tlv serialized_sct;

    // for now, we don't parse the TLS-style formatting

    signed_certificate_timestamp_list(struct parser *p) {
        serialized_sct.parse(p);
    }
    void print_as_json(FILE *f, const char *name, const char *pre="", const char *post="") const {
        fprintf(f, "%s", pre);
        serialized_sct.print_as_json_hex(f, name);
        fprintf(f, "%s", post);
    }

};

/*
   id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }

   AuthorityInfoAccessSyntax  ::=
           SEQUENCE SIZE (1..MAX) OF AccessDescription

   AccessDescription  ::=  SEQUENCE {
           accessMethod          OBJECT IDENTIFIER,
           accessLocation        GeneralName  }

   id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }

   id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }

   id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }

 */

struct access_description {
    struct tlv sequence;
    struct tlv access_method;            // object identifier
    struct general_name access_location;

    access_description() : sequence{}, access_method{}, access_location{} {}
    access_description(struct parser *x) : sequence{}, access_method{}, access_location{} {
        parse(x);
    }
   void parse(struct parser *x) {
        sequence.parse(x);
        // sequence.fprint(stderr, "sequence");
        access_method.parse(&sequence.value, tlv::OBJECT_IDENTIFIER);
        // access_method.fprint(stderr, "access_method");
        access_location.parse(&sequence.value);
    }
    void print_as_json(FILE *f, const char *name, const char *pre="", const char *post="") const {
        fprintf(f, "%s", pre);
        if (access_method.is_not_null()) {
            access_method.print_as_json(f, name);
        }
        if (access_location.explicit_tag.is_not_null()) {
            fprintf(f, ",\"access_method\":");
            access_location.print_as_json(f);  // TBD: remove unneeded {}
        }
        fprintf(f, "%s", post);
    }
};

struct authority_info_access_syntax {
    struct tlv sequence;

    authority_info_access_syntax(struct parser *p) : sequence{} {
        parse(p);
    }
    void parse(struct parser *p) {
        sequence.parse(p, tlv::SEQUENCE);
    }
    void print_as_json(FILE *f, const char *name, const char *pre="", const char *post="") const {
        fprintf(f, "%s\"%s\":[", pre, name);

        const char *comma = "{";
        struct access_description ad;
        struct parser tlv_sequence = sequence.value;
        while (tlv_sequence.is_not_empty()) {
            ad.parse(&tlv_sequence);
            ad.print_as_json(f, "access_description", comma, "}");
            // break; // TBD: FIXME
            comma = ",{";
        }

        fprintf(f, "]%s", post);
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

    extension(struct parser &p) : sequence{&p}, extnID{}, critical{}, extnValue{} {
        if (sequence.is_constructed()) {
            extnID.parse(&sequence.value, 0, "extnID");
            extnValue.parse(&sequence.value, 0, "extnValue");
            if (extnValue.tag == tlv::BOOLEAN) {
                critical = extnValue;
                extnValue.parse(&sequence.value, 0, "critical");
            }
        }
        if (extnValue.value.is_not_empty() == false) {
            p.set_empty();
        }
        // TBD: if parsing fails, propagate failue upwards
    }

    void print_as_json(FILE *f, const char *comma) const {
        if (sequence.is_constructed()) {
            const char *true_str = "true";
            const char *false_str = "false";
            const char *oid_string = "uknown_oid";
            const char *critical_str = false_str;
            if (extnID.tag == tlv::OBJECT_IDENTIFIER) {
                oid_string = parser_get_oid_string(&extnID.value);
            }
            if (critical.tag == tlv::BOOLEAN) {
                critical_str = true_str;
            }

            fprintf(f, "%s{", comma); // open extension object
            struct parser value = extnValue.value;
            if (oid_string && strcmp("id-ce-SignedCertificateTimestampList", oid_string) == 0) {
                struct signed_certificate_timestamp_list x(&value);
                x.print_as_json(f, "signed_certificate_timestamp_list");
            }
            else if (oid_string && strcmp("id-ce-nameConstraints", oid_string) == 0) {
                struct name_constraints x(&value);
                x.print_as_json(f, "name_constraints");
            }
            else if (oid_string && strcmp("id-ce-cRLDistributionPoints", oid_string) == 0) {
                struct crl_distribution_points x(&value);
                x.print_as_json(f, "crl_distribution_points");
            }
            else if (oid_string && strcmp("id-ce-certificatePolicies", oid_string) == 0) {
                struct certificate_policies x(&value);
                x.print_as_json(f, "certificate_policies");
            }
            else if (oid_string && strcmp("id-ce-privateKeyUsagePeriod", oid_string) == 0) {
                struct private_key_usage_period x(&value);
                x.print_as_json(f, "private_key_usage_period");
            }
            else if (oid_string && strcmp("id-ce-basicConstraints", oid_string) == 0) {
                struct basic_constraints x(&value);
                x.print_as_json(f);
            }
            else if (oid_string && strcmp("id-ce-keyUsage", oid_string) == 0) {
                struct key_usage x(&value);
                x.print_as_json(f, "key_usage");
            }
            else if (oid_string && strcmp("id-ce-extKeyUsage", oid_string) == 0) {
                struct ext_key_usage x(&value);
                x.print_as_json(f);
            }
            else if (oid_string && strcmp("id-ce-subjectAltName", oid_string) == 0) {
                struct subject_alt_name x(&value);
                x.print_as_json(f, "subject_alt_name");
            }
            else if (oid_string && strcmp("id-ce-issuerAltName", oid_string) == 0) {
                struct subject_alt_name x(&value);
                x.print_as_json(f, "issuer_alt_name");
            }
            else if (oid_string && strcmp("id-ce-authorityKeyIdentifier", oid_string) == 0) {
                struct authority_key_identifier x(&value);
                x.print_as_json(f);
            }
            else if (oid_string && strcmp("id-ce-subjectKeyIdentifier", oid_string) == 0) {
                struct tlv x(&value);
                x.print_as_json_hex(f, "subject_key_identifier");
            }
            else if (oid_string && strcmp("id-pe-authorityInfoAccess", oid_string) == 0) {
                struct authority_info_access_syntax x(&value);
                x.print_as_json(f, "authority_info_access");
            }
            else if (oid_string && strcmp("NetscapeCertificateComment", oid_string) == 0) {
                struct tlv x(&value);
                x.print_as_json(f, "netscape_certificate_comment");
            }
            else if (oid_string && strcmp("NetscapeCertType", oid_string) == 0) {
                struct tlv x(&value);
                x.print_as_json_hex(f, "netscape_cert_type");
            } else {
                struct tlv x(&value);
                fprintf(f, "\"unsupported\":{");
                extnID.print_as_json_oid(f, "oid");
                x.print_as_json_hex(f, "value", true);
                fprintf(f, "}");
            }
            fprintf(f, ",\"critical\":%s", critical_str);
            fprintf(f, "}"); // close extension object

        }
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

    void print_as_json(FILE *f, const char *name, bool comma=false) const {
        fprintf(f, comma ? ",\"%s\":{" : "\"%s\":{", name);
        if (modulus.is_not_null() && exponent.is_not_null()) {
            modulus.print_as_json_hex(f, "modulus", false);
            exponent.print_as_json_hex(f, "exponent", true);
        }
        fprintf(f, "}");
    }
};

/*
   From RFC 5480:

   The subjectPublicKey from SubjectPublicKeyInfo is the ECC public key.
   ECC public keys have the following syntax:

     ECPoint ::= OCTET STRING

   Implementations of Elliptic Curve Cryptography according to this
   document MUST support the uncompressed form and MAY support the
   compressed form of the ECC public key.  The hybrid form of the ECC
   public key from [X9.62] MUST NOT be used.  As specified in [SEC1]:

      o The elliptic curve public key (a value of type ECPoint that is
        an OCTET STRING) is mapped to a subjectPublicKey (a value of
        type BIT STRING) as follows: the most significant bit of the
        OCTET STRING value becomes the most significant bit of the BIT
        STRING value, and so on; the least significant bit of the OCTET
        STRING becomes the least significant bit of the BIT STRING.
        Conversion routines are found in Sections 2.3.1 and 2.3.2 of
        [SEC1].

      o The first octet of the OCTET STRING indicates whether the key is
        compressed or uncompressed.  The uncompressed form is indicated
        by 0x04 and the compressed form is indicated by either 0x02 or
        0x03 (see 2.3.3 in [SEC1]).  The public key MUST be rejected if
        any other value is included in the first octet.
 */

struct ec_public_key {
    struct parser d;
    // struct tlv tmp;   // TBD: ec public key is *not* ASN.1 formatted

    ec_public_key(struct parser *p) : d{} {
        d = *p;
    }
    void print_as_json(FILE *f, const char *name, bool comma) const {
        if (comma) {
            fprintf(f, ",");
        }
        fprintf(f, "\"%s\":{", name);
        ssize_t data_length = d.data_end - d.data;
        const uint8_t *data = d.data;
        if (data && data_length) {
            if (data[0] == 0x04) {
                data++;
                data_length--;
                fprintf(f, "\"x\":\"");
                fprintf_raw_as_hex(f, data, data_length/2);
                fprintf(f, "\"");
                data += data_length/2;
                fprintf(f, ",\"y\":\"");
                fprintf_raw_as_hex(f, data, data_length/2);
                fprintf(f, "\"");
            } else if (data[0] == 0x02) {
                data++;
                data_length--;
                fprintf(f, "\"x\":\"");
                fprintf_raw_as_hex(f, data, data_length);
                fprintf(f, "\"");
                fprintf(f, ",\"y\":\"00\"");
            } else if (data[0] == 0x03) {
                data++;
                data_length--;
                fprintf(f, "\"x\":\"");
                fprintf_raw_as_hex(f, data, data_length);
                fprintf(f, "\"");
                fprintf(f, ",\"y\":\"01\"");
            }
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
    struct tlv null;
    struct tlv parameters;

    algorithm_identifier() : sequence{}, algorithm{}, parameters{} {}
    algorithm_identifier(struct parser *p) : sequence{}, algorithm{}, parameters{} {
        parse(p);
    }
    void parse(struct parser *p) {
        sequence.parse(p, tlv::SEQUENCE);
        algorithm.parse(&sequence.value, tlv::OBJECT_IDENTIFIER);
        if (sequence.value.is_not_empty()) {
            null.parse(&sequence.value, tlv::NULL_TAG);
        }
        if (sequence.value.is_not_empty()) {
            parameters.parse(&sequence.value);
        }
    }
    void print_as_json(FILE *f, const char *name, const char *pre="", const char *post="") const {
        fprintf(f, "%s\"%s\":{", pre, name);
        algorithm.print_as_json_oid(f, "algorithm");
        if (parameters.is_not_null()) {
            fprintf(f, ",");
            if (parameters.tag == tlv::OBJECT_IDENTIFIER) {
                parameters.print_as_json_oid(f, "parameters");
            } else {
                parameters.print_as_json_hex(f, "parameters");
            }
        }
        fprintf(f, "}%s", post);
    }
    const char *type() const {
        if (algorithm.is_not_null()) {
            return parser_get_oid_string(&algorithm.value);
        }
        return NULL;
    }
    const char *get_parameters() const {
        if (parameters.is_not_null()) {
            return parser_get_oid_string(&parameters.value);
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
    void print_as_json(FILE *f, const char *name) const {
        fprintf(f, ",\"%s\":{", name);
        algorithm.print_as_json(f, "algorithm_identifier");
        struct tlv tmp_key = subject_public_key;
        if (strcmp(algorithm.type(), "rsaEncryption") == 0) {
            tmp_key.remove_bitstring_encoding();
            struct rsa_public_key pub_key(&tmp_key.value);
            pub_key.print_as_json(f, "subject_public_key", true);

        } else if (strcmp(algorithm.type(), "id-ecPublicKey") == 0) {
            tmp_key.remove_bitstring_encoding();
            struct ec_public_key pub_key(&tmp_key.value);
            pub_key.print_as_json(f, "subject_public_key", true);

        } else {
            subject_public_key.print_as_json_hex(f, "subject_public_key", true);
        }
        fprintf(f, "}");
    }
};



/*
 * X509/PKIX Certificate Format (see RFCs 5280 and 1422)
 *
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
          explicitly_tagged_extensions{},
          extensions{},
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

        if (tbs_certificate.value.is_not_empty() == false) {
            return;    // optional extensions are not present
        }

        // parse extensions
        explicitly_tagged_extensions.parse(&tbs_certificate.value, tlv::explicit_tag_constructed(3));
        if (explicitly_tagged_extensions.is_not_null()) {
            extensions.parse(&explicitly_tagged_extensions.value, 0, "explicitly tagged extensions");
        } else {
            extensions.parse(&tbs_certificate.value, 0, "untagged extensions");
        }

        // tbs_certificate should be out of data now
        if (tbs_certificate.value.is_not_empty()) {
            fprintf(stderr, "warning: tbs_certificate has trailing data\n");
        }

        signature_algorithm.parse(&certificate.value);
        signature.parse(&certificate.value, tlv::BIT_STRING, "signature");

    }

    void print_as_json(FILE *f) const {

        fprintf(f, "{");   // open JSON object
        serial_number.print_as_json_hex(f, "serial_number");
        algorithm_identifier.print_as_json(f, "algorithm_identifier", ",");
        issuer.print_as_json(f, "issuer");
        validity.print_as_json(f);
        subject.print_as_json(f, "subject");
        subjectPublicKeyInfo.print_as_json(f, "subject_public_key_info");

        fprintf(f, ",\"extensions\":[");  // open JSON array for extensions
        const char *comma = "";
        struct parser tlv_sequence = extensions.value;
        while (tlv_sequence.is_not_empty()) {
            struct extension xtn(tlv_sequence);
            xtn.print_as_json(f, comma);
            comma = ",";
        }
        fprintf(f, "]");  // closing extensions JSON array

        signature_algorithm.print_as_json(f, "signature_algorithm", ",");
        fprintf(f, ",");
        struct tlv tmp_sig = signature;        // to avoid modifying signature
        tmp_sig.remove_bitstring_encoding();
        tmp_sig.print_as_json_hex(f, "signature");
        fprintf(f, "}\n"); // close JSON line

    }

    bool is_weak(bool unsigned_is_weak=false) const {

        const char *alg_type = subjectPublicKeyInfo.algorithm.type();
        if (strcmp(alg_type, "rsaEncryption") == 0) {
            struct tlv tmp_key = subjectPublicKeyInfo.subject_public_key;  // make copy to leave original intact
            tmp_key.remove_bitstring_encoding();
            struct rsa_public_key pub_key(&tmp_key.value);
            unsigned int bits_in_key = (pub_key.modulus.length-1)*8;  // we should check integer formatting, but instead we assume a leading 0x00
            if (bits_in_key < 2048) {
                return true;
            }
            unsigned int bytes_in_exponent = pub_key.exponent.length; // TBD: make proper
            if (bytes_in_exponent < 3) {
                return true;
            }
        }
        if (strcmp(alg_type, "id-ecPublicKey") == 0) {
            const char *parameters = subjectPublicKeyInfo.algorithm.get_parameters();
            std::unordered_set<std::string> weak_parameters {
              "secp192r1",
              "secp224r1",
              "prime192v1",
              "prime192v2",
              "prime192v3",
              "prime239v1",
              "prime239v2",
              "prime239v3"
              "brainpoolP160r1",
              "brainpoolP160t1",
              "brainpoolP192r1",
              "brainpoolP192t1",
              "brainpoolP224r1",
              "brainpoolP224t1",
              // "prime256v1"
            };
            if (parameters == NULL || weak_parameters.find(parameters) != weak_parameters.end()) {
                return true;
            }
        }
        const char *sig_alg_type = signature_algorithm.type();
        std::unordered_set<std::string> weak_sig_algs= {
            "rsaEncryption",
            "md2WithRSAEncryption",
            "md5WithRSAEncryption",
            "sha-1WithRSAEncryption",
            "sha1WithRSAEncryption",
            "sha224WithRSAEncryption"
            // "sha256WithRSAEncryption",
            // "sha384WithRSAEncryption",
            // "sha512WithRSAEncryption"
        };
        if (sig_alg_type == NULL) {
            if (unsigned_is_weak) {  // TBD: check trusted roots to see if this is one
                return true;
            }
        } else {
            if (weak_sig_algs.find(sig_alg_type) != weak_sig_algs.end()) {
                return true;
            }
        }
        return false;
    }

    bool is_nonconformant() {
        const char *sig_alg_type = signature_algorithm.type();
        const char *tbs_sig_alg_type = algorithm_identifier.type();
        if (sig_alg_type && tbs_sig_alg_type && strcmp(sig_alg_type, tbs_sig_alg_type) != 0) {
            return true;
        }
        return false;
    }

    bool is_not_currently_valid() const {
        char time_str[16];
        time_t t = time(NULL);
        struct tm *tt = localtime(&t);
        size_t retval = strftime(time_str, sizeof(time_str), "%y%m%d%H%M%SZ", tt);
        if (retval == 0) {
            return true;  // error: can't get current time
        }

        struct tlv tmp;
        tmp.set(tlv::UTCTime, time_str, sizeof(time_str));
        if (validity.notBefore.time_cmp(tmp) <= 0) {
            if (validity.notAfter.time_cmp(tmp) >= 0) {
                return false;
            }
        }
        return true;
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
        struct tlv version;

        struct parser p;
        data = (const uint8_t *)buffer;
        parser_init(&p, (const unsigned char *)buffer, len);

        struct tlv certificate(&p, tlv::SEQUENCE, "certificate");

        struct tlv tbs_certificate(&certificate.value, tlv::SEQUENCE, "tbs_certificate");

        // parse (implicit or explicit) version
        struct tlv explicitly_tagged_version(&tbs_certificate.value, tlv::explicit_tag_constructed(0), "version_tag");
        if (explicitly_tagged_version.is_not_null()) {
            version.parse(&explicitly_tagged_version.value, tlv::INTEGER, "version");

        } else {
            struct tlv version_or_serial_number(&tbs_certificate.value, tlv::INTEGER, "version_or_serial_number");
            if (version_or_serial_number.length ==1 && version_or_serial_number.value.data[0] < 3) {
                version = version_or_serial_number;
            } else {
                serial_number = version_or_serial_number;
                // no version in certificate; assume it is the default
            }
        }
        if (serial_number.is_null()) {
            serial_number.parse(&tbs_certificate.value, tlv::INTEGER, "serial number");
        }

        struct tlv algorithm_identifier(&tbs_certificate.value, 0, "algorithm_identifier");

        // parse issuer
        issuer.parse(&tbs_certificate.value);
        if (issuer.is_not_null()) {
            data_end = tbs_certificate.value.data;  // found the end of the issuer, so set data_end
        } else {
            data = NULL;                            // indicate that we didn't get a complete prefix
        }
    }

    size_t get_length() const {
        if (issuer.is_null()) {
            return 0;
        }
        return data_end - data;
    }

    void print_as_json(FILE *f) const {
        fprintf(f, "{");   // open JSON object
        serial_number.print_as_json_hex(f, "serial_number");
        fprintf(f, ",");
        issuer.print_as_json_hex(f, "issuer");
        fprintf(f, "}\n"); // close JSON line
    }

    void print_as_json_hex(FILE *f) const {
        fprintf(f, "{\"cert_prefix\":\"");   // open JSON object
        if (data && data_end) {
            fprintf_raw_as_hex(f, data, data_end - data);
        }
        fprintf(f, "\"}\n"); // close JSON line
    }

};


/*

  Certificate Fingerprinting Notes

  From RFC 2986:

     A certification authority ... constructs an X.509 certificate
     from the [subject] distinguished name and public key, the issuer
     name, and the certification authority's choice of serial number,
     validity period, and signature algorithm.  If the certification
     request contains any PKCS #9 attributes, the certification
     authority may also use the values in these attributes as well as
     other information known to the certification authority to
     construct X.509 certificate extensions.

  From RFC 5280:

     Conforming CAs MUST support the key identifiers, basic
     constraints, key usage, and certificate policies extensions.  If
     the CA issues certificates with an empty sequence for the subject
     field, the CA MUST support the subject alternative name
     extension.  Support for the remaining extensions is OPTIONAL.
     Conforming CAs MAY support extensions that are not identified
     within this specification; certificate issuers are cautioned that
     marking such extensions as critical may inhibit interoperability.
     At a minimum, applications conforming to this profile MUST
     recognize the following extensions: key usage, certificate
     policies, subject alternative name, basic constraints, name
     constraints, policy constraints, extended key usage, and inhibit
     anyPolicy.  In addition, applications conforming to this profile
     SHOULD recognize the authority and subject key identifier
     and policy mappings extensions.


    Data Feature         Source
    ----------------------------------------------------
    version              CA
    serialNumber         CA
    signature            CA
    issuer               CA
    validity             CA
    subject              Subject
    subjectPublicKeyInfo Subject
    extensions           CA or Subject (see below)

    Extensions                      Source
    ---------------------------------------------------
    authorityKeyIdentifier          CA
    basicConstraints                CA
    certificateIssuer               CA
    certificatePolicies             CA
    cRLDistributionPoints           CA
    cRLNumber                       CA
    cRLReasons                      CA
    deltaCRLIndicator               CA
    extKeyUsage                     Subject?
    freshestCRL
    holdInstructionCode
    inhibitAnyPolicy
    invalidityDate
    issuerAltName
    issuingDistributionPoint
    keyUsage                        CA?
    nameConstraints
    policyConstraints
    policyMappings
    privateKeyUsagePeriod
    SignedCertificateTimestampList  ??
    subjectAltName                  Subject
    subjectDirectoryAttributes      Subject
    subjectKeyIdentifier            Subject

 */




#endif /* X509_H */
