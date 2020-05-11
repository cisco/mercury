/*
 * x509.h
 *
 */

#ifndef X509_H
#define X509_H

#include <stdio.h>
#include <unordered_set>
#include "oid_list.h"    // oid dictionary

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

    void print_as_json(struct json_object_asn1 &o) const {
        if (attribute_type.is_not_null()) {
            const char *oid_string = parser_get_oid_string(&attribute_type.value);
            if (oid_string != oid_empty_string) {
                attribute_value.print_as_json_escaped_string(o, oid_string);
            } else {
                attribute_type.print_as_json_oid(o, "attribute_type");
                if (attribute_value.is_not_null()) {
                    attribute_value.print_as_json_hex(o, "attribute_value");
                }
            }
        }
    }

    bool matches(const struct attribute &r) {
        return attribute_type == r.attribute_type && attribute_value == r.attribute_value;
    }
};

struct name {
    struct tlv RDNsequence;

    name() : RDNsequence{} {}
    void parse(struct parser *p, const char *label=NULL) {
        RDNsequence.parse(p, tlv::SEQUENCE, label);
    }

    void print_as_json(struct json_object_asn1 &o, const char *name) const {

        struct json_array array{o, name};
        struct parser tlv_sequence = RDNsequence.value;
        while (tlv_sequence.is_not_empty()) {
            struct attribute attr(&tlv_sequence);
            struct json_object_asn1 attr_obj{array};
            attr.print_as_json(attr_obj);
            attr_obj.close();
        }
        array.close();
    }

    bool matches(const struct name &r) const {
        struct parser tlv_sequence = RDNsequence.value;
        struct parser tlv_sequence_r = r.RDNsequence.value;
        while (tlv_sequence.is_not_empty() && tlv_sequence_r.is_not_empty()) {
            struct attribute attr(&tlv_sequence);
            struct attribute attr_r(&tlv_sequence_r);
            if (attr.matches(attr_r)) {
                ;
            } else {
                return false;
            }
        }
        return true;
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

    void print_as_json(struct json_object_asn1 &o) const {
        bool ca_flag = false;  // default
        unsigned int length = 0;   // default
        // TBD: report actual non-default data
        if (ca.length) {  // Check value as well as length!
            ca_flag = true;
        }
        struct json_object_asn1 bc{o, "basic_constraints"};
        bc.print_key_bool("ca", ca_flag);
        bc.print_key_uint("path_len_constraint", length);
        bc.close();
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

    void print_as_json(struct json_object_asn1 &o) const {
        struct json_array_asn1 a{o, "ext_key_usage"};
        struct parser p = sequence.value;
        while (p.is_not_empty()) {
            struct tlv key_purpose_id(&p);
            const char *oid_string = parser_get_oid_string(&key_purpose_id.value);
            if (oid_string != oid_empty_string) {
                a.print_string(oid_string);
            } else {
                a.print_oid(key_purpose_id.value);
            }
        }
        a.close();
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

    void print_as_json(struct json_object_asn1 &o, const char *name) const {
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
        bit_string.print_as_json_bitstring_flags(o, name, flags);
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
    void print_as_json(struct json_object_asn1 &o, const char *name) const {
        struct json_object_asn1 q{o, name};
        qualifier_id.print_as_json_oid(q, "qualifier_id");
        qualifier.print_as_json_escaped_string(q, "qualifier");
        q.close();
    }
    bool is_not_null() { return sequence.is_not_null(); }
};

struct policy_information {
    struct tlv sequence;

    policy_information() : sequence{} {}
    policy_information(struct parser *p) {
        sequence.parse(p, tlv::SEQUENCE);
        if (sequence.is_null()) { p->set_null(); } // handle unexpected data
    }
    void print_as_json(struct json_object_asn1 &o, const char *name) const {
        struct parser tlv_sequence = sequence.value;
        struct tlv policy_identifier(&tlv_sequence, tlv::OBJECT_IDENTIFIER);
        struct tlv policy_qualifiers;
        if (tlv_sequence.is_not_empty()) {
            policy_qualifiers.parse(&tlv_sequence, tlv::SEQUENCE);
        }
        struct json_array a{o, name};
        struct json_object_asn1 wrapper{a};
        policy_identifier.print_as_json_oid(wrapper, "policy_identifier");
        if (policy_qualifiers.is_not_null()) {
            struct policy_qualifier_info policy_qualifier_info(&policy_qualifiers.value);
            policy_qualifier_info.print_as_json(wrapper, "policy_qualifier_info");
        }
        wrapper.close();
        a.close();
    }
};

struct certificate_policies {
    struct tlv sequence;

    certificate_policies(struct parser *p) : sequence{} { //, policy_information{} {
        sequence.parse(p, tlv::SEQUENCE);
    }
    void print_as_json(struct json_object_asn1 &o, const char *name) const {
        struct json_array a{o, name};
        struct parser tlv_sequence = sequence.value;
        while (tlv_sequence.is_not_empty()) {
            struct policy_information pi(&tlv_sequence);
            struct json_object_asn1 wrapper{a};
            pi.print_as_json(wrapper, "policy_information");
            wrapper.close();
        }
        a.close();
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
            } else if (tmp.tag == tlv::explicit_tag(1)) {
                notAfter = tmp;
            } else {
                p->set_null();  // handle unexpected data
            }
        }
    }
    void print_as_json(struct json_object_asn1 &o, const char *name) const {
        struct json_array a{o, name};
        if (notBefore.is_not_null()) {
            struct json_object_asn1 wrapper{a};
            notBefore.print_as_json_generalized_time(wrapper, "not_before");
            wrapper.close();
        }
        if (notAfter.is_not_null()) {
            struct json_object_asn1 wrapper{a};
            notAfter.print_as_json_generalized_time(wrapper, "not_after");
            wrapper.close();
        }
        a.close();
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
        // explicit_tag.fprint_tlv(stderr, "explicit_tag");
    }
    void print_as_json(struct json_object_asn1 &o) const {
        if (explicit_tag.tag == otherName) {
            struct parser tlv_sequence = explicit_tag.value;
            struct tlv type_id(&tlv_sequence, tlv::OBJECT_IDENTIFIER);
            struct tlv value(&tlv_sequence, 0);
            struct json_object_asn1 other_name{o, "other_name"};
            type_id.print_as_json_oid(other_name, "type_id");
            value.print_as_json_hex(other_name, "value");
            other_name.close();
        } else if (explicit_tag.tag == rfc822Name) {
            explicit_tag.print_as_json_escaped_string(o, "rfc822_name");
        } else if (explicit_tag.tag == dNSName) {
            explicit_tag.print_as_json_escaped_string(o, "dns_name");
        } else if (explicit_tag.tag == uniformResourceIdentifier) {
            explicit_tag.print_as_json_escaped_string(o, "uri");
        } else if (explicit_tag.tag == iPAddress) {
            explicit_tag.print_as_json_ip_address(o, "ip_address");
        } else if (explicit_tag.tag == directoryName) {
            struct parser tmp = explicit_tag.value;
            struct name n;
            n.parse(&tmp);
            n.print_as_json(o, "directory_name");
        } else {
            o.print_key_int("explicit_tag", explicit_tag.tag);
            o.print_key_hex("value", explicit_tag.value);
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

    void print_as_json(struct json_object &o, const char *name) const {
        struct json_array a{o, name};
        struct parser tlv_sequence = sequence.value;
        while (tlv_sequence.is_not_empty()) {
            struct general_name general_name(&tlv_sequence);
            struct json_object_asn1 wrapper{a};
            general_name.print_as_json(wrapper);
            wrapper.close();
        }
        a.close();
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

    void print_as_json(struct json_object_asn1 &o, const char *name) const {
        struct json_object_asn1 wrapper{o, name};
        if (full_name.explicit_tag.is_not_null()) {
            struct json_object_asn1 full{wrapper, "full_name"};
            full_name.print_as_json(full);
            full.close();
        } else if (name_relative_to_crl_issuer.set.is_not_null()) {
            struct json_object_asn1 relative{wrapper, "name_relative_to_crl_issuer"};
            name_relative_to_crl_issuer.print_as_json(relative);
            relative.close();
        }
        wrapper.close();
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

    void print_as_json(struct json_object_asn1 &o, const char *name) const {
        struct json_array a{o, name};
        struct parser tlv_sequence = sequence.value;
        while (tlv_sequence.is_not_empty()) {
            struct tlv tmp(&tlv_sequence);
            if (tmp.tag == tlv::explicit_tag_constructed(0)) {
                struct distribution_point_name distribution_point_name(&tmp.value);
                struct json_object_asn1 wrapper{a};
                distribution_point_name.print_as_json(wrapper, "distribution_point_name");
                wrapper.close();
            }
        }
        a.close();
    }
};

struct crl_distribution_points {
    struct tlv sequence;

    crl_distribution_points(struct parser *p) : sequence{p} {  }

    void print_as_json(struct json_object_asn1 &o, const char *name) const {
        struct json_array a{o, name};
        struct parser tlv_sequence = sequence.value;
        while (tlv_sequence.is_not_empty()) {
            struct distribution_point dp(&tlv_sequence);
            struct json_object_asn1 tmp{a};
            dp.print_as_json(tmp, "crl_distribution_point");
            tmp.close();
        }
        a.close();
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

    void print_as_json(struct json_object_asn1 &o) const {
        struct json_object_asn1 aki{o, "authority_key_identifier"};
        if (key_identifier.is_not_null()) {
            key_identifier.print_as_json_hex(aki, "key_identifier");
        }
        if (cert_issuer.is_not_null()) {
            struct parser tlv_sequence = cert_issuer.value; // avoid modifying cert_issuer
            struct name n;
            n.parse(&tlv_sequence);
            n.print_as_json(aki, "cert_issuer");
        }
        if (cert_serial_number.is_not_null()) {
            cert_serial_number.print_as_json_hex(aki, "cert_serial_number");
        }
        aki.close();
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

    void print_as_json(struct json_object_asn1 &o, const char *name) const {
        struct json_object_asn1 gst{o, name};
        base.print_as_json(gst);
        if (minimum.is_not_null()) {
            // TBD: print out minimum (what about default?)
        } else {
            gst.print_key_int("minimim", 0);
        }
        gst.close();
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

    void print_as_json(struct json_object_asn1 &o, const char *name) const {
        struct json_object_asn1 ps{o, name};
        if (permitted_subtrees.is_not_null()) {
            struct parser tmp = permitted_subtrees.value;  // to avoid modifying permitted_subtrees
            general_subtree subtree(&tmp);
            subtree.print_as_json(ps, "permitted_subtree");
        }
        ps.close();
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

    void print_as_json(struct json_object_asn1 &o) const {
        struct json_array array{o, "validity"};
        struct json_object_asn1 obj{array};
        if (notBefore.is_not_null()) {
            notBefore.print_as_json(obj, "not_before");
        }
        if (notAfter.is_not_null()) {
            obj.reinit(array);
            notAfter.print_as_json(obj, "not_after");
        }
        obj.close();
        array.close();
    }
    bool contains(const char *time_str, size_t time_str_len) const {
        struct tlv tmp;
        tmp.set(tlv::UTCTime, time_str, time_str_len);
        if (notBefore.time_cmp(tmp) <= 0) {
            if (notAfter.time_cmp(tmp) >= 0) {
                return true;
            }
        }
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

    void print_as_json(struct json_object_asn1 &o, const char *name) const {
        serialized_sct.print_as_json_hex(o, name);
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
        if (sequence.is_null()) {
            x->set_null();
        }
        // sequence.fprint(stderr, "sequence");
        access_method.parse(&sequence.value, tlv::OBJECT_IDENTIFIER, "access_method");
        if (access_method.is_null()) {
            x->set_null();
        }
        // access_method.fprint(stderr, "access_method");
        access_location.parse(&sequence.value);
        if (access_location.explicit_tag.is_null()) {
            x->set_null();
        }
    }

    void print_as_json(struct json_object_asn1 &o) const {
        if (access_method.is_not_null()) {
            access_method.print_as_json_oid(o, "access_method");
        }
        if (access_location.explicit_tag.is_not_null()) {
            struct json_object_asn1 al{o, "access_location"};
            access_location.print_as_json(al);
            al.close();
        }
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

    void print_as_json(struct json_object_asn1 &o, const char *name) const {
        struct json_array a{o, name};
        struct access_description ad;
        struct parser tlv_sequence = sequence.value;
        while (tlv_sequence.is_not_empty()) {
            ad.parse(&tlv_sequence);
            struct json_object_asn1 wrapper{a};
            ad.print_as_json(wrapper);
            wrapper.close();
            // break; // TBD: FIXME
        }
        a.close();
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
            extnValue.parse(&sequence.value, 0, "critical or extnValue");
            if (extnValue.tag == tlv::BOOLEAN) {
                critical = extnValue;
                extnValue.parse(&sequence.value, 0, "extnValue");
            }
        }
        if (extnValue.value.is_not_empty() == false) {
            p.set_empty();
        }
        // TBD: if parsing fails, propagate failue upwards
    }

    void print_as_json(struct json_object_asn1 &o) const {
        if (sequence.is_constructed()) {
            const char *oid_string = "uknown_oid";
            bool critical_flag = false;
            if (extnID.tag == tlv::OBJECT_IDENTIFIER) {
                oid_string = parser_get_oid_string(&extnID.value);
            }
            if (critical.tag == tlv::BOOLEAN) {
                critical_flag = true;
            }
            struct parser value = extnValue.value;
            if (oid_string && strcmp("id-ce-SignedCertificateTimestampList", oid_string) == 0) {
                struct signed_certificate_timestamp_list x(&value);
                x.print_as_json(o, "signed_certificate_timestamp_list");
            }
            else if (oid_string && strcmp("id-ce-nameConstraints", oid_string) == 0) {
                struct name_constraints x(&value);
                x.print_as_json(o, "name_constraints");
            }
            else if (oid_string && strcmp("id-ce-cRLDistributionPoints", oid_string) == 0) {
                struct crl_distribution_points x(&value);
                x.print_as_json(o, "crl_distribution_points");
            }
            else if (oid_string && strcmp("id-ce-certificatePolicies", oid_string) == 0) {
                struct certificate_policies x(&value);
                x.print_as_json(o, "certificate_policies");
            }
            else if (oid_string && strcmp("id-ce-privateKeyUsagePeriod", oid_string) == 0) {
                struct private_key_usage_period x(&value);
                x.print_as_json(o, "private_key_usage_period");
            }
            else if (oid_string && strcmp("id-ce-basicConstraints", oid_string) == 0) {
                struct basic_constraints x(&value);
                x.print_as_json(o);
            }
            else if (oid_string && strcmp("id-ce-keyUsage", oid_string) == 0) {
                struct key_usage x(&value);
                x.print_as_json(o, "key_usage");
            }
            else if (oid_string && strcmp("id-ce-extKeyUsage", oid_string) == 0) {
                struct ext_key_usage x(&value);
                x.print_as_json(o);
            }
            else if (oid_string && strcmp("id-ce-subjectAltName", oid_string) == 0) {
                struct subject_alt_name x(&value);
                x.print_as_json(o, "subject_alt_name");
            }
            else if (oid_string && strcmp("id-ce-issuerAltName", oid_string) == 0) {
                struct subject_alt_name x(&value);
                x.print_as_json(o, "issuer_alt_name");
            }
            else if (oid_string && strcmp("id-ce-authorityKeyIdentifier", oid_string) == 0) {
                struct authority_key_identifier x(&value);
                x.print_as_json(o);
            }
            else if (oid_string && strcmp("id-ce-subjectKeyIdentifier", oid_string) == 0) {
                struct tlv x(&value);
                x.print_as_json_hex(o, "subject_key_identifier");
            }
            else if (oid_string && strcmp("id-pe-authorityInfoAccess", oid_string) == 0) {
                struct authority_info_access_syntax x(&value);
                x.print_as_json(o, "authority_info_access");
            }
            else if (oid_string && strcmp("NetscapeCertificateComment", oid_string) == 0) {
                struct tlv x(&value);
                x.print_as_json_escaped_string(o, "netscape_certificate_comment");
            }
            else if (oid_string && strcmp("NetscapeCertType", oid_string) == 0) {
                struct tlv x(&value);
                x.print_as_json_hex(o, "netscape_cert_type");
            } else {
                struct tlv x(&value);
                struct json_object_asn1 unsprt{o, "unsupported"};
                extnID.print_as_json_oid(unsprt, "oid");
                x.print_as_json_hex(unsprt, "value");
                unsprt.close();
            }
            o.print_key_bool("critical", critical_flag);
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

    void print_as_json(struct json_object_asn1 &o, const char *name) const {
        struct json_object_asn1 pub_key{o, name};
        if (modulus.is_not_null() && exponent.is_not_null()) {
            modulus.print_as_json_hex(pub_key, "modulus");
            exponent.print_as_json_hex(pub_key, "exponent");
        }
        pub_key.close();
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

    void print_as_json(struct json_object_asn1 &o, const char *name) const {
        struct json_object_asn1 pub_key{o, name};
        ssize_t data_length = d.data_end - d.data;
        const uint8_t *data = d.data;
        if (data && data_length) {
            if (data[0] == 0x04) {
                data++;
                data_length--;
                struct parser tmp = { data, data + data_length/2};
                pub_key.print_key_hex("x", tmp);
                data += data_length/2;
                struct parser tmp2 = { data, data + data_length/2};
                pub_key.print_key_hex("y", tmp2);
            } else if (data[0] == 0x02) {
                data++;
                data_length--;
                struct parser tmp = { data, data + data_length };
                pub_key.print_key_hex("x", tmp);
                pub_key.print_key_string("y", "00");
            } else if (data[0] == 0x03) {
                data++;
                data_length--;
                struct parser tmp = { data, data + data_length };
                pub_key.print_key_hex("x", tmp);
                pub_key.print_key_string("y", "01");
            }
        }
        pub_key.close();
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

    void print_as_json(struct json_object &o, const char *name) const {
        if (algorithm.is_not_null()) {
            json_object_asn1 alg_id(o, name);
            algorithm.print_as_json_oid(alg_id, "algorithm");
            if (parameters.is_not_null()) {
                if (parameters.tag == tlv::OBJECT_IDENTIFIER) {
                    parameters.print_as_json_oid(alg_id, "parameters");
                } else {
                    parameters.print_as_json_hex(alg_id, "parameters");
                }
            }
            alg_id.close();
        }
    }

    const char *type() const {
        if (algorithm.is_not_null()) {
            return parser_get_oid_string(&algorithm.value);
        }
        return "";
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

    void print_as_json(struct json_object_asn1 &o, const char *name) const {
        struct json_object_asn1 alg_id{o, name};
        algorithm.print_as_json(alg_id, "algorithm_identifier");
        struct tlv tmp_key = subject_public_key;
        if (strcmp(algorithm.type(), "rsaEncryption") == 0) {
            tmp_key.remove_bitstring_encoding();
            struct rsa_public_key pub_key(&tmp_key.value);
            pub_key.print_as_json(alg_id, "subject_public_key");

        } else if (strcmp(algorithm.type(), "id-ecPublicKey") == 0) {
            tmp_key.remove_bitstring_encoding();
            struct ec_public_key pub_key(&tmp_key.value);
            pub_key.print_as_json(alg_id, "subject_public_key");

        } else {
            subject_public_key.print_as_json_hex(alg_id, "subject_public_key");
        }
        alg_id.close();
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
    struct algorithm_identifier signature_identifier; // note: confusingly called 'signature' in RFC5280
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
          signature_identifier{},
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
            if (version_or_serial_number.is_not_null() && version_or_serial_number.length == 1 && version_or_serial_number.value.data[0] < 3) {
                version = version_or_serial_number;
            } else {
                serial_number = version_or_serial_number;
            }
        }

        if (serial_number.is_null()) {
            serial_number.parse(&tbs_certificate.value, tlv::INTEGER, "serial number");
        }

        signature_identifier.parse(&tbs_certificate.value);

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
            struct parser tmp = tbs_certificate.value;
            struct tlv tmp_tlv(&tmp, 0, "tbs_certificate trailing data");
            //            tmp_tlv.fprint_tlv(stderr, "tbs_certificate trailing data");
        }

        signature_algorithm.parse(&certificate.value);
        signature.parse(&certificate.value, tlv::BIT_STRING, "signature");

    }

    std::string get_json_string() const {
        char buffer[8192*8];
        struct buffer_stream buf(buffer, sizeof(buffer));
        print_as_json(buf);
        std::string tmp_str(buffer, buf.length());
        return tmp_str;
    }
    void print_as_json(FILE *f) const {
        char buffer[8192*8];
        struct buffer_stream buf(buffer, sizeof(buffer));
        print_as_json(buf);
        buf.write_line(f);
    }
    void print_as_json(struct buffer_stream &buf) const {

        struct json_object_asn1 o{&buf};
        if (!version.is_null()) {
            version.print_as_json_hex(o, "version");
        }
        if (!serial_number.is_null()) {
            serial_number.print_as_json_hex(o, "serial_number");
        }
        if (!signature_identifier.sequence.is_null()) {
            signature_identifier.print_as_json(o, "signature_identifier");
        }
        if (!issuer.RDNsequence.is_null()) {
            issuer.print_as_json(o, "issuer");
        }
        if (!validity.sequence.is_null()) {
            validity.print_as_json(o);
        }
        if (!subject.RDNsequence.is_null()) {
            subject.print_as_json(o, "subject");
        }
        if (!subjectPublicKeyInfo.sequence.is_null()) {
            subjectPublicKeyInfo.print_as_json(o, "subject_public_key_info");
        }

        if (!extensions.is_null()) {
            struct json_array extensions_array{o, "extensions"};
            struct parser tlv_sequence = extensions.value;
            while (tlv_sequence.is_not_empty()) {
                struct extension xtn(tlv_sequence);
                struct json_object_asn1 wrapper{extensions_array};
                xtn.print_as_json(wrapper);
                wrapper.close();
            }
            extensions_array.close();
        }

        if (!signature_algorithm.sequence.is_null()) {
            signature_algorithm.print_as_json(o, "signature_algorithm");
        }
        if (!signature.is_null()) {
            struct tlv tmp_sig = signature;        // to avoid modifying signature
            tmp_sig.remove_bitstring_encoding();
            tmp_sig.print_as_json_hex(o, "signature");
        }
        o.close();
    }

    bool is_self_issued() const {
        return issuer.matches(subject);
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
        const char *tbs_sig_alg_type = signature_identifier.type();
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

        return !validity.contains(time_str, sizeof(time_str));
    }
};

struct x509_cert_prefix {
    struct tlv version;
    struct tlv serial_number;
    struct name issuer;
    struct parser prefix;

    x509_cert_prefix() : version{}, serial_number{}, issuer{}, prefix{NULL, NULL} {   }

    x509_cert_prefix(const void *buffer, unsigned int len) : serial_number{}, issuer{}, prefix{NULL, NULL} {
        parse(buffer, len);
    }

    void parse(const void *buffer, unsigned int len) {

        struct parser p;
        prefix.data = (const uint8_t *)buffer;
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
        if (issuer.RDNsequence.is_not_null()) {
            prefix.data_end = tbs_certificate.value.data;  // found the end of the issuer, so set data_end
        } else {
            prefix.data = NULL;                            // indicate that we didn't get a complete prefix
        }
    }

    size_t get_length() const {
        if (issuer.RDNsequence.is_null()) {
            return 0;
        }
        return prefix.data_end - prefix.data;
    }

    void print_as_json(struct buffer_stream &buf) const {
        json_object_asn1 o{&buf};
        o.print_key_hex("version", version.value);
        o.print_key_hex("serial_number", serial_number.value);
        issuer.print_as_json(o, "issuer");
        o.close();
    }
    void print_as_json(FILE *f) const {
        char buffer[8192];
        struct buffer_stream buf(buffer, sizeof(buffer));
        print_as_json(buf);
        buf.write_line(f);
    }
    void print_as_json_base64(struct buffer_stream &buf) const {
        json_object o{&buf};
        o.print_key_base64("cert_prefix", prefix);
        o.close();
    }
    void print_as_json_hex(struct buffer_stream &buf) const {
        json_object o{&buf};
        o.print_key_hex("cert_prefix", prefix);
        o.close();
    }
    void print_as_json_hex(FILE *f) const {
        char buffer[8192];
        struct buffer_stream buf(buffer, sizeof(buffer));
        print_as_json_hex(buf);
        buf.write_line(f);
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
