// pkcs8.hpp
//
// pkcs/pkix/x509 rsa private key encoding and decoding

#ifndef PKCS8_HPP
#define PKCS8_HPP

#include "libmerc/datum.h"
#include "libmerc/asn1.h"
#include "libmerc/json_object.h"
#include "libmerc/base64.h"
#include "pem.hpp"

// ASN.1 defintions, following RFC 3447
//
// Version ::= INTEGER { two-prime(0), multi(1) }
//     (CONSTRAINED BY
//     {-- version must be multi if otherPrimeInfos present --})
//
// RSAPrivateKey ::= SEQUENCE {
//     version           Version,
//     modulus           INTEGER,  -- n
//     publicExponent    INTEGER,  -- e
//     privateExponent   INTEGER,  -- d
//     prime1            INTEGER,  -- p
//     prime2            INTEGER,  -- q
//     exponent1         INTEGER,  -- d mod (p-1)
//     exponent2         INTEGER,  -- d mod (q-1)
//     coefficient       INTEGER,  -- (inverse of q) mod p
//     otherPrimeInfos   OtherPrimeInfos OPTIONAL
// }
//

class rsa_private_key {
    tlv sequence;
    tlv version;
    tlv modulus;
    tlv public_exponent;
    tlv private_exponent;
    tlv prime1;
    tlv prime2;
    tlv exponent1;
    tlv exponent2;
    tlv coefficient;
    // no other prime info for now

    static constexpr std::array<uint8_t, 1> vers{ 0x00 };
    static constexpr std::array<uint8_t, 3> pub_exp{ 0x01, 0x00, 0x01};
    static constexpr std::array<uint8_t, 0> nil{};

public:
    rsa_private_key(datum &d) {
        sequence.parse(&d, tlv::SEQUENCE);
        version.parse(&sequence.value, tlv::INTEGER);
        modulus.parse(&sequence.value, tlv::INTEGER);
        public_exponent.parse(&sequence.value, tlv::INTEGER);
        private_exponent.parse(&sequence.value, tlv::INTEGER);
        prime1.parse(&sequence.value, tlv::INTEGER);
        prime2.parse(&sequence.value, tlv::INTEGER);
        exponent1.parse(&sequence.value, tlv::INTEGER);
        exponent2.parse(&sequence.value, tlv::INTEGER);
        coefficient.parse(&sequence.value, tlv::INTEGER);
    }

    rsa_private_key(datum mod,
                    datum priv_exp,
                    datum p1,
                    datum p2,
                    datum e1,
                    datum e2,
                    datum coef) :
        sequence{},
        version{tlv::INTEGER, datum{vers}},
        modulus{tlv::INTEGER, mod},
        public_exponent{tlv::INTEGER, pub_exp},
        private_exponent{tlv::INTEGER, priv_exp},
        prime1{tlv::INTEGER, p1},
        prime2{tlv::INTEGER, p2},
        exponent1{tlv::INTEGER, e1},
        exponent2{tlv::INTEGER, e2},
        coefficient{tlv::INTEGER, coef}
    {
        // datum_array<1> v{ { 0x00  }};
        // datum_array<3> pe{{  0x01, 0x00, 0x01} };
        // sequence.parse(&d, tlv::SEQUENCE);
        //version.set(tlv::INTEGER, v);
        //public_exponent.set(tlv::INTEGER, pe);
        //private_exponent.parse(&sequence.value, tlv::INTEGER);
        //prime1.parse(&sequence.value, tlv::INTEGER);
        //prime2.parse(&sequence.value, tlv::INTEGER);
        //exponent1.parse(&sequence.value, tlv::INTEGER);
        //exponent2.parse(&sequence.value, tlv::INTEGER);
        //coefficient.parse(&sequence.value, tlv::INTEGER);

        sequence.tag = tlv::SEQUENCE;
        sequence.length =
            version.encoded_length() +
            modulus.encoded_length() +
            public_exponent.encoded_length() +
            private_exponent.encoded_length() +
            prime1.encoded_length() +
            prime2.encoded_length() +
            exponent1.encoded_length() +
            exponent2.encoded_length() +
            coefficient.encoded_length();
        sequence.value = { nullptr, nullptr };

        // fprintf(stderr, "constructor\n");
        // fprintf(stderr, "version.length: %lu\n", version.length);
        // fprintf(stderr, "modulus.length: %lu\n", modulus.length);
        // fprintf(stderr, "public_exponent.length: %lu\n", public_exponent.length);
        // fprintf(stderr, "private_exponent.length: %lu\n", private_exponent.length);
        // fprintf(stderr, "sequence.tag:    %02x\n", sequence.tag);
        // fprintf(stderr, "sequence.length: %lu\n", sequence.length);
    }

    size_t encoded_length() const {
        return sizeof(tlv::tag) + tlv::length_of_length(sequence.length) + sequence.length;
    }

    bool is_valid() const { return coefficient.is_not_null(); }

    void write_json(json_object &o) const {
        o.print_key_hex("version", version.value);
        o.print_key_hex("modulus", modulus.value);
        o.print_key_hex("public_exponent", public_exponent.value);
        o.print_key_hex("private_exponent", private_exponent.value);
        o.print_key_hex("prime1", prime1.value);
        o.print_key_hex("prime2", prime2.value);
        o.print_key_hex("exponent1", exponent1.value);
        o.print_key_hex("exponent2", exponent2.value);
        o.print_key_hex("coefficient", coefficient.value);
    }

    void write(writeable &buf) const {

        if (!is_valid()) {
            fprintf(stderr, "rsa_private_key object is not valid\n");
            //buf.set_null();
            //return;
        }
        // fprintf(stderr, "%s\n", __func__);
        // fprintf(stderr, "sequence.tag: %02x\n", sequence.tag);
        // fprintf(stderr, "sequence.length: %lu\n", sequence.length);
        sequence.write_tag_and_length(buf);
        buf << version;
        buf << modulus;
        buf << public_exponent;
        buf << private_exponent;
        buf << prime1;
        buf << prime2;
        buf << exponent1;
        buf << exponent2;
        buf << coefficient;

    }

    // rsa_private_key::unit_test() is a static member function that
    // performs a unit test of the rsa_private_key class and returns
    // true if the unit tests passed, and false otherwise
    //
    static bool unit_test() {

        return true;
    }

};

// PrivateKeyInfo, following RFC 5208
//
// PKCS-8 {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-8(8)
//          modules(1) pkcs-8(1)}
//
// -- $Revision: 1.5 $
//
// -- This module has been checked for conformance with the ASN.1
// -- standard by the OSS ASN.1 Tools
//
// DEFINITIONS IMPLICIT TAGS ::=
//
// BEGIN
//
// -- EXPORTS All --
// -- All types and values defined in this module is exported for use in
// -- other ASN.1 modules.
//
// IMPORTS
//
// informationFramework
//          FROM UsefulDefinitions {joint-iso-itu-t(2) ds(5) module(1)
//                                  usefulDefinitions(0) 3}
//
// Attribute
//          FROM InformationFramework informationFramework
//
// AlgorithmIdentifier, ALGORITHM-IDENTIFIER
//          FROM PKCS-5 {iso(1) member-body(2) us(840) rsadsi(113549)
//          pkcs(1) pkcs-5(5) modules(16) pkcs-5(1)};
//
// -- Private-key information syntax
//
// PrivateKeyInfo ::= SEQUENCE {
//    version Version,
//    privateKeyAlgorithm AlgorithmIdentifier {{PrivateKeyAlgorithms}},
//    privateKey PrivateKey,
//    attributes [0] Attributes OPTIONAL }
//
// Version ::= INTEGER {v1(0)} (v1,...)
//
// PrivateKey ::= OCTET STRING
//
// Attributes ::= SET OF Attribute

class private_key_info {
    tlv sequence;
    tlv version;
    tlv algorithm_identifier_sequence;
    tlv alg_id;
    tlv null_tag;
    tlv private_key_string;
    datum tmp;
    //
    // optional attributes are not yet supported

    rsa_private_key rsa_priv;
    bool valid = false;

    static constexpr std::array<uint8_t, 1> vers{ 0x00 };
    static constexpr std::array<uint8_t, 0> null{ };
    static constexpr std::array<uint8_t, 9> rsa_alg_id{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

public:

    private_key_info(datum &d) :
        sequence{d, tlv::SEQUENCE, "sequence"},
        version{sequence, tlv::INTEGER, "version"},
        algorithm_identifier_sequence{sequence, tlv::SEQUENCE, "alg_id_sequence"},
        alg_id{algorithm_identifier_sequence, tlv::OBJECT_IDENTIFIER, "alg_id"},
        null_tag{algorithm_identifier_sequence, tlv::NULL_TAG, "null"},
        private_key_string{sequence, tlv::OCTET_STRING, "priv_key"},
        tmp{private_key_string.value},
        rsa_priv{tmp}

        // TODO: set valid here?

        //        rsa_priv{private_key_string.value}

    {
        // sequence.parse(&d, tlv::SEQUENCE, "sequence");
        // version.parse(&sequence.value, tlv::INTEGER, "version");
        // algorithm_identifier_sequence.parse(&sequence.value, tlv::SEQUENCE, "alg_id_sequence");
        // alg_id.parse(&algorithm_identifier_sequence.value, tlv::OBJECT_IDENTIFIER, "alg_id");
        // algorithm_identifier_sequence.value.fprint_hex(stderr); fputc('\n', stderr);
        // null_tag.parse(&algorithm_identifier_sequence.value, tlv::NULL_TAG, "null");
        // private_key_string.parse(&sequence.value, tlv::OCTET_STRING, "priv_key");

        // datum tmp = private_key_string.value;
        // fprintf(stderr, "tmp:\t"); tmp.fprint_hex(stderr); fputc('\n', stderr);
        // rsa_private_key rsa_priv{tmp};                             // TODO: move out of constructor
        // valid = true;

        valid = algorithm_identifier_sequence.value.is_not_null() && private_key_string.value.is_not_null();
    }

    private_key_info(rsa_private_key &key) :
        sequence{},
        version{tlv::INTEGER, datum{vers}},
        algorithm_identifier_sequence{},
        alg_id{tlv::OBJECT_IDENTIFIER, datum{rsa_alg_id}},
        null_tag{tlv::NULL_TAG, null},
        private_key_string{},  // note: not actually initialized
        rsa_priv{key}
    {

        // construct algorithm_identifier
        //
        algorithm_identifier_sequence.tag = tlv::SEQUENCE;
        algorithm_identifier_sequence.length =
            alg_id.encoded_length() +
            null_tag.encoded_length();

        // construct private key octet string from private key
        //
        private_key_string.tag = tlv::OCTET_STRING;
        private_key_string.length =
            sizeof(tlv::tag) +
            rsa_priv.encoded_length();
        //
        // TODO: verify length accounting; should we use length_of_length()?
        //

        // construct outer sequence for private_key_info
        //
        sequence.tag = tlv::SEQUENCE;
        sequence.length =
            sizeof(tlv::tag) +
            version.encoded_length() +
            algorithm_identifier_sequence.encoded_length() +
            private_key_string.encoded_length();


        valid = true;  // TODO: this should be conditional
    }

    const rsa_private_key &get_rsa_private_key() const {
        return rsa_priv;
    }

    bool is_valid() const { return valid; }

    void write(writeable &buf) const {

        if (!is_valid()) {
            fprintf(stderr, "private_key_info object is not valid\n");
            //buf.set_null();
            //return;
        }
        // fprintf(stdout, "%s\n", __func__);
        // fprintf(stdout, "sequence.tag: %02x\n", sequence.tag);
        // fprintf(stdout, "sequence.length: %lu\n", sequence.length);
        sequence.write_tag_and_length(buf);
        buf << version
            << algorithm_identifier_sequence
            << alg_id
            << null_tag;
        // fprintf(stdout, "%s\n", __func__);
        // fprintf(stdout, "private_key_string.tag: %02x\n", private_key_string.tag);
        // fprintf(stdout, "private_key_string.length: %lu\n", private_key_string.length);
        private_key_string.write_tag_and_length(buf);
        buf << rsa_priv;
        //            << private_key_string;

    }

    // private_key_info::unit_test() returns true if the unit tests
    // passed, and false otherwise
    //
    static bool unit_test(bool verbose=false) {

        uint8_t file[] = {
            0x30, 0x82, 0x04, 0xbd, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a,
            0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
            0x04, 0xa7, 0x30, 0x82, 0x04, 0xa3, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01,
            0x01, 0x00, 0xf2, 0xf9, 0x32, 0x99, 0xe0, 0x98, 0xcd, 0x62, 0x57, 0x85,
            0xa4, 0x4b, 0x4e, 0x20, 0x43, 0x73, 0x56, 0x33, 0xaa, 0x42, 0x42, 0x53,
            0xee, 0xce, 0x01, 0x00, 0xa8, 0x5e, 0x01, 0x63, 0x84, 0x1f, 0x0f, 0x2e,
            0x8b, 0x85, 0xb4, 0x5e, 0xc4, 0x87, 0x69, 0xed, 0x76, 0xcd, 0xca, 0xa3,
            0x5f, 0x37, 0x50, 0x0d, 0xd9, 0x36, 0x09, 0x9b, 0x79, 0xb4, 0x69, 0x9d,
            0x7c, 0x4a, 0x75, 0x48, 0xfa, 0xf4, 0x9b, 0xb1, 0xb9, 0x94, 0x95, 0xeb,
            0xbe, 0x8a, 0xca, 0x37, 0x61, 0x7e, 0x7c, 0xf6, 0x7a, 0xb8, 0xb6, 0x3a,
            0xe1, 0x50, 0x06, 0x98, 0xe1, 0xf0, 0x55, 0x09, 0xa4, 0x6c, 0x0f, 0x91,
            0xf0, 0xea, 0x3a, 0xaa, 0x02, 0x92, 0x83, 0x6c, 0x0c, 0xad, 0x5a, 0xb1,
            0x66, 0x25, 0xe8, 0xe2, 0x34, 0xaf, 0x43, 0xf7, 0x8c, 0x5f, 0xf5, 0x8d,
            0x46, 0x29, 0x4b, 0xbe, 0x38, 0xd7, 0x13, 0xb0, 0x6c, 0xe6, 0x53, 0xeb,
            0xf2, 0xc5, 0x69, 0x24, 0x87, 0xe7, 0xa0, 0xe0, 0x27, 0x41, 0x8d, 0x59,
            0x9a, 0xf4, 0xeb, 0xa5, 0x6a, 0x2c, 0x7f, 0x7f, 0xd4, 0xf3, 0x91, 0x6c,
            0xb1, 0xb7, 0x01, 0xd2, 0xf3, 0xb0, 0xf2, 0x07, 0x5a, 0x58, 0x9e, 0x4a,
            0x5f, 0x31, 0x2d, 0x32, 0x48, 0x7c, 0xb6, 0x66, 0xaf, 0x4f, 0xb3, 0x80,
            0xe5, 0x92, 0x70, 0xcc, 0xd9, 0x5c, 0xfb, 0xe8, 0x6d, 0xcf, 0xa6, 0x6e,
            0x53, 0xc4, 0x12, 0xf7, 0xcd, 0x91, 0x8c, 0x8f, 0xb9, 0xc4, 0x5b, 0x0e,
            0x1e, 0x6d, 0x8a, 0x06, 0xd4, 0x9c, 0x99, 0x56, 0x9e, 0x6f, 0x13, 0x25,
            0xcd, 0xf7, 0x59, 0x27, 0x91, 0x50, 0x08, 0x82, 0x6d, 0xd6, 0x56, 0x82,
            0x32, 0x44, 0x2d, 0x7e, 0xf3, 0x16, 0xbc, 0x32, 0xa1, 0xec, 0x72, 0x8a,
            0x22, 0xed, 0x11, 0x86, 0xe3, 0xc7, 0xc6, 0xf5, 0xd4, 0xa4, 0x49, 0x2b,
            0x16, 0x6b, 0x4a, 0x9c, 0x38, 0x63, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02,
            0x82, 0x01, 0x01, 0x00, 0xce, 0x1e, 0x30, 0x9a, 0xf1, 0x39, 0x2f, 0x22,
            0x79, 0xf4, 0xd9, 0x47, 0x38, 0xe3, 0x8d, 0xd4, 0xce, 0x0f, 0xce, 0x23,
            0x9f, 0x78, 0xec, 0x60, 0xbd, 0xe0, 0xfc, 0xf3, 0xa2, 0x61, 0xf5, 0xb7,
            0x13, 0x7d, 0xfc, 0xc6, 0x54, 0x19, 0x00, 0xc7, 0x8f, 0x48, 0xef, 0x3b,
            0xec, 0xe7, 0x62, 0xe2, 0xdd, 0x7a, 0xa2, 0x05, 0x81, 0x68, 0xef, 0x79,
            0xe9, 0x0e, 0xbc, 0x5d, 0xbd, 0xd9, 0x47, 0x6b, 0x32, 0x99, 0x36, 0x41,
            0xa2, 0x5c, 0xf6, 0xab, 0x6e, 0x98, 0x44, 0x90, 0xb5, 0x19, 0xb3, 0x49,
            0xf6, 0xed, 0x44, 0x2e, 0x4b, 0x2a, 0x6e, 0xa1, 0x1e, 0xc2, 0xab, 0x45,
            0x30, 0x80, 0x31, 0xcb, 0xc2, 0x30, 0x6f, 0x36, 0x33, 0x5e, 0xf9, 0xf2,
            0x25, 0xb9, 0xd0, 0x59, 0xe0, 0x91, 0xe4, 0xf7, 0xb9, 0xc4, 0xca, 0xc4,
            0xac, 0xde, 0x47, 0xe2, 0xc8, 0x6a, 0x7a, 0x75, 0x9a, 0x32, 0x54, 0x6d,
            0xf9, 0x16, 0x30, 0x2b, 0x9f, 0xb6, 0xff, 0xce, 0x53, 0x90, 0x25, 0xc1,
            0xb8, 0x1b, 0xf8, 0xfd, 0xb2, 0x0f, 0x9a, 0x32, 0x1a, 0x35, 0x2c, 0xf1,
            0xb2, 0x82, 0xd0, 0x82, 0xaa, 0xcb, 0xf4, 0x37, 0x43, 0x43, 0x4a, 0x3c,
            0x24, 0x95, 0x34, 0xd5, 0xe1, 0xf0, 0x97, 0x4b, 0xe1, 0xd6, 0x6e, 0x23,
            0x3e, 0x93, 0x2c, 0x3f, 0x4b, 0x06, 0x08, 0x14, 0xad, 0x5c, 0x07, 0x68,
            0x6a, 0x7f, 0xee, 0xa2, 0xe7, 0x1f, 0xd8, 0x92, 0x13, 0xec, 0x34, 0x98,
            0x76, 0x6e, 0xcd, 0x9e, 0x52, 0x28, 0x9e, 0x27, 0x0f, 0xcf, 0x14, 0x9c,
            0x8a, 0x1b, 0x0e, 0x81, 0x93, 0x6a, 0x9b, 0x6f, 0x1b, 0xec, 0x2c, 0x68,
            0x9c, 0x03, 0xbf, 0xe0, 0xf9, 0x0c, 0x45, 0x10, 0xbb, 0xc4, 0x34, 0x72,
            0x2d, 0x61, 0x4f, 0xe6, 0x75, 0x24, 0xd4, 0x9e, 0xd1, 0xc2, 0x58, 0x97,
            0x49, 0x6a, 0x2a, 0x58, 0x1b, 0x5f, 0x04, 0xc1, 0x02, 0x81, 0x81, 0x00,
            0xfd, 0x9d, 0x96, 0x1f, 0x92, 0xea, 0xca, 0xad, 0x8d, 0xfd, 0xcd, 0x32,
            0x4d, 0x7c, 0x71, 0x40, 0x89, 0xad, 0xfe, 0xcd, 0xd9, 0x08, 0x16, 0x73,
            0xdb, 0x19, 0x5f, 0x6c, 0x23, 0x9b, 0x53, 0xa5, 0x37, 0xf9, 0x35, 0x10,
            0xc4, 0x86, 0x60, 0x74, 0x7e, 0x65, 0xa9, 0x65, 0xcb, 0xfa, 0xc3, 0xeb,
            0xbd, 0x13, 0x76, 0xc3, 0x17, 0x65, 0x4d, 0x96, 0x76, 0xd1, 0xbf, 0x39,
            0x68, 0x3d, 0x57, 0x9b, 0x46, 0x10, 0xbd, 0x90, 0x85, 0x52, 0xfc, 0xa3,
            0x00, 0xad, 0x99, 0x3a, 0x85, 0xc6, 0xa3, 0x14, 0x5c, 0xff, 0x60, 0x0c,
            0xb1, 0x7a, 0x13, 0x1f, 0xe1, 0x7d, 0xbb, 0xb7, 0x5a, 0x33, 0x5c, 0xa8,
            0x45, 0x25, 0xd3, 0xe8, 0x4d, 0x55, 0x6c, 0xe0, 0xa4, 0xfd, 0x11, 0x30,
            0x4b, 0xf9, 0xa5, 0xca, 0x9f, 0x63, 0x36, 0xf3, 0xa2, 0x7f, 0xf8, 0x54,
            0xa1, 0xb7, 0x8a, 0x43, 0x58, 0x6c, 0xe5, 0x2b, 0x02, 0x81, 0x81, 0x00,
            0xf5, 0x41, 0xff, 0x4b, 0x45, 0xec, 0x16, 0xae, 0x0a, 0x45, 0x74, 0xc6,
            0xbe, 0xcc, 0x0c, 0x06, 0x4b, 0x65, 0xd1, 0xbb, 0x7f, 0x1c, 0x4c, 0xbb,
            0x80, 0x60, 0x04, 0x30, 0xd8, 0x83, 0x8d, 0x18, 0xc0, 0x49, 0x93, 0x55,
            0x98, 0xab, 0x08, 0x06, 0x32, 0x71, 0xaa, 0x2c, 0xe2, 0x45, 0x17, 0xdd,
            0x19, 0x30, 0xcd, 0xe4, 0xcf, 0x6c, 0xb9, 0xca, 0x82, 0x94, 0x96, 0x83,
            0x01, 0x50, 0xf9, 0x0d, 0x4f, 0xcf, 0x2c, 0xcd, 0x45, 0x0e, 0xd6, 0x57,
            0x9e, 0x61, 0xc1, 0x0d, 0xf5, 0x9c, 0xe4, 0x8f, 0xf6, 0x65, 0x42, 0x20,
            0x01, 0xbf, 0xa7, 0xec, 0x40, 0xcf, 0xdf, 0xc1, 0x6c, 0xff, 0xf5, 0x2e,
            0x1a, 0x4a, 0xcc, 0x38, 0xf3, 0x20, 0xac, 0x71, 0x94, 0x31, 0x87, 0xdd,
            0x59, 0xd8, 0x18, 0x2a, 0x36, 0xb4, 0xb1, 0xe9, 0xf0, 0x67, 0x72, 0x49,
            0x45, 0xa4, 0x56, 0xe5, 0xbd, 0xe1, 0x4d, 0xa9, 0x02, 0x81, 0x80, 0x76,
            0x55, 0xb8, 0x3d, 0x65, 0x3c, 0xbe, 0x72, 0xfa, 0x84, 0xc8, 0xe0, 0xc6,
            0xbc, 0xe0, 0xce, 0xff, 0x2e, 0xbb, 0x6c, 0x6a, 0xee, 0xd6, 0x23, 0x1a,
            0xc1, 0x1d, 0x00, 0x05, 0x21, 0x2d, 0x87, 0x32, 0xb5, 0xc9, 0xe7, 0xd7,
            0xfa, 0xe7, 0x38, 0x93, 0xdd, 0x75, 0x8b, 0xf5, 0x00, 0x3d, 0xb8, 0x5a,
            0x11, 0xa1, 0xe1, 0x67, 0xa2, 0x31, 0xf0, 0x99, 0xe2, 0x46, 0x3a, 0x50,
            0x04, 0x07, 0x43, 0x81, 0x0e, 0xc0, 0x94, 0x95, 0x50, 0xe2, 0x66, 0x60,
            0x23, 0xa0, 0x12, 0x69, 0x67, 0x04, 0xa2, 0xb4, 0xbd, 0xc7, 0xa0, 0x44,
            0x93, 0x34, 0x27, 0x34, 0xfc, 0x88, 0xc1, 0x05, 0x8a, 0x5f, 0x9a, 0x78,
            0x21, 0x2d, 0x5d, 0xff, 0xef, 0x73, 0x0c, 0xe2, 0x8e, 0xde, 0x1d, 0x4d,
            0xe5, 0xdf, 0x50, 0xca, 0xcb, 0xed, 0x51, 0x02, 0xaa, 0x79, 0x41, 0x6b,
            0xef, 0x8a, 0xc8, 0xdf, 0x92, 0x77, 0xdf, 0x02, 0x81, 0x80, 0x37, 0x6e,
            0x3f, 0x20, 0xe8, 0x20, 0xbf, 0xcf, 0x7e, 0x0a, 0xcc, 0xa5, 0xce, 0xa1,
            0x97, 0x66, 0x24, 0xcc, 0x52, 0x66, 0xaa, 0x07, 0xdf, 0x5f, 0xd1, 0x57,
            0xe2, 0x1a, 0x98, 0x14, 0xc3, 0x63, 0x00, 0xb2, 0xa0, 0x56, 0x0c, 0x37,
            0x3b, 0x8d, 0x0b, 0x01, 0x9d, 0x90, 0x9f, 0x63, 0x36, 0x4d, 0x86, 0x4f,
            0xfd, 0x78, 0xe5, 0x58, 0x91, 0x75, 0x2f, 0xa6, 0x1d, 0x8e, 0x66, 0x51,
            0xc2, 0xb8, 0x3b, 0x7d, 0x7b, 0x86, 0xb9, 0x40, 0xed, 0x38, 0xc8, 0x57,
            0x17, 0xa6, 0xec, 0x08, 0x15, 0xb0, 0x63, 0xe3, 0xe6, 0xda, 0x0d, 0x0b,
            0x20, 0x0c, 0xc9, 0x69, 0x32, 0x0d, 0x29, 0x71, 0x80, 0x1c, 0x77, 0x5c,
            0xc8, 0x63, 0x66, 0xaf, 0xcf, 0xc9, 0xab, 0xd0, 0xb6, 0x00, 0x55, 0x39,
            0xfd, 0xdc, 0x2c, 0x99, 0x12, 0x4c, 0xe9, 0x44, 0xb8, 0x13, 0xcf, 0x65,
            0xa1, 0x2e, 0x33, 0x88, 0x24, 0x61, 0x02, 0x81, 0x80, 0x11, 0xa6, 0x9a,
            0x5c, 0x71, 0xe1, 0x7e, 0x9e, 0x71, 0x87, 0x0d, 0x34, 0x1d, 0x2d, 0x8f,
            0x66, 0x76, 0xc4, 0x47, 0x96, 0xaf, 0xc2, 0xae, 0x06, 0xd5, 0xd4, 0xf3,
            0xf2, 0x79, 0x6b, 0x42, 0x71, 0xe9, 0x0f, 0x98, 0x99, 0x19, 0x15, 0x2d,
            0x42, 0x7e, 0x92, 0x32, 0xd6, 0x46, 0xa0, 0x7a, 0x36, 0xa0, 0x9d, 0x02,
            0x6b, 0x3a, 0x2f, 0xb2, 0xfc, 0x61, 0xa3, 0xd0, 0xee, 0xac, 0xd7, 0xd0,
            0x97, 0x87, 0x30, 0x9d, 0x4b, 0x7c, 0x8b, 0xa2, 0x81, 0x5e, 0x32, 0x77,
            0x71, 0xe4, 0x52, 0x26, 0x20, 0x8b, 0xba, 0xd3, 0x49, 0xa1, 0xdc, 0x32,
            0xef, 0xa7, 0x9f, 0x6c, 0x37, 0x46, 0x83, 0x2c, 0x69, 0xc4, 0x21, 0x16,
            0x35, 0x09, 0x5b, 0x11, 0xf9, 0x7d, 0x79, 0x44, 0xb0, 0x7c, 0x3d, 0x5a,
            0x50, 0x10, 0x41, 0x2f, 0xfc, 0x09, 0xe4, 0x61, 0x78, 0xca, 0x6c, 0x8e,
            0x3a, 0xbf, 0x3d, 0x8f, 0xb1
        };
        datum f{file, file + sizeof(file)};

        private_key_info pkinfo{f};

        data_buffer<4096> dbuf;
        pkinfo.write(dbuf);
        datum result = dbuf.contents();

        // create second pkinfo from public key, then compare to original
        //
        rsa_private_key rsa_priv = pkinfo.get_rsa_private_key();
        private_key_info pkinfo2{rsa_priv};
        data_buffer<4096> dbuf2;
        pkinfo2.write(dbuf2);
        datum result2 = dbuf2.contents();

        if (dbuf != dbuf2) {
            if (verbose) {
                fprintf(stdout, "failure: result != result2\n          ");
                for (ssize_t i=0; i<std::min(dbuf.readable_length(), dbuf2.readable_length()); i++) {
                    if (dbuf.buffer[i] == dbuf2.buffer[i]) {
                        fprintf(stdout, "%02x", dbuf.buffer[i]);
                    } else {
                        fprintf(stdout, "**");
                    }
                }
                fputc('\n', stdout);
                fprintf(stdout, "result:   "); result.fprint_hex(stdout); fputc('\n', stdout);
                fprintf(stdout, "result2:  "); result2.fprint_hex(stdout); fputc('\n', stdout);
            }
            return false;
        }

        return true;
    }

};

static bool write_pem(FILE *f, const uint8_t *data, size_t length, const char *label="RSA PRIVATE KEY") {

    const char opening_line[] = "-----BEGIN ";
    const char closing_line[] = "-----END ";

    fprintf(f, "%s%s-----\n", opening_line, label);
    std::string b64 = base64_encode(data, length);
    const char *data_end = b64.data() + b64.length();
    for (char *c=b64.data(); c < data_end; c+=64) {
        int ll = (c + 64 < data_end) ? 64 : data_end - c;
        fprintf(f, "%.*s\n", ll, c);
    }
    fprintf(f, "%s%s-----\n", closing_line, label);

    return true;
}

#endif // PKCS8_HPP