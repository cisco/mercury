// ocsp.hpp
//
// lightweight directory access protocol

#ifndef OCSP_HPP
#define OCSP_HPP

// #define ASN1_DEBUG 1
// #define TLV_ERR_INFO 1

#include <cstdio>
#include "datum.h"
#include "x509.h"
#include "json_object.h"
#include "match.h"

namespace ocsp {

    // Signature ::= SEQUENCE {
    //    signatureAlgorithm      AlgorithmIdentifier,
    //    signature               BIT STRING,
    //    certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
    //
    // Version ::= INTEGER { v1(0) }
    //

    // CertID ::= SEQUENCE {
    //    hashAlgorithm           AlgorithmIdentifier,
    //    issuerNameHash          OCTET STRING, -- Hash of issuer's DN
    //    issuerKeyHash           OCTET STRING, -- Hash of issuer's public key
    //    serialNumber            CertificateSerialNumber }
    //
    class cert_id {
        tlv sequence;
        algorithm_identifier alg_id;
        tlv issuer_name_hash;
        tlv issuer_key_hash;
        tlv serial_number;

    public:

        cert_id(datum &d) {
            parse(d);
        }

        void parse(datum &d) {
            sequence.parse(&d, tlv::SEQUENCE, "cert_id.sequence");
            alg_id.parse(&sequence.value);
            issuer_name_hash.parse(&sequence.value, tlv::OCTET_STRING);
            issuer_key_hash.parse(&sequence.value, tlv::OCTET_STRING);
            serial_number.parse(&sequence.value, tlv::INTEGER);
        }

        void write_json(json_object_asn1 &o) const {
            alg_id.print_as_json(o, "hash_algorithm");
            issuer_name_hash.print_as_json_hex(o, "issuer_name_hash");
            issuer_key_hash.print_as_json_hex(o, "issuer_key_hash");
            serial_number.print_as_json_hex(o, "serial_number");
        }

    };

    // Request ::= SEQUENCE {
    //    reqCert                     CertID,
    //    singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL }
    //
    class cert_request {
        tlv sequence;
        bool valid;

    public:

        cert_request(datum &d) {
            parse(d);
        }

        cert_request() {}

        void parse(datum &d) {
            sequence.parse(&d, tlv::SEQUENCE, "cert_request.sequence");
            valid = d.is_not_null();
        }

        void write_json(json_object_asn1 &o) const {
            if (!valid) {
                return;
            }
            json_array array{o, "cert_ids"};
            datum seq = sequence.value;
            while (seq.is_not_empty()) {
                cert_id cid(seq);
                if (!sequence.value.is_not_null()) {
                    break;
                }
                json_object_asn1 tmp{array};
                cid.write_json(tmp);
                tmp.close();
            }
            array.close();

        }

    };

    // TBSRequest ::= SEQUENCE {
    //    version             [0] EXPLICIT Version DEFAULT v1,
    //    requestorName       [1] EXPLICIT GeneralName OPTIONAL,
    //    requestList             SEQUENCE OF Request,
    //    requestExtensions   [2] EXPLICIT Extensions OPTIONAL }
    //
    class tbs_request {
        tlv outer_sequence;
        tlv inner_sequence;
        cert_request cert_req;

    public:

        tbs_request() { }

        void parse(datum &d) {
            outer_sequence.parse(&d, tlv::SEQUENCE, "tbs.outer_sequence");
            inner_sequence.parse(&outer_sequence.value, tlv::SEQUENCE, "tbs.inner_sequence");
            cert_req.parse(inner_sequence.value);  // TBD: parse multiple
        }

        tbs_request(datum &d) {
            parse(d);
        }

        void write_json(json_object_asn1 &o) const {
            json_object_asn1 json{o, "ocsp_request"};
            json_array a{json, "cert_requests"};
            json_object_asn1 tmp{a};
            cert_req.write_json(tmp);
            tmp.close();
            a.close();
            json.close();
        }

    };

    // OCSPRequest ::= SEQUENCE {
    //    tbsRequest              TBSRequest,
    //    optionalSignature   [0] EXPLICIT Signature OPTIONAL }
    //
    class request {
        tlv sequence;
        tbs_request tbs;

    public:

        request(datum &d) {
            sequence.parse(&d, tlv::SEQUENCE);
            tbs.parse(sequence.value);
        }

        void write_json(json_object_asn1 &o) const {
            tbs.write_json(o);
        }


        static bool unit_test(FILE *output=nullptr) {
            constexpr std::array<uint8_t, 83> ocsp_req = {
                0x30, 0x51, 0x30, 0x4f, 0x30, 0x4d, 0x30, 0x4b, 0x30, 0x49, 0x30, 0x09,
                0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0x33,
                0xf5, 0xaa, 0xc6, 0x1d, 0x66, 0xe7, 0x05, 0x5d, 0x03, 0x17, 0x3a, 0x4d,
                0x1f, 0x3e, 0x18, 0x71, 0x38, 0x85, 0x0d, 0x04, 0x14, 0x59, 0xa4, 0x66,
                0x06, 0x52, 0xa0, 0x7b, 0x95, 0x92, 0x3c, 0xa3, 0x94, 0x07, 0x27, 0x96,
                0x74, 0x5b, 0xf9, 0x3d, 0xd0, 0x02, 0x10, 0x06, 0x8b, 0xfa, 0xfd, 0x70,
                0xb9, 0xa1, 0xcc, 0x42, 0xf2, 0xdb, 0xa0, 0x27, 0x45, 0x88, 0x27
            };
            constexpr const char json_output[] = "{\"ocsp_request\":{\"cert_requests\":[{\"cert_ids\":[{\"hash_algorithm\":{\"algorithm\":\"id-sha1\"},\"issuer_name_hash\":\"33f5aac61d66e7055d03173a4d1f3e187138850d\",\"issuer_key_hash\":\"59a4660652a07b95923ca394072796745bf93dd0\",\"serial_number\":\"068bfafd70b9a1cc42f2dba027458827\"}]}]}}";

            datum d{ocsp_req};
            // if (output) { d.fprint_hex(output); fputc('\n', output); }

            ocsp::request req{d};

            output_buffer<2048> buf;
            json_object_asn1 o{&buf};
            req.write_json(o);
            o.close();
            // buf.write_line(stdout);
            if (output) { fprintf(output, "%s\n", json_output); }

            return (buf.memcmp(json_output, strlen(json_output)) == 0);

        }

    };

};  // namespace ocsp

[[maybe_unused]] inline int ocsp_request_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<ocsp_request>(data, size);
}

#endif // OCSP_HPP
