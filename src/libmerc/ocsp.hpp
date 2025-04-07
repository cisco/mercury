// ocsp.hpp
//
// lightweight directory access protocol

#ifndef OCSP_HPP
#define OCSP_HPP

#define ASN1_DEBUG 1
#define TLV_ERR_INFO 1

#include <cstdio>
#include "datum.h"
#include "x509.h"
#include "json_object.h"
#include "match.h"
#include "oid.hpp"

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
        bool valid;

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
            valid = sequence.value.is_not_null();
        }

        void write_json(json_object_asn1 &o) const {
            if (!valid) { return; }
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

        bool is_valid() const { return valid; }
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

        bool is_valid() const { return cert_req.is_valid(); }
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

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata;
            json_object_asn1 asn1_obj{o};
            tbs.write_json(asn1_obj);
        }

        void write_json(json_object_asn1 &asn1_obj) const {
            tbs.write_json(asn1_obj);
        }

        bool is_valid() const { return tbs.is_valid(); }

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

    // ResponderID ::= CHOICE {
    //    byName               [1] Name,
    //    byKey                [2] KeyHash }
    //
    class responder_id {
        tlv choice;
    public:
        responder_id(datum &d) :
            choice{d, 0x00, "responder_id.choice"} // ???
        { }

        void write_json(json_object_asn1 &o) const {
            choice.print_as_json(o, "choice");
            datum tmp{choice.value};
            while (tmp.is_not_empty()) {
                tlv unknown{tmp, 0x00, "responder_id.unknown"};
            }
        }

    };

    // BasicOCSPResponse       ::= SEQUENCE {
    //    tbsResponseData      ResponseData,
    //    signatureAlgorithm   AlgorithmIdentifier,
    //    signature            BIT STRING,
    //    certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
    //
    // The value for signature SHALL be computed on the hash of the DER
    // encoding of ResponseData.  The responder MAY include certificates in
    // the certs field of BasicOCSPResponse that help the OCSP client verify
    // the responder's signature.  If no certificates are included, then
    // certs SHOULD be absent.
    //
    // ResponseData ::= SEQUENCE {
    //    version              [0] EXPLICIT Version DEFAULT v1,
    //    responderID              ResponderID,
    //    producedAt               GeneralizedTime,
    //    responses                SEQUENCE OF SingleResponse,
    //    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
    //
    class response_data {
        tlv sequence;
        tlv explicit_tag;
        responder_id responder;
        //tlv responder_id;
        tlv produced_at;
        tlv sequence_of_responses;

    public:

        response_data(datum &d) :
            sequence{d, tlv::SEQUENCE, "response_data.sequence"},
            explicit_tag{sequence.value, 0x00, "response_data.explicit_tag"}, // tlv::explicit_tag(0)
            responder{explicit_tag.value},
            produced_at{explicit_tag.value, 0x00, "response_data.produced_at"},
            sequence_of_responses{explicit_tag.value}
        { }

        void write_json(json_object_asn1 &o) const {
            responder.write_json(o);
            // responder_id.print_as_json(o, "responder_id");
            produced_at.print_as_json(o, "produced_at");
        }

    };

    // KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
    // (excluding the tag and length fields)
    //
    // SingleResponse ::= SEQUENCE {
    //    certID                       CertID,
    //    certStatus                   CertStatus,
    //    thisUpdate                   GeneralizedTime,
    //    nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
    //    singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
    //
    // CertStatus ::= CHOICE {
    //     good        [0]     IMPLICIT NULL,
    //     revoked     [1]     IMPLICIT RevokedInfo,
    //     unknown     [2]     IMPLICIT UnknownInfo }
    //
    // RevokedInfo ::= SEQUENCE {
    //     revocationTime              GeneralizedTime,
    //     revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
    //
    // UnknownInfo ::= NULL

    constexpr static std::array<uint8_t, 9> oid_id_pkix_ocsp_basic = asn1::oid<1,3,6,1,5,5,7,48,1,1>();

    class id_pkix_ocsp_basic {
        tlv sequence;
        // tlv::arbitrary arb;
    public:
        id_pkix_ocsp_basic(datum &d) :
            sequence{d, tlv::SEQUENCE, "id_pkix_ocsp_basic.sequence"}
        { }

        void write_json(json_object_asn1 &o) const {
            json_object_asn1 obj{o, "id_pkix_ocsp_basic"};
            datum tmp{sequence.value};
            response_data{tmp}.write_json(obj);
            obj.close();
            // json_array_asn1 a{o, "id_pkix_ocsp_basic"};
            // datum tmp{sequence.value};
            // while (tmp.is_readable()) {
            //     json_object_asn1 obj{a};
            //     tlv{tmp}.print_as_json(obj, "tlv");
            //     obj.close();
            // }
            // // tlv::recursive_parse(tmp, a);
            // a.close();
            // // arb.write_json(o);
        }

    };

    //   OCSPResponse ::= SEQUENCE {
    //    responseStatus         OCSPResponseStatus,
    //    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
    //
    //   OCSPResponseStatus ::= ENUMERATED {
    //     successful            (0),  -- Response has valid confirmations
    //     malformedRequest      (1),  -- Illegal confirmation request
    //     internalError         (2),  -- Internal error in issuer
    //     tryLater              (3),  -- Try again later
    //                                 -- (4) is not used
    //     sigRequired           (5),  -- Must sign the request
    //     unauthorized          (6)   -- Request unauthorized
    //   }
    //
    //   The value for responseBytes consists of an OBJECT IDENTIFIER and a
    //   response syntax identified by that OID encoded as an OCTET STRING.
    //
    //   ResponseBytes ::=       SEQUENCE {
    //       responseType   OBJECT IDENTIFIER,
    //       response       OCTET STRING }
    //
    class response_bytes {
        tlv explicit_tag;
        tlv sequence;
        tlv response_type;
        tlv response;

    public:

        response_bytes(datum &d) :
            explicit_tag{d, tlv::explicit_tag_constructed(0)},
            sequence{explicit_tag.value, tlv::SEQUENCE},
            response_type{sequence.value, tlv::OBJECT_IDENTIFIER},
            response{sequence.value, tlv::OCTET_STRING}
        { }

        void write_json(json_object_asn1 &o) const {
            response_type.print_as_json(o, "type");
            //   o.print_key_hex("oid_hex", response_type.value);
            if (response_type.value.cmp(oid_id_pkix_ocsp_basic)) {
                datum tmp{response.value};
                id_pkix_ocsp_basic{tmp}.write_json(o);
            } else {
                response.print_as_json(o, "unknown_response");
            }
        }

    };

    // For a basic OCSP responder, responseType will be id-pkix-ocsp-basic.
    //
    // id-pkix-ocsp           OBJECT IDENTIFIER ::= { id-ad-ocsp }
    // id-pkix-ocsp-basic     OBJECT IDENTIFIER ::= { id-pkix-ocsp 1 }
    //
    class response {
        //tlv::arbitrary arb;
        tlv sequence;
        tlv response_status;
        response_bytes bytes;

    public:

        response(datum &d) :
            // arb{d}
            sequence{d, tlv::SEQUENCE},
            response_status{sequence.value, tlv::ENUMERATED},
            bytes{sequence.value}
        { }

        bool is_valid() { return sequence.is_not_null(); } // arb.is_valid(); }  // sequence.is_not_null(); }

        void write_json(json_object_asn1 &o) {
            json_object_asn1 response{o, "response"};
            response_status.print_as_json(response, "status");
            bytes.write_json(response);
            response.close();
        }

    };

};  // namespace ocsp

[[maybe_unused]] inline int ocsp_request_fuzz_disabled_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<ocsp::request>(data, size);
}

#endif // OCSP_HPP
