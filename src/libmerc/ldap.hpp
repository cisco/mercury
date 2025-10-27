// ldap.hpp
//
// lightweight directory access protocol

#ifndef LDAP_HPP
#define LDAP_HPP

// for ASN.1 debugging, uncomment the following lines
//
// #define ASN1_DEBUG 1
// #define TLV_ERR_INFO 1

#include "datum.h"
#include "x509.h"
#include "json_object.h"
#include "match.h"
#include "protocol.h"

namespace ldap {

    //   LDAPResult ::= SEQUENCE {
    //         resultCode         ENUMERATED {
    //              success                      (0),
    //              operationsError              (1),
    //              protocolError                (2),
    //              timeLimitExceeded            (3),
    //              sizeLimitExceeded            (4),
    //              compareFalse                 (5),
    //              compareTrue                  (6),
    //              authMethodNotSupported       (7),
    //              strongerAuthRequired         (8),
    //                   -- 9 reserved --
    //              referral                     (10),
    //              adminLimitExceeded           (11),
    //              unavailableCriticalExtension (12),
    //              confidentialityRequired      (13),
    //              saslBindInProgress           (14),
    //              noSuchAttribute              (16),
    //              undefinedAttributeType       (17),
    //              inappropriateMatching        (18),
    //              constraintViolation          (19),
    //              attributeOrValueExists       (20),
    //              invalidAttributeSyntax       (21),
    //                   -- 22-31 unused --
    //              noSuchObject                 (32),
    //              aliasProblem                 (33),
    //              invalidDNSyntax              (34),
    //                   -- 35 reserved for undefined isLeaf --
    //              aliasDereferencingProblem    (36),
    //                   -- 37-47 unused --
    //              inappropriateAuthentication  (48),
    //              invalidCredentials           (49),
    //              insufficientAccessRights     (50),
    //              busy                         (51),
    //              unavailable                  (52),
    //              unwillingToPerform           (53),
    //              loopDetect                   (54),
    //                   -- 55-63 unused --
    //              namingViolation              (64),
    //              objectClassViolation         (65),
    //              notAllowedOnNonLeaf          (66),
    //              notAllowedOnRDN              (67),
    //              entryAlreadyExists           (68),
    //              objectClassModsProhibited    (69),
    //                   -- 70 reserved for CLDAP --
    //              affectsMultipleDSAs          (71),
    //                   -- 72-79 unused --
    //              other                        (80),
    //              ...  },
    //         matchedDN          LDAPDN,
    //         diagnosticMessage  LDAPString,
    //         referral           [3] Referral OPTIONAL }

    enum result_codes {
        success                      = 0,
        operationsError              = 1,
        protocolError                = 2,
        timeLimitExceeded            = 3,
        sizeLimitExceeded            = 4,
        compareFalse                 = 5,
        compareTrue                  = 6,
        authMethodNotSupported       = 7,
        strongerAuthRequired         = 8,
        referral                     = 10,
        adminLimitExceeded           = 11,
        unavailableCriticalExtension = 12,
        confidentialityRequired      = 13,
        saslBindInProgress           = 14,
        noSuchAttribute              = 16,
        undefinedAttributeType       = 17,
        inappropriateMatching        = 18,
        constraintViolation          = 19,
        attributeOrValueExists       = 20,
        invalidAttributeSyntax       = 21,
        noSuchObject                 = 32,
        aliasProblem                 = 33,
        invalidDNSyntax              = 34,
        aliasDereferencingProblem    = 36,
        inappropriateAuthentication  = 48,
        invalidCredentials           = 49,
        insufficientAccessRights     = 50,
        busy                         = 51,
        unavailable                  = 52,
        unwillingToPerform           = 53,
        loopDetect                   = 54,
        namingViolation              = 64,
        objectClassViolation         = 65,
        notAllowedOnNonLeaf          = 66,
        notAllowedOnRDN              = 67,
        entryAlreadyExists           = 68,
        objectClassModsProhibited    = 69,
        affectsMultipleDSAs          = 71,
        other                        = 80,
    };

    static const char *get_name(const tlv &resp_code) {
        uint8_t code{0xff};
        if (resp_code.is_valid() and resp_code.length == 1) {
            code = *resp_code.value.data;
        }
        switch(code) {
        case success:                      return "success";
        case operationsError:              return "operationsError";
        case protocolError:                return "protocolError";
        case timeLimitExceeded:            return "timeLimitExceeded";
        case sizeLimitExceeded:            return "sizeLimitExceeded";
        case compareFalse:                 return "compareFalse";
        case compareTrue:                  return "compareTrue";
        case authMethodNotSupported:       return "authMethodNotSupported";
        case strongerAuthRequired:         return "strongerAuthRequired";
        case referral:                     return "referral";
        case adminLimitExceeded:           return "adminLimitExceeded";
        case unavailableCriticalExtension: return "unavailableCriticalExtension";
        case confidentialityRequired:      return "confidentialityRequired";
        case saslBindInProgress:           return "saslBindInProgress";
        case noSuchAttribute:              return "noSuchAttribute";
        case undefinedAttributeType:       return "undefinedAttributeType";
        case inappropriateMatching:        return "inappropriateMatching";
        case constraintViolation:          return "constraintViolation";
        case attributeOrValueExists:       return "attributeOrValueExists";
        case invalidAttributeSyntax:       return "invalidAttributeSyntax";
        case noSuchObject:                 return "noSuchObject";
        case aliasProblem:                 return "aliasProblem";
        case invalidDNSyntax:              return "invalidDNSyntax";
        case aliasDereferencingProblem:    return "aliasDereferencingProblem";
        case inappropriateAuthentication:  return "inappropriateAuthentication";
        case invalidCredentials:           return "invalidCredentials";
        case insufficientAccessRights:     return "insufficientAccessRights";
        case busy:                         return "busy";
        case unavailable:                  return "unavailable";
        case unwillingToPerform:           return "unwillingToPerform";
        case loopDetect:                   return "loopDetect";
        case namingViolation:              return "namingViolation";
        case objectClassViolation:         return "objectClassViolation";
        case notAllowedOnNonLeaf:          return "notAllowedOnNonLeaf";
        case notAllowedOnRDN:              return "notAllowedOnRDN";
        case entryAlreadyExists:           return "entryAlreadyExists";
        case objectClassModsProhibited:    return "objectClassModsProhibited";
        case affectsMultipleDSAs:          return "affectsMultipleDSAs";
        case other:                        return "other";
        default:
            ;
        }
        return "UNKNOWN";
    }

    // LDAP BindResponse, following RFC 4511
    //
    // BindResponse ::= [APPLICATION 1] SEQUENCE {
    //      COMPONENTS OF LDAPResult,
    //      serverSaslCreds    [7] OCTET STRING OPTIONAL }
    //
    class bind_response {
        tlv result_code;
        tlv matched_dn;
        tlv diagnostic_msg;
        // tlv referral;
        // TODO: server_sasl_creds
        bool valid{false};

    public:

        void parse(datum &d) {
            result_code.parse(&d);
            matched_dn.parse(&d);
            diagnostic_msg.parse(&d);
            valid = d.is_not_null();
        }

        void write_json(json_object &o) const {
            if (!valid) { return; }
            json_object bind_resp_json{o, "bind_response"};
            bind_resp_json.print_key_string("result_code", get_name(result_code));
            matched_dn.print_as_json(bind_resp_json, "matched_dn");
            diagnostic_msg.print_as_json(bind_resp_json, "diagnostic_message");
            bind_resp_json.close();
        }

    };

    // LDAP BindRequest, following RFC 4511
    //
    //   BindRequest ::= [APPLICATION 0] SEQUENCE {
    //        version                 INTEGER (1 ..  127),
    //        name                    LDAPDN,
    //        authentication          AuthenticationChoice }
    //
    //   AuthenticationChoice ::= CHOICE {
    //        simple                  [0] OCTET STRING,
    //                                -- 1 and 2 reserved
    //        sasl                    [3] SaslCredentials,
    //        ...  }
    //
    //   SaslCredentials ::= SEQUENCE {
    //        mechanism               LDAPString,
    //        credentials             OCTET STRING OPTIONAL }
    //
    class sasl_credentials {
        tlv mechanism;
        tlv credentials;
        bool valid;

    public:

        void parse(datum &d) {
            mechanism.parse(&d, 0x00, "sasl_credentials.mechanism");
            credentials.parse(&d, tlv::OCTET_STRING, "sasl_credentials.credentials");
            valid = d.is_not_null();
        }

        bool is_not_empty() const { return valid; }

        void write_json(json_object &o) const {
            if (!valid) { return; }
            json_object sasl_json{o, "sasl"};
            json_object mechanism_json{sasl_json, mechanism_type_get_name(get_type(mechanism.value))};
            mechanism_json.print_key_base64("base64", credentials.value);
            mechanism_json.close();
            sasl_json.close();
        }

    private:

        // SASL mechanism types, which correspond to the IANA registry
        // https://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xhtml
        //
        enum mechanism_type {
            unknown,
            GSSAPI,
            GSS_SPNEGO,
        };

        static const char *mechanism_type_get_name(mechanism_type t) {
            switch(t) {
            case mechanism_type::GSSAPI: return "gssapi";
            case mechanism_type::GSS_SPNEGO: return "gss_spnego";
            case mechanism_type::unknown:
            default:
                ;
            };
            return "UNKNOWN";
        }

        static mechanism_type get_type(const datum &d) {
            if (d.cmp(std::array<uint8_t,6>{'G','S','S','A','P','I'})) {
                return mechanism_type::GSSAPI;
            }
            if (d.cmp(std::array<uint8_t,10>{'G','S','S','-','S','P','N','E','G','O'})) {
                return mechanism_type::GSS_SPNEGO;
            }
            return mechanism_type::unknown;
        }

    };

    class bind_request {
        tlv version;
        tlv ldapdn;
        tlv auth;

    public:

        bind_request(datum &d) {
            version.parse(&d, tlv::INTEGER, "version");
            ldapdn.parse(&d, 0x00, "ldapdn");
            auth.parse(&d, 0x00, "auth");

        }

        void write_json(json_object &o) const {
            json_object bind_req_json{o, "bind_request"};
            bind_req_json.print_key_hex("version", version.value);
            ldapdn.print_as_json_escaped_string(bind_req_json, "ldapdn");
            json_object auth_json{bind_req_json, "auth"};
            if (auth.tag == 0x80) {
                auth.print_as_json_escaped_string(auth_json, "simple");
            } else if (auth.tag == 0xa3) {
                datum tmp = auth.value;
                sasl_credentials sasl_cred;
                sasl_cred.parse(tmp);
                sasl_cred.write_json(auth_json);
            } else {
                auth_json.print_key_hex("unknown", auth.value);
            }
            auth_json.close();
            bind_req_json.close();
        }

    };

    // LDAPMessage ::= SEQUENCE {
    //      messageID       MessageID,
    //      protocolOp      CHOICE {
    //           bindRequest           BindRequest,
    //           bindResponse          BindResponse,
    //           unbindRequest         UnbindRequest,
    //           searchRequest         SearchRequest,
    //           searchResEntry        SearchResultEntry,
    //           searchResDone         SearchResultDone,
    //           searchResRef          SearchResultReference,
    //           modifyRequest         ModifyRequest,
    //           modifyResponse        ModifyResponse,
    //           addRequest            AddRequest,
    //           addResponse           AddResponse,
    //           delRequest            DelRequest,
    //           delResponse           DelResponse,
    //           modDNRequest          ModifyDNRequest,
    //           modDNResponse         ModifyDNResponse,
    //           compareRequest        CompareRequest,
    //           compareResponse       CompareResponse,
    //           abandonRequest        AbandonRequest,
    //           extendedReq           ExtendedRequest,
    //           extendedResp          ExtendedResponse,
    //           ...,
    //           intermediateResponse  IntermediateResponse },
    //      controls       [0] Controls OPTIONAL }
    //
    // MessageID ::= INTEGER (0 ..  maxInt)
    //
    // maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
    //
    class message : public base_protocol {
        tlv outer_sequence; // SEQUENCE
        tlv message_id;     // INTEGER
        tlv protocol_op;    // ???
        bool valid{false};

    public:

        message(datum &d) {
            if (d.length() == 0) {
                return;  // don't process zero-length inputs
            }
            outer_sequence.parse(&d, tlv::SEQUENCE, "outer_sequence");
            message_id.parse(&outer_sequence.value, tlv::INTEGER, "message_id");
            valid = message_id.value.is_not_empty();
            protocol_op.parse(&outer_sequence.value, 0x00, "protocol_op");

        }

        bool is_not_empty() const {
            return valid;
        }

        void write_json(struct json_object &o, bool output_metadata) {
            if (!valid) {
                return;   // nothing to report on
            }
            (void)output_metadata;
            json_object ldap_json{o, "ldap"};
            ldap_json.print_key_hex("message_id", message_id.value);
            // ldap_json.print_key_hex("protocol_op", protocol_op.value);

            constexpr uint8_t bind_req_tag = 0x60;  // TODO: make this programmatic
            constexpr uint8_t bind_resp_tag = 0x61; // TODO: make this programmatic
            switch(protocol_op.tag) {
            case bind_req_tag:
                {
                    // fprintf(stderr, "got bind_req_tag\n");
                    bind_request bind_req{protocol_op.value};
                    bind_req.write_json(ldap_json);
                }
                break;
            case bind_resp_tag:
                {
                    // fprintf(stderr, "got bind_req_tag\n");
                    bind_response bind_resp;
                    bind_resp.parse(protocol_op.value);
                    bind_resp.write_json(ldap_json);
                }
                break;
            default:
                // fprintf(stderr, "got tag %02x (not %02x or %02x)\n", protocol_op.tag, bind_req_tag, tlv::explicit_tag_constructed(0));
                ;
            }

            ldap_json.close();
        }

        void write_l7_metadata(cbor_object &o, bool) {
            cbor_array protocols{o, "protocols"};
            protocols.print_string("ldap");
            protocols.close();
        }

        // empty functions for unsupported functionality
        //
        void compute_fingerprint(fingerprint &) const { }
        bool do_analysis(const struct key &, struct analysis_context &, classifier*) { return false; }

    };

    static constexpr uint16_t default_port = 34049; // TODO: hton<uint16_t>(389);

};  // namespace ldap


[[maybe_unused]] inline int ldap_message_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<ldap::message>(data, size);
}

#endif // LDAP_HPP
