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

namespace ldap {

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

    class bind_request {
        // tlv outer_sequence;
        // tlv message_id;
        // tlv sequence;
        tlv version;
        tlv ldapdn;
        tlv auth;

    public:

        bind_request(datum &d) {
            // outer_sequence.parse(&d, tlv::SEQUENCE);
            // message_id.parse(&outer_sequence.value, tlv::INTEGER);
            // sequence.parse(&d);
            //            sequence.parse(&outer_sequence.value, tlv::SEQUENCE);
            //   version.parse(&sequence.value, tlv::INTEGER);
            version.parse(&d, tlv::INTEGER);
            ldapdn.parse(&d);
            auth.parse(&d);

        }

        void write_json(json_object &o) const {
            json_object_asn1 bind_req_json{o, "bind_request"};
            // o.print_key_hex("message_id", message_id.value);
            bind_req_json.print_key_hex("version", version.value);
            bind_req_json.print_key_hex("ldapdn", ldapdn.value);
            bind_req_json.print_key_hex("auth", auth.value);
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
            // fprintf(stderr, "ldap::message::%s\n", __func__);
            // d.fprint_hex(stderr); fputc('\n', stderr);
            outer_sequence.parse(&d, tlv::SEQUENCE, "outer_sequence");
            message_id.parse(&outer_sequence.value, tlv::INTEGER, "message_id");
            valid = message_id.value.is_not_empty();
            protocol_op.parse(&outer_sequence.value, 0x00, "protocol_op");

            // valid = d.is_not_null();
            // fprintf(stderr, "datum after parsing:\t");
            // d.fprint_hex(stderr); fputc('\n', stderr);
        }

        bool is_not_empty() const {
            return valid;
        }

        void write_json(struct json_object &o, bool output_metadata) {
            if (!valid) {
                return;   // nothing to report on
            }
            (void)output_metadata;
            json_object_asn1 ldap_json{o, "ldap"};
            ldap_json.print_key_hex("message_id", message_id.value);
            // ldap_json.print_key_hex("protocol_op", protocol_op.value);

            constexpr uint8_t bind_req_tag = 0x60;  // TODO: make this programmatic
            switch(protocol_op.tag) {
            case bind_req_tag:
                {
                    // fprintf(stderr, "got bind_req_tag\n");
                    bind_request bind_req{protocol_op.value};
                    bind_req.write_json(ldap_json);
                }
                break;
            default:
                // fprintf(stderr, "got tag %02x (not %02x or %02x)\n", protocol_op.tag, bind_req_tag, tlv::explicit_tag_constructed(0));
                ;
            }

            ldap_json.close();
        }

        // empty functions for unsupported functionality
        //
        void compute_fingerprint(fingerprint &) const { }
        bool do_analysis(const struct key &, struct analysis_context &, classifier*) { return false; }

    };

    static constexpr uint16_t default_port = 34049; // TODO: hton<uint16_t>(389);

};  // namespace ldap

#endif // LDAP_HPP
