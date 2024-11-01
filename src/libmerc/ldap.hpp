// ldap.hpp
//
// lightweight directory access protocol

#ifndef LDAP_HPP
#define LDAP_HPP

#define ASN1_DEBUG 1
#define TLV_ERR_INFO 1

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
        tlv outer_sequence;
        tlv message_id;
        tlv sequence;
        tlv version;

    public:

        bind_request(datum &d) {
            outer_sequence.parse(&d, tlv::SEQUENCE);
            message_id.parse(&outer_sequence.value, tlv::INTEGER);
            sequence.parse(&outer_sequence.value);
            //            sequence.parse(&outer_sequence.value, tlv::SEQUENCE);
            //   version.parse(&sequence.value, tlv::INTEGER);
            version.parse(&sequence.value, tlv::INTEGER);

        }

        void write_json(json_object &o) const {
            o.print_key_hex("message_id", message_id.value);
            o.print_key_hex("version", version.value);
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

};  // namespace ldap

#endif // LDAP_HPP
