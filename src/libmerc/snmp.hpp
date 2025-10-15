// snmp.h
//

#ifndef SNMP_HPP
#define SNMP_HPP

#define ASN1_DEBUG 1

#include "x509.h"
#include "json_object.h"
#include "cbor_object.hpp"
#include "protocol.h"
#include "match.h"

#include <variant>

namespace snmp {

    // forward declarations
    //
    inline uint8_t snmp_version_get_uint(const tlv &version);

    // The trap_pdu type was defined in SNMPv1, and was obsoleted by
    // the snmpv2_trap type
    //
    // Trap-PDU ::=
    //         [4]
    //
    //              IMPLICIT SEQUENCE {
    //                 enterprise          -- type of object generating
    //                                     -- trap, see sysObjectID in [2]
    //                     OBJECT IDENTIFIER,
    //
    //                 agent-addr          -- address of object generating
    //                     NetworkAddress, -- trap
    //
    //                 generic-trap        -- generic trap type
    //                     INTEGER {
    //                         coldStart(0),
    //                         warmStart(1),
    //                         linkDown(2),
    //                         linkUp(3),
    //                         authenticationFailure(4),
    //                         egpNeighborLoss(5),
    //                         enterpriseSpecific(6)
    //                     },
    //
    //                 specific-trap     -- specific code, present even
    //                     INTEGER,      -- if generic-trap is not
    //                                   -- enterpriseSpecific
    //
    //                 time-stamp        -- time elapsed between the last
    //                   TimeTicks,      -- (re)initialization of the network
    //                                   -- entity and the generation of the
    //                                      trap
    //
    //                 variable-bindings   -- "interesting" information
    //                      VarBindList
    //             }
    //
    class trap {

    };


    //    ObjectName ::= OBJECT IDENTIFIER
    //
    //    ObjectSyntax ::= CHOICE {
    //          simple           SimpleSyntax,
    //          application-wide ApplicationSyntax }
    //
    //    SimpleSyntax ::= CHOICE {
    //          integer-value   INTEGER (-2147483648..2147483647),
    //          string-value    OCTET STRING (SIZE (0..65535)),
    //          objectID-value  OBJECT IDENTIFIER }
    //
    //    ApplicationSyntax ::= CHOICE {
    //          ipAddress-value        IpAddress,
    //          counter-value          Counter32,
    //          timeticks-value        TimeTicks,
    //          arbitrary-value        Opaque,
    //          big-counter-value      Counter64,
    //          unsigned-integer-value Unsigned32 }
    //
    //    IpAddress ::= [APPLICATION 0] IMPLICIT OCTET STRING (SIZE (4))
    //
    //    Counter32 ::= [APPLICATION 1] IMPLICIT INTEGER (0..4294967295)
    //
    //    Unsigned32 ::= [APPLICATION 2] IMPLICIT INTEGER (0..4294967295)
    //
    //    Gauge32 ::= Unsigned32
    //
    //    TimeTicks ::= [APPLICATION 3] IMPLICIT INTEGER (0..4294967295)
    //
    //    Opaque ::= [APPLICATION 4] IMPLICIT OCTET STRING
    //
    //    Counter64 ::= [APPLICATION 6]
    //                  IMPLICIT INTEGER (0..18446744073709551615)
    //
    class object_syntax {
        datum body;

    public:

        object_syntax(datum &d) : body{d} { }

        bool is_not_empty() const { return body.is_not_empty(); }

        void write_json(json_object &o) const {
            // json_object value{o, "value"};
            // value.print_key_hex("body", body);
            json_object &value = o;

            datum tmp{body};
            tlv object{tmp};
            if (!object.is_valid()) {
                return;
            }
            value.print_key_uint("tag", object.tag & 31);
            switch(object.tag & 31) {
            case 0:
                value.print_key_hex("ipv4_address", object.value);
                break;
            case 1:
                value.print_key_uint("counter32", encoded<uint32_t>{object.value}.value());
                break;
            case 2:
                value.print_key_uint("unsigned32", encoded<uint32_t>{object.value}.value());
                break;
            case 3:
                value.print_key_hex("time_ticks", object.value);
                break;
            case 4:
                value.print_key_hex("opaque", object.value);
                break;
            case 5:
                value.print_key_null("null");
                break;
            case 6:
                value.print_key_uint("counter64", encoded<uint64_t>{object.value}.value());
                break;
            default:
                value.print_key_hex("unknown", object.value);
            }

            // value.close();
        }

    };


    // SNMPv2 PDU format, from RFC 3416 Sec. 3.
    //
    //       -- variable binding
    //    VarBind ::= SEQUENCE {
    //            name ObjectName,
    //
    //            CHOICE {
    //                value          ObjectSyntax,
    //                unSpecified    NULL,    -- in retrieval requests
    //
    //                                        -- exceptions in responses
    //                noSuchObject   [0] IMPLICIT NULL,
    //                noSuchInstance [1] IMPLICIT NULL,
    //                endOfMibView   [2] IMPLICIT NULL
    //            }
    //        }
    //
    //    -- variable-binding list
    //
    //    VarBindList ::= SEQUENCE (SIZE (0..max-bindings)) OF VarBind
    //
    class var_bind {
        tlv seq;
        tlv name;
        //tlv value;
        object_syntax value;
        bool valid;

    public:

        var_bind(datum &d) :
            seq{d, tlv::SEQUENCE, "seq"},
            name{&seq.value, tlv::OBJECT_IDENTIFIER, "oid"},
            value{seq.value},
            valid{seq.value.is_not_null()}
        { }

        void write_json(json_object &o) const {
            o.print_key_value("name", raw_oid{name.value});
            value.write_json(o);
            // o.print_key_hex("value", value.value); // TODO: handle different types
        }

        bool is_not_empty() const { return valid; }

    };

    // From RFC 1905 Section 3:
    //
    //      PDU ::=
    //          SEQUENCE {
    //              request-id
    //                  Integer32,
    //
    //              error-status            -- sometimes ignored
    //                  INTEGER {
    //                      noError(0),
    //                      tooBig(1),
    //                      noSuchName(2),   -- for proxy compatibility
    //                      badValue(3),     -- for proxy compatibility
    //                      readOnly(4),     -- for proxy compatibility
    //                      genErr(5),
    //                      noAccess(6),
    //                      wrongType(7),
    //                      wrongLength(8),
    //                      wrongEncoding(9),
    //                      wrongValue(10),
    //                      noCreation(11),
    //                      inconsistentValue(12),
    //                      resourceUnavailable(13),
    //                      commitFailed(14),
    //                      undoFailed(15),
    //                      authorizationError(16),
    //                      notWritable(17),
    //                      inconsistentName(18)
    //                  },
    //
    //              error-index            -- sometimes ignored
    //                  INTEGER (0..max-bindings),
    //
    //              variable-bindings   -- values are sometimes ignored
    //                  VarBindList
    //          }
    //
    class v2_pdu {
        tlv seq;
        tlv request_id;
        tlv error_status;
        tlv error_index;
        tlv variable_bindings;
        tlv var_bind_list_seq;
        bool valid;

    public:

        v2_pdu(datum &d) :
            // seq{&d, 0x00, "v2_pdu_seq"},
            // seq{&d, tlv::SEQUENCE, "v2_pdu_seq"},
            request_id{&d, 0x00, "request_id"},
            error_status{&d, tlv::INTEGER, "error_status"},
            error_index{&d, tlv::INTEGER, "error_index"},
            variable_bindings{&d, 0x00, "variable_bindings"},
            var_bind_list_seq{variable_bindings.value, tlv::SEQUENCE, "var_bind_list_seq"},
            valid{d.is_not_null()}
        { }

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata;
            if (!is_not_empty()) {
                return;
            }
            json_object pdu{o, "pdu"};
            pdu.print_key_hex("request_id", request_id.value);
            pdu.print_key_hex("error_status", error_status.value);
            pdu.print_key_hex("error_index", error_index.value);
            pdu.print_key_hex("variable_bindings", variable_bindings.value);
            // pdu.print_key_hex("var_bind_list_seq", var_bind_list_seq.value);

            json_array a{pdu, "variable_binding_list"};
            datum tmp{variable_bindings.value};
            while (tmp.is_readable()) {
                var_bind vb{tmp};
                if (vb.is_not_empty()) {
                    json_object bindings{a};
                    vb.write_json(bindings);
                    bindings.close();
                } else {
                    break;
                }
                // // tmp.fprint_hex(stderr); fputc('\n', stderr);
                // // tlv oid{&tmp, tlv::OBJECT_IDENTIFIER, "oid"};
                // a.print_hex(tmp);
                // tlv oid{tmp, tlv::OBJECT_IDENTIFIER, "oid"};
                // tlv value{tmp, 0x00, "value"};
                // if (oid.is_valid()) {
                //     json_object obj{a};
                //     raw_oid ro{oid.value};
                //     obj.print_key_hex("oid_hex", ro);
                //     obj.print_key_value("oid", ro);
                //     obj.print_key_hex("value", value.value);
                //     obj.close();
                // }
            }
            a.close();

            pdu.close();
        }

        bool is_not_empty() const { return valid; }

    };

    static const char *UNKNOWN = "UNKNOWN";

    const char *v2_pdu_type(uint8_t tag_number) {
        switch(tag_number) {
        case 0: return "get_request";
        case 1: return "get_next_request";
        case 2: return "get_response";
        case 3: return "set_request";
        case 4: return "trap";
        case 5: return "get_bulk_request";
        case 6: return "inform_request";
        case 7: return "snmpv2_trap";
        default:
            ;
        }
        return UNKNOWN;
    }

    class v2_packet {
        tlv seq;
        tlv version;
        tlv community;
        tlv data;
        bool valid;

    public:

        v2_packet(datum &d) :
            seq{&d, tlv::SEQUENCE, "snmpv2"},
            version{&seq.value, tlv::INTEGER, "version"},
            community{&seq.value, tlv::OCTET_STRING, "community"},
            data{&seq.value, 0x00, "data"},
            valid{seq.value.is_not_null()}
        { }

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata;
            if (!is_not_empty()) {
                return;
            }
            json_object snmp{o, "snmp"};
            snmp.print_key_uint("version", snmp_version_get_uint(version));
            snmp.print_key_json_string("community", community.value);
            // snmp.print_key_hex("data", data.value);
            // snmp.print_key_uint("data.explicit_tag", data.tag_number());

            const char *pdu_type = v2_pdu_type(data.tag_number());
            if (pdu_type != UNKNOWN) {
                snmp.print_key_string("pdu_type", pdu_type);
            } else {
                snmp.print_key_unknown_code("pdu_type", data.tag_number());
            }

            snmp.print_key_hex("pdu", data.value);
            datum tmp{data.value};
            v2_pdu pdu{tmp};
            if (pdu.is_not_empty()) {
                pdu.write_json(snmp);
            }
            snmp.close();
        }

        bool is_not_empty() const {
            return valid;
        }


    };

    //
    // PDU ::= SEQUENCE {
    //         request-id INTEGER (-214783648..214783647),
    //
    //         error-status                -- sometimes ignored
    //             INTEGER {
    //                 noError(0),
    //                 tooBig(1),
    //                 noSuchName(2),      -- for proxy compatibility
    //                 badValue(3),        -- for proxy compatibility
    //                 readOnly(4),        -- for proxy compatibility
    //                 genErr(5),
    //                 noAccess(6),
    //                 wrongType(7),
    //                 wrongLength(8),
    //                 wrongEncoding(9),
    //                 wrongValue(10),
    //                 noCreation(11),
    //                 inconsistentValue(12),
    //                 resourceUnavailable(13),
    //                 commitFailed(14),
    //                 undoFailed(15),
    //                 authorizationError(16),
    //                 notWritable(17),
    //                 inconsistentName(18)
    //             },
    //
    //         error-index                 -- sometimes ignored
    //             INTEGER (0..max-bindings),
    //
    //         variable-bindings           -- values are sometimes ignored
    //             VarBindList
    //     }
    //
    class pdu {
            tlv request_id;
            tlv error_status;
            tlv error_index;
            tlv any;
    public:
        pdu(datum &d) :
            request_id{&d, tlv::INTEGER, "request-id"},
            error_status{&d, tlv::INTEGER, "error-status"},
            error_index{&d, tlv::INTEGER, "error-index"},
            any{&d, 0x00, "any"}
        {
            // tlv request_id;
            // request_id.parse(&d, tlv::INTEGER, "request-id");
            // tlv error_status;
            // error_status.parse(&d, tlv::INTEGER, "error-status");
            // tlv error_index;
            // error_index.parse(&d, tlv::INTEGER, "error-index");
            // tlv any;
            // any.parse(&d, 0x00, "any");
        }

        void write_json(json_object &o) const {
            o.print_key_hex("request_id", request_id.value);
            o.print_key_hex("error_status", error_status.value);
            o.print_key_hex("error_index", error_index.value);
            o.print_key_hex("any", any.value);
        }
    };

    //  GetRequest-PDU ::= [0] IMPLICIT PDU
    //  GetNextRequest-PDU ::= [1] IMPLICIT PDU
    //  Response-PDU ::= [2] IMPLICIT PDU
    //  SetRequest-PDU ::= [3] IMPLICIT PDU
    //  -- [4] is obsolete
    //  GetBulkRequest-PDU ::= [5] IMPLICIT BulkPDU
    //  InformRequest-PDU ::= [6] IMPLICIT PDU
    //  SNMPv2-Trap-PDU ::= [7] IMPLICIT PDU

    //     HeaderData ::= SEQUENCE {
    //     msgID      INTEGER (0..2147483647),
    //     msgMaxSize INTEGER (484..2147483647),
    //
    //     msgFlags   OCTET STRING (SIZE(1)),
    //                --  .... ...1   authFlag
    //                --  .... ..1.   privFlag
    //                --  .... .1..   reportableFlag
    //                --              Please observe:
    //                --  .... ..00   is OK, means noAuthNoPriv
    //                --  .... ..01   is OK, means authNoPriv
    //                --  .... ..10   reserved, MUST NOT be used.
    //                --  .... ..11   is OK, means authPriv
    //
    //     msgSecurityModel INTEGER (1..2147483647)
    // }
    //
    class header_data {
        tlv seq;
        tlv msgID;
        tlv msgMaxSize;
        tlv msgFlags;
        encoded<uint8_t> tmp;
        tlv msgSecurityModel;
        bool valid;

    public:
        bool priv;

        header_data(datum &d) :
            seq{&d, tlv::SEQUENCE, "header_data sequence"},
            msgID{&seq.value, tlv::INTEGER, "msgID"},
            msgMaxSize{&seq.value, tlv::INTEGER, "msgMaxSize"},
            msgFlags{&seq.value, tlv::OCTET_STRING, "msgFlags"},
            tmp{msgFlags.value},
            msgSecurityModel{&seq.value, tlv::INTEGER, "msgSecurityModel"},
            valid{seq.value.is_not_null()},
            priv{tmp & 0x3}
        { }

        void write_json(json_object &o) const {
            if (!valid) { return; }
            if (false) {
                o.print_key_hex("msgID", msgID.value);
                o.print_key_hex("msgMaxSize", msgMaxSize.value);
                o.print_key_hex("msgFlags", msgFlags.value);
            }
            o.print_key_hex("msgSecurityModel", msgSecurityModel.value);
            o.print_key_bool("priv", priv);
        }
    };

    //    The scopedPduData field represents either the plain text scopedPDU if
    //    the privFlag in the msgFlags is zero, or it represents an
    //    encryptedPDU (encoded as an OCTET STRING) which MUST be decrypted by
    //    the securityModel in use to produce a plaintext scopedPDU.
    //
    //    ScopedPduData ::= CHOICE {
    //        plaintext    ScopedPDU,
    //        encryptedPDU OCTET STRING  -- encrypted scopedPDU value
    //    }
    //
    //    ScopedPDU ::= SEQUENCE {
    //        contextEngineID  OCTET STRING,
    //        contextName      OCTET STRING,
    //        data             ANY -- e.g., PDUs as defined in [RFC3416]
    //    }
    //
    class scoped_pdu_data {
            tlv seq;
            tlv contextEngineID;
            tlv contextName;
            tlv any;

    public:
        scoped_pdu_data(datum &d) :
            seq{&d, tlv::SEQUENCE, "scoped_pdu_data sequence"},
            contextEngineID{&seq.value, tlv::OCTET_STRING, "contextEngineID"},
            contextName{&seq.value, tlv::OCTET_STRING, "contextName"},
            any{&seq.value, 0x00, "any"}
        {
            // TODO: class tlv should have an explicit_tag() accessor method
        }

        void write_json(json_object &o) const {

            if (false) {
                o.print_key_hex("contextEngineID", contextEngineID.value);
                o.print_key_hex("contextName", contextName.value);
            }

            // report PDU type based on explicit tag
            //
            switch(any.tag & 31) {
            case 0: o.print_key_string("pdu_type", "get_request"); break;
            case 1: o.print_key_string("pdu_type", "get_next_request"); break;
            case 2: o.print_key_string("pdu_type", "get_response"); break;
            case 3: o.print_key_string("pdu_type", "set_request"); break;
            case 5: o.print_key_string("pdu_type", "get_bulk_request"); break;
            case 6: o.print_key_string("pdu_type", "inform_request"); break;
            case 7: o.print_key_string("pdu_type", "snmpv2_trap"); break;
            case 8: o.print_key_string("pdu_type", "report"); break;
            default:
                o.print_key_string("pdu_type", "UNKNOWN PDU"); // (tag: %u)", any.tag); break;
            }

            if (false) {
                datum tmp = any.value;
                pdu data{tmp};
                data.write_json(o);
            }

        }
    };

    // class engine_id represents an SNMP Engine ID as defined by the
    // "SnmpEngineID TEXTUAL-CONVENTION" in RFC 3411; v3 formats and
    // pre-v3 formats are both handled
    //
    class engine_id {
        bool v3_format;
        encoded<uint32_t> enterprise_number;
        datum body;

        static bool initial_bit(const datum & d) {
            if (d.length() > 0) {
                return d.data[0] & 0x80;
            }
            return false;
        }

    public:

        engine_id(datum d) :
            v3_format{initial_bit(d)},
            enterprise_number{d},
            body{d}
        { }


        // formats defined in RFC 3411, Section 5.
        //
        enum format {
            ipv4_address = 1,
            ipv6_address = 2,
            mac_address  = 3,
            text         = 4,
            octets       = 5,
            local        = 6,   // RFC 5343
        };

        void write_json(json_object &o) const {
            if (!this->is_valid()) {
                return;
            }
            json_object eid{o, "engine_id"};
            eid.print_key_bool("v3_format", v3_format);
            if (v3_format) {

                eid.print_key_uint("enterprise_number", enterprise_number.value() & 0x7fffffff);

                if (lookahead<encoded<uint8_t>> format_type{body}) {

                    datum remainder = format_type.advance();

                    switch (format_type.value.value()) {
                    case format::ipv4_address:
                        if (remainder.length() == 4) {
                            eid.print_key_ipv4_addr("address", remainder.data);
                        }
                        break;
                    case format::ipv6_address:
                        if (remainder.length() == 16) {
                            eid.print_key_ipv6_addr("address", remainder.data);
                        }
                        break;
                    case format::mac_address:
                        eid.print_key_hex("mac", remainder);
                        break;
                    case format::text:
                        eid.print_key_json_string("text", remainder);
                        break;
                    case format::octets:
                        eid.print_key_hex("octets", remainder);
                        break;
                    case format::local:
                        eid.print_key_hex("octets", remainder);
                        break;
                    default:
                        eid.print_key_uint("format_type", format_type.value.value());
                        eid.print_key_hex("data", remainder);
                    }

                }

            } else { // v3_format == false

                eid.print_key_uint("enterprise_number", enterprise_number.value());
                if (body.length() == 8) {
                    eid.print_key_hex("agent_id", body);
                } else {
                    eid.print_key_hex("data", body);
                }
            }

            eid.close();
        }

        bool is_valid() const { return body.is_not_null(); }

    };

    /// return the password recovery string for an snmpv3
    /// encrypted/authenticated message
    ///
    static auto get_password_recovery_string(const datum &pdu,
                                             const datum &engine_id,
                                             const datum &auth_params)
    {
        data_buffer<512> result;

        result << datum{"$SNMPv3$1$3$"};
        result.write_hex(pdu.data, pdu.length());
        result << datum{"$"};
        result.write_hex(engine_id.data, engine_id.length());
        result << datum{"$"};
        result.write_hex(auth_params.data, auth_params.length());

        return result;
    }

    // USMSecurityParameters, following RFC 3414
    //
    //
    //       UsmSecurityParameters ::=
    //           SEQUENCE {
    //            -- global User-based security parameters
    //               msgAuthoritativeEngineID     OCTET STRING,
    //               msgAuthoritativeEngineBoots  INTEGER (0..2147483647),
    //               msgAuthoritativeEngineTime   INTEGER (0..2147483647),
    //               msgUserName                  OCTET STRING (SIZE(0..32)),
    //            -- authentication protocol specific parameters
    //               msgAuthenticationParameters  OCTET STRING,
    //            -- privacy protocol specific parameters
    //               msgPrivacyParameters         OCTET STRING
    //     }
    //
   class usm_security_parameters {
       tlv seq;
       tlv authoritative_engine_id;
       tlv authoritative_engine_boots;
       tlv authoritative_engine_time;
       tlv user_name;
       tlv authentication_parameters;
       tlv privacy_parameters;

    public:

       usm_security_parameters(datum d) :
           seq{&d, tlv::SEQUENCE, "seq"},
           authoritative_engine_id{&seq.value, tlv::OCTET_STRING, "engine_id"},
           authoritative_engine_boots{&seq.value, tlv::INTEGER, "boots"},
           authoritative_engine_time{&seq.value, tlv::INTEGER, "time"},
           user_name{&seq.value, tlv::OCTET_STRING, "user_name"},
           authentication_parameters{&seq.value, tlv::OCTET_STRING, "authentication_parameters"},
           privacy_parameters{&seq.value, tlv::OCTET_STRING, "privacy_parameters"}
        { }

       void write_json(json_object &o, const datum & pdu_copy) const {
           o.print_key_hex("engine_id_raw", authoritative_engine_id.value);

           engine_id{authoritative_engine_id.value}.write_json(o);

           o.print_key_json_string("user_name", user_name.value);

           auto pwd_recovery_string = get_password_recovery_string(pdu_copy, authoritative_engine_id.value, authentication_parameters.value);
           o.print_key_json_string("password_recovery", pwd_recovery_string.contents());

       }

   };

    // SNMPv3 message format, following RFC 3412, Sec. 6.
    //
    // SNMPv3Message ::= SEQUENCE {
    //            -- identify the layout of the SNMPv3Message
    //            -- this element is in same position as in SNMPv1
    //            -- and SNMPv2c, allowing recognition
    //            -- the value 3 is used for snmpv3
    //            msgVersion INTEGER ( 0 .. 2147483647 ),
    //            -- administrative parameters
    //            msgGlobalData HeaderData,
    //            -- security model-specific parameters
    //            -- format defined by Security Model
    //            msgSecurityParameters OCTET STRING,
    //            msgData  ScopedPduData
    //        }
    //
    class v3_packet {
        datum pdu_copy;
        tlv seq;
        tlv version;
        header_data hd;
        tlv msgSecurityParameters;
        bool valid;
        datum body;

    public:

        v3_packet(datum &d) :
            pdu_copy{d},
            seq{&d, tlv::SEQUENCE, "snmpv3 message"},
            version{&seq.value, tlv::INTEGER, "version"},
            hd{seq.value},
            msgSecurityParameters{&seq.value, tlv::OCTET_STRING, "msgSecurityParameters"},
            valid{seq.value.is_not_null()},
            body{seq.value}
        { }

        static constexpr bool verbose = false;  // suppress verbose output

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata;
            if (!is_not_empty()) {
                return;
            }
            json_object snmp{o, "snmp"};
            snmp.print_key_uint("version", snmp_version_get_uint(version));
            if (true) {
                hd.write_json(o);
            }
            if (verbose) {
                o.print_key_hex("msgSecurityParameters", msgSecurityParameters.value);
            }
            usm_security_parameters usm_params{msgSecurityParameters.value};
            usm_params.write_json(o, pdu_copy);

            datum tmp = body;
            if (hd.priv) {
                tlv encrypted_pdu{&tmp, 0x00, "encrypted-pdu"}; // TODO: implement decryption
                if (verbose) {
                    o.print_key_hex("encrypted_pdu", body);
                }
            } else {
                scoped_pdu_data msgData{tmp};
                msgData.write_json(o);
            }
            snmp.close();
        }

        void write_l7_metadata(cbor_object &o, bool) {
            cbor_array protocols{o, "protocols"};
            protocols.print_string("snmp");
            protocols.close();
        }

        bool is_not_empty() const {
            return valid;
        }

        static constexpr mask_and_value<8> matcher{
            { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            { 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
        };

    };

    class packet : public base_protocol {
        std::variant<std::monostate,v2_packet,v3_packet> body;

        static uint8_t get_version(datum d) {
            tlv seq{d, tlv::SEQUENCE};
            tlv version{&seq.value, tlv::INTEGER};
            if (seq.value.is_not_null() and version.length == 1) {
                return version.value.data[0];
            }
            return 255; // not a valid version
        }

    public:

        packet(datum &d) {

            switch(get_version(d)) {
            case 0x00:
            case 0x01:
                body.emplace<v2_packet>(d);
                break;
            case 0x03:
                body.emplace<v3_packet>(d);
            default:
                ;
            }

        }

        struct do_write_json {
            json_object &record;

            do_write_json(json_object &obj) : record{obj} { }

            void operator()(const std::monostate &) { }

            template <typename T>
            void operator()(T &t) { t.write_json(record); }

        };

        void write_json(json_object &o, bool metadata=true) const {
            (void)metadata;
            std::visit(do_write_json{o}, body);
        }

        struct do_is_not_empty {

            bool operator()(const std::monostate &) { return false; }

            template <typename T>
            bool operator()(T &t) { return t.is_not_empty(); }

        };

        bool is_not_empty() const {
            return std::visit(do_is_not_empty{}, body);
        }

    };

    inline uint8_t snmp_version_get_uint(const tlv &version) {
        if (version.is_not_null() and version.length == 1) {
            switch(version.value.data[0]) {
            case 0: return 1;
            case 1: return 2;
            case 3: return 3;
            default:
                ;
            }
        }
        return 255; // not a valid version
    }

    [[maybe_unused]] static bool unit_test() {
        const unsigned char get_request[] = {
            0x30, 0x3e, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x5d, 0x05, 0x5b,
            0xa3, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03,
            0x04, 0x10, 0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x30, 0x14, 0x04, 0x00, 0x04, 0x00,
            0xa0, 0x0e, 0x02, 0x04, 0x2e, 0xd1, 0xe4, 0xaa, 0x02, 0x01, 0x00, 0x02,
            0x01, 0x00, 0x30, 0x00
        };

        datum get_request_datum{get_request, get_request + sizeof(get_request)};
        snmp::v3_packet snmp{get_request_datum};
        return snmp.is_not_empty();
    }

}

[[maybe_unused]] static int snmp_fuzz_test(const uint8_t *data, size_t size) {
    datum snmp_data{data, data+size};
    snmp::packet snmp{snmp_data};
    output_buffer<4096> buf;
    json_object o{&buf};
    snmp.write_json(o);
    o.close();
    return 0;
}

#endif // SNMP_HPP
