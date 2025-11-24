// snmp.h
//

#ifndef SNMP_HPP
#define SNMP_HPP

#include "x509.h"
#include "json_object.h"
#include "cbor_object.hpp"
#include "protocol.h"
#include "match.h"

#include <variant>


/// return the integer formed by interpreting the bytes of \ref datum
/// \param d as an unsigned integer in network byte order
///
/// \note: ASN.1 integers will have a leading 0x00 byte if they are
/// unsigned
///
inline uint64_t get_uint64(const datum &d) {
    uint64_t result = 0;
    if (d.is_readable()) {
        for (const auto & byte : d) {
            result *= 256;
            result += byte;
        }
    }
    return result;
}

namespace snmp {

    // forward declarations
    //
    inline uint8_t snmp_version_get_uint(const tlv &version);

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
            json_object &value = o;

            datum tmp{body};
            tlv object{tmp};
            if (!object.is_valid()) {
                return;
            }

            tlv::tag_class tc = object.get_tag_class();
            if (tc == tlv::tag_class::application) {
                switch(object.tag_number()) {
                case 0:
                    if (object.value.length() == 4) {
                        value.print_key_ipv4_addr("ipv4_address", object.value.data);
                        return;
                    }
                    break;
                case 1:
                    if (object.value.length() <= 5) {
                        value.print_key_uint("counter32", get_uint64(object.value));
                        return;
                    }
                    break;
                case 2:
                    if (object.value.length() <= 5) {
                        value.print_key_uint("unsigned32", encoded<uint32_t>{object.value}.value());
                        return;
                    }
                    break;
                case 3:
                    if (object.value.length() <= 5) {
                        value.print_key_uint("time_ticks", encoded<uint32_t>{object.value}.value());  // note: could report value/100 as float
                        return;
                    }
                    break;
                case 4:
                    value.print_key_hex("opaque", object.value);
                    return;
                    break;
                case 5:
                    value.print_key_bool("null", true);
                    return;
                    break;
                case 6:
                    if (object.value.length() <= 9) {
                        value.print_key_uint("counter64", encoded<uint64_t>{object.value}.value());
                        return;
                    }
                    break;
                default:
                    ;     // pass through to end of function
                }

            } else if (tc == tlv::tag_class::universal) {

                switch(object.get_little_tag()) {
                case tlv::OBJECT_IDENTIFIER:
                    object.print_as_json_oid(value, "oid");
                    return;
                case tlv::PRINTABLE_STRING:
                case tlv::T61String:
                case tlv::VIDEOTEX_STRING:
                case tlv::IA5String:
                case tlv::GraphicString:
                case tlv::VisibleString:
                    object.print_as_json_escaped_string(value, "string");
                    return;
                case tlv::BIT_STRING:
                    value.print_key_hex("bit_string_hex", object.value);
                    return;
                case tlv::OCTET_STRING:
                    value.print_key_hex("octet_string", object.value);
                    return;
                case tlv::INTEGER:
                    value.print_key_uint("integer", get_uint64(object.value));
                    return;
                case tlv::NULL_TAG:
                    value.print_key_bool("null", true);
                    return;
                case tlv::BOOLEAN:
                    value.print_key_bool("boolean", object.value.matches(std::array<uint8_t,1>{0xff}));
                    return;
                default:
                    ;     // pass through to end of function
                }

            }

            // handle unexpected universal and application tags, as
            // well as all context-specific tags and private tags, by
            // writing the raw TLV information
            //
            value.print_key_hex("value_tlv_hex", body);

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
        datum tmp;
        object_syntax value;
        bool valid;

    public:

        var_bind(datum &d) :
            seq{d, tlv::SEQUENCE, "seq"},
            name{&seq.value, tlv::OBJECT_IDENTIFIER, "oid"},
            tmp{seq.value},
            value{seq.value},
            valid{seq.value.is_not_null()}
        { }

        void write_json(json_object &o) const {
            o.print_key_value("name", raw_oid{name.value});
            value.write_json(o);
        }

        void write_json(json_array &a) const {
            json_object o{a};
            o.print_key_value("name", raw_oid{name.value});
            // o.print_key_hex("raw_value", tmp);
            value.write_json(o);
            o.close();
        }

        bool is_not_empty() const { return valid; }

    };

    // The trap_pdu type was defined in SNMPv1, and was obsoleted by
    // the snmpv2_trap type in SNMPv2
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
        tlv enterprise_oid;
        tlv agent_addr;
        tlv generic_trap;
        tlv specific_trap;
        tlv timestamp;
        tlv variable_bindings_list;
        datum remainder;

    public:

        trap(datum &d) :
            enterprise_oid{d, tlv::OBJECT_IDENTIFIER, "enterprise_oid"},
            agent_addr{d, 0x00, "agent_addr"},
            generic_trap{d, tlv::INTEGER, "generic_trap"},
            specific_trap{d, tlv::INTEGER, "specific_trap"},
            timestamp{d, 0x00, "timestamp"},
            variable_bindings_list{d, tlv::SEQUENCE, "variable_bindings_list"},
            remainder{d}
        { }

        static const char *trap_number_get_string(unsigned int n) {
            switch(n) {
            case 0: return "cold_start";
            case 1: return "warm_start";
            case 2: return "link_down";
            case 3: return "link_up";
            case 4: return "authentication_failure";
            case 5: return "egp_neighbor_loss";
            case 6: return "enterprise_specific";
            default:
                ;
            }
            return "UNKNOWN";
        }

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata;
            if (remainder.is_null()) {
                return;  // object is invalid
            }

            json_object trap{o, "trap"};
            trap.print_key_value("enterprise", raw_oid{enterprise_oid.value});
            trap.print_key_hex("agent_addr", agent_addr.value);
            trap.print_key_string("generic_trap", trap_number_get_string(get_uint64(generic_trap.value)));
            trap.print_key_hex("specific_trap", specific_trap.value);
            trap.print_key_hex("timestamp", timestamp.value);

            trap.write_json_array_of<var_bind>(variable_bindings_list.value, "var_bind_list");

            trap.print_key_hex("remainder", remainder);
            trap.close();
        }

        bool is_not_empty() const { return !remainder.is_null(); }
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
        tlv request_id;
        tlv error_status;
        tlv error_index;
        tlv variable_bindings;
        bool valid;

    public:

        v2_pdu(datum &d) :
            request_id{&d, 0x00, "request_id"},
            error_status{&d, tlv::INTEGER, "error_status"},
            error_index{&d, tlv::INTEGER, "error_index"},
            variable_bindings{&d, 0x00, "variable_bindings"},
            valid{d.is_not_null()}
        { }

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata;
            if (!is_not_empty()) {
                return;
            }
            json_object pdu{o, "pdu"};
            pdu.print_key_uint("request_id", get_uint64(request_id.value));
            std::array<uint8_t,1> zero{0x00};
            if (!error_status.value.matches(zero)) {
                pdu.print_key_hex("error_status", error_status.value);
            }
            if (!error_index.value.matches(zero)) {
                pdu.print_key_hex("error_index", error_index.value);
            }
            pdu.write_json_array_of<var_bind>(variable_bindings.value, "var_bind_list");

            pdu.close();
        }

        bool is_not_empty() const { return valid; }

    };

    static const char *UNKNOWN = "UNKNOWN";

    enum pdu_type_code {
        get_request       = 0,
        get_next_request  = 1,
        get_response      = 2,
        set_request       = 3,
        v1_trap           = 4,
        get_bulk_request  = 5,
        inform_request    = 6,
        snmpv2_trap       = 7,
    };

    const char *v2_pdu_type(uint8_t tag_number) {
        switch(tag_number) {
        case get_request:      return "get_request";
        case get_next_request: return "get_next_request";
        case get_response:     return "get_response";
        case set_request:      return "set_request";
        case v1_trap:          return "trap";
        case get_bulk_request: return "get_bulk_request";
        case inform_request:   return "inform_request";
        case snmpv2_trap:      return "snmpv2_trap";
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

            uint8_t pdu_code = data.tag_number();
            const char *pdu_type = v2_pdu_type(pdu_code);
            if (pdu_type != UNKNOWN) {
                snmp.print_key_string("pdu_type", pdu_type);
            } else {
                snmp.print_key_unknown_code("pdu_type", data.tag_number());
            }

            datum tmp{data.value};
            if (pdu_code == pdu_type_code::v1_trap) {
                trap{tmp}.write_json(snmp);
            } else {
                v2_pdu{tmp}.write_json(snmp);
            }

            snmp.close();
        }

        void write_l7_metadata(cbor_object &o) const {
            if (!valid) {
                return;
            }
            cbor_array protocols{o, "protocols"};
            protocols.print_string("snmp");
            protocols.close();
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
        { }

        void write_json(json_object &o) const {
            o.print_key_uint("request_id", get_uint64(request_id.value));
            o.print_key_hex("error_status", error_status.value);
            o.print_key_hex("error_index", error_index.value);
            tlv tmp{any};
            v2_pdu{tmp.value}.write_json(o);
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

        bool priv() const { return tmp & 2; }
        bool auth() const { return tmp & 1; }

        header_data(datum &d) :
            seq{&d, tlv::SEQUENCE, "header_data sequence"},
            msgID{&seq.value, tlv::INTEGER, "msgID"},
            msgMaxSize{&seq.value, tlv::INTEGER, "msgMaxSize"},
            msgFlags{&seq.value, tlv::OCTET_STRING, "msgFlags"},
            tmp{msgFlags.value},
            msgSecurityModel{&seq.value, tlv::INTEGER, "msgSecurityModel"},
            valid{seq.value.is_not_null()}
        { }

        void write_json(json_object &o) const {
            if (!valid) { return; }
            if constexpr (false) {
                o.print_key_hex("msg_id", msgID.value);
                o.print_key_hex("msg_max_size", msgMaxSize.value);
                o.print_key_hex("msg_flags", msgFlags.value);
            }
            o.print_key_uint("msg_security_model", get_uint64(msgSecurityModel.value));
            o.print_key_bool("auth", auth());
            o.print_key_bool("priv", priv());
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

            o.print_key_hex("context_engine_id", contextEngineID.value);
            o.print_key_hex("context_name", contextName.value);

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
                o.print_key_unknown_code("pdu_type", (uint8_t)(any.tag & 31));
            }

            tlv tmp{any};
            v2_pdu{tmp.value}.write_json(o);

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
        bool valid;

    public:

        usm_security_parameters(datum d) :
            seq{&d, tlv::SEQUENCE, "seq"},
            authoritative_engine_id{&seq.value, tlv::OCTET_STRING, "engine_id"},
            authoritative_engine_boots{&seq.value, tlv::INTEGER, "boots"},
            authoritative_engine_time{&seq.value, tlv::INTEGER, "time"},
            user_name{&seq.value, tlv::OCTET_STRING, "user_name"},
            authentication_parameters{&seq.value, tlv::OCTET_STRING, "authentication_parameters"},
            privacy_parameters{&seq.value, tlv::OCTET_STRING, "privacy_parameters"},
            valid{d.is_not_null()}
        { }

        /// return the password recovery string for an snmpv3
        /// authenticated message
        ///
        auto get_password_recovery_string(const datum &pdu) const {
            data_buffer<1500> result;

            // datum before_auth_param{pdu.data, authentication_parameters.value.data};
            // datum after_auth_param{authentication_parameters.value.data_end, pdu.data_end};
            auto [ before_auth_param, after_auth_param ] = symmetric_difference(pdu, authentication_parameters.value);

            result << datum{"$SNMPv3$0$0$"};

            // write the PDU with the value field of the auth_params
            // set to the all-zero string (as per RFC2574, Section
            // 6.3.1) into the password recovery string
            //
            result.write_hex(before_auth_param.data, before_auth_param.length());
            for (ssize_t i=0; i<authentication_parameters.value.length(); i++) {
                result << datum{"00"};
            }
            result.write_hex(after_auth_param.data, after_auth_param.length());

            result << datum{"$"};
            result.write_hex(authoritative_engine_id.value.data, authoritative_engine_id.value.length());
            result << datum{"$"};
            result.write_hex(authentication_parameters.value.data, authentication_parameters.value.length());

            return result;
        }

        void write_json(json_object &o, const datum & pdu_copy, bool is_priv, bool is_auth) const {
            (void)is_priv;
            if (!valid) {
                return;
            }

            o.print_key_hex("engine_id_raw", authoritative_engine_id.value);

            engine_id{authoritative_engine_id.value}.write_json(o);

            o.print_key_json_string("user_name", user_name.value);

            if (is_auth) {
                auto pwd_recovery_string = get_password_recovery_string(pdu_copy);
                o.print_key_json_string("password_recovery", pwd_recovery_string.contents());
            }

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
        {
        }

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata;
            if (!is_not_empty()) {
                return;
            }
            json_object snmp{o, "snmp"};
            snmp.print_key_uint("version", get_uint64(version.value));
            hd.write_json(o);
            usm_security_parameters{msgSecurityParameters.value}.write_json(o, pdu_copy, hd.priv(), hd.auth());

            datum tmp = body;
            if (hd.priv()) {
                tlv encrypted_pdu{&tmp, tlv::OCTET_STRING, "encrypted-pdu"}; // TODO: implement decryption
                o.print_key_uint("encrypted_pdu_length", encrypted_pdu.length);
            } else {
                scoped_pdu_data msgData{tmp};
                msgData.write_json(o);
            }
            snmp.close();
        }

        void write_l7_metadata(cbor_object &o) const {
            if (!valid) {
                return;
            }
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
                return get_uint64(version.value);
            }
            return 255; // not a valid version
        }

    public:

        packet(datum &d) {

            switch(get_version(d)) {
            case 0x00:
                [[fallthrough]];
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

        struct do_write_l7_metadata {
            cbor_object &record;

            do_write_l7_metadata(cbor_object &obj) : record{obj} { }

            void operator()(const std::monostate &) { }

            template <typename T>
            void operator()(T &t) { t.write_l7_metadata(record); }

        };

        void write_l7_metadata(cbor_object &o, bool metadata=true) const {
            (void)metadata;
            std::visit(do_write_l7_metadata{o}, body);
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
    return json_output_fuzzer<snmp::packet>(data, size);
}

[[maybe_unused]] static int snmp_trap_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<snmp::trap>(data, size);
}

[[maybe_unused]] static int snmp_v2_pdu_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<snmp::v2_pdu>(data, size);
}

#endif // SNMP_HPP
