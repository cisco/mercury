// snmp.h
//

#ifndef SNMP_H
#define SNMP_H

#include "x509.h"
#include "json_object.h"
#include "match.h"

namespace snmp {

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
            o.print_key_hex("msgID", msgID.value);
            o.print_key_hex("msgMaxSize", msgMaxSize.value);
            o.print_key_hex("msgFlags", msgFlags.value);
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

            o.print_key_hex("contextEngineID", contextEngineID.value);
            o.print_key_hex("contextName", contextName.value);

            // report PDU type based on explicit tag
            //
            switch(any.tag & 31) {
            case 0: o.print_key_string("pdu_type", "GetRequest"); break;
            case 1: o.print_key_string("pdu_type", "GetNextRequest"); break;
            case 2: o.print_key_string("pdu_type", "Response"); break;
            case 3: o.print_key_string("pdu_type", "SetRequest"); break;
            case 5: o.print_key_string("pdu_type", "GetBulkRequest"); break;
            case 6: o.print_key_string("pdu_type", "InformRequest"); break;
            case 7: o.print_key_string("pdu_type", "SNMPv2-Trap"); break;
            case 8: o.print_key_string("pdu_type", "Report"); break;
            default:
                o.print_key_string("pdu_type", "UNKNOWN PDU"); // (tag: %u)", any.tag); break;
            }
            datum tmp = any.value;
            pdu data{tmp};
            data.write_json(o);

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
    class packet {
        tlv seq;
        tlv version;
        header_data hd;
        tlv msgSecurityParameters;
        bool valid;
        datum body;

    public:
        packet(datum &d) :
            seq{&d, tlv::SEQUENCE, "snmpv3 message"},
            version{&seq.value, tlv::INTEGER, "version"},
            hd{seq.value},
            msgSecurityParameters{&seq.value, tlv::OCTET_STRING, "msgSecurityParameters"},
            valid{seq.value.is_not_null()},
            body{seq.value}
        {
        }

        void fprint(FILE *) {
        }

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata;
            if (!is_not_empty()) {
                return;
            }
            json_object snmp{o, "snmp"};
            snmp.print_key_hex("version", version.value);
            hd.write_json(o);
            datum tmp = body;
            if (hd.priv) {
                tlv encrypted_pdu{&tmp, 0x00, "encrypted-pdu"}; // TODO: implement decryption
                o.print_key_hex("encrypted_pdu", body);
            } else {
                scoped_pdu_data msgData{tmp};
                msgData.write_json(o);
            }
            snmp.close();
        }

        bool is_not_empty() const {
            return valid;
        }

        explicit operator bool() const {
            return valid;
        }

        static constexpr mask_and_value<8> matcher{
            { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            { 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
        };

    };

#ifndef NDEBUG
    const unsigned char get_request[] = {
        0x30, 0x3e, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x5d, 0x05, 0x5b,
        0xa3, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03,
        0x04, 0x10, 0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
        0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x30, 0x14, 0x04, 0x00, 0x04, 0x00,
        0xa0, 0x0e, 0x02, 0x04, 0x2e, 0xd1, 0xe4, 0xaa, 0x02, 0x01, 0x00, 0x02,
        0x01, 0x00, 0x30, 0x00
    };

    [[maybe_unused]] static bool unit_test() {
        datum get_request_datum{get_request, get_request + sizeof(get_request)};
        snmp::packet snmp{get_request_datum};
        return (bool)snmp;
    }

#endif // NDEBUG

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

#endif // SNMP_H
