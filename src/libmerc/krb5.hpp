// krb5.h
//
// kerberos protocol

#ifndef KRB5_HPP
#define KRB5_HPP

// #define ASN1_DEBUG 1
// #define TLV_ERR_INFO 1

#include <variant>
#include "datum.h"
#include "x509.h"
#include "json_object.h"
#include "match.h"
#include "protocol.h"

namespace krb5 {

#include "krb5_params.hpp"

    // hashcat 
    //
    // 7500	Kerberos 5, etype 23, AS-REQ Pre-Auth	$krb5pa$23$user$realm$salt$4e751db65422b2117f7eac7b721932dc8aa0d9966785ecd958f971f622bf5c42dc0c70b532363138363631363132333238383835

    static uint64_t to_uint64(const datum &d) {
        uint64_t result = 0;
        for (const uint8_t & x : d) {
            result = result * 256 + x;
        }
        return result;
    }

    static uint64_t to_uint64(const tlv &x) {
        return to_uint64(x.value);
    }


    // KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
    //                     -- minimum number of bits shall be sent,
    //                     -- but no fewer than 32
    //
    // KDCOptions      ::= KerberosFlags
    //         -- reserved(0),
    //         -- forwardable(1),
    //         -- forwarded(2),
    //         -- proxiable(3),
    //         -- proxy(4),
    //         -- allow-postdate(5),
    //         -- postdated(6),
    //         -- unused7(7),
    //         -- renewable(8),
    //         -- unused9(9),
    //         -- unused10(10),
    //         -- opt-hardware-auth(11),
    //         -- unused12(12),
    //         -- unused13(13),
    // -- 15 is reserved for canonicalize
    //         -- unused15(15),
    // -- 26 was unused in 1510
    //         -- disable-transited-check(26),
    // --
    //         -- renewable-ok(27),
    //         -- enc-tkt-in-skey(28),
    //         -- renew(30),
    //         -- validate(31)
    //
    struct kdc_options {
        struct tlv bit_string;

        kdc_options() : bit_string{} {}
        kdc_options(datum p) : bit_string{} {
            parse(p);
        }
        void parse(datum &p) {
            bit_string.parse(&p, tlv::BIT_STRING);
        }

        void print_as_json(struct json_object &o, const char *name) const {
            varint<uint32_t> flags{bit_string.value, varint<uint32_t>::asn1_bitstring};
            json_array_bitflags f{o, name, flags};
            f.flag<1>("forwardable");
            f.flag<2>("forwarded");
            f.flag<3>("proxiable");
            f.flag<4>("proxy");
            f.flag<5>("allow-postdate");
            f.flag<6>("postdated");
            f.flag<8>("renewable");
            f.flag<11>("opt-hardware-auth");
            f.flag<15>("canonicalize");
            f.flag<26>("disable-transited-check");
            f.flag<27>("renewable-ok");
            f.flag<28>("enc-tkt-in-skey");
            f.flag<30>("renew");
            f.flag<31>("validate");
            f.check_for_unknown_flags<1,2,3,4,5,6,8,11,15,26,27,28,30,31>();
            f.close();
        }
    };


    //  KerberosString  ::= GeneralString (IA5String)
    //
    //  Realm           ::= KerberosString
    //
    //  PrincipalName   ::= SEQUENCE {
    //          name-type       [0] Int32,
    //          name-string     [1] SEQUENCE OF KerberosString
    //  }
    //
    class principal_name {
        tlv sequence;
        tlv name_type;
        tlv name_sequence;

    public:

        enum type {
            NT_UNKNOWN        =  0,   // Name type not known
            NT_PRINCIPAL      =  1,   // Just the name of the principal as in DCE, or for users
            NT_SRV_INST       =  2,   // Service and other unique instance (krbtgt)
            NT_SRV_HST        =  3,   // Service with host name as instance (telnet, rcommands)
            NT_SRV_XHST       =  4,   // Service with host as remaining components
            NT_UID            =  5,   // Unique ID
            NT_X500_PRINCIPAL =  6,   // Encoded X.509 Distinguished name [RFC2253]
            NT_SMTP_NAME      =  7,   // Name in form of SMTP email name  (e.g., user@example.com)
            NT_ENTERPRISE     = 10,   // Enterprise name - may be mapped to principal name
        };

        static const char *name_type_get_string(uint8_t t) {
            switch(t) {
            case NT_UNKNOWN:        return "UNKNOWN";
            case NT_PRINCIPAL:      return "PRINCIPAL";
            case NT_SRV_INST:       return "SRV_INST";
            case NT_SRV_HST:        return "SRV_HST";
            case NT_SRV_XHST:       return "SRV_XHST";
            case NT_UID:            return "UID";
            case NT_X500_PRINCIPAL: return "X500_PRINCIPAL";
            case NT_SMTP_NAME:      return "SMTP_NAME";
            case NT_ENTERPRISE:     return "ENTERPRISE";
            default:
                ;
            }
            return nullptr;
        }

        static void name_type_write_json(uint32_t t, const char *key, json_object &o) {
            const char *name = name_type_get_string(t);
            if (name) {
                o.print_key_string(key, name_type_get_string(t));
            } else {
                o.print_key_unknown_code(key, t);
            }
        }

        principal_name(datum d) :
            sequence{d, 0, "pn.sequence"},
            name_type{sequence.value, 0, "name_type"},
            name_sequence{sequence.value, 0, "name_sequence"}
        { }

        void write_json(json_object &o, const char *object_name) {
            json_object pn{o, object_name};
            tlv type_int{name_type.value, tlv::INTEGER, "type"};
            // pn.print_key_string("type", name_type_get_string(to_uint64(type_int.value)));  // TODO: int32
            name_type_write_json(to_uint64(type_int.value), "type", pn);
            json_array array{pn, "names"};
            tlv tmp_seq{name_sequence.value, tlv::SEQUENCE, "tmp_seq"};
            while (tmp_seq.value.is_not_empty()) {
                // tmp_seq.value.fprint_hex(stderr); fputc('\n', stderr);
                tlv name{tmp_seq};
                array.print_json_string(name.value);
            }
            array.close();
            pn.close();
        }

    };


    //     EncryptedData   ::= SEQUENCE {
    //         etype   [0] Int32 -- EncryptionType --,
    //         kvno    [1] UInt32 OPTIONAL,
    //         cipher  [2] OCTET STRING -- ciphertext
    //     }
    //
    class encrypted_data {
        tlv seq;
        tlv etype;
        tlv kvno;
        tlv cipher;
        bool valid;

    public:

        encrypted_data(datum d) :
            seq{d, tlv::SEQUENCE, "encrypted_data.seq"}
        {
            while (seq.value.is_not_empty()) {
                tlv tmp{&seq.value};
                switch(tmp.tag) {
                case tlv::explicit_tag_constructed(0):
                    etype.parse(&tmp.value, tlv::INTEGER);
                    break;
                case tlv::explicit_tag_constructed(1):
                    kvno.parse(&tmp.value, tlv::INTEGER);
                    break;
                case tlv::explicit_tag_constructed(2):
                    cipher.parse(&tmp.value, tlv::OCTET_STRING);
                    break;
                default:
                    ;
                }
            }
            valid = (bool)etype and (bool)cipher;
        }

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata;
            if (!valid) {
                return;
            }
            json_object enc_data{o, "enc_data"};
            enc_data.print_key_string("etype", encryption_type<uint32_t>{to_uint64(etype.value)}.get_name());
            if (kvno) {
                enc_data.print_key_uint("kvno", to_uint64(kvno.value));
            }
            enc_data.print_key_hex("ciphertext", cipher.value);
            enc_data.close();
        }

    };

    // Ticket          ::= [APPLICATION 1] SEQUENCE {
    //         tkt-vno         [0] INTEGER (5),
    //         realm           [1] Realm,
    //         sname           [2] PrincipalName,
    //         enc-part        [3] EncryptedData -- EncTicketPart
    // }
    //
    class ticket {
        tlv seq;
        tlv tkt_vno;
        tlv realm;
        tlv sname;
        tlv enc_part;

    public:
        ticket(datum d) :
            seq{d, tlv::SEQUENCE, "seq"}
        {
            while (seq.value.is_not_empty()) {
                tlv tmp{&seq.value};
                switch(tmp.tag) {
                case tlv::explicit_tag_constructed(0):
                    tkt_vno.parse(&tmp.value, tlv::INTEGER, "tkt_vno");
                    break;
                case tlv::explicit_tag_constructed(1):
                    realm.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(2):
                    sname = tmp;
                    //sname.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(3):
                    enc_part = tmp;
                    //enc_part.parse(&tmp.value);
                    break;
                default:
                    ;
                }
            }
        }

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata;
            json_object tkt{o, "ticket"};
            tkt.print_key_hex("vno", tkt_vno.value);
            if (realm) {
                tkt.print_key_json_string("realm", realm.value);
            }
            if (sname) {
                principal_name{sname.value}.write_json(tkt, "sname");
            }
            if (enc_part) {
                // tkt.print_key_hex("enc_part", enc_part.value);
                encrypted_data{enc_part.value}.write_json(tkt, metadata);
            }
            tkt.close();
        }

    };


    // KDC-REQ-BODY    ::= SEQUENCE {
    //         kdc-options             [0] KDCOptions,
    //         cname                   [1] PrincipalName OPTIONAL
    //                                     -- Used only in AS-REQ --,
    //         realm                   [2] Realm
    //                                     -- Server's realm
    //                                     -- Also client's in AS-REQ --,
    //         sname                   [3] PrincipalName OPTIONAL,
    //         from                    [4] KerberosTime OPTIONAL,
    //         till                    [5] KerberosTime,
    //         rtime                   [6] KerberosTime OPTIONAL,
    //         nonce                   [7] UInt32,
    //         etype                   [8] SEQUENCE OF Int32 -- EncryptionType
    //                                     -- in preference order --,
    //         addresses               [9] HostAddresses OPTIONAL,
    //         enc-authorization-data  [10] EncryptedData OPTIONAL
    //                                     -- AuthorizationData --,
    //         additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
    //                                        -- NOTE: not empty
    // }
    //
    class kdc_req_body {
        tlv kdc_opt;
        tlv cname;                    // optional
        tlv realm;
        tlv sname;                    // optional
        tlv from;                     // optional
        tlv till;
        tlv rtime;                    // optional
        tlv nonce;
        tlv etype;
        tlv address;                  // optional
        tlv enc_authorization_data;   // optional
        tlv additional_tickets;       // optional

    public:

        kdc_req_body(datum &d) {
            //tlv seq{&d, tlv::SEQUENCE, "kdc_req_body.sequence"};
            while (d.is_not_empty()) {
                tlv tmp{&d};
                //fprintf(stderr, "kdc_req_body.tag: %x\n", tmp.tag);
                switch(tmp.tag) {
                case tlv::explicit_tag_constructed(0):
                    kdc_opt = tmp;
                    // kdc_options.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(1):
                    cname = tmp;
                    // cname.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(2):
                    realm.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(3):
                    sname = tmp;
                    // sname.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(4):
                    from.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(5):
                    till.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(6):
                    rtime.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(7):
                    nonce.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(8):
                    etype.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(9):
                    address.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(10):
                    enc_authorization_data.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(11):
                    additional_tickets.parse(&tmp.value);
                    break;
                default:
                    ; // error
                }
                // TODO: verify that required fields are present
            }
        }

        void write_json(json_object &record) const {
            json_object o{record, "body"};
            kdc_options{kdc_opt.value}.print_as_json(o, "kdc_options");
            if (cname) {
                principal_name{cname.value}.write_json(o, "cname");
            }
            o.print_key_json_string("realm", realm.value);
            if (sname) {
                principal_name{sname.value}.write_json(o, "sname");
            }
            if (from) {
                from.print_as_json_generalized_time(o, "from");
            }
            // o.print_key_hex("from", from.value);
            till.print_as_json_generalized_time(o, "till");
            if (rtime) {
                rtime.print_as_json_generalized_time(o, "rtime");
            }
            o.print_key_hex("nonce", nonce.value);
            // o.print_key_hex("etype", etype.value);

            json_array etype_array{o, "etype"};
            datum tmp = etype.value;
            while (tmp.is_not_empty()) {
                tlv e{tmp};
                const char *ename = encryption_type<uint32_t>{to_uint64(e.value)}.get_name();
                if (ename) {
                    etype_array.print_string(ename);
                } else {
                    etype_array.print_unknown_code(to_uint64(e.value));
                }
            }
            etype_array.close();

            if (address) {
                o.print_key_hex("address", address.value);
            }
            if (enc_authorization_data) {
                o.print_key_hex("enc_authorization_data", enc_authorization_data.value);
            }
            if (additional_tickets) {
                o.print_key_hex("additional_tickets", additional_tickets.value);
            }
            o.close();
        }

    };

    // PA-DATA         ::= SEQUENCE {
    //     -- NOTE: first tag is [1], not [0]
    //     padata-type     [1] Int32,
    //     padata-value    [2] OCTET STRING -- might be encoded AP-REQ
    // }
    //
    class pa_data {
        tlv seq;
        tlv type;
        tlv pa_data_value;
        bool valid;

    public:
        pa_data(datum &d) :
            seq{&d, tlv::SEQUENCE, "seq"},
            // pa_data_type{&seq.value, 0x00, "pa_data_type"},
            // pa_data_value{&seq.value, 0x00, "pa_data_value"}
            type{&seq.value, tlv::explicit_tag_constructed(1), "pa_data_type"},
            pa_data_value{&seq.value, tlv::explicit_tag_constructed(2), "pa_data_value"},
            valid{d.is_not_null()}
        {
            if (pa_data_value.is_null()) {
                d.set_null();
            }
        }

        void write_json(json_array &a) const {
            if (!valid) { return; }
            json_object pad{a};
            //pa_data_type.print_as_json(pad, "type");
            datum tmp = type.value;
            pa_data_type<uint32_t>{to_uint64(tlv{tmp})}.write_json(pad);
            // pa_data_type.print_as_json(pad, "type");
            pa_data_value.print_as_json(pad, "value");
            pad.close();
        }

    };


    // KDC-REQ         ::= SEQUENCE {
    //         -- NOTE: first tag is [1], not [0]
    //         pvno            [1] INTEGER (5) ,
    //         msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
    //         padata          [3] SEQUENCE OF PA-DATA OPTIONAL
    //                             -- NOTE: not empty --,
    //         req-body        [4] KDC-REQ-BODY
    // }
    //
    class kdc_req {
        //literal<4> prefix;
        //tlv application;
        tlv seq;
        tlv pvno;
        tlv msg_type;
        tlv padata;    // optional
        tlv req_body;
        bool valid;

    public:

        kdc_req(datum &d) :
            //application{&d, 0x00, "application"},
            //prefix{application.value, { 0x6a, 0x82, 0x01, 0x1f }},
            seq{&d, tlv::SEQUENCE, "seq"}
            // pvno{&seq.value, tlv::explicit_tag(1), "pvno"},
            // valid{seq.value.is_not_null()}
        {
            //fprintf(stderr, "FUNCTION: %s\n", __func__);
            tlv tmp{&seq.value};
            if (tmp.tag == tlv::explicit_tag_constructed(1)) {
                pvno.parse(&tmp.value);
            }
            tmp.parse(&seq.value);
            if (tmp.tag == tlv::explicit_tag_constructed(2)) {
                msg_type.parse(&tmp.value);
            }
            tmp.parse(&seq.value);
            if (tmp.tag == tlv::explicit_tag_constructed(3)) {  // optional
                padata.parse(&tmp.value);
            }
            tmp.parse(&seq.value);
            if (tmp.tag == tlv::explicit_tag_constructed(4)) {
                req_body.parse(&tmp.value, tlv::SEQUENCE, "body");
            }
            valid = seq.value.is_not_null();
        }

        void write_json(json_object &o) const {
            //            if (!valid) { return; }
            json_object kdc_req_json{o, "kdc_req"};
            kdc_req_json.print_key_hex("pvno", pvno.value);
            kdc_req_json.print_key_hex("msg_type", msg_type.value);
            // kdc_req_json.print_key_hex("padata", padata.value);
            // if (lookahead<pa_data> pad{padata.value}) {

            json_array pa_array{kdc_req_json, "pa_data"};
            datum tmp = padata.value;
            while (tmp.is_not_empty()) {
                pa_data data{tmp};
                data.write_json(pa_array);
            }
            pa_array.close();
            //kdc_req.print_key_hex("req_body", req_body.value);
            if (req_body.is_valid()) {
                if (lookahead<kdc_req_body> body{req_body.value}) {
                    body.value.write_json(kdc_req_json);
                }
            }
            kdc_req_json.close();
        }

    };

    static void print_key_error_code(json_object &o, const char *key, size_t code) {
        const char * description[] = {
            "KDC_ERR_NONE",                          //  0
            "KDC_ERR_NAME_EXP",                      //  1
            "KDC_ERR_SERVICE_EXP",                   //  2
            "KDC_ERR_BAD_PVNO",                      //  3
            "KDC_ERR_C_OLD_MAST_KVNO",               //  4
            "KDC_ERR_S_OLD_MAST_KVNO",               //  5
            "KDC_ERR_C_PRINCIPAL_UNKNOWN",           //  6
            "KDC_ERR_S_PRINCIPAL_UNKNOWN",           //  7
            "KDC_ERR_PRINCIPAL_NOT_UNIQUE",          //  8
            "KDC_ERR_NULL_KEY",                      //  9
            "KDC_ERR_CANNOT_POSTDATE",               // 10
            "KDC_ERR_NEVER_VALID",                   // 11
            "KDC_ERR_POLICY",                        // 12
            "KDC_ERR_BADOPTION",                     // 13
            "KDC_ERR_ETYPE_NOSUPP",                  // 14
            "KDC_ERR_SUMTYPE_NOSUPP",                // 15
            "KDC_ERR_PADATA_TYPE_NOSUPP",            // 16
            "KDC_ERR_TRTYPE_NOSUPP",                 // 17
            "KDC_ERR_CLIENT_REVOKED",                // 18
            "KDC_ERR_SERVICE_REVOKED",               // 19
            "KDC_ERR_TGT_REVOKED",                   // 20
            "KDC_ERR_CLIENT_NOTYET",                 // 21
            "KDC_ERR_SERVICE_NOTYET",                // 22
            "KDC_ERR_KEY_EXPIRED",                   // 23
            "KDC_ERR_PREAUTH_FAILED",                // 24
            "KDC_ERR_PREAUTH_REQUIRED",              // 25
            "KDC_ERR_SERVER_NOMATCH",                // 26
            "KDC_ERR_MUST_USE_USER2USER",            // 27
            "KDC_ERR_PATH_NOT_ACCEPTED",             // 28
            "KDC_ERR_SVC_UNAVAILABLE",               // 29
            nullptr,                                 // 30
            "KRB_AP_ERR_BAD_INTEGRITY",              // 31
            "KRB_AP_ERR_TKT_EXPIRED",                // 32
            "KRB_AP_ERR_TKT_NYV",                    // 33
            "KRB_AP_ERR_REPEAT",                     // 34
            "KRB_AP_ERR_NOT_US",                     // 35
            "KRB_AP_ERR_BADMATCH",                   // 36
            "KRB_AP_ERR_SKEW",                       // 37
            "KRB_AP_ERR_BADADDR",                    // 38
            "KRB_AP_ERR_BADVERSION",                 // 39
            "KRB_AP_ERR_MSG_TYPE",                   // 40
            "KRB_AP_ERR_MODIFIED",                   // 41
            "KRB_AP_ERR_BADORDER",                   // 42
            nullptr,                                 // 43
            "KRB_AP_ERR_BADKEYVER",                  // 44
            "KRB_AP_ERR_NOKEY",                      // 45
            "KRB_AP_ERR_MUT_FAIL",                   // 46
            "KRB_AP_ERR_BADDIRECTION",               // 47
            "KRB_AP_ERR_METHOD",                     // 48
            "KRB_AP_ERR_BADSEQ",                     // 49
            "KRB_AP_ERR_INAPP_CKSUM",                // 50
            "KRB_AP_PATH_NOT_ACCEPTED",              // 51
            "KRB_ERR_RESPONSE_TOO_BIG",              // 52
            nullptr,                                 // 53
            nullptr,                                 // 54
            nullptr,                                 // 55
            nullptr,                                 // 56
            nullptr,                                 // 57
            nullptr,                                 // 58
            nullptr,                                 // 59
            "KRB_ERR_GENERIC",                       // 60
            "KRB_ERR_FIELD_TOOLONG",                 // 61
            "KDC_ERROR_CLIENT_NOT_TRUSTED",          // 62
            "KDC_ERROR_KDC_NOT_TRUSTED",             // 63
            "KDC_ERROR_INVALID_SIG",                 // 64
            "KDC_ERR_KEY_TOO_WEAK",                  // 65
            "KDC_ERR_CERTIFICATE_MISMATCH",          // 66
            "KRB_AP_ERR_NO_TGT",                     // 67
            "KDC_ERR_WRONG_REALM",                   // 68
            "KRB_AP_ERR_USER_TO_USER_REQUIRED",      // 69
            "KDC_ERR_CANT_VERIFY_CERTIFICATE",       // 70
            "KDC_ERR_INVALID_CERTIFICATE",           // 71
            "KDC_ERR_REVOKED_CERTIFICATE",           // 72
            "KDC_ERR_REVOCATION_STATUS_UNKNOWN",     // 73
            "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE", // 74
            "KDC_ERR_CLIENT_NAME_MISMATCH",          // 75
            "KDC_ERR_KDC_NAME_MISMATCH",             // 76
        };

        constexpr size_t num_entries = sizeof(description)/sizeof(description[0]);

        const char *descr = nullptr;
        if (code < num_entries) {
            descr = description[code];
        }
        if (descr) {
            o.print_key_string(key, descr);
        } else {
            o.print_key_unknown_code<uint64_t>(key, code);
        }
    }


    // KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
    //         pvno            [0] INTEGER (5),
    //         msg-type        [1] INTEGER (30),
    //         ctime           [2] KerberosTime OPTIONAL,
    //         cusec           [3] Microseconds OPTIONAL,
    //         stime           [4] KerberosTime,
    //         susec           [5] Microseconds,
    //         error-code      [6] Int32,
    //         crealm          [7] Realm OPTIONAL,
    //         cname           [8] PrincipalName OPTIONAL,
    //         realm           [9] Realm -- service realm --,
    //         sname           [10] PrincipalName -- service name --,
    //         e-text          [11] KerberosString OPTIONAL,
    //         e-data          [12] OCTET STRING OPTIONAL
    // }
    //
    class error {
        tlv seq;
        tlv pvno;
        tlv msg_type;
        tlv ctime;           // optional
        tlv cusec;           // optional
        tlv stime;
        tlv susec;
        tlv error_code;
        tlv crealm;          // optional
        tlv cname;           // optional
        tlv realm;
        tlv sname;
        tlv e_text;          // optional
        tlv e_data;          // optional
    public:

        error(datum &d) : seq{&d, tlv::SEQUENCE, "seq"} {
            //fprintf(stderr, "FUNCTION: %s\n", __func__);
            while (seq.value.is_not_empty()) {
                tlv tmp{&seq.value};
                switch(tmp.tag) {
                case tlv::explicit_tag_constructed(0):
                    pvno.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(1):
                    msg_type.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(2):
                    ctime.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(3):
                    cusec.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(4):
                    stime.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(5):
                    susec.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(6):
                    error_code.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(7):
                    crealm.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(8):
                    cname = tmp;
                    //cname.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(9):
                    realm.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(10):
                    sname = tmp;
                    // sname.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(11):
                    e_text.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(12):
                    e_data.parse(&tmp.value);
                    break;
                default:
                    ;
                }
            }
        }

        void write_json(json_object &o) const {
            json_object error_json{o, "error"};
            error_json.print_key_hex("pvno", pvno.value);
            error_json.print_key_hex("msg_type", msg_type.value);
            if (ctime) {
                ctime.print_as_json_generalized_time(error_json, "ctime");
            }
            error_json.print_key_hex("cusec", cusec.value);
            stime.print_as_json_generalized_time(error_json, "stime");
            error_json.print_key_hex("susec", susec.value);
            print_key_error_code(error_json, "error_code", to_uint64(error_code.value));
            if (crealm) {
                error_json.print_key_json_string("crealm", crealm.value);
            }
            if (cname) {
                principal_name{cname.value}.write_json(error_json, "cname");
            }
            error_json.print_key_json_string("realm", realm.value);
            principal_name{sname.value}.write_json(error_json, "sname");
            error_json.print_key_json_string("e_text", e_text.value);
            error_json.print_key_hex("e_data", e_data.value);
            error_json.close();
        }
    };


    // AS-REP          ::= [APPLICATION 11] KDC-REP
    //
    // TGS-REP         ::= [APPLICATION 13] KDC-REP
    //
    // KDC-REP         ::= SEQUENCE {
    //         pvno            [0] INTEGER (5),
    //         msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
    //         padata          [2] SEQUENCE OF PA-DATA OPTIONAL
    //                                 -- NOTE: not empty --,
    //         crealm          [3] Realm,
    //         cname           [4] PrincipalName,
    //         ticket          [5] Ticket,
    //         enc-part        [6] EncryptedData
    //                                 -- EncASRepPart or EncTGSRepPart,
    //                                 -- as appropriate
    // }
    //
    class kdc_rep {
        tlv seq;
        tlv pvno;
        tlv msg_type;
        tlv padata;
        tlv crealm;
        tlv cname;
        tlv tkt;
        tlv enc_part;
    public:
        kdc_rep(datum &d) : seq{&d, tlv::SEQUENCE, "seq"} {
            //fprintf(stderr, "FUNCTION: %s\n", __func__);
            while (seq.value.is_not_empty()) {
                tlv tmp{&seq.value};
                switch(tmp.tag) {
                case tlv::explicit_tag_constructed(0):
                    pvno.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(1):
                    msg_type.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(2):
                    padata.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(3):
                    crealm.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(4):
                    cname = tmp;
                    //cname.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(5):
                    tkt.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(6):
                    enc_part = tmp;
                    // enc_part.parse(&tmp.value);
                    break;
                }
            }
        }

        void write_json(json_object &o) const {
            json_object kdc_rep_json{o, "kdc_rep"};
            kdc_rep_json.print_key_hex("pnvo", pvno.value);
            kdc_rep_json.print_key_hex("msg_type", msg_type.value);

            json_array pa_array{kdc_rep_json, "pa_data"};
            datum tmp = padata.value;
            while (tmp.is_not_empty()) {
                pa_data data{tmp};
                data.write_json(pa_array);
            }
            pa_array.close();
            kdc_rep_json.print_key_json_string("crealm", crealm.value);
            principal_name{cname.value}.write_json(kdc_rep_json, "cname");
            ticket{tkt.value}.write_json(kdc_rep_json);
            if (enc_part) {
                encrypted_data{enc_part.value}.write_json(kdc_rep_json);
            }

            kdc_rep_json.close();
        }
    };

    class unknown_application {
        datum body;

    public:

        unknown_application(datum &d) : body{d} { }

        void write_json(json_object &o) const {
            datum tmp{body};
            tlv application{tmp, 0x00};
            json_object u{o, "unknown_application"};
            u.print_key_hex("body",body);
            u.print_key_uint("tag", application.tag);
            u.print_key_uint("length", application.length);
            u.print_key_hex("value", application.value);
            u.close();
        }
    };

    using message = std::variant<std::monostate, error, kdc_req, kdc_rep, unknown_application>;

    struct do_write_json {
        json_object &record;

        do_write_json(json_object &obj) : record{obj} { }

        void operator()(const std::monostate &) { }

        template <typename T>
        void operator()(T &t) { t.write_json(record); }
    };

    class packet : public base_protocol {
        datum body;
        tlv application;
        tlv app2;
        message msg;

    public:
        packet(datum &d) :
            body{d},
            application{&d, 0x00, "application"}
        {
            app2 = application;  // copy
            switch(application.tag) {
            case 0x6a:
                msg.emplace<kdc_req>(application.value);
                break;
            case 0x6b:
                msg.emplace<kdc_rep>(application.value);
                break;
            case 0x6c:
                msg.emplace<kdc_req>(application.value);
                break;
            case 0x6d:
                msg.emplace<kdc_rep>(application.value);
                break;
            case 0x7e:
                msg.emplace<error>(application.value);
                break;
            default:
                msg.emplace<unknown_application>(body);
            }
        }

        bool is_not_empty() const { return application.is_not_null(); }

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata;
            json_object krb_json{o, "kerberos"};
            // json_array raw_krb{krb_json, "raw"};
            // tlv tmp{app2};
            // tlv::recursive_parse(tmp.value, raw_krb);
            // raw_krb.close();
            std::visit(do_write_json{krb_json}, msg);
            krb_json.close();
        }

        void write_l7_metadata(cbor_object &o, bool) {
            cbor_array protocols{o, "protocols"};
            protocols.print_string("kerberos");
            protocols.close();
        }

        // weight 14 matcher, derived from example PCAPs
        //
        static constexpr mask_and_value<8> matcher{
            { 0xff,
              0xfc,
              0x00, 0x00,
              0x4e,
              0x00, 0x00, 0x00
            },
            { 0x68,         // APPLICATION tag
              0x80,         // length is over 128 bytes
              0x00, 0x00,
              0x00,         // SEQ or first octet of length
              0x00, 0x00, 0x00 }
        };

    };

} // namespace krb5

[[maybe_unused]] inline int krb5_fuzz_disabled_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<krb5::packet>(data, size);
}

#endif // KRB5_H
