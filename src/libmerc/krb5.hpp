// krb5.h
//
// kerberos protocol

#ifndef KRB5_HPP
#define KRB5_HPP

#define ASN1_DEBUG 1
// #define TLV_ERR_INFO 1

#include <variant>
#include "datum.h"
#include "x509.h"
#include "json_object.h"
#include "match.h"
#include "protocol.h"

namespace krb5 {

#include "krb5_params.hpp"

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
                // case NT_UNKNOWN:        return "UNKNOWN";
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
        tlv kdc_options;
        tlv cname;
        tlv realm;
        tlv sname;
        tlv from;
        tlv till;
        tlv rtime;
        tlv nonce;
        tlv etype;
        tlv address;
        tlv enc_authorization_data;
        tlv additional_tickets;

    public:

        kdc_req_body(datum &d) {
            //tlv seq{&d, tlv::SEQUENCE, "kdc_req_body.sequence"};
            while (d.is_not_empty()) {
                tlv tmp{&d};
                //fprintf(stderr, "kdc_req_body.tag: %x\n", tmp.tag);
                switch(tmp.tag) {
                case tlv::explicit_tag_constructed(0):
                    kdc_options.parse(&tmp.value);
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
            json_object_asn1 o{record, "body"};
            o.print_key_hex("kdc_options", kdc_options.value);
            principal_name{cname.value}.write_json(o, "cname");
            // o.print_key_hex("cname", cname.value);
            o.print_key_json_string("realm", realm.value);
            // o.print_key_hex("sname_string", sname.value);
            // json_array_asn1 sname_array{o, "sname_array"};
            // datum tmp{sname.value};
            // tlv::recursive_parse(tmp, sname_array);
            // sname_array.close();
            principal_name{sname.value}.write_json(o, "sname");
            o.print_key_hex("from", from.value);
            // o.print_key_hex("till", till.value);
            till.print_as_json_generalized_time(o, "till");
            o.print_key_hex("rtime", rtime.value);
            o.print_key_hex("nonce", nonce.value);
            // o.print_key_hex("etype", etype.value);

            json_array etype_array{o, "etype"};
            datum tmp = etype.value;
            while (tmp.is_not_empty()) {
                tlv e{tmp};
                etype_array.print_string(encryption_type<uint32_t>{to_uint64(e.value)}.get_name());
            }
            etype_array.close();

            o.print_key_hex("address", address.value);
            o.print_key_hex("enc_authorization_data", enc_authorization_data.value);
            o.print_key_hex("additional_tickets", additional_tickets.value);
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

        void write_json(json_object_asn1 &o) const {
            if (!valid) { return; }
            json_object_asn1 pad{o, "pa_data"};
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

        void write_json(json_object_asn1 &o) const {
            //            if (!valid) { return; }
            json_object_asn1 kdc_req_json{o, "kdc_req"};
            kdc_req_json.print_key_hex("pvno", pvno.value);
            kdc_req_json.print_key_hex("msg_type", msg_type.value);
            // kdc_req_json.print_key_hex("padata", padata.value);
            // if (lookahead<pa_data> pad{padata.value}) {
            datum tmp = padata.value;
            while (tmp.is_not_empty()) {
                pa_data data{tmp};
                data.write_json(kdc_req_json);
            }
            //kdc_req.print_key_hex("req_body", req_body.value);
            if (req_body.is_valid()) {
                if (lookahead<kdc_req_body> body{req_body.value}) {
                    body.value.write_json(kdc_req_json);
                }
            }
            kdc_req_json.close();
        }

    };

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
        tlv ctime;
        tlv cusec;
        tlv stime;
        tlv susec;
        tlv error_code;
        tlv crealm;
        tlv cname;
        tlv realm;
        tlv sname;
        tlv e_text;
        tlv e_data;
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
                    cname.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(9):
                    realm.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(10):
                    sname.parse(&tmp.value);
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
            o.print_key_hex("pvno", pvno.value);
            o.print_key_hex("msg_type", msg_type.value);
            o.print_key_hex("ctime", ctime.value);
            o.print_key_hex("cusec", cusec.value);
            o.print_key_hex("stime", stime.value);
            o.print_key_hex("susec", susec.value);
            o.print_key_hex("error_code", error_code.value);
            o.print_key_hex("crealm", crealm.value);
            o.print_key_hex("cname", cname.value);
            o.print_key_hex("realm", realm.value);
            o.print_key_hex("sname", sname.value);
            o.print_key_hex("e_text", e_text.value);
            o.print_key_hex("e_data", e_data.value);
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
        tlv ticket;
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
                    ticket.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(6):
                    enc_part.parse(&tmp.value);
                    break;
                }
            }
        }

        void write_json(json_object &o) const {
            o.print_key_hex("pnvo", pvno.value);
            o.print_key_hex("msg_type", msg_type.value);
            o.print_key_hex("padata", padata.value);
            o.print_key_json_string("crealm", crealm.value);
            principal_name{cname.value}.write_json(o, "cname");
            o.print_key_hex("cname", cname.value);
            o.print_key_hex("ticket", ticket.value);
            o.print_key_hex("enc_part", enc_part.value);
        }
    };

    using message = std::variant<std::monostate, error, kdc_req, kdc_rep>;

    struct do_write_json {
        json_object_asn1 &record;

        do_write_json(json_object_asn1 &obj) : record{obj} { }

        void operator()(const std::monostate &) { }

        template <typename T>
        void operator()(T &t) { t.write_json(record); }
    };

    class packet : public base_protocol {
        tlv application;
        tlv app2;
        message msg;

    public:
        packet(datum &d) : application{&d, 0x00, "application"} {
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
                fprintf(stderr, "UNKNOWN APPLICATION (%x)\n", application.tag);
                ;
            }
        }

        bool is_not_empty() const { return application.is_not_null(); }

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata;
            json_object_asn1 krb_json{o, "kerberos"};
            // json_array_asn1 raw_krb{krb_json, "raw"};
            // tlv tmp{app2};
            // tlv::recursive_parse(tmp.value, raw_krb);
            // raw_krb.close();
            std::visit(do_write_json{krb_json}, msg);
            krb_json.close();
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

