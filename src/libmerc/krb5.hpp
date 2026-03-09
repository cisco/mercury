// krb5.h
//
// kerberos protocol

#ifndef KRB5_HPP
#define KRB5_HPP


#include <variant>
#include "datum.h"
#include "x509.h"
#include "json_object.h"
#include "match.h"
#include "protocol.h"

namespace krb5 {

#include "krb5_params.hpp"

#ifndef KRB5_JSON_FULL_CIPHERTEXT
#define KRB5_JSON_FULL_CIPHERTEXT 0
#endif

    static constexpr bool json_full_ciphertext = (KRB5_JSON_FULL_CIPHERTEXT != 0);

    [[maybe_unused]] inline const char *msg_type_get_string(uint64_t msg_type);
    [[maybe_unused]] inline const char *etype_get_string(int64_t etype);
    static inline void print_key_ciphertext(json_object &o, const datum &ciphertext);

    [[maybe_unused]] inline uint64_t to_uint64(const datum &d) {
        uint64_t result = 0;
        for (const uint8_t & x : d) {
            result = result * 256 + x;
        }
        return result;
    }

    [[maybe_unused]] inline uint64_t to_uint64(const tlv &x) {
        return to_uint64(x.value);
    }

    [[maybe_unused]] inline int64_t to_int64(const datum &d) {
        if (d.is_not_readable() || d.length() == 0 || d.length() > 8) {
            return 0;
        }

        uint64_t result = 0;
        for (const uint8_t &x : d) {
            result = (result << 8) | x;
        }

        const bool is_negative = (d.data[0] & 0x80) != 0;
        const size_t bits = static_cast<size_t>(d.length()) * 8;
        if (is_negative && bits < 64) {
            result |= (~uint64_t{0}) << bits;
        }

        return static_cast<int64_t>(result);
    }

    [[maybe_unused]] inline int64_t to_int64(const tlv &x) {
        return to_int64(x.value);
    }

    [[maybe_unused]] inline bool int_conversion_unit_test() {
        bool passed = true;

        // unsigned conversion from datum
        const uint8_t u16_bytes[] = { 0x01, 0x00 };
        datum u16_datum{u16_bytes, u16_bytes + sizeof(u16_bytes)};
        passed &= to_uint64(u16_datum) == 256;

        // unsigned conversion from tlv
        tlv u16_tlv;
        u16_tlv.set(tlv::INTEGER, u16_bytes, sizeof(u16_bytes));
        passed &= to_uint64(u16_tlv) == 256;

        // positive signed values
        const uint8_t p7_bytes[] = { 0x7f };
        datum p7_datum{p7_bytes, p7_bytes + sizeof(p7_bytes)};
        passed &= to_int64(p7_datum) == 127;

        // negative signed values (two's complement)
        const uint8_t n1_bytes[] = { 0xff };
        datum n1_datum{n1_bytes, n1_bytes + sizeof(n1_bytes)};
        passed &= to_int64(n1_datum) == -1;

        const uint8_t n256_bytes[] = { 0xff, 0x00 };
        datum n256_datum{n256_bytes, n256_bytes + sizeof(n256_bytes)};
        passed &= to_int64(n256_datum) == -256;

        // 64-bit boundary value
        const uint8_t int64_min_bytes[] = { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        datum int64_min_datum{int64_min_bytes, int64_min_bytes + sizeof(int64_min_bytes)};
        passed &= to_int64(int64_min_datum) == INT64_MIN;

        // signed conversion from tlv
        tlv n1_tlv;
        n1_tlv.set(tlv::INTEGER, n1_bytes, sizeof(n1_bytes));
        passed &= to_int64(n1_tlv) == -1;

        // invalid inputs should fail closed to zero
        datum empty{u16_bytes, u16_bytes};
        passed &= to_int64(empty) == 0;

        const uint8_t too_long_bytes[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        datum too_long{too_long_bytes, too_long_bytes + sizeof(too_long_bytes)};
        passed &= to_int64(too_long) == 0;

        // overflow-prone unsigned decode should remain deterministic
        passed &= to_uint64(too_long) == 0;

        return passed;
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
        kdc_options(const tlv &t) : bit_string{t} {}
        void parse(datum &p) {
            bit_string.parse(&p, tlv::BIT_STRING);
        }

        void print_as_json(struct json_object &o, const char *name) const {
            var_int<uint32_t> flags{bit_string.value, var_int<uint32_t>::asn1_bitstring};
            json_array_bitflags<uint32_t> f{o, name, flags.value()};
            f.flag<1>("forwardable");
            f.flag<2>("forwarded");
            f.flag<3>("proxiable");
            f.flag<4>("proxy");
            f.flag<5>("allow-postdate");
            f.flag<6>("postdated");
            f.flag<8>("renewable");
            f.flag<11>("opt-hardware-auth");
            f.flag<14>("constrained-delegation");
            f.flag<15>("canonicalize");
            f.flag<16>("request-anonymous");
            f.flag<26>("disable-transited-check");
            f.flag<27>("renewable-ok");
            f.flag<28>("enc-tkt-in-skey");
            f.flag<30>("renew");
            f.flag<31>("validate");
            f.check_for_unknown_flags<1,2,3,4,5,6,8,11,14,15,16,26,27,28,30,31>();
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

        principal_name(const tlv &pn) :
            sequence{pn},
            name_type{sequence.value, 0, "name_type"},
            name_sequence{sequence.value, 0, "name_sequence"}
        { }

        void write_json(json_object &o, const char *object_name) {
            json_object pn{o, object_name};
            tlv type_int{name_type.value, tlv::INTEGER, "type"};
            const int64_t name_type_value = to_int64(type_int.value);
            pn.print_key_string_or_unknown_code("type", name_type_get_string(name_type_value), name_type_value);
            json_array array{pn, "names"};
            tlv tmp_seq{name_sequence.value, tlv::SEQUENCE, "tmp_seq"};
            while (tmp_seq.value.is_not_empty()) {
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
        asn1::tlv_expected etype{tlv::INTEGER};       // [0]
        asn1::tlv_expected kvno{tlv::INTEGER};        // [1] OPTIONAL
        asn1::tlv_expected cipher{tlv::OCTET_STRING}; // [2]
        bool valid;

    public:

        encrypted_data(const tlv &ed) :
            seq{ed}
        {
            asn1::parse_explicitly_tagged_positional(seq.value, etype, kvno, cipher);
            valid = (bool)etype and (bool)cipher; // kvno is optional
        }

        void write_json(json_object &o, const char *name, bool metadata=false) const {
            (void)metadata;
            if (!valid) {
                return;
            }
            json_object enc_data{o, name};
            enc_data.print_key_string_or_unknown_code("etype",
                                                      etype_get_string(to_int64(etype.value)),
                                                      to_int64(etype.value));
            if (kvno) {
                enc_data.print_key_uint("kvno", to_uint64(kvno.value));
            }
            print_key_ciphertext(enc_data, cipher.value);
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
        bool valid;

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
                    sname.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(3):
                    enc_part.parse(&tmp.value);
                    break;
                default:
                    ;
                }
            }
            valid = tkt_vno.is_not_null()
                 && realm.is_not_null()
                 && sname.is_not_null()
                 && enc_part.is_not_null();
        }

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata;
            if (!valid) {
                return;
            }
            json_object tkt{o, "ticket"};
            tkt.print_key_uint("vno", static_cast<unsigned long int>(to_uint64(tkt_vno.value)));
            if (realm) {
                tkt.print_key_json_string("realm", realm.value);
            }
            if (sname) {
                principal_name{sname}.write_json(tkt, "sname");
            }
            if (enc_part) {
                encrypted_data{enc_part}.write_json(tkt, "enc_data", metadata);
            }
            tkt.close();
        }

    };


    enum krb5_host_address_type : uint64_t {
        KRB5_ADDR_IPV4             = 2,
        KRB5_ADDR_DIRECTIONAL      = 3,
        KRB5_ADDR_CHAOSNET         = 5,
        KRB5_ADDR_XNS              = 6,
        KRB5_ADDR_ISO              = 7,
        KRB5_ADDR_DECNET_PHASE_IV  = 12,
        KRB5_ADDR_APPLETALK_DDP    = 16,
        KRB5_ADDR_NETBIOS          = 20,
        KRB5_ADDR_IPV6             = 24,
    };

    // HostAddress      ::= SEQUENCE  {
    //         addr-type       [0] Int32,
    //         address         [1] OCTET STRING
    // }
    //
    // HostAddresses    ::= SEQUENCE OF HostAddress
    //
    class host_address {
        tlv seq;
        tlv addr_type;
        tlv addr_value;
        bool valid;

        static const char *addr_type_name(uint64_t t) {
            switch (t) {
            case KRB5_ADDR_IPV4:            return "ipv4";
            case KRB5_ADDR_DIRECTIONAL:     return "directional";
            case KRB5_ADDR_CHAOSNET:        return "chaosnet";
            case KRB5_ADDR_XNS:             return "xns";
            case KRB5_ADDR_ISO:             return "iso";
            case KRB5_ADDR_DECNET_PHASE_IV: return "decnet_phase_iv";
            case KRB5_ADDR_APPLETALK_DDP:   return "appletalk_ddp";
            case KRB5_ADDR_NETBIOS:         return "netbios";
            case KRB5_ADDR_IPV6:            return "ipv6";
            default: return nullptr;
            }
        }

    public:
        host_address(datum &d) :
            seq{&d, tlv::SEQUENCE, "host_address.seq"},
            valid{false}
        {
            while (seq.value.is_not_empty()) {
                tlv tmp{&seq.value};
                switch (tmp.tag) {
                case tlv::explicit_tag_constructed(0):
                    addr_type.parse(&tmp.value, tlv::INTEGER, "host_address.addr_type");
                    break;
                case tlv::explicit_tag_constructed(1):
                    addr_value.parse(&tmp.value, tlv::OCTET_STRING, "host_address.address");
                    break;
                default:
                    break;
                }
            }
            valid = addr_type.is_not_null() && addr_value.is_not_null();
        }

        void write_json(json_array &a) const {
            if (!valid) {
                return;
            }

            json_object h{a};
            const uint64_t t = to_uint64(addr_type.value);
            h.print_key_uint("type", static_cast<unsigned long int>(t));

            const char *name = addr_type_name(t);
            if (name) {
                h.print_key_string("type_name", name);
            }

            if (t == KRB5_ADDR_IPV4 && addr_value.value.length() == 4) {
                h.print_key_ipv4_addr("address", addr_value.value.data);
            } else if (t == KRB5_ADDR_IPV6 && addr_value.value.length() == 16) {
                h.print_key_ipv6_addr("address", addr_value.value.data);
            } else if (t == KRB5_ADDR_NETBIOS) {
                h.print_key_json_string("address", addr_value.value);
            } else {
                h.print_key_hex("address", addr_value.value);
            }
            h.close();
        }
    };

    class host_addresses {
        tlv seq;
        bool valid;

    public:
        host_addresses(const tlv &t) :
            seq{t},
            valid{seq.is_not_null()}
        { }

        host_addresses(datum d) :
            seq{d, tlv::SEQUENCE, "host_addresses.seq"},
            valid{seq.is_not_null()}
        { }

        void write_json(json_object &o, const char *name) const {
            if (!valid) {
                return;
            }

            json_array arr{o, name};
            datum tmp = seq.value;
            while (tmp.is_not_empty()) {
                host_address h{tmp};
                h.write_json(arr);
            }
            arr.close();
        }
    };

    // APOptions       ::= KerberosFlags
    // -- reserved(0),
    // -- use-session-key(1),
    // -- mutual-required(2)
    //
    class ap_options {
        struct tlv bit_string;

    public:

        ap_options() : bit_string{} {}
        ap_options(datum p) : bit_string{} {
            parse(p);
        }
        void parse(datum &p) {
            bit_string.parse(&p, tlv::BIT_STRING);
        }

        void print_as_json(struct json_object &o, const char *name) const {
            var_int<uint32_t> flags{bit_string.value, var_int<uint32_t>::asn1_bitstring};
            json_array_bitflags f{o, name, flags};
            f.flag<0>("reserved");
            f.flag<1>("use_session_key");
            f.flag<2>("mutual_required");
            f.check_for_unknown_flags<0,1,2>();
            f.close();
        }
    };

    //     AP-REQ          ::= [APPLICATION 14] SEQUENCE {
    //         pvno            [0] INTEGER (5),
    //         msg-type        [1] INTEGER (14),
    //         ap-options      [2] APOptions,
    //         ticket          [3] Ticket,
    //         authenticator   [4] EncryptedData -- Authenticator
    // }
    //
    class ap_req {
        tlv seq;
        tlv pvno;
        tlv msg_type;
        tlv ap_opt;
        tlv tkt;
        tlv auth;
        bool valid;
    public:

        ap_req(datum &d) :
            seq{d, tlv::SEQUENCE, "ap_req.sequence"},
            valid{false}
        {
            datum body{seq.value};
            while (body.is_readable()) {
                tlv tmp{body};
                switch(tmp.tag) {
                case tlv::explicit_tag_constructed(0):
                    pvno.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(1):
                    msg_type.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(2):
                    ap_opt.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(3):
                    tkt.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(4):
                    auth.parse(&tmp.value);
                    break;
                default:
                    ;
                }
            }
            valid = pvno.is_not_null()
                 && msg_type.is_not_null()
                 && ap_opt.is_not_null()
                 && tkt.is_not_null()
                 && auth.is_not_null();
        }

        bool is_valid() const { return valid; }

        void write_json(json_object &o) const {
            if (!valid) {
                return;
            }
            json_object ap_req_json{o, "ap_req"};
            ap_req_json.print_key_uint("pvno", static_cast<unsigned long int>(to_uint64(pvno.value)));
            ap_req_json.print_key_string_or_unknown_code("msg_type",
                                                         msg_type_get_string(to_uint64(msg_type.value)),
                                                         to_uint64(msg_type.value));
            ap_options{ap_opt.value}.print_as_json(ap_req_json, "ap_options");
            ticket{tkt.value}.write_json(ap_req_json);
            encrypted_data{auth}.write_json(ap_req_json, "authenticator");
            ap_req_json.close();
        }

    };

    //     AP-REP          ::= [APPLICATION 15] SEQUENCE {
    //         pvno            [0] INTEGER (5),
    //         msg-type        [1] INTEGER (15),
    //         enc-part        [2] EncryptedData -- EncAPRepPart
    // }
    //
    class ap_rep {
        tlv seq;
        tlv pvno;
        tlv msg_type;
        tlv enc_part;
        bool valid;

    public:
        ap_rep(datum &d) :
            seq{d, tlv::SEQUENCE, "ap_rep.sequence"},
            valid{false}
        {
            datum body{seq.value};
            while (body.is_not_empty()) {
                tlv tmp{&body};
                switch (tmp.tag) {
                case tlv::explicit_tag_constructed(0):
                    pvno.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(1):
                    msg_type.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(2):
                    enc_part.parse(&tmp.value);
                    break;
                default:
                    break;
                }
            }
            valid = pvno.is_not_null() && msg_type.is_not_null() && enc_part.is_not_null();
        }

        bool is_valid() const { return valid; }

        void write_json(json_object &o, const char *name="ap_rep") const {
            if (!valid) {
                return;
            }
            json_object ap_rep_json{o, name};
            ap_rep_json.print_key_uint("pvno", static_cast<unsigned long int>(to_uint64(pvno.value)));
            ap_rep_json.print_key_string_or_unknown_code("msg_type",
                                                         msg_type_get_string(to_uint64(msg_type.value)),
                                                         to_uint64(msg_type.value));
            encrypted_data{enc_part}.write_json(ap_rep_json, "enc_data");
            ap_rep_json.close();
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
        bool valid;

    public:

        kdc_req_body(datum &d) {
            while (d.is_not_empty()) {
                tlv tmp{&d};
                switch(tmp.tag) {
                case tlv::explicit_tag_constructed(0):
                    kdc_opt.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(1):
                    cname.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(2):
                    realm.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(3):
                    sname.parse(&tmp.value);
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
            valid = kdc_opt.is_not_null()
                 && realm.is_not_null()
                 && till.is_not_null()
                 && nonce.is_not_null()
                 && etype.is_not_null();
        }

        void write_json(json_object &record) const {
            if (!valid) {
                return;
            }
            json_object o{record, "body"};
            kdc_options{kdc_opt}.print_as_json(o, "kdc_options");
            if (cname) {
                principal_name{cname}.write_json(o, "cname");
            }
            o.print_key_json_string("realm", realm.value);
            if (sname) {
                principal_name{sname}.write_json(o, "sname");
            }
            if (from) {
                from.print_as_json_generalized_time(o, "from");
            }
            till.print_as_json_generalized_time(o, "till");
            if (rtime) {
                rtime.print_as_json_generalized_time(o, "rtime");
            }
            o.print_key_uint("nonce", static_cast<unsigned long int>(to_uint64(nonce.value)));
            json_array etype_array{o, "etype"};
            datum tmp = etype.value;
            while (tmp.is_not_empty()) {
                tlv e{tmp};
                const int64_t etype_code = to_int64(e.value);
                etype_array.print_string_or_unknown_code(etype_get_string(etype_code), etype_code);
            }
            etype_array.close();

            if (address) {
                host_addresses{address}.write_json(o, "addresses");
            }
            if (enc_authorization_data) {
                encrypted_data enc_auth_data{enc_authorization_data};
                enc_auth_data.write_json(o, "enc_authorization_data");
            }
            if (additional_tickets) {
                o.print_key_hex("additional_tickets", additional_tickets.value);
            }
            o.close();
        }

    };

    enum krb5_application_tag : uint8_t {
        KRB5_APP_AS_REQ    = 0x6a,
        KRB5_APP_AS_REP    = 0x6b,
        KRB5_APP_TGS_REQ   = 0x6c,
        KRB5_APP_TGS_REP   = 0x6d,
        KRB5_APP_AP_REQ    = 0x6e,
        KRB5_APP_AP_REP    = 0x6f,
        KRB5_APP_KRB_ERROR = 0x7e,
    };

    // PA-DATA         ::= SEQUENCE {
    //     -- NOTE: first tag is [1], not [0]
    //     padata-type     [1] Int32,
    //     padata-value    [2] OCTET STRING -- might be encoded AP-REQ
    // }
    //
    // ETYPE-INFO2-ENTRY ::= SEQUENCE {
    //     etype      [0] Int32,
    //     salt       [1] KerberosString OPTIONAL,
    //     s2kparams  [2] OCTET STRING OPTIONAL
    // }
    class etype_info2_entry {
        tlv sequence;
        tlv etype;
        tlv salt;
        tlv s2kparams;
        bool valid;

    public:
        etype_info2_entry(datum &d) :
            sequence{&d, tlv::SEQUENCE, "etype_info2_entry.sequence"},
            etype{},
            salt{},
            s2kparams{},
            valid{d.is_not_null()}
        {
            datum tmp = sequence.value;
            while (tmp.is_not_empty()) {
                tlv field{&tmp};
                switch (field.tag) {
                case tlv::explicit_tag_constructed(0):
                    etype.parse(&field.value, tlv::INTEGER, "etype_info2_entry.etype");
                    break;
                case tlv::explicit_tag_constructed(1):
                    salt.parse(&field.value, 0x00, "etype_info2_entry.salt");
                    break;
                case tlv::explicit_tag_constructed(2):
                    s2kparams.parse(&field.value, tlv::OCTET_STRING, "etype_info2_entry.s2kparams");
                    break;
                default:
                    break;
                }
            }
            valid = sequence.is_not_null() && etype.is_not_null();
        }

        void write_json(json_object &o) const {
            if (!valid || !etype) {
                return;
            }

            o.print_key_string_or_unknown_code("etype",
                                               etype_get_string(to_int64(etype.value)),
                                               to_int64(etype.value));
            if (salt) {
                o.print_key_json_string("salt", salt.value);
            }
            if (s2kparams) {
                o.print_key_hex("s2kparams", s2kparams.value);
            }
        }
    };

    class pa_data {
        tlv seq;
        tlv type;
        tlv pa_data_value;
        bool valid;

    public:
        pa_data(datum &d) :
            seq{&d, tlv::SEQUENCE, "seq"},
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

            datum tmp = type.value;
            const uint64_t pa_type_code = to_uint64(tlv{tmp});
            pa_data_type<uint32_t> pa_type{pa_type_code};
            const char *pa_type_name = pa_type.get_name();
            pad.print_key_string_or_unknown_code("pa_data_type", pa_type_name, pa_type_code);

            datum octets_data = pa_data_value.value;
            tlv octets{octets_data, tlv::OCTET_STRING, "pa_data_value.octets"};
            if (octets.is_valid()) {
                bool handled = false;
                if (pa_type_code == pa_data_type<uint32_t>::PA_TGS_REQ) {
                    datum app_data = octets.value;
                    tlv app_req_tlv{app_data, KRB5_APP_AP_REQ, "pa_tgs_req.ap_req"};
                    if (app_req_tlv.is_valid()) {
                        ap_req req{app_req_tlv.value};
                        if (req.is_valid()) {
                            json_object value{pad, pa_type_name};
                            req.write_json(value);
                            value.close();
                            handled = true;
                        }
                    }
                } else if (pa_type_code == pa_data_type<uint32_t>::PA_ETYPE_INFO2) {
                    datum seq_data = octets.value;
                    tlv seq{seq_data, tlv::SEQUENCE, "pa_etype_info2.sequence"};
                    if (seq.is_valid()) {
                        json_array value{pad, pa_type_name};
                        datum entries = seq.value;
                        while (entries.is_not_empty()) {
                            etype_info2_entry entry{entries};
                            json_object entry_json{value};
                            entry.write_json(entry_json);
                            entry_json.close();
                        }
                        value.close();
                        handled = true;
                    }
                } else if (pa_type_code == pa_data_type<uint32_t>::PA_ENC_TIMESTAMP) {
                    datum enc_data = octets.value;
                    tlv enc_tlv{enc_data, tlv::SEQUENCE, "pa_enc_timestamp.encrypted_data"};
                    if (enc_tlv.is_valid()) {
                        encrypted_data enc{enc_tlv};
                        json_object value{pad, pa_type_name};
                        enc.write_json(value, "enc_timestamp");
                        value.close();
                        handled = true;
                    }
                }

                if (!handled) {
                    pad.print_key_hex("value_hex", octets.value);
                }
            }
            pad.close();
        }

    };

    class pa_data_sequence {
        datum content;
        bool valid;

    public:
        pa_data_sequence(datum d) :
            content{nullptr, nullptr},
            valid{false}
        {
            content = d;
            valid = d.is_not_null();
        }

        bool is_valid() const { return valid; }

        void write_json(json_object &o, const char *name) const {
            if (!valid) {
                return;
            }
            json_array pa_array{o, name};
            datum tmp = content;
            while (tmp.is_not_empty()) {
                pa_data data{tmp};
                data.write_json(pa_array);
            }
            pa_array.close();
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
        tlv seq;
        tlv pvno;
        tlv msg_type;
        tlv padata;    // optional
        tlv req_body;
        bool valid;

    public:

        kdc_req(datum &d) :
            seq{&d, tlv::SEQUENCE, "seq"},
            valid{false}
        {
            while (seq.value.is_not_empty()) {
                tlv tmp{&seq.value};
                switch(tmp.tag) {
                case tlv::explicit_tag_constructed(1):
                    pvno.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(2):
                    msg_type.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(3):  // optional
                    padata.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(4):
                    req_body.parse(&tmp.value, tlv::SEQUENCE, "body");
                    break;
                default:
                    break;
                }
            }
            valid = seq.is_not_null() && pvno.is_not_null() && msg_type.is_not_null() && req_body.is_not_null();
        }

        bool is_valid() const {
            return valid;
        }

        uint64_t get_msg_type() const {
            return to_uint64(msg_type.value);
        }

        void write_json(json_object &o, const char *name) const {
            if (!valid) {
                return;
            }
            json_object req_json{o, name};
            req_json.print_key_uint("pvno", static_cast<unsigned long int>(to_uint64(pvno.value)));
            req_json.print_key_string_or_unknown_code("msg_type",
                                                      msg_type_get_string(to_uint64(msg_type.value)),
                                                      to_uint64(msg_type.value));
            pa_data_sequence{padata.value}.write_json(req_json, "pa_data");
            if (req_body.is_valid()) {
                if (lookahead<kdc_req_body> body{req_body.value}) {
                    body.value.write_json(req_json);
                }
            }
            req_json.close();
        }

        void write_json(json_object &o) const {
            write_json(o, "kdc_req");
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
        o.print_key_string_or_unknown_code(key, descr, static_cast<uint64_t>(code));
    }

    enum krb5_message_type : uint64_t {
        KRB5_MSG_AS_REQ         = 10,
        KRB5_MSG_AS_REP         = 11,
        KRB5_MSG_TGS_REQ        = 12,
        KRB5_MSG_TGS_REP        = 13,
        KRB5_MSG_AP_REQ         = 14,
        KRB5_MSG_AP_REP         = 15,
        KRB5_MSG_KRB_RESERVED16 = 16,
        KRB5_MSG_KRB_RESERVED17 = 17,
        KRB5_MSG_KRB_SAFE       = 20,
        KRB5_MSG_KRB_PRIV       = 21,
        KRB5_MSG_KRB_CRED       = 22,
        KRB5_MSG_KRB_ERROR      = 30,
    };

    [[maybe_unused]] inline const char *msg_type_get_string(uint64_t msg_type) {
        switch (msg_type) {
        case KRB5_MSG_AS_REQ:         return "AS_REQ";
        case KRB5_MSG_AS_REP:         return "AS_REP";
        case KRB5_MSG_TGS_REQ:        return "TGS_REQ";
        case KRB5_MSG_TGS_REP:        return "TGS_REP";
        case KRB5_MSG_AP_REQ:         return "AP_REQ";
        case KRB5_MSG_AP_REP:         return "AP_REP";
        case KRB5_MSG_KRB_RESERVED16: return "KRB_RESERVED16";
        case KRB5_MSG_KRB_RESERVED17: return "KRB_RESERVED17";
        case KRB5_MSG_KRB_SAFE:       return "KRB_SAFE";
        case KRB5_MSG_KRB_PRIV:       return "KRB_PRIV";
        case KRB5_MSG_KRB_CRED:       return "KRB_CRED";
        case KRB5_MSG_KRB_ERROR:      return "KRB_ERROR";
        default:
            break;
        }
        return nullptr;
    }

    [[maybe_unused]] inline const char *etype_get_string(int64_t etype) {
        switch (etype) {
        // IANA-assigned / RFC-defined etypes not currently in krb5_params.hpp.
        case 4:    return "des_cbc_raw";
        case 6:    return "des3_cbc_raw";
        case 8:    return "des_hmac_sha1";
        // Microsoft private-use etypes (from SSPI/KILE headers and docs).
        case -128: return "rc4_md4";
        case -129: return "rc4_plain2";
        case -130: return "rc4_lm";
        case -131: return "rc4_sha";
        case -132: return "des_plain";
        case -133: return "rc4_hmac_old";
        case -134: return "rc4_plain_old";
        case -135: return "rc4_hmac_old_exp";
        case -136: return "rc4_plain_old_exp";
        case -140: return "rc4_plain";
        case -141: return "rc4_plain_exp";
        default:
            break;
        }
        if (etype < 0 || etype > INT64_C(0xffffffff)) {
            return nullptr;
        }
        return encryption_type<uint32_t>{static_cast<uint32_t>(etype)}.get_name();
    }

    static inline void print_key_ciphertext(json_object &o, const datum &ciphertext) {
        if constexpr (json_full_ciphertext) {
            o.print_key_hex("ciphertext", ciphertext);
        } else {
            o.print_key_uint("ciphertext_length", static_cast<unsigned long int>(ciphertext.length()));
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
        bool valid;

        void write_e_data_json(json_object &o) const {
            if (!e_data) {
                return;
            }

            datum e_data_octets;
            if (e_data.tag == tlv::OCTET_STRING) {
                e_data_octets = e_data.value;
            } else {
                // Handle explicit [12] wrapper that contains an OCTET STRING.
                datum wrapped = e_data.value;
                tlv octets{wrapped, tlv::OCTET_STRING, "krb_error.e_data.octets"};
                if (octets.is_valid()) {
                    e_data_octets = octets.value;
                }
            }

            if (e_data_octets.is_not_null()) {
                tlv method_data{e_data_octets, tlv::SEQUENCE, "krb_error.e_data.method_data"};
                if (method_data.is_valid()) {
                    pa_data_sequence seq{method_data.value};
                    if (seq.is_valid()) {
                        seq.write_json(o, "e_data");
                        return;
                    }
                }
            }
            o.print_key_hex("e_data_hex", e_data.value);
        }
    public:

        error(datum &d) : seq{&d, tlv::SEQUENCE, "seq"} {
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
            valid = pvno.is_not_null()
                 && msg_type.is_not_null()
                 && stime.is_not_null()
                 && susec.is_not_null()
                 && error_code.is_not_null()
                 && realm.is_not_null()
                 && sname.is_not_null();
        }

        bool is_valid() const { return valid; }

        void write_json(json_object &o) const {
            if (!valid) {
                return;
            }
            json_object error_json{o, "error"};
            error_json.print_key_uint("pvno", static_cast<unsigned long int>(to_uint64(pvno.value)));
            error_json.print_key_string_or_unknown_code("msg_type",
                                                        msg_type_get_string(to_uint64(msg_type.value)),
                                                        to_uint64(msg_type.value));
            if (ctime) {
                ctime.print_as_json_generalized_time(error_json, "ctime");
            }
            if (cusec) {
                error_json.print_key_uint("cusec", static_cast<unsigned long int>(to_uint64(cusec.value)));
            }
            stime.print_as_json_generalized_time(error_json, "stime");
            error_json.print_key_uint("susec", static_cast<unsigned long int>(to_uint64(susec.value)));
            const int64_t error_code_value = to_int64(error_code.value);
            if (error_code_value >= 0) {
                print_key_error_code(error_json, "error_code", static_cast<size_t>(error_code_value));
            } else {
                error_json.print_key_int("error_code", static_cast<long int>(error_code_value));
            }
            if (crealm) {
                error_json.print_key_json_string("crealm", crealm.value);
            }
            if (cname) {
                principal_name{cname}.write_json(error_json, "cname");
            }
            error_json.print_key_json_string("realm", realm.value);
            principal_name{sname}.write_json(error_json, "sname");
            error_json.print_key_json_string("e_text", e_text.value);
            write_e_data_json(error_json);
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
        bool valid;
    public:
        kdc_rep(datum &d) : seq{&d, tlv::SEQUENCE, "seq"} {
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
                    cname.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(5):
                    tkt.parse(&tmp.value);
                    break;
                case tlv::explicit_tag_constructed(6):
                    enc_part.parse(&tmp.value);
                    break;
                }
            }
            valid = pvno.is_not_null()
                 && msg_type.is_not_null()
                 && crealm.is_not_null()
                 && cname.is_not_null()
                 && tkt.is_not_null()
                 && enc_part.is_not_null();
        }

        bool is_valid() const {
            return valid;
        }

        uint64_t get_msg_type() const {
            return to_uint64(msg_type.value);
        }

        void write_json(json_object &o, const char *name) const {
            if (!valid) {
                return;
            }
            json_object rep_json{o, name};
            rep_json.print_key_uint("pvno", static_cast<unsigned long int>(to_uint64(pvno.value)));
            rep_json.print_key_string_or_unknown_code("msg_type",
                                                      msg_type_get_string(to_uint64(msg_type.value)),
                                                      to_uint64(msg_type.value));
            pa_data_sequence{padata.value}.write_json(rep_json, "pa_data");
            rep_json.print_key_json_string("crealm", crealm.value);
            principal_name{cname}.write_json(rep_json, "cname");
            ticket{tkt.value}.write_json(rep_json);
            encrypted_data{enc_part}.write_json(rep_json, "enc_data");

            rep_json.close();
        }

        void write_json(json_object &o) const {
            write_json(o, "kdc_rep");
        }
    };

    class tgs_req {
        kdc_req req;
        bool valid;

    public:
        tgs_req(datum &d) :
            req{d},
            valid{req.is_valid() && req.get_msg_type() == KRB5_MSG_TGS_REQ}
        { }

        bool is_valid() const { return valid; }

        void write_json(json_object &o) const {
            if (!valid) {
                return;
            }
            req.write_json(o, "tgs_req");
        }
    };

    class tgs_rep {
        kdc_rep rep;
        bool valid;

    public:
        tgs_rep(datum &d) :
            rep{d},
            valid{rep.is_valid() && rep.get_msg_type() == KRB5_MSG_TGS_REP}
        { }

        bool is_valid() const { return valid; }

        void write_json(json_object &o) const {
            if (!valid) {
                return;
            }
            rep.write_json(o, "tgs_rep");
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
            u.print_key_uint_hex("tag", application.tag);
            u.print_key_uint("length", application.length);
            u.print_key_hex("value", application.value);
            u.close();
        }
    };

    using message = std::variant<std::monostate, error, kdc_req, kdc_rep, tgs_req, tgs_rep>;

    struct do_write_json {
        json_object &record;

        do_write_json(json_object &obj) : record{obj} { }

        void operator()(const std::monostate &) { }

        template <typename T>
        void operator()(T &t) { t.write_json(record); }
    };

    struct do_is_valid {

        bool operator()(const std::monostate &) { return false; }

        template <typename T>
        bool operator()(T &t) { return t.is_valid(); }
    };

    /// \brief parses a four byte element as a kerberos TCP
    /// record_marker if it represents a uint32_t in network byte
    /// order that is less than 0xffffff, and trims \p d to that
    /// length; otherwise, it leaves \p d unchanged.
    ///
    class optional_record_marker {
    public:

        optional_record_marker(datum &d) {
            if (lookahead<encoded<uint32_t>> marker{d}) {
                if (marker.value.value() < 0xffffff) {
                    d = marker.advance();
                    d.trim_to_length(marker.value.value());
                }
            }
        }
    };

    class packet : public base_protocol {
        optional_record_marker marker;
        tlv application;
        message msg;

    public:
        packet(datum &d) :
            marker{d},
            application{&d, 0x00, "application"}
        {
            switch(application.tag) {
            case KRB5_APP_AS_REQ:
                msg.emplace<kdc_req>(application.value);
                break;
            case KRB5_APP_AS_REP:
                msg.emplace<kdc_rep>(application.value);
                break;
            case KRB5_APP_TGS_REQ:
                msg.emplace<tgs_req>(application.value);
                break;
            case KRB5_APP_TGS_REP:
                msg.emplace<tgs_rep>(application.value);
                break;
            case KRB5_APP_KRB_ERROR:
                msg.emplace<error>(application.value);
                break;
            default:
                ;
            }
        }

        bool is_not_empty() const {
            return std::visit(do_is_valid{}, msg);
        }

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata;
            json_object krb_json{o, "kerberos"};
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
