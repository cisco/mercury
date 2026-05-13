// cbor_messages.hpp
//
// Non-owning feature classes for the CBOR metadata interface.
// Each class is used for both encoding (libmerc) and decoding (inspector).

#ifndef CBOR_MESSAGES_HPP
#define CBOR_MESSAGES_HPP

#include "cbor.hpp"
#include "exposed_creds.hpp"

/// Tags for exposed credentials.
enum class exposed_creds_tag : uint8_t {
    plaintext,
    token,      
    derived      
};

template<exposed_creds_tag Tag>
class exposed_creds_message {
    cbor::text_string protocol_;
    cbor::text_string auth_method_;
    cbor::text_string username_;
    datum cbor_span_;
    bool valid_ = false;

public:
    
    static constexpr const char* KEY =
        Tag == exposed_creds_tag::plaintext ? "exposed_credentials_plaintext" :
        Tag == exposed_creds_tag::token     ? "exposed_credentials_token" :
                                              "exposed_credentials_derived";

    /// Construct from raw data (encoding path).
    static exposed_creds_message construct(datum protocol,
                                            datum auth_method,
                                            datum username) {
        exposed_creds_message msg;
        msg.protocol_ = cbor::text_string::construct(protocol);
        msg.auth_method_ = cbor::text_string::construct(auth_method);
        msg.username_ = cbor::text_string::construct(username);
        msg.valid_ = true;
        return msg;
    }

    /// Decode from CBOR indefinite map (decoding path).
    /// d must point at the 0xBF opening byte.
    static exposed_creds_message decode(datum &d) {
        exposed_creds_message msg;
        const uint8_t* begin = d.data;
        cbor::map m{d};
        while (d.is_not_empty() && *d.data != 0xff) {
            cbor::text_string key = cbor::text_string::decode(d);
            datum k = key.value();
            if (k.match("protocol"))                   msg.protocol_ = cbor::text_string::decode(d);
            else if (k.match("authentication_method")) msg.auth_method_ = cbor::text_string::decode(d);
            else if (k.match("username"))              msg.username_ = cbor::text_string::decode(d);
            else cbor::skip_cbor_value(d);
        }
        m.close();
        msg.cbor_span_ = datum{begin, d.data};
        msg.valid_ = !d.is_null();
        return msg;
    }

    /// Templated write 
    template<typename Object, typename Array>
    void write(Object &parent) const {
        Object o{parent, KEY};
        if (protocol_.is_valid())
            o.print_key_string("protocol", protocol_.value());
        if (auth_method_.is_valid())
            o.print_key_string("authentication_method", auth_method_.value());
        if (username_.is_valid())
            o.print_key_string("username", username_.value());
        o.close();
    }

    bool is_valid() const { return valid_; }
    datum key() const { return datum{KEY}; }
    datum protocol() const { return protocol_.value(); }
    datum auth_method() const { return auth_method_.value(); }
    datum username() const { return username_.value(); }
    datum cbor_span() const { return cbor_span_; }
};

using exposed_creds_plaintext_message = exposed_creds_message<exposed_creds_tag::plaintext>;
using exposed_creds_token_message     = exposed_creds_message<exposed_creds_tag::token>;
using exposed_creds_derived_message   = exposed_creds_message<exposed_creds_tag::derived>;


/// CNSA 2.0 crypto assessment (quantum_safe policy).
/// write() produces an anonymous object (no KEY) for use inside the
/// "cryptographic_security_assessment" array. KEY is used only by the
/// outer CBOR metadata dispatch.
class crypto_cnsa_message {
    static constexpr size_t MAX_ITEMS = 48;
    static constexpr size_t HEX_STR_LEN = 5; // "xxxx" + null

    cbor::text_string policy_;
    cbor::text_string target_;

    cbor::text_string cs_not_allowed_[MAX_ITEMS];
    size_t            cs_not_allowed_count_ = 0;
    char              cs_hex_bufs_[MAX_ITEMS][HEX_STR_LEN];
    cbor::text_string cs_allowed_;

    cbor::text_string grp_not_allowed_[MAX_ITEMS];
    size_t            grp_not_allowed_count_ = 0;
    char              grp_hex_bufs_[MAX_ITEMS][HEX_STR_LEN];
    cbor::text_string grp_allowed_;

    bool psk_mode_ = false;

    cbor::text_string psk_non_compliant_key_;
    cbor::text_string psk_non_compliant_reason_;

    bool compliant_ = true;
    bool valid_ = false;
    datum cbor_span_;

public:
    static constexpr const char* KEY = "cnsa_2_0_non_conformant";

    void set_policy(const char* p)              { policy_ = cbor::text_string(p); }
    void set_target(const char* t)              { target_ = cbor::text_string(t); }
    void add_cs_not_allowed(const char* name) {
        if (cs_not_allowed_count_ < MAX_ITEMS)
            cs_not_allowed_[cs_not_allowed_count_++] = cbor::text_string(name);
    }
    void add_cs_not_allowed_hex(uint16_t value) {
        if (cs_not_allowed_count_ < MAX_ITEMS) {
            size_t idx = cs_not_allowed_count_;
            snprintf(cs_hex_bufs_[idx], HEX_STR_LEN, "%04x", value);
            cs_not_allowed_[cs_not_allowed_count_++] = cbor::text_string(cs_hex_bufs_[idx]);
        }
    }
    void set_cs_allowed(const char* q)          { cs_allowed_ = cbor::text_string(q); }
    void add_grp_not_allowed(const char* name) {
        if (grp_not_allowed_count_ < MAX_ITEMS)
            grp_not_allowed_[grp_not_allowed_count_++] = cbor::text_string(name);
    }
    void add_grp_not_allowed_hex(uint16_t value) {
        if (grp_not_allowed_count_ < MAX_ITEMS) {
            size_t idx = grp_not_allowed_count_;
            snprintf(grp_hex_bufs_[idx], HEX_STR_LEN, "%04x", value);
            grp_not_allowed_[grp_not_allowed_count_++] = cbor::text_string(grp_hex_bufs_[idx]);
        }
    }
    void set_grp_allowed(const char* q)         { grp_allowed_ = cbor::text_string(q); }
    void set_psk_mode(bool v)                   { psk_mode_ = v; }
    void set_psk_non_compliant(const char* key, const char* reason) {
        psk_non_compliant_key_ = cbor::text_string(key);
        psk_non_compliant_reason_ = cbor::text_string(reason);
    }
    void set_compliant(bool c)                  { compliant_ = c; }
    void set_valid()                            { valid_ = true; }

    bool is_compliant() const { return compliant_; }
    bool is_valid()     const { return valid_; }

    /// Templated write
    template<typename Object, typename Array, typename Parent>
    void write(Parent &parent) const {
        Object o{parent};
        if (policy_.is_valid())
            o.print_key_string("policy", policy_.value());

        if (!target_.is_valid()) { o.close(); return; }
        Object tgt{o, target_.value()};

        if (cs_not_allowed_count_ > 0) {
            Array cs_arr{tgt, "ciphersuites_not_allowed"};
            for (size_t i = 0; i < cs_not_allowed_count_; i++)
                cs_arr.print_string(cs_not_allowed_[i].value());
            cs_arr.close();
        }
        if (cs_allowed_.is_valid())
            tgt.print_key_string("ciphersuites_allowed", cs_allowed_.value());

        if (grp_not_allowed_count_ > 0) {
            Array grp_arr{tgt, "groups_not_allowed"};
            for (size_t i = 0; i < grp_not_allowed_count_; i++)
                grp_arr.print_string(grp_not_allowed_[i].value());
            grp_arr.close();
        }
        if (grp_allowed_.is_valid())
            tgt.print_key_string("groups_allowed", grp_allowed_.value());

        tgt.print_key_bool("tls_cert_with_extern_psk", psk_mode_);

        if (psk_non_compliant_key_.is_valid())
            tgt.print_key_string(psk_non_compliant_key_.value(),
                                  psk_non_compliant_reason_.value());

        tgt.close();
        o.close();
    }

    static crypto_cnsa_message decode(datum &d) {
        crypto_cnsa_message msg;
        const uint8_t* begin = d.data;
        cbor::map m{d};
        while (d.is_not_empty() && *d.data != 0xff) {
            cbor::text_string key = cbor::text_string::decode(d);
            datum k = key.value();
            if (k.match("policy")) {
                msg.policy_ = cbor::text_string::decode(d);
            }
            else if (k.match("client") || k.match("session")
                     || k.match("offered")) {
                msg.target_ = key;
                cbor::map tgt{d};
                while (d.is_not_empty() && *d.data != 0xff) {
                    cbor::text_string tkey = cbor::text_string::decode(d);
                    datum tk = tkey.value();
                    if (tk.match("ciphersuites_not_allowed")) {
                        cbor::array arr{d};
                        while (d.is_not_empty() && *d.data != 0xff) {
                            if (msg.cs_not_allowed_count_ < MAX_ITEMS)
                                msg.cs_not_allowed_[msg.cs_not_allowed_count_++] =
                                    cbor::text_string::decode(d);
                            else
                                cbor::skip_cbor_value(d);
                        }
                        arr.close();
                    }
                    else if (tk.match("ciphersuites_allowed")) {
                        msg.cs_allowed_ = cbor::text_string::decode(d);
                    }
                    else if (tk.match("groups_not_allowed")) {
                        cbor::array arr{d};
                        while (d.is_not_empty() && *d.data != 0xff) {
                            if (msg.grp_not_allowed_count_ < MAX_ITEMS)
                                msg.grp_not_allowed_[msg.grp_not_allowed_count_++] =
                                    cbor::text_string::decode(d);
                            else
                                cbor::skip_cbor_value(d);
                        }
                        arr.close();
                    }
                    else if (tk.match("groups_allowed")) {
                        msg.grp_allowed_ = cbor::text_string::decode(d);
                    }
                    else if (tk.match("tls_cert_with_extern_psk")) {
                        msg.psk_mode_ = cbor::decode_bool(d);
                    }
                    else {
                        msg.psk_non_compliant_key_ = tkey;
                        msg.psk_non_compliant_reason_ = cbor::text_string::decode(d);
                    }
                }
                tgt.close();
            }
            else {
                cbor::skip_cbor_value(d);
            }
        }
        m.close();
        msg.cbor_span_ = datum{begin, d.data};
        msg.valid_ = !d.is_null();
        return msg;
    }

    datum key()       const { return datum{KEY}; }
    datum cbor_span() const { return cbor_span_; }

    size_t cs_not_allowed_count() const { return cs_not_allowed_count_; }
    cbor::text_string cs_not_allowed_at(size_t i) const { return cs_not_allowed_[i]; }
    bool cs_allowed_valid() const { return cs_allowed_.is_valid(); }
    cbor::text_string cs_allowed_value() const { return cs_allowed_; }
    size_t grp_not_allowed_count() const { return grp_not_allowed_count_; }
    cbor::text_string grp_not_allowed_at(size_t i) const { return grp_not_allowed_[i]; }
    bool grp_allowed_valid() const { return grp_allowed_.is_valid(); }
    cbor::text_string grp_allowed_value() const { return grp_allowed_; }
    bool psk_mode() const { return psk_mode_; }
    bool psk_non_compliant_key_valid() const { return psk_non_compliant_key_.is_valid(); }
    cbor::text_string psk_non_compliant_key_value() const { return psk_non_compliant_key_; }
    cbor::text_string psk_non_compliant_reason_value() const { return psk_non_compliant_reason_; }
};


/// NIST SP 800-52 Rev 2 crypto assessment.
/// Same anonymous-object write pattern as crypto_cnsa_message.
class crypto_nist_message {
    static constexpr size_t MAX_EXTENSIONS = 32;

    cbor::text_string policy_;

    bool has_negotiated_params_ = false;
    cbor::text_string protocol_version_;
    cbor::text_string extensions_[MAX_EXTENSIONS];
    size_t            extensions_count_ = 0;
    cbor::text_string cipher_suite_;
    cbor::text_string supported_group_;

    bool compliant_ = true;
    cbor::text_string non_compliant_key_;
    cbor::text_string non_compliant_reason_;

    bool valid_ = false;
    datum cbor_span_;

public:
    static constexpr const char* KEY = "nist_sp_800_52_2_non_conformant";

    void set_policy(const char* p)              { policy_ = cbor::text_string(p); }
    void set_protocol_version(const char* v)    { protocol_version_ = cbor::text_string(v); }
    void add_extension(const char* name) {
        if (extensions_count_ < MAX_EXTENSIONS)
            extensions_[extensions_count_++] = cbor::text_string(name);
    }
    void set_cipher_suite(const char* name)     { cipher_suite_ = cbor::text_string(name); }
    void set_supported_group(const char* name)  { supported_group_ = cbor::text_string(name); }
    void set_has_negotiated_params()            { has_negotiated_params_ = true; }

    void set_non_compliant(const char* key, const char* reason) {
        compliant_ = false;
        non_compliant_key_ = cbor::text_string(key);
        non_compliant_reason_ = cbor::text_string(reason);
    }
    void set_valid()                            { valid_ = true; }

    bool is_compliant() const { return compliant_; }
    bool is_valid()     const { return valid_; }

    template<typename Object, typename Array, typename Parent>
    void write(Parent &parent) const {
        Object o{parent};
        if (policy_.is_valid())
            o.print_key_string("policy", policy_.value());

        if (has_negotiated_params_) {
            Object params{o, "negotiated_parameters"};
            if (protocol_version_.is_valid())
                params.print_key_string("protocol_version", protocol_version_.value());
            {
                Array exts_arr{params, "extensions"};
                for (size_t i = 0; i < extensions_count_; i++)
                    exts_arr.print_string(extensions_[i].value());
                exts_arr.close();
            }
            if (cipher_suite_.is_valid())
                params.print_key_string("cipher_suite", cipher_suite_.value());
            if (supported_group_.is_valid())
                params.print_key_string("supported_group", supported_group_.value());
            params.close();
        }

        Object compliance{o, "compliance_result"};
        if (non_compliant_key_.is_valid())
            compliance.print_key_string(non_compliant_key_.value(),
                                         non_compliant_reason_.value());
        compliance.print_key_bool("compliant", compliant_);
        compliance.close();

        o.close();
    }

    static crypto_nist_message decode(datum &d) {
        crypto_nist_message msg;
        const uint8_t* begin = d.data;
        cbor::map m{d};
        while (d.is_not_empty() && *d.data != 0xff) {
            cbor::text_string key = cbor::text_string::decode(d);
            datum k = key.value();
            if (k.match("policy")) {
                msg.policy_ = cbor::text_string::decode(d);
            }
            else if (k.match("negotiated_parameters")) {
                msg.has_negotiated_params_ = true;
                cbor::map params{d};
                while (d.is_not_empty() && *d.data != 0xff) {
                    cbor::text_string pkey = cbor::text_string::decode(d);
                    datum pk = pkey.value();
                    if (pk.match("protocol_version")) {
                        msg.protocol_version_ = cbor::text_string::decode(d);
                    }
                    else if (pk.match("extensions")) {
                        cbor::array arr{d};
                        while (d.is_not_empty() && *d.data != 0xff) {
                            if (msg.extensions_count_ < MAX_EXTENSIONS)
                                msg.extensions_[msg.extensions_count_++] =
                                    cbor::text_string::decode(d);
                            else
                                cbor::skip_cbor_value(d);
                        }
                        arr.close();
                    }
                    else if (pk.match("cipher_suite")) {
                        msg.cipher_suite_ = cbor::text_string::decode(d);
                    }
                    else if (pk.match("supported_group")) {
                        msg.supported_group_ = cbor::text_string::decode(d);
                    }
                    else cbor::skip_cbor_value(d);
                }
                params.close();
            }
            else if (k.match("compliance_result")) {
                cbor::map comp{d};
                while (d.is_not_empty() && *d.data != 0xff) {
                    cbor::text_string ckey = cbor::text_string::decode(d);
                    datum ck = ckey.value();
                    if (ck.match("compliant")) {
                        msg.compliant_ = cbor::decode_bool(d);
                    }
                    else {
                        msg.non_compliant_key_ = ckey;
                        msg.non_compliant_reason_ = cbor::text_string::decode(d);
                        msg.compliant_ = false;
                    }
                }
                comp.close();
            }
            else {
                cbor::skip_cbor_value(d);
            }
        }
        m.close();
        msg.cbor_span_ = datum{begin, d.data};
        msg.valid_ = !d.is_null();
        return msg;
    }

    datum key()       const { return datum{KEY}; }
    datum cbor_span() const { return cbor_span_; }
};

#endif // CBOR_MESSAGES_HPP
