// cbor_messages.hpp
//
// Non-owning feature classes for the CBOR metadata interface.
// Each class both encodes and decodes its feature

#ifndef CBOR_MESSAGES_HPP
#define CBOR_MESSAGES_HPP

#include <variant>
#include "cbor.hpp"
#include "null_terminated_string.hpp"

inline constexpr null_terminated_string CBOR_METADATA_VERSION_KEY = "v1";

// Reserved key for the packet/handshake truncation status. It is a
// packet-level status and the
// decoder captures it into typed_decoder::truncation.
inline constexpr null_terminated_string CBOR_METADATA_TRUNCATION_KEY = "truncation";

// Guideline for Features written into the CBOR Interface
// 1. Every Feature's value must be an indefinite-length CBOR map.
// 2. Only those CBOR primitives must be used that the consumers of this
//    interface understand. Currently the allowed CBOR primitives are unsigned
//    integers, byte strings, text strings, true, false, null, tagged items,
//    indefinite-length maps and indefinite-length arrays.
// 3. An unsigned integer used as a key should be less than 65536.
// 4. A text key should be less than 128 bytes once JSON-escaped.
// 5. A fingerprint must be written as a text string in NPF form. Do not use the
//    NPF presentation-hint tag 18000 here, a consumer of this interface treats a
//    tagged value as opaque bytes, so a fingerprint sent that way does not get
//    picked up.
// 6. A key should not be repeated at any level: as a version key, as a Feature key
//    inside a version, or as a key inside a Feature's own value map.
// 7. A repeated version key or Feature key loses to its first occurrence: a consumer
//    decodes the first and skips the rest, so the repeat is silently lost rather than
//    merged.
// 8. A Feature's value map is opaque to this interface, so rule 6 inside it is that
//    Feature's own responsibility: its write() must not emit the same key twice.
// 9. A Feature that fires more than once per packet, or that has several entries in
//    one packet, combines them inside its class and is written once.
// 10. Every field a Feature treats as fixed must be present in every occurrence of that
//    Feature. Fixed means whatever that Feature's own decode requires in order to report
//    is_valid(): each class defines its own set, so that is where to look rather than here.
//    A consumer that registers the Feature reads a missing fixed field as an error and
//    discards the whole buffer, so omitting one costs the other Features in that packet
//    too. Adding fields is always safe: a consumer skips the ones it does not know.

/// Reserved packet-level status: the truncation state of the packet/handshake.
class truncation_message {
    cbor::text_string status_;

public:
    static constexpr const char* KEY = CBOR_METADATA_TRUNCATION_KEY.c_str();

    static bool matches(datum key) { return key.match(KEY); }
    void decode_into(datum /*key*/, datum &d) { status_ = cbor::text_string::decode(d); }

    bool  is_valid() const { return status_.is_valid(); }
    datum status()   const { return status_.value(); }
};

/// Exposed credentials message — runtime KEY distinguishes plaintext/token/derived.
class exposed_creds_message {
public:
    enum class message_type { plaintext, token, derived };

private:
    inline static constexpr null_terminated_string plaintext_key_ = "exposed_credentials_plaintext";
    inline static constexpr null_terminated_string token_key_ = "exposed_credentials_token";
    inline static constexpr null_terminated_string derived_key_ = "exposed_credentials_derived";

    static constexpr const null_terminated_string *key_for(message_type type) {
        switch (type) {
        case message_type::plaintext: return &plaintext_key_;
        case message_type::token:     return &token_key_;
        case message_type::derived:   return &derived_key_;
        }
        return nullptr;
    }

    const null_terminated_string* key_ = nullptr;
    cbor::text_string protocol_;
    cbor::text_string auth_method_;
    cbor::text_string username_;
    datum cbor_span_;
    bool valid_ = false;

public:
    static exposed_creds_message construct(message_type type,
                                           datum protocol,
                                           datum auth_method,
                                           datum username) {
        exposed_creds_message msg;
        msg.key_ = key_for(type);
        msg.protocol_ = cbor::text_string::construct(protocol);
        msg.auth_method_ = cbor::text_string::construct(auth_method);
        msg.username_ = cbor::text_string::construct(username);
        msg.valid_ = msg.key_ != nullptr && msg.protocol_.is_valid() && msg.auth_method_.is_valid();
        return msg;
    }

    static exposed_creds_message decode(datum &d, message_type type) {
        exposed_creds_message msg;
        msg.key_ = key_for(type);
        const uint8_t* begin = d.data;
        cbor::map m{d};
        while (d.is_not_empty() && !cbor::is_break(d)) {
            cbor::text_string k = cbor::text_string::decode(d);
            datum kv = k.value();
            if (kv.match("protocol")) {
                msg.protocol_ = cbor::text_string::decode(d);
            } else if (kv.match("authentication_method")) {
                msg.auth_method_ = cbor::text_string::decode(d);
            } else if (kv.match("username")) {
                msg.username_ = cbor::text_string::decode(d);
            } else {
                cbor::skip_cbor_value(d);
            }
        }
        m.close();
        msg.cbor_span_ = datum{begin, d.data};
        msg.valid_ = msg.key_ != nullptr && !d.is_null() && msg.protocol_.is_valid() && msg.auth_method_.is_valid();
        return msg;
    }

    // typed_decoder contract: recognize this feature's key(s), and decode in place.
    static bool matches(datum key) {
        return key.match(plaintext_key_.c_str()) || key.match(token_key_.c_str()) || key.match(derived_key_.c_str());
    }
    void decode_into(datum key, datum &d) {
        if (key.match(plaintext_key_.c_str())) {
            *this = decode(d, message_type::plaintext);
        } else if (key.match(token_key_.c_str())) {
            *this = decode(d, message_type::token);
        } else if (key.match(derived_key_.c_str())) {
            *this = decode(d, message_type::derived);
        }
    }

    template<typename Object>
    void write(Object &parent) const {
        if (key_ == nullptr) {
            return;
        }
        Object o{parent, *key_};
        if (protocol_.is_valid()) {
            o.print_key_string("protocol", protocol_.value());
        }
        if (auth_method_.is_valid()) {
            o.print_key_string("authentication_method", auth_method_.value());
        }
        if (username_.is_valid()) {
            o.print_key_string("username", username_.value());
        }
        o.close();
    }

    bool is_valid() const { return valid_; }
    datum key() const { return datum{key_ == nullptr ? nullptr : key_->c_str()}; }
    datum protocol() const { return protocol_.value(); }
    datum auth_method() const { return auth_method_.value(); }
    datum username() const { return username_.value(); }
    datum cbor_span() const { return cbor_span_; }
};


/// CNSA 2.0 TLS crypto assessment (quantum_safe policy).
/// Caller writes KEY before calling write(). write() produces anonymous object.
class crypto_cnsa_tls_message {
    static constexpr size_t MAX_ITEMS = 48;
    static constexpr size_t MAX_PSK_ENTRIES = 4;
    cbor::text_string policy_;
    cbor::text_string target_;

    cbor::text_string cs_not_allowed_[MAX_ITEMS];
    uint16_t          cs_not_allowed_hex_[MAX_ITEMS];
    bool              cs_not_allowed_is_hex_[MAX_ITEMS] = {};
    size_t            cs_not_allowed_count_ = 0;
    cbor::text_string cs_allowed_;

    cbor::text_string grp_not_allowed_[MAX_ITEMS];
    uint16_t          grp_not_allowed_hex_[MAX_ITEMS];
    bool              grp_not_allowed_is_hex_[MAX_ITEMS] = {};
    size_t            grp_not_allowed_count_ = 0;
    cbor::text_string grp_allowed_;

    bool psk_mode_ = false;

    cbor::text_string psk_non_compliant_keys_[MAX_PSK_ENTRIES];
    cbor::text_string psk_non_compliant_reasons_[MAX_PSK_ENTRIES];
    size_t            psk_non_compliant_count_ = 0;

    bool compliant_ = true;
    bool valid_ = false;
    datum cbor_span_;

public:
    static constexpr const char* KEY = "cnsa_2_0_non_conformant";

    void set_policy(const char* p)              { policy_ = cbor::text_string(p); }
    void set_target(const char* t)              { target_ = cbor::text_string(t); }
    void add_cs_not_allowed(const char* name) {
        if (cs_not_allowed_count_ < MAX_ITEMS) {
            cs_not_allowed_[cs_not_allowed_count_] = cbor::text_string(name);
            cs_not_allowed_is_hex_[cs_not_allowed_count_] = false;
            cs_not_allowed_count_++;
        }
    }
    void add_cs_not_allowed_hex(uint16_t value) {
        if (cs_not_allowed_count_ < MAX_ITEMS) {
            cs_not_allowed_hex_[cs_not_allowed_count_] = value;
            cs_not_allowed_is_hex_[cs_not_allowed_count_] = true;
            cs_not_allowed_count_++;
        }
    }
    void set_cs_allowed(const char* q)          { cs_allowed_ = cbor::text_string(q); }
    void add_grp_not_allowed(const char* name) {
        if (grp_not_allowed_count_ < MAX_ITEMS) {
            grp_not_allowed_[grp_not_allowed_count_] = cbor::text_string(name);
            grp_not_allowed_is_hex_[grp_not_allowed_count_] = false;
            grp_not_allowed_count_++;
        }
    }
    void add_grp_not_allowed_hex(uint16_t value) {
        if (grp_not_allowed_count_ < MAX_ITEMS) {
            grp_not_allowed_hex_[grp_not_allowed_count_] = value;
            grp_not_allowed_is_hex_[grp_not_allowed_count_] = true;
            grp_not_allowed_count_++;
        }
    }
    void set_grp_allowed(const char* q)         { grp_allowed_ = cbor::text_string(q); }
    void set_psk_mode(bool v)                   { psk_mode_ = v; }
    void set_psk_non_compliant(const char* key, const char* reason) {
        if (psk_non_compliant_count_ < MAX_PSK_ENTRIES) {
            psk_non_compliant_keys_[psk_non_compliant_count_] = cbor::text_string(key);
            psk_non_compliant_reasons_[psk_non_compliant_count_] = cbor::text_string(reason);
            psk_non_compliant_count_++;
        }
    }
    void set_compliant(bool c)                  { compliant_ = c; }
    void set_valid()                            { valid_ = policy_.is_valid() && target_.is_valid(); }

    bool is_compliant() const { return compliant_; }
    bool is_valid()     const { return valid_; }

    template<typename Object, typename Parent>
    void write(Parent &parent) const {
        using Array = typename Object::array_type;
        Object o{parent};
        if (policy_.is_valid()) {
            o.print_key_string("policy", policy_.value());
        }
        o.print_key_string("cnsa_variant", "tls");
        if (!target_.is_valid()) { o.close(); return; }
        Object tgt{o, target_.value()};
        if (cs_not_allowed_count_ > 0) {
            Array cs_arr{tgt, "ciphersuites_not_allowed"};
            for (size_t i = 0; i < cs_not_allowed_count_; i++) {
                if (cs_not_allowed_is_hex_[i]) {
                    cs_arr.print_uint(cs_not_allowed_hex_[i]);
                }
                else {
                    cs_arr.print_string(cs_not_allowed_[i].value());
                }
            }
            cs_arr.close();
        }
        if (cs_allowed_.is_valid()) {
            tgt.print_key_string("ciphersuites_allowed", cs_allowed_.value());
        }
        if (grp_not_allowed_count_ > 0) {
            Array grp_arr{tgt, "groups_not_allowed"};
            for (size_t i = 0; i < grp_not_allowed_count_; i++) {
                if (grp_not_allowed_is_hex_[i]) {
                    grp_arr.print_uint(grp_not_allowed_hex_[i]);
                }
                else {
                    grp_arr.print_string(grp_not_allowed_[i].value());
                }
            }
            grp_arr.close();
        }
        if (grp_allowed_.is_valid()) {
            tgt.print_key_string("groups_allowed", grp_allowed_.value());
        }
        tgt.print_key_bool("tls_cert_with_extern_psk", psk_mode_);
        for (size_t i = 0; i < psk_non_compliant_count_; i++) {
            tgt.print_key_string(psk_non_compliant_keys_[i].value(),
                                  psk_non_compliant_reasons_[i].value());
        }
        tgt.close();
        o.close();
    }

    static crypto_cnsa_tls_message decode(datum &d) {
        crypto_cnsa_tls_message msg;
        const uint8_t* begin = d.data;
        cbor::map m{d};
        while (d.is_not_empty() && !cbor::is_break(d)) {
            cbor::text_string key = cbor::text_string::decode(d);
            datum k = key.value();
            if (k.match("policy")) {
                msg.policy_ = cbor::text_string::decode(d);
            }
            else if (k.match("cnsa_variant")) {
                cbor::text_string::decode(d);   // protocol discriminator; consumed on decode
            }
            else if (k.match("client") || k.match("session")) {
                msg.target_ = key;
                cbor::map tgt{d};
                while (d.is_not_empty() && !cbor::is_break(d)) {
                    cbor::text_string tkey = cbor::text_string::decode(d);
                    datum tk = tkey.value();
                    if (tk.match("ciphersuites_not_allowed")) {
                        cbor::array arr{d};
                        while (d.is_not_empty() && !cbor::is_break(d)) {
                            if (msg.cs_not_allowed_count_ < MAX_ITEMS) {
                                lookahead<cbor::initial_byte> ib{d};
                                if (ib && ib.value.major_type() == cbor::unsigned_integer_type) {
                                    msg.cs_not_allowed_hex_[msg.cs_not_allowed_count_]    = (uint16_t)cbor::uint64::decode_max(d, 0xffff).value();
                                    msg.cs_not_allowed_is_hex_[msg.cs_not_allowed_count_] = true;
                                }
                                else {
                                    msg.cs_not_allowed_[msg.cs_not_allowed_count_]        = cbor::text_string::decode(d);
                                    msg.cs_not_allowed_is_hex_[msg.cs_not_allowed_count_] = false;
                                }
                                msg.cs_not_allowed_count_++;
                            }
                            else { cbor::skip_cbor_value(d); }
                        }
                        arr.close();
                    }
                    else if (tk.match("ciphersuites_allowed")) {
                        msg.cs_allowed_ = cbor::text_string::decode(d);
                    }
                    else if (tk.match("groups_not_allowed")) {
                        cbor::array arr{d};
                        while (d.is_not_empty() && !cbor::is_break(d)) {
                            if (msg.grp_not_allowed_count_ < MAX_ITEMS) {
                                lookahead<cbor::initial_byte> ib{d};
                                if (ib && ib.value.major_type() == cbor::unsigned_integer_type) {
                                    msg.grp_not_allowed_hex_[msg.grp_not_allowed_count_]    = (uint16_t)cbor::uint64::decode_max(d, 0xffff).value();
                                    msg.grp_not_allowed_is_hex_[msg.grp_not_allowed_count_] = true;
                                }
                                else {
                                    msg.grp_not_allowed_[msg.grp_not_allowed_count_]        = cbor::text_string::decode(d);
                                    msg.grp_not_allowed_is_hex_[msg.grp_not_allowed_count_] = false;
                                }
                                msg.grp_not_allowed_count_++;
                            }
                            else { cbor::skip_cbor_value(d); }
                        }
                        arr.close();
                    }
                    else if (tk.match("groups_allowed")) {
                        msg.grp_allowed_ = cbor::text_string::decode(d);
                    }
                    else if (tk.match("tls_cert_with_extern_psk")) {
                        msg.psk_mode_ = cbor::Bool{d}.is_true();
                    }
                    else if (tk.match("tls_cert_with_extern_psk_non_compliant") ||
                             tk.match("psk_key_exchange_modes_non_compliant") ||
                             tk.match("psk_key_exchange_mlkem1024_non_compliant") ||
                             tk.match("pre_shared_key_non_compliant")) {
                        if (msg.psk_non_compliant_count_ < MAX_PSK_ENTRIES) {
                            msg.psk_non_compliant_keys_[msg.psk_non_compliant_count_] = tkey;
                            msg.psk_non_compliant_reasons_[msg.psk_non_compliant_count_] = cbor::text_string::decode(d);
                            msg.psk_non_compliant_count_++;
                        } else { cbor::skip_cbor_value(d); }
                    }
                    else { cbor::skip_cbor_value(d); }
                }
                tgt.close();
            }
            else { cbor::skip_cbor_value(d); }
        }
        m.close();
        msg.cbor_span_ = datum{begin, d.data};
        msg.valid_ = !d.is_null() && msg.policy_.is_valid() && msg.target_.is_valid();
        return msg;
    }

    datum key()       const { return datum{KEY}; }
    datum cbor_span() const { return cbor_span_; }

    size_t cs_not_allowed_count() const { return cs_not_allowed_count_; }
    cbor::text_string cs_not_allowed_at(size_t i) const { return cs_not_allowed_[i]; }
    bool cs_not_allowed_is_hex(size_t i) const { return cs_not_allowed_is_hex_[i]; }
    uint16_t cs_not_allowed_code_at(size_t i) const { return cs_not_allowed_hex_[i]; }
    bool cs_allowed_valid() const { return cs_allowed_.is_valid(); }
    cbor::text_string cs_allowed_value() const { return cs_allowed_; }
    size_t grp_not_allowed_count() const { return grp_not_allowed_count_; }
    cbor::text_string grp_not_allowed_at(size_t i) const { return grp_not_allowed_[i]; }
    bool grp_not_allowed_is_hex(size_t i) const { return grp_not_allowed_is_hex_[i]; }
    uint16_t grp_not_allowed_code_at(size_t i) const { return grp_not_allowed_hex_[i]; }
    bool grp_allowed_valid() const { return grp_allowed_.is_valid(); }
    cbor::text_string grp_allowed_value() const { return grp_allowed_; }
    bool psk_mode() const { return psk_mode_; }
    size_t psk_non_compliant_count() const { return psk_non_compliant_count_; }
    cbor::text_string psk_non_compliant_key_at(size_t i) const { return psk_non_compliant_keys_[i]; }
    cbor::text_string psk_non_compliant_reason_at(size_t i) const { return psk_non_compliant_reasons_[i]; }
};


/// CNSA 2.0 SSH crypto assessment (quantum_safe policy).
/// Caller writes KEY before calling write(). write() produces anonymous object.
/// No target_ member — always writes "offered" hardcoded.
class crypto_cnsa_ssh_message {
    static constexpr size_t MAX_ITEMS = 48;
    cbor::text_string policy_;

    cbor::text_string kex_not_allowed_[MAX_ITEMS];
    size_t            kex_not_allowed_count_ = 0;
    cbor::text_string kex_allowed_;
    cbor::text_string c2s_cs_not_allowed_[MAX_ITEMS];
    size_t            c2s_cs_not_allowed_count_ = 0;
    cbor::text_string c2s_cs_allowed_;
    cbor::text_string s2c_cs_not_allowed_[MAX_ITEMS];
    size_t            s2c_cs_not_allowed_count_ = 0;
    cbor::text_string s2c_cs_allowed_;

    bool compliant_ = true;
    bool valid_ = false;
    datum cbor_span_;

public:
    static constexpr const char* KEY = "cnsa_2_0_non_conformant";

    void set_policy(const char* p)              { policy_ = cbor::text_string(p); }
    void add_kex_not_allowed(const char* name) {
        if (kex_not_allowed_count_ < MAX_ITEMS) {
            kex_not_allowed_[kex_not_allowed_count_++] = cbor::text_string(name);
        }
    }
    void add_kex_not_allowed(datum d) {
        if (kex_not_allowed_count_ < MAX_ITEMS) {
            kex_not_allowed_[kex_not_allowed_count_++] = cbor::text_string::construct(d);
        }
    }
    void set_kex_allowed(const char* q)         { kex_allowed_ = cbor::text_string(q); }
    void add_c2s_cs_not_allowed(const char* name) {
        if (c2s_cs_not_allowed_count_ < MAX_ITEMS) {
            c2s_cs_not_allowed_[c2s_cs_not_allowed_count_++] = cbor::text_string(name);
        }
    }
    void add_c2s_cs_not_allowed(datum d) {
        if (c2s_cs_not_allowed_count_ < MAX_ITEMS) {
            c2s_cs_not_allowed_[c2s_cs_not_allowed_count_++] = cbor::text_string::construct(d);
        }
    }
    void set_c2s_cs_allowed(const char* q)      { c2s_cs_allowed_ = cbor::text_string(q); }
    void add_s2c_cs_not_allowed(const char* name) {
        if (s2c_cs_not_allowed_count_ < MAX_ITEMS) {
            s2c_cs_not_allowed_[s2c_cs_not_allowed_count_++] = cbor::text_string(name);
        }
    }
    void add_s2c_cs_not_allowed(datum d) {
        if (s2c_cs_not_allowed_count_ < MAX_ITEMS) {
            s2c_cs_not_allowed_[s2c_cs_not_allowed_count_++] = cbor::text_string::construct(d);
        }
    }
    void set_s2c_cs_allowed(const char* q)      { s2c_cs_allowed_ = cbor::text_string(q); }
    void set_compliant(bool c)                  { compliant_ = c; }
    void set_valid()                            { valid_ = policy_.is_valid(); }

    bool is_compliant() const { return compliant_; }
    bool is_valid()     const { return valid_; }

    template<typename Object, typename Parent>
    void write(Parent &parent) const {
        using Array = typename Object::array_type;
        Object o{parent};
        if (policy_.is_valid()) {
            o.print_key_string("policy", policy_.value());
        }
        o.print_key_string("cnsa_variant", "ssh");
        Object offered{o, "offered"};
        if (kex_not_allowed_count_ > 0) {
            Array kex_arr{offered, "kex_not_allowed"};
            for (size_t i = 0; i < kex_not_allowed_count_; i++)
                kex_arr.print_string(kex_not_allowed_[i].value());
            kex_arr.close();
        }
        if (kex_allowed_.is_valid()) {
            offered.print_key_string("kex_allowed", kex_allowed_.value());
        }
        {
            Object c2s{offered, "client_to_server"};
            if (c2s_cs_not_allowed_count_ > 0) {
                Array cs_arr{c2s, "ciphersuites_not_allowed"};
                for (size_t i = 0; i < c2s_cs_not_allowed_count_; i++)
                    cs_arr.print_string(c2s_cs_not_allowed_[i].value());
                cs_arr.close();
            }
            if (c2s_cs_allowed_.is_valid()) {
                c2s.print_key_string("ciphersuites_allowed", c2s_cs_allowed_.value());
            }
            c2s.close();
        }
        {
            Object s2c{offered, "server_to_client"};
            if (s2c_cs_not_allowed_count_ > 0) {
                Array cs_arr{s2c, "ciphersuites_not_allowed"};
                for (size_t i = 0; i < s2c_cs_not_allowed_count_; i++)
                    cs_arr.print_string(s2c_cs_not_allowed_[i].value());
                cs_arr.close();
            }
            if (s2c_cs_allowed_.is_valid()) {
                s2c.print_key_string("ciphersuites_allowed", s2c_cs_allowed_.value());
            }
            s2c.close();
        }
        offered.close();
        o.close();
    }

    static crypto_cnsa_ssh_message decode(datum &d) {
        crypto_cnsa_ssh_message msg;
        const uint8_t* begin = d.data;
        cbor::map m{d};
        while (d.is_not_empty() && !cbor::is_break(d)) {
            cbor::text_string key = cbor::text_string::decode(d);
            datum k = key.value();
            if (k.match("policy")) {
                msg.policy_ = cbor::text_string::decode(d);
            }
            else if (k.match("cnsa_variant")) {
                cbor::text_string::decode(d);   // protocol discriminator; consumed on decode
            }
            else if (k.match("offered")) {
                cbor::map offered{d};
                while (d.is_not_empty() && !cbor::is_break(d)) {
                    cbor::text_string tkey = cbor::text_string::decode(d);
                    datum tk = tkey.value();
                    if (tk.match("kex_not_allowed")) {
                        cbor::array arr{d};
                        while (d.is_not_empty() && !cbor::is_break(d)) {
                            if (msg.kex_not_allowed_count_ < MAX_ITEMS) {
                                msg.kex_not_allowed_[msg.kex_not_allowed_count_++] = cbor::text_string::decode(d);
                            }
                            else { cbor::skip_cbor_value(d); }
                        }
                        arr.close();
                    }
                    else if (tk.match("kex_allowed")) {
                        msg.kex_allowed_ = cbor::text_string::decode(d);
                    }
                    else if (tk.match("client_to_server")) {
                        cbor::map c2s{d};
                        while (d.is_not_empty() && !cbor::is_break(d)) {
                            cbor::text_string ckey = cbor::text_string::decode(d);
                            datum ck = ckey.value();
                            if (ck.match("ciphersuites_not_allowed")) {
                                cbor::array arr{d};
                                while (d.is_not_empty() && !cbor::is_break(d)) {
                                    if (msg.c2s_cs_not_allowed_count_ < MAX_ITEMS) {
                                        msg.c2s_cs_not_allowed_[msg.c2s_cs_not_allowed_count_++] = cbor::text_string::decode(d);
                                    }
                                    else { cbor::skip_cbor_value(d); }
                                }
                                arr.close();
                            }
                            else if (ck.match("ciphersuites_allowed")) {
                                msg.c2s_cs_allowed_ = cbor::text_string::decode(d);
                            }
                            else { cbor::skip_cbor_value(d); }
                        }
                        c2s.close();
                    }
                    else if (tk.match("server_to_client")) {
                        cbor::map s2c{d};
                        while (d.is_not_empty() && !cbor::is_break(d)) {
                            cbor::text_string skey = cbor::text_string::decode(d);
                            datum sk = skey.value();
                            if (sk.match("ciphersuites_not_allowed")) {
                                cbor::array arr{d};
                                while (d.is_not_empty() && !cbor::is_break(d)) {
                                    if (msg.s2c_cs_not_allowed_count_ < MAX_ITEMS) {
                                        msg.s2c_cs_not_allowed_[msg.s2c_cs_not_allowed_count_++] = cbor::text_string::decode(d);
                                    }
                                    else { cbor::skip_cbor_value(d); }
                                }
                                arr.close();
                            }
                            else if (sk.match("ciphersuites_allowed")) {
                                msg.s2c_cs_allowed_ = cbor::text_string::decode(d);
                            }
                            else { cbor::skip_cbor_value(d); }
                        }
                        s2c.close();
                    }
                    else { cbor::skip_cbor_value(d); }
                }
                offered.close();
            }
            else { cbor::skip_cbor_value(d); }
        }
        m.close();
        msg.cbor_span_ = datum{begin, d.data};
        msg.valid_ = !d.is_null() && msg.policy_.is_valid();
        return msg;
    }

    datum key()       const { return datum{KEY}; }
    datum cbor_span() const { return cbor_span_; }

    size_t kex_not_allowed_count() const { return kex_not_allowed_count_; }
    cbor::text_string kex_not_allowed_at(size_t i) const { return kex_not_allowed_[i]; }
    bool kex_allowed_valid() const { return kex_allowed_.is_valid(); }
    cbor::text_string kex_allowed_value() const { return kex_allowed_; }
    size_t c2s_cs_not_allowed_count() const { return c2s_cs_not_allowed_count_; }
    cbor::text_string c2s_cs_not_allowed_at(size_t i) const { return c2s_cs_not_allowed_[i]; }
    bool c2s_cs_allowed_valid() const { return c2s_cs_allowed_.is_valid(); }
    cbor::text_string c2s_cs_allowed_value() const { return c2s_cs_allowed_; }
    size_t s2c_cs_not_allowed_count() const { return s2c_cs_not_allowed_count_; }
    cbor::text_string s2c_cs_not_allowed_at(size_t i) const { return s2c_cs_not_allowed_[i]; }
    bool s2c_cs_allowed_valid() const { return s2c_cs_allowed_.is_valid(); }
    cbor::text_string s2c_cs_allowed_value() const { return s2c_cs_allowed_; }
};


// Legacy alias: producer/crypto_assess code uses crypto_cnsa_message as the TLS cnsa
// encoder type. Decode-side routing uses cnsa_feature (below).
using crypto_cnsa_message = crypto_cnsa_tls_message;

/// Decode-side wrapper for the CNSA 2.0 feature. One wire key
/// ("cnsa_2_0_non_conformant") carries either a TLS or an SSH schema; the "cnsa_variant"
/// field selects which. Holds the decoded body in a variant and exposes typed access via
/// tls_if()/ssh_if(). This is the type registered in the typed_decoder.
class cnsa_feature {
    std::variant<std::monostate, crypto_cnsa_tls_message, crypto_cnsa_ssh_message> body_;

    /// Returns true iff the sub-map's "cnsa_variant" field equals "ssh". Scans a copy of
    /// the datum (non-destructive) and is independent of key order. Defaults to false
    /// (TLS) when the field is absent.
    static bool peek_variant_is_ssh(const uint8_t* begin, const uint8_t* end) {
        datum peek{begin, end};
        cbor::map m{peek};
        while (peek.is_not_empty() && !cbor::is_break(peek)) {
            cbor::text_string key = cbor::text_string::decode(peek);
            if (key.value().match("cnsa_variant")) {
                return cbor::text_string::decode(peek).value().match("ssh");
            }
            cbor::skip_cbor_value(peek);
        }
        return false;
    }

public:
    static constexpr const char* KEY = crypto_cnsa_tls_message::KEY; // "cnsa_2_0_non_conformant"

    // typed_decoder contract.
    static bool matches(datum key) { return key.match(KEY); }
    void decode_into(datum /*key*/, datum &d) {
        // Commit the decoded body only if it is valid; a failed decode leaves body_ as
        // monostate. This keeps index() != 0 an exact validity test and guarantees
        // tls_if()/ssh_if()/cbor_span() never expose a half-decoded object.
        if (peek_variant_is_ssh(d.data, d.data_end)) {
            crypto_cnsa_ssh_message m = crypto_cnsa_ssh_message::decode(d);
            if (m.is_valid()) { body_ = m; }
        } else {
            crypto_cnsa_tls_message m = crypto_cnsa_tls_message::decode(d);
            if (m.is_valid()) { body_ = m; }
        }
    }
    bool  is_valid()  const { return body_.index() != 0; }
    datum key()       const { return datum{KEY}; }
    datum cbor_span() const {
        if (auto* t = std::get_if<crypto_cnsa_tls_message>(&body_)) { return t->cbor_span(); }
        if (auto* s = std::get_if<crypto_cnsa_ssh_message>(&body_)) { return s->cbor_span(); }
        return datum{};
    }
    const crypto_cnsa_tls_message* tls_if() const { return std::get_if<crypto_cnsa_tls_message>(&body_); }
    const crypto_cnsa_ssh_message* ssh_if() const { return std::get_if<crypto_cnsa_ssh_message>(&body_); }
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
        if (extensions_count_ < MAX_EXTENSIONS) {
            extensions_[extensions_count_++] = cbor::text_string(name);
        }
    }
    void set_cipher_suite(const char* name)     { cipher_suite_ = cbor::text_string(name); }
    void set_supported_group(const char* name)  { supported_group_ = cbor::text_string(name); }
    void set_has_negotiated_params()            { has_negotiated_params_ = true; }

    void set_non_compliant(const char* key, const char* reason) {
        compliant_ = false;
        non_compliant_key_ = cbor::text_string(key);
        non_compliant_reason_ = cbor::text_string(reason);
    }
    void set_valid()                            { valid_ = policy_.is_valid(); }

    bool is_compliant() const { return compliant_; }
    bool is_valid()     const { return valid_; }

    template<typename Object, typename Parent>
    void write(Parent &parent) const {
        using Array = typename Object::array_type;
        Object o{parent};
        if (policy_.is_valid()) {
            o.print_key_string("policy", policy_.value());
        }

        if (has_negotiated_params_) {
            Object params{o, "negotiated_parameters"};
            if (protocol_version_.is_valid()) {
                params.print_key_string("protocol_version", protocol_version_.value());
            }
            {
                Array exts_arr{params, "extensions"};
                for (size_t i = 0; i < extensions_count_; i++)
                    exts_arr.print_string(extensions_[i].value());
                exts_arr.close();
            }
            if (cipher_suite_.is_valid()) {
                params.print_key_string("cipher_suite", cipher_suite_.value());
            }
            if (supported_group_.is_valid()) {
                params.print_key_string("supported_group", supported_group_.value());
            }
            params.close();
        }

        Object compliance{o, "compliance_result"};
        if (non_compliant_key_.is_valid()) {
            compliance.print_key_string(non_compliant_key_.value(),
                                         non_compliant_reason_.value());
        }
        compliance.print_key_bool("compliant", compliant_);
        compliance.close();

        o.close();
    }

    static crypto_nist_message decode(datum &d) {
        crypto_nist_message msg;
        const uint8_t* begin = d.data;
        cbor::map m{d};
        while (d.is_not_empty() && !cbor::is_break(d)) {
            cbor::text_string key = cbor::text_string::decode(d);
            datum k = key.value();
            if (k.match("policy")) {
                msg.policy_ = cbor::text_string::decode(d);
            }
            else if (k.match("negotiated_parameters")) {
                msg.has_negotiated_params_ = true;
                cbor::map params{d};
                while (d.is_not_empty() && !cbor::is_break(d)) {
                    cbor::text_string pkey = cbor::text_string::decode(d);
                    datum pk = pkey.value();
                    if (pk.match("protocol_version")) {
                        msg.protocol_version_ = cbor::text_string::decode(d);
                    }
                    else if (pk.match("extensions")) {
                        cbor::array arr{d};
                        while (d.is_not_empty() && !cbor::is_break(d)) {
                            if (msg.extensions_count_ < MAX_EXTENSIONS) {
                                msg.extensions_[msg.extensions_count_++] =
                                    cbor::text_string::decode(d);
                            }
                            else {
                                cbor::skip_cbor_value(d);
                            }
                        }
                        arr.close();
                    }
                    else if (pk.match("cipher_suite")) {
                        msg.cipher_suite_ = cbor::text_string::decode(d);
                    }
                    else if (pk.match("supported_group")) {
                        msg.supported_group_ = cbor::text_string::decode(d);
                    }
                    else { cbor::skip_cbor_value(d); }
                }
                params.close();
            }
            else if (k.match("compliance_result")) {
                cbor::map comp{d};
                while (d.is_not_empty() && !cbor::is_break(d)) {
                    cbor::text_string ckey = cbor::text_string::decode(d);
                    datum ck = ckey.value();
                    if (ck.match("compliant")) {
                        msg.compliant_ = cbor::Bool{d}.is_true();
                    }
                    else if (ck.match("tls_version_non_compliant") ||
                             ck.match("compression_method_non_compliant") ||
                             ck.match("cipher_suite_non_compliant") ||
                             ck.match("supported_groups_missing") ||
                             ck.match("ec_points_format_non_compliant") ||
                             ck.match("supported_group_non_compliant") ||
                             ck.match("encrypt_then_mac_non_compliant")) {
                        msg.non_compliant_key_ = ckey;
                        msg.non_compliant_reason_ = cbor::text_string::decode(d);
                        msg.compliant_ = false;
                    }
                    else {
                        cbor::skip_cbor_value(d);
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
        msg.valid_ = !d.is_null() && msg.policy_.is_valid();
        return msg;
    }

    // typed_decoder contract.
    static bool matches(datum key) { return key.match(KEY); }
    void decode_into(datum /*key*/, datum &d) { *this = decode(d); }

    datum key()       const { return datum{KEY}; }
    datum cbor_span() const { return cbor_span_; }
};

#endif // CBOR_MESSAGES_HPP
