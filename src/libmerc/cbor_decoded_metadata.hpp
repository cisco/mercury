// cbor_decoded_metadata.hpp
//
// Decode container for the CBOR metadata interface.
// Used by the inspector to decode the buffer from get_cbor_metadata().

#ifndef CBOR_DECODED_METADATA_HPP
#define CBOR_DECODED_METADATA_HPP

#include <variant>
#include "cbor.hpp"
#include "cbor_object.hpp"
#include "cbor_messages.hpp"

/// Forwards unknown CBOR keys to the enrichment string unchanged.
class unknown_feature {
    datum key_;
    datum cbor_span_;
    bool valid_ = false;

    unknown_feature(datum key, datum cbor_span, bool valid)
        : key_{key}, cbor_span_{cbor_span}, valid_{valid} {}

public:
    unknown_feature() = default;

    static unknown_feature decode(datum key, datum &d) {
        const uint8_t* begin = d.data;
        cbor::skip_cbor_value(d);
        datum span{begin, d.data};
        return unknown_feature{key, span, !d.is_null()};
    }

    bool is_valid() const { return valid_; }
    datum key() const { return key_; }
    datum cbor_span() const { return cbor_span_; }
};

using metadata_entry = std::variant<
    exposed_creds_message,
    crypto_cnsa_tls_message,
    crypto_cnsa_ssh_message,
    crypto_nist_message,
    unknown_feature
>;

struct cbor_decoded_metadata {
    static constexpr size_t MAX_ENTRIES = 8;
    metadata_entry entries[MAX_ENTRIES];
    size_t count = 0;
    bool valid = false;

    void reset() { count = 0; valid = false; }
};

static inline bool peek_cnsa_is_ssh(const uint8_t* begin, const uint8_t* end) {
    datum peek{begin, end};
    cbor::map m{peek};
    while (peek.is_not_empty() && !cbor::is_break(peek)) {
        cbor::text_string key = cbor::text_string::decode(peek);
        datum k = key.value();
        if (k.match("offered")) return true;
        if (k.match("client") || k.match("session")) return false;
        cbor::skip_cbor_value(peek);
    }
    return false;
}

inline void decode_v1(datum &d, cbor_decoded_metadata& out) {
    while (d.is_not_empty() && !cbor::is_break(d) && out.count < cbor_decoded_metadata::MAX_ENTRIES) {
        cbor::text_string feature_key = cbor::text_string::decode(d);
        if (d.is_null()) return;

        datum k = feature_key.value();
        if (k.match(exposed_creds_message::KEY_PLAINTEXT))
            out.entries[out.count++] = exposed_creds_message::decode(d, exposed_creds_message::KEY_PLAINTEXT);
        else if (k.match(exposed_creds_message::KEY_TOKEN))
            out.entries[out.count++] = exposed_creds_message::decode(d, exposed_creds_message::KEY_TOKEN);
        else if (k.match(exposed_creds_message::KEY_DERIVED))
            out.entries[out.count++] = exposed_creds_message::decode(d, exposed_creds_message::KEY_DERIVED);
        else if (k.match(crypto_cnsa_tls_message::KEY)) {
            if (peek_cnsa_is_ssh(d.data, d.data_end))
                out.entries[out.count++] = crypto_cnsa_ssh_message::decode(d);
            else
                out.entries[out.count++] = crypto_cnsa_tls_message::decode(d);
        }
        else if (k.match(crypto_nist_message::KEY))
            out.entries[out.count++] = crypto_nist_message::decode(d);
        else
            out.entries[out.count++] = unknown_feature::decode(feature_key.value(), d);

        if (d.is_null()) return;
    }
    // skip remaining entries if container was full
    while (d.is_not_empty() && !cbor::is_break(d)) {
        cbor::skip_cbor_value(d);  // key
        if (d.is_null()) return;
        cbor::skip_cbor_value(d);  // value
        if (d.is_null()) return;
    }
}

inline void decode_cbor_metadata(const uint8_t* buf, size_t len,
                                  cbor_decoded_metadata& out) {
    out.reset();
    if (!buf || len == 0) return;

    datum d{buf, buf + len};
    cbor::map outer{d};
    if (d.is_null()) return;

    if (d.is_not_empty() && !cbor::is_break(d)) {
        cbor::text_string ver_key = cbor::text_string::decode(d);
        if (d.is_null()) return;

        datum k = ver_key.value();
        if (k.match("v1")) {
            cbor::map inner{d};
            if (d.is_null()) return;
            decode_v1(d, out);
            inner.close();
        } else {
            cbor::skip_cbor_value(d);
        }
    }

    outer.close();
    out.valid = !d.is_null();
}

#endif // CBOR_DECODED_METADATA_HPP
