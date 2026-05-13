// cbor_decoded_metadata.hpp
//
// Decode container for the CBOR metadata interface.
// Used by the inspector to decode the buffer from get_cbor_metadata().

#ifndef CBOR_DECODED_METADATA_HPP
#define CBOR_DECODED_METADATA_HPP

#include <variant>
#include "cbor.hpp"
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
    exposed_creds_plaintext_message,
    exposed_creds_token_message,
    exposed_creds_derived_message,
    crypto_cnsa_message,
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

inline void decode_cbor_metadata(const uint8_t* buf, size_t len,
                                  cbor_decoded_metadata& out) {
    out.reset();
    if (!buf || len == 0) return;

    datum d{buf, buf + len};
    cbor::map m{d};
    if (d.is_null()) return;

    while (d.is_not_empty() && *d.data != 0xff && out.count < cbor_decoded_metadata::MAX_ENTRIES) {
        cbor::text_string feature_key = cbor::text_string::decode(d);
        if (d.is_null()) return;

        datum k = feature_key.value();
        if (k.match(exposed_creds_plaintext_message::KEY))
            out.entries[out.count++] = exposed_creds_plaintext_message::decode(d);
        else if (k.match(exposed_creds_token_message::KEY))
            out.entries[out.count++] = exposed_creds_token_message::decode(d);
        else if (k.match(exposed_creds_derived_message::KEY))
            out.entries[out.count++] = exposed_creds_derived_message::decode(d);
        else if (k.match(crypto_cnsa_message::KEY))
            out.entries[out.count++] = crypto_cnsa_message::decode(d);
        else if (k.match(crypto_nist_message::KEY))
            out.entries[out.count++] = crypto_nist_message::decode(d);
        else
            out.entries[out.count++] = unknown_feature::decode(feature_key.value(), d);

        if (d.is_null()) return;
    }

    m.close();
    out.valid = !d.is_null();
}

#endif // CBOR_DECODED_METADATA_HPP
