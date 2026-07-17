// cbor_decoded_metadata.hpp
//
// Decode container for the CBOR metadata interface.
// Used by the inspector to decode the buffer from get_cbor_metadata().

#ifndef CBOR_DECODED_METADATA_HPP
#define CBOR_DECODED_METADATA_HPP

#include <vector>
#include <tuple>
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

/// Per-thread decode container for CBOR metadata. Holds a typed slot for each REGISTERED
/// feature (in a std::tuple) plus an unknown vector for everything else. A feature must
/// provide the contract: static matches(datum), decode_into(datum,datum&), is_valid(),
/// cbor_span(), key(). Unregistered features flow through the unknown vector.
/// All datum accessors reference the source buffer passed to decode_cbor_metadata(); they
/// are invalidated when that buffer is freed or reused, and by the next decode (reset()).
template<class... Features>
struct typed_decoder {
    static constexpr size_t unknown_reserve_count = 1;

    std::tuple<Features...>      slots;
    std::vector<unknown_feature> unknown;
    cbor::text_string            truncation;   // packet-level status (see decode_v1); empty if absent
    bool valid = false;

    typed_decoder() { unknown.reserve(unknown_reserve_count); }

    void reset() {
        std::apply([](auto&... f){ ((f = {}), ...); }, slots);
        unknown.clear();
        truncation = {};
        valid = false;
    }

    // Route one feature key: the first registered feature whose matches() accepts it
    // decodes in place; if none match, capture it as an unknown_feature.
    template<class F>
    bool try_one(datum key, datum &d) {
        if (F::matches(key)) { std::get<F>(slots).decode_into(key, d); return true; }
        return false;
    }
    void dispatch(datum key, datum &d) {
        if (!(try_one<Features>(key, d) || ...)) {
            unknown.push_back(unknown_feature::decode(key, d));
        }
    }

    // Typed access to a registered feature (compile error if F is not registered).
    template<class F> const F& get() const { return std::get<F>(slots); }
};

/// cbor_decoded_metadata is the shipped decode container: a concrete, forward-declarable
/// struct (matching the `struct cbor_decoded_metadata;` forward declaration in the inspector's
/// mercury_config.h) deriving from an EMPTY typed_decoder<>. No feature is registered, so
/// every feature — known or future — flows through the `unknown` vector and is harvested
/// uniformly by key + CBOR span; the shipped path needs no typed field access. A consumer that
/// wants typed, fine-grained access to specific features instantiates
/// typed_decoder<Features...> with those features directly (see the unit tests).
struct cbor_decoded_metadata : typed_decoder<> {};

template<class Decoder>
inline void decode_v1(datum &d, Decoder& out) {
    while (d.is_not_empty() && !cbor::is_break(d)) {
        cbor::text_string feature_key = cbor::text_string::decode(d);
        if (d.is_null()) { return; }
        // "truncation" is a reserved packet-level status key in v1, not a feature: capture
        // it separately so it never lands in a feature slot or the unknown vector.
        if (feature_key.value().match(CBOR_METADATA_TRUNCATION_KEY)) {
            out.truncation = cbor::text_string::decode(d);
        } else {
            out.dispatch(feature_key.value(), d);
        }
        if (d.is_null()) { return; }
    }
}

/// Decode a CBOR metadata buffer into `out`. All datum-valued results (feature slots'
/// key()/cbor_span(), the unknown vector's spans, and `truncation`) are NON-OWNING views
/// into `buf` — they stay valid only while `buf` does. Copy or consume them before `buf`
/// is freed or reused (the mercury path reuses one buffer per packet).
template<class Decoder>
inline void decode_cbor_metadata(const uint8_t* buf, size_t len,
                                  Decoder& out) {
    out.reset();
    if (!buf || len == 0) { return; }

    bool recognized_version = false;

    datum d{buf, buf + len};
    cbor::map outer{d};
    if (d.is_null()) { return; }

    if (d.is_not_empty() && !cbor::is_break(d)) {
        cbor::text_string ver_key = cbor::text_string::decode(d);
        if (d.is_null()) { return; }

        datum k = ver_key.value();
        if (k.match(CBOR_METADATA_VERSION_KEY)) {
            recognized_version = true;
            cbor::map inner{d};
            if (d.is_null()) { return; }
            decode_v1(d, out);
            inner.close();
        } else {
            // Early bail out on unrecognized version key
            return;
        }
    }

    outer.close();

    out.valid = recognized_version && !d.is_null();
}

namespace {

    // Fuzz target for the shipped decoder: feed arbitrary bytes to
    // decode_cbor_metadata() and confirm it never crashes / reads out of bounds.
    // The generator script discovers this by its name suffix and drives it with
    // the seed corpus under test/fuzz/cbor_decoded_metadata/.
    [[maybe_unused]] int cbor_decoded_metadata_fuzz_test(const uint8_t *data, size_t size) {
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(data, size, decoded);
        return 0;
    }

}

#endif // CBOR_DECODED_METADATA_HPP
