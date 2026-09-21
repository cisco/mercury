// cbor_decoded_metadata.hpp
//
// Decode container for the CBOR metadata interface.

#ifndef CBOR_DECODED_METADATA_HPP
#define CBOR_DECODED_METADATA_HPP

#include <vector>
#include <tuple>
#include "cbor.hpp"
#include "cbor_object.hpp"
#include "cbor_messages.hpp"


/// Stores the key and CBOR span of a feature that the decoder does not recognize
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

/// Decode container for CBOR metadata. A key lands in exactly one
/// of three places: the reserved `truncation` member, a typed slot for a REGISTERED feature
/// (in a std::tuple), or the `unknown` vector.
template<class... Features>
struct typed_decoder {
    static constexpr size_t unknown_reserve_count = 1;

    std::tuple<Features...>      slots;
    std::vector<unknown_feature> unknown;
    truncation_message           truncation;   // reserved packet-level status (see dispatch)
    bool valid = false;

    typed_decoder() { unknown.reserve(unknown_reserve_count); }

    void reset() {
        std::apply([](auto&... f){ ((f = {}), ...); }, slots);
        unknown.clear();
        truncation = {};
        valid = false;
    }

    // Offer one key to one destination object: if it owns the key, it decodes in place and
    // consumes the value from d. Returns false without consuming if it does not.  A key this
    // object has already decoded is consumed and discarded, so the first occurrence is the one
    // kept.  A first occurrence that fails to decode nulls the datum and the walk returns, so
    // decoding does not continue past a failed key and no later occurrence of it is reached.
    template<class F>
    static bool try_one(F &f, datum key, datum &d) {
        if (!F::matches(key)) { return false; }
        if (f.is_valid()) { cbor::skip_cbor_value(d); return true; }
        f.decode_into(key, d);
        return true;
    }

    // true if an unrecognized key of this name has already been captured
    bool unknown_holds(datum key) const {
        for (const auto &u : unknown) {
            if (u.key().cmp(key) == 0) { return true; }
        }
        return false;
    }

    void dispatch(datum key, datum &d) {
        // Reserved keys first, then registered features; anything left over is unknown.
        if (!(try_one(truncation, key, d) || ... || try_one(std::get<Features>(slots), key, d))) {
            if (unknown_holds(key)) {   // first occurrence wins, as on the registered path
                cbor::skip_cbor_value(d);
                return;
            }
            unknown.push_back(unknown_feature::decode(key, d));
        }
    }

    // Typed access to a registered feature (compile error if F is not registered).
    template<class F> const F& get() const { return std::get<F>(slots); }
};

/// A typed_decoder that registers no feature, so every key is returned through
/// unknown() as a key and CBOR span.
struct cbor_decoded_metadata : typed_decoder<> {};

// Decode the inner v1 map: read each key and hand it to the decoder.
template<class Decoder>
inline void decode_v1(datum &d, Decoder& out) {
    while (d.is_not_empty() && !cbor::is_break(d)) {
        cbor::text_string key = cbor::text_string::decode(d);
        if (d.is_null()) { return; }
        out.dispatch(key.value(), d);
        if (d.is_null()) { return; }
    }
}

/// Decodes a CBOR metadata buffer into out. Every datum this yields, whether from a
/// feature slot, an unknown entry, or the truncation status, points into buf rather
/// than owning a copy. Consume or copy them before buf is freed or overwritten.
template<class Decoder>
inline void decode_cbor_metadata(const uint8_t* buf, size_t len,
                                  Decoder& out) {
    out.reset();
    if (!buf || len == 0) { return; }

    datum d{buf, buf + len};
    cbor::map outer{d};        // head is checked here; the break is not required
    if (d.is_null()) { return; }

    bool version_decoded = false;   // CBOR_METADATA_VERSION_KEY is decoded once

    while (d.is_not_empty() && !cbor::is_break(d)) {
        cbor::text_string ver_key = cbor::text_string::decode(d);
        if (d.is_null()) { return; }

        if (!version_decoded && ver_key.value().match(CBOR_METADATA_VERSION_KEY.c_str())) {
            version_decoded = true;
            cbor::map inner{d};
            if (d.is_null()) { return; }
            decode_v1(d, out);
            if (d.is_null()) { return; }
            inner.close();
            if (d.is_null()) { return; }
            // Only CBOR_METADATA_VERSION_KEY is decoded, which today is v1; the
            // loop walks d so that other versions can be skipped.  If a schema
            // change brings a v2, the library may emit both so that consumers
            // built against v1 keep working.
            //
            // valid is set here, inside the loop, because inner.close() has
            // already consumed v1's break: v1 is complete at this point, and
            // nothing later in the buffer takes that away -- neither a malformed
            // sibling version nor a missing outer break.  valid means v1 was
            // decoded, not that the buffer is well formed: a malformed sibling
            // returns from the skip below, and a malformed v1 head or body returns
            // from the checks above, so neither reaches this line.
            out.valid = true;
        } else {
            // a version this decoder does not implement, or a repeat of the one it
            // does.  Keys should not be repeated in this interface, and if a key is
            // repeated anyway only the first occurrence is considered and the rest
            // are skipped.
            cbor::skip_cbor_value(d);
            if (d.is_null()) { return; }
        }
    }
}

namespace {

    [[maybe_unused]] int cbor_decoded_metadata_fuzz_test(const uint8_t *data, size_t size) {
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(data, size, decoded);
        return 0;
    }

}

#endif // CBOR_DECODED_METADATA_HPP
