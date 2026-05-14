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

inline void decode_v1(datum &d, cbor_decoded_metadata& out) {
    while (d.is_not_empty() && !cbor::is_break(d) && out.count < cbor_decoded_metadata::MAX_ENTRIES) {
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
}

inline void decode_cbor_metadata(const uint8_t* buf, size_t len,
                                  cbor_decoded_metadata& out) {
    out.reset();
    if (!buf || len == 0) return;

    datum d{buf, buf + len};
    cbor::map m{d};
    if (d.is_null()) return;

    // first key-value pair must be schema_version
    if (d.is_not_empty() && !cbor::is_break(d)) {
        cbor::text_string ver_key = cbor::text_string::decode(d);
        if (d.is_null() || !ver_key.value().match("schema_version")) return;
        cbor::uint64 ver{d};
        if (d.is_null()) return;

        uint32_t version = ver.value();
        if (version == 1) {
            decode_v1(d, out);
        } else if (version > CBOR_METADATA_SCHEMA_VERSION) {
            return;  // future schema — fail-fast
        }
    }

    m.close();
    out.valid = !d.is_null();
}

inline bool cbor_metadata_unit_test(FILE *f = nullptr) {
    bool all_passed = true;

    auto report = [&](const char *name, bool pass) {
        if (!pass) {
            all_passed = false;
            if (f) fprintf(f, "  FAIL: %s\n", name);
        } else {
            if (f) fprintf(f, "  pass: %s\n", name);
        }
    };

    // Test 1: exposed_creds_plaintext round-trip
    {
        data_buffer<512> buf;
        cbor_object outer{buf};
        outer.print_key_uint("schema_version", CBOR_METADATA_SCHEMA_VERSION);
        auto msg = exposed_creds_plaintext_message::construct(
            datum{"imap"}, datum{"LOGIN"}, datum{"alice"});
        msg.template write<cbor_object, cbor_array>(outer);
        outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("exposed_creds_plaintext decode valid", decoded.valid);
        report("exposed_creds_plaintext count == 1", decoded.count == 1);

        if (decoded.count >= 1) {
            bool is_plaintext = std::holds_alternative<exposed_creds_plaintext_message>(decoded.entries[0]);
            report("exposed_creds_plaintext variant type", is_plaintext);
            if (is_plaintext) {
                auto &dec = std::get<exposed_creds_plaintext_message>(decoded.entries[0]);
                report("protocol == imap", dec.protocol().match("imap"));
                report("auth_method == LOGIN", dec.auth_method().match("LOGIN"));
                report("username == alice", dec.username().match("alice"));
                report("key == exposed_credentials_plaintext",
                       dec.key().match("exposed_credentials_plaintext"));
            }
        }
    }

    // Test 2: exposed_creds_token round-trip
    {
        data_buffer<512> buf;
        cbor_object outer{buf};
        outer.print_key_uint("schema_version", CBOR_METADATA_SCHEMA_VERSION);
        auto msg = exposed_creds_token_message::construct(
            datum{"imap"}, datum{"OAUTHBEARER"}, datum{});
        msg.template write<cbor_object, cbor_array>(outer);
        outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("exposed_creds_token decode valid", decoded.valid);
        report("exposed_creds_token count == 1", decoded.count == 1);
        if (decoded.count >= 1) {
            bool is_token = std::holds_alternative<exposed_creds_token_message>(decoded.entries[0]);
            report("exposed_creds_token variant type", is_token);
            if (is_token) {
                auto &dec = std::get<exposed_creds_token_message>(decoded.entries[0]);
                report("protocol == imap", dec.protocol().match("imap"));
                report("auth_method == OAUTHBEARER", dec.auth_method().match("OAUTHBEARER"));
                report("username is empty (not readable)", !dec.username().is_readable());
            }
        }
    }

    // Test 3: crypto_cnsa round-trip
    {
        data_buffer<1024> buf;
        cbor_object outer{buf};
        outer.print_key_uint("schema_version", CBOR_METADATA_SCHEMA_VERSION);

        crypto_cnsa_message msg;
        msg.set_policy("quantum_safe");
        msg.set_target("client");
        msg.add_cs_not_allowed("TLS_RSA_WITH_RC4_128_SHA");
        msg.set_cs_allowed("some");
        msg.set_grp_allowed("all");
        msg.set_psk_mode(false);
        msg.set_compliant(false);
        msg.set_valid();

        cbor::text_string(crypto_cnsa_message::KEY).write(buf);
        msg.template write<cbor_object, cbor_array>(outer);
        outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("crypto_cnsa decode valid", decoded.valid);
        report("crypto_cnsa count == 1", decoded.count == 1);
        if (decoded.count >= 1) {
            bool is_cnsa = std::holds_alternative<crypto_cnsa_message>(decoded.entries[0]);
            report("crypto_cnsa variant type", is_cnsa);
            if (is_cnsa) {
                auto &dec = std::get<crypto_cnsa_message>(decoded.entries[0]);
                report("cnsa is_valid", dec.is_valid());
                report("cnsa key matches", dec.key().match("cnsa_2_0_non_conformant"));
            }
        }
    }

    // Test 4: multiple features in one buffer
    {
        data_buffer<2048> buf;
        cbor_object outer{buf};
        outer.print_key_uint("schema_version", CBOR_METADATA_SCHEMA_VERSION);

        exposed_creds_plaintext_message::construct(
            datum{"http"}, datum{"basic"}, datum{"admin"})
            .template write<cbor_object, cbor_array>(outer);

        crypto_cnsa_message cnsa;
        cnsa.set_policy("quantum_safe");
        cnsa.set_target("session");
        cnsa.set_cs_allowed("all");
        cnsa.set_grp_allowed("all");
        cnsa.set_psk_mode(false);
        cnsa.set_valid();
        cbor::text_string(crypto_cnsa_message::KEY).write(buf);
        cnsa.template write<cbor_object, cbor_array>(outer);

        outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("multi-feature decode valid", decoded.valid);
        report("multi-feature count == 2", decoded.count == 2);
        if (decoded.count >= 2) {
            report("entry[0] is exposed_creds_plaintext",
                   std::holds_alternative<exposed_creds_plaintext_message>(decoded.entries[0]));
            report("entry[1] is crypto_cnsa",
                   std::holds_alternative<crypto_cnsa_message>(decoded.entries[1]));
        }
    }

    // Test 5: empty buffer
    {
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(nullptr, 0, decoded);
        report("empty buffer valid == false", !decoded.valid);
        report("empty buffer count == 0", decoded.count == 0);
    }

    // Test 6: unknown feature forwarded
    {
        data_buffer<512> buf;
        cbor_object outer{buf};
        outer.print_key_uint("schema_version", CBOR_METADATA_SCHEMA_VERSION);
        outer.print_key_string("some_future_feature", "some_value");
        outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("unknown feature decode valid", decoded.valid);
        report("unknown feature count == 1", decoded.count == 1);
        if (decoded.count >= 1) {
            report("entry[0] is unknown_feature",
                   std::holds_alternative<unknown_feature>(decoded.entries[0]));
            if (std::holds_alternative<unknown_feature>(decoded.entries[0])) {
                auto &uf = std::get<unknown_feature>(decoded.entries[0]);
                report("unknown key matches", uf.key().match("some_future_feature"));
            }
        }
    }

    return all_passed;
}

#endif // CBOR_DECODED_METADATA_HPP
