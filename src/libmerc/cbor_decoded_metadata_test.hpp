// cbor_decoded_metadata_test.hpp
//
// Unit tests for the CBOR metadata decode interface.
// This file is NOT copied to the inspector — tests only run in the mercury build.
//
// Two decoder shapes are exercised:
//   - full_decoder = typed_decoder<exposed_creds_message, cnsa_feature, crypto_nist_message>
//     is what a consumer that wants typed, fine-grained field access instantiates. Group A
//     tests feature-decode correctness through it (matches / decode_into / typed fields).
//   - cbor_decoded_metadata = typed_decoder<> is the SHIPPED container (library + inspector).
//     Nothing is registered, so every feature — known or future — flows through the `unknown`
//     vector and is harvested uniformly by key + CBOR span. Group B tests that path's edge cases.

#ifndef CBOR_DECODED_METADATA_TEST_HPP
#define CBOR_DECODED_METADATA_TEST_HPP

#include "cbor_decoded_metadata.hpp"
#include "cbor_metadata.hpp"

inline bool cbor_metadata_unit_test(FILE *f = nullptr) {
    bool all_passed = true;

    auto report = [&](const char *name, bool pass) {
        if (!pass) {
            all_passed = false;
            if (f) { fprintf(f, "  FAIL: %s\n", name); }
        } else {
            if (f) { fprintf(f, "  pass: %s\n", name); }
        }
    };

    // A decoder that registers every known feature, giving typed slot access via get<F>().
    // Group A uses this to verify per-feature decode correctness.
    using full_decoder = typed_decoder<exposed_creds_message, cnsa_feature, crypto_nist_message>;

    // Renders a decoded CBOR span to a JSON object string (the inspector's harvest step).
    auto render_json = [](datum span) -> std::string {
        output_buffer<4096> buf;
        if (decode_cbor_map_to_json(span, buf, nullptr)) {
            return std::string(buf.dstr, buf.length());
        }
        return std::string();
    };

    // ================================================================
    // Group A — feature-decode correctness via full_decoder (typed slots)
    // ================================================================

    // Test 1: exposed_creds — all three kinds (plaintext / token / derived) route to the
    // exposed_creds slot with the right fields and key.
    {
        // 1a: plaintext (username readable)
        {
            data_buffer<512> buf;
            cbor_object cbor_outer{buf};
            cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
            exposed_creds_message::construct(exposed_creds_message::KEY_PLAINTEXT,
                datum{"imap"}, datum{"LOGIN"}, datum{"alice"}).template write<cbor_object>(outer);
            outer.close();
            cbor_outer.close();

            datum encoded = buf.contents();
            full_decoder d;
            decode_cbor_metadata(encoded.data, encoded.length(), d);
            report("exposed_creds plaintext valid", d.valid);
            report("exposed_creds plaintext only-slot",
                   d.get<exposed_creds_message>().is_valid()
                   && d.get<cnsa_feature>().tls_if() == nullptr
                   && d.get<cnsa_feature>().ssh_if() == nullptr
                   && !d.get<crypto_nist_message>().is_valid() && d.unknown.empty());
            auto &ec = d.get<exposed_creds_message>();
            report("plaintext protocol == imap", ec.protocol().match("imap"));
            report("plaintext auth_method == LOGIN", ec.auth_method().match("LOGIN"));
            report("plaintext username == alice", ec.username().match("alice"));
            report("plaintext key", ec.key().match("exposed_credentials_plaintext"));
        }
        // 1b: token (username empty / not readable)
        {
            data_buffer<512> buf;
            cbor_object cbor_outer{buf};
            cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
            exposed_creds_message::construct(exposed_creds_message::KEY_TOKEN,
                datum{"imap"}, datum{"OAUTHBEARER"}, datum{}).template write<cbor_object>(outer);
            outer.close();
            cbor_outer.close();

            datum encoded = buf.contents();
            full_decoder d;
            decode_cbor_metadata(encoded.data, encoded.length(), d);
            auto &ec = d.get<exposed_creds_message>();
            report("token valid + slot", d.valid && ec.is_valid());
            report("token auth_method == OAUTHBEARER", ec.auth_method().match("OAUTHBEARER"));
            report("token username not readable", !ec.username().is_readable());
        }
        // 1c: derived
        {
            data_buffer<512> buf;
            cbor_object cbor_outer{buf};
            cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
            exposed_creds_message::construct(exposed_creds_message::KEY_DERIVED,
                datum{"ldap"}, datum{"DIGEST-MD5"}, datum{}).template write<cbor_object>(outer);
            outer.close();
            cbor_outer.close();

            datum encoded = buf.contents();
            full_decoder d;
            decode_cbor_metadata(encoded.data, encoded.length(), d);
            auto &ec = d.get<exposed_creds_message>();
            report("derived valid + slot", d.valid && ec.is_valid());
            report("derived protocol == ldap", ec.protocol().match("ldap"));
            report("derived key", ec.key().match("exposed_credentials_derived"));
        }
    }

    // Test 2: crypto_cnsa TLS — string fields + PSK, hex cipher/group values, and a
    // forward-compat unknown field inside the target map (must be skipped, decode still valid).
    {
        // 2a: string values + multiple PSK non-compliant entries
        {
            data_buffer<2048> buf;
            cbor_object cbor_outer{buf};
            cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
            crypto_cnsa_tls_message msg;
            msg.set_policy("quantum_safe");
            msg.set_target("client");
            msg.add_cs_not_allowed("TLS_RSA_WITH_RC4_128_SHA");
            msg.set_cs_allowed("some");
            msg.set_grp_allowed("all");
            msg.set_psk_mode(true);
            msg.set_psk_non_compliant("tls_cert_with_extern_psk_non_compliant",
                                      "tls_cert_with_extern_psk requires pre_shared_key, psk_key_exchange_modes, and key_share");
            msg.set_psk_non_compliant("psk_key_exchange_modes_non_compliant",
                                      "psk_key_exchange_modes must include psk_dhe_ke and must not include psk_ke");
            msg.set_compliant(false);
            msg.set_valid();
            cbor::text_string(crypto_cnsa_tls_message::KEY).write(buf);
            msg.template write<cbor_object>(outer);
            outer.close();
            cbor_outer.close();

            datum encoded = buf.contents();
            full_decoder d;
            decode_cbor_metadata(encoded.data, encoded.length(), d);
            report("cnsa tls only-slot",
                   d.valid && d.get<cnsa_feature>().tls_if() != nullptr
                   && d.get<cnsa_feature>().ssh_if() == nullptr
                   && !d.get<exposed_creds_message>().is_valid()
                   && !d.get<crypto_nist_message>().is_valid() && d.unknown.empty());
            auto &c = *d.get<cnsa_feature>().tls_if();
            report("cnsa tls is_valid + key", c.is_valid() && c.key().match("cnsa_2_0_non_conformant"));
            report("cnsa tls psk_count == 2", c.psk_non_compliant_count() == 2);
            if (c.psk_non_compliant_count() >= 2) {
                report("cnsa psk[0] key", c.psk_non_compliant_key_at(0).value().match("tls_cert_with_extern_psk_non_compliant"));
                report("cnsa psk[1] key", c.psk_non_compliant_key_at(1).value().match("psk_key_exchange_modes_non_compliant"));
            }
        }
        // 2b: numeric cipher-suite and group codes (exercises print_uint)
        {
            data_buffer<1024> buf;
            cbor_object cbor_outer{buf};
            cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
            crypto_cnsa_tls_message msg;
            msg.set_policy("quantum_safe");
            msg.set_target("client");
            msg.add_cs_not_allowed_hex(0xc02c);
            msg.add_cs_not_allowed_hex(0x0005);
            msg.add_grp_not_allowed_hex(0x001d);
            msg.set_cs_allowed("some");
            msg.set_grp_allowed("some");
            msg.set_psk_mode(false);
            msg.set_valid();
            cbor::text_string(crypto_cnsa_tls_message::KEY).write(buf);
            msg.template write<cbor_object>(outer);
            outer.close();
            cbor_outer.close();

            datum encoded = buf.contents();
            full_decoder d;
            decode_cbor_metadata(encoded.data, encoded.length(), d);
            report("cnsa code slot", d.valid && d.get<cnsa_feature>().tls_if() != nullptr);
            auto &c = *d.get<cnsa_feature>().tls_if();
            report("cnsa code cs_count == 2", c.cs_not_allowed_count() == 2);
            if (c.cs_not_allowed_count() >= 2) {
                report("cnsa code cs[0] numeric", c.cs_not_allowed_is_hex(0));
                report("cnsa code cs[0] == 0xc02c", c.cs_not_allowed_code_at(0) == 0xc02c);
                report("cnsa code cs[1] numeric", c.cs_not_allowed_is_hex(1));
                report("cnsa code cs[1] == 0x0005", c.cs_not_allowed_code_at(1) == 0x0005);
            }
            report("cnsa code grp_count == 1", c.grp_not_allowed_count() == 1);
            if (c.grp_not_allowed_count() >= 1) {
                report("cnsa code grp[0] numeric", c.grp_not_allowed_is_hex(0));
                report("cnsa code grp[0] == 0x001d", c.grp_not_allowed_code_at(0) == 0x001d);
            }
        }
        // 2b': mixed array — one name, one numeric code. Exercises the decode peek
        // branch routing each element by its major type.
        {
            data_buffer<1024> buf;
            cbor_object cbor_outer{buf};
            cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
            crypto_cnsa_tls_message msg;
            msg.set_policy("quantum_safe");
            msg.set_target("client");
            msg.add_cs_not_allowed("TLS_RSA_WITH_RC4_128_SHA");
            msg.add_cs_not_allowed_hex(0xc02c);
            msg.set_cs_allowed("some");
            msg.set_grp_allowed("all");
            msg.set_psk_mode(false);
            msg.set_valid();
            cbor::text_string(crypto_cnsa_tls_message::KEY).write(buf);
            msg.template write<cbor_object>(outer);
            outer.close();
            cbor_outer.close();

            datum encoded = buf.contents();
            full_decoder d;
            decode_cbor_metadata(encoded.data, encoded.length(), d);
            report("cnsa mixed slot", d.valid && d.get<cnsa_feature>().tls_if() != nullptr);
            auto &c = *d.get<cnsa_feature>().tls_if();
            report("cnsa mixed cs_count == 2", c.cs_not_allowed_count() == 2);
            if (c.cs_not_allowed_count() >= 2) {
                report("cnsa mixed cs[0] textual", !c.cs_not_allowed_is_hex(0));
                report("cnsa mixed cs[0] name",
                       c.cs_not_allowed_at(0).value().match("TLS_RSA_WITH_RC4_128_SHA"));
                report("cnsa mixed cs[1] numeric", c.cs_not_allowed_is_hex(1));
                report("cnsa mixed cs[1] == 0xc02c", c.cs_not_allowed_code_at(1) == 0xc02c);
            }
        }
        // 2c: forward-compat unknown field in the target map is skipped; decode still valid
        {
            data_buffer<2048> buf;
            cbor_object cbor_outer{buf};
            cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
            cbor::text_string(crypto_cnsa_tls_message::KEY).write(buf);
            cbor_object cnsa_body{outer};
            cnsa_body.print_key_string("policy", "quantum_safe");
            cbor_object target{cnsa_body, "client"};
            target.print_key_string("ciphersuites_allowed", "all");
            target.print_key_string("groups_allowed", "all");
            target.print_key_bool("tls_cert_with_extern_psk", false);
            target.print_key_string("signature_algorithms_not_allowed", "rsa_pkcs1_sha256"); // future field
            target.close();
            cnsa_body.close();
            outer.close();
            cbor_outer.close();

            datum encoded = buf.contents();
            full_decoder d;
            decode_cbor_metadata(encoded.data, encoded.length(), d);
            report("cnsa fwd-compat slot", d.valid && d.get<cnsa_feature>().tls_if() != nullptr);
            auto &c = *d.get<cnsa_feature>().tls_if();
            report("cnsa fwd-compat is_valid", c.is_valid());
            report("cnsa fwd-compat cs/grp allowed", c.cs_allowed_valid() && c.grp_allowed_valid());
            report("cnsa fwd-compat psk_count == 0", c.psk_non_compliant_count() == 0);
        }
    }

    // Test 3: crypto_cnsa SSH — routes to the ssh side of cnsa_feature via the cnsa_variant
    // discriminator (never to tls).
    {
        data_buffer<1024> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        crypto_cnsa_ssh_message msg;
        msg.set_policy("quantum_safe");
        msg.add_kex_not_allowed("curve25519-sha256");
        msg.set_kex_allowed("none");
        msg.add_c2s_cs_not_allowed("chacha20-poly1305@openssh.com");
        msg.add_s2c_cs_not_allowed("chacha20-poly1305@openssh.com");
        msg.set_compliant(false);
        msg.set_valid();
        cbor::text_string(crypto_cnsa_ssh_message::KEY).write(buf);
        msg.template write<cbor_object>(outer);
        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        full_decoder d;
        decode_cbor_metadata(encoded.data, encoded.length(), d);
        report("cnsa ssh valid", d.valid);
        report("cnsa ssh routed to ssh (not tls)",
               d.get<cnsa_feature>().ssh_if() != nullptr
               && d.get<cnsa_feature>().tls_if() == nullptr
               && !d.get<exposed_creds_message>().is_valid()
               && !d.get<crypto_nist_message>().is_valid() && d.unknown.empty());
        report("cnsa ssh key",
               d.get<cnsa_feature>().ssh_if() != nullptr
               && d.get<cnsa_feature>().ssh_if()->key().match("cnsa_2_0_non_conformant"));
    }

    // Test 4: cnsa_variant routing is order-independent — the discriminator placed AFTER the
    // structural "client" key must still route to the tls side (no reliance on key order).
    {
        data_buffer<1024> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        cbor::text_string(crypto_cnsa_tls_message::KEY).write(buf);
        {
            cbor_object cnsa{outer};
            cnsa.print_key_string("policy", "quantum_safe");
            {
                cbor_object tgt{cnsa, "client"};                  // structural key first
                tgt.print_key_string("ciphersuites_allowed", "none");
                tgt.print_key_bool("tls_cert_with_extern_psk", false);
                tgt.close();
            }
            cnsa.print_key_string("cnsa_variant", "tls");         // discriminator last
            cnsa.close();
        }
        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        full_decoder d;
        decode_cbor_metadata(encoded.data, encoded.length(), d);
        report("cnsa order-independent valid", d.valid);
        report("cnsa_variant after target still routes to tls",
               d.get<cnsa_feature>().tls_if() != nullptr && d.get<cnsa_feature>().ssh_if() == nullptr);
    }

    // Test 5: crypto_nist round-trip.
    {
        data_buffer<1024> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        crypto_nist_message nist;
        nist.set_policy("nist_sp_800_52_2");
        nist.set_has_negotiated_params();
        nist.set_protocol_version("TLSv1.0");
        nist.set_cipher_suite("TLS_RSA_WITH_RC4_128_SHA");
        nist.set_supported_group("UNKNOWN");
        nist.set_non_compliant("tls_version_non_compliant", "TLSv1.0");
        nist.set_valid();
        cbor::text_string(crypto_nist_message::KEY).write(buf);
        nist.template write<cbor_object>(outer);
        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        full_decoder d;
        decode_cbor_metadata(encoded.data, encoded.length(), d);
        report("nist only-slot",
               d.valid && d.get<crypto_nist_message>().is_valid()
               && !d.get<exposed_creds_message>().is_valid()
               && d.get<cnsa_feature>().tls_if() == nullptr
               && d.get<cnsa_feature>().ssh_if() == nullptr && d.unknown.empty());
        report("nist key", d.get<crypto_nist_message>().key().match("nist_sp_800_52_2_non_conformant"));
    }

    // Test 6: multiple registered features in one buffer land in their respective slots.
    {
        data_buffer<2048> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        exposed_creds_message::construct(exposed_creds_message::KEY_PLAINTEXT,
            datum{"http"}, datum{"basic"}, datum{"admin"}).template write<cbor_object>(outer);
        crypto_cnsa_tls_message cnsa;
        cnsa.set_policy("quantum_safe");
        cnsa.set_target("session");
        cnsa.set_cs_allowed("all");
        cnsa.set_grp_allowed("all");
        cnsa.set_psk_mode(false);
        cnsa.set_valid();
        cbor::text_string(crypto_cnsa_tls_message::KEY).write(buf);
        cnsa.template write<cbor_object>(outer);
        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        full_decoder d;
        decode_cbor_metadata(encoded.data, encoded.length(), d);
        report("multi-feature valid", d.valid);
        report("multi-feature both slots",
               d.get<exposed_creds_message>().is_valid()
               && d.get<cnsa_feature>().tls_if() != nullptr
               && d.get<cnsa_feature>().ssh_if() == nullptr
               && !d.get<crypto_nist_message>().is_valid() && d.unknown.empty());
    }

    // Test 7: cbor_metadata_buffer has_data gating — no feature written, feature written,
    // and reset clears the flag (producer-side plumbing used by the packet path).
    {
        // 7a: no feature written -> no data
        {
            cbor_metadata_buffer ctx{};   // default (4096) buffer
            ctx.reset();
            writeable& w = ctx.get_writer();
            cbor_object cbor_outer{w};
            cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
            outer.close();
            cbor_outer.close();
            report("no-feature has_data == false", !ctx.has_data());
            report("no-feature length == 0", ctx.get_length() == 0);
        }
        // 7b: feature written -> data present and decodable (as an unknown on the shipped type)
        {
            cbor_metadata_buffer ctx{};   // default (4096) buffer
            ctx.reset();
            writeable& w = ctx.get_writer();
            cbor_object cbor_outer{w};
            cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
            exposed_creds_message::construct(exposed_creds_message::KEY_PLAINTEXT,
                datum{"http"}, datum{"basic"}, datum{"admin"}).template write<cbor_object>(outer);
            ctx.set_feature_written();
            outer.close();
            cbor_outer.close();
            report("with-feature has_data == true", ctx.has_data());
            report("with-feature length > 0", ctx.get_length() > 0);

            cbor_decoded_metadata decoded;
            decode_cbor_metadata(ctx.get_buffer(), ctx.get_length(), decoded);
            report("with-feature decode valid", decoded.valid);
            report("with-feature -> one unknown",
                   decoded.unknown.size() == 1
                   && decoded.unknown[0].key().match("exposed_credentials_plaintext"));
        }
        // 7c: reset clears the flag
        {
            cbor_metadata_buffer ctx{};   // default (4096) buffer
            ctx.reset();
            writeable& w = ctx.get_writer();
            cbor_object cbor_outer{w};
            cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
            ctx.set_feature_written();
            outer.close();
            cbor_outer.close();
            report("before reset has_data == true", ctx.has_data());

            ctx.reset();
            writeable& w2 = ctx.get_writer();
            cbor_object cbor_outer2{w2};
            cbor_object outer2{cbor_outer2, CBOR_METADATA_VERSION_KEY};
            outer2.close();
            cbor_outer2.close();
            report("after reset has_data == false", !ctx.has_data());
        }
        // 7d: truncation status key — a reserved packet-level status, NOT a feature. Mirrors
        // the producer: emit "truncation" as part of the header WITHOUT set_feature_written,
        // then write a feature + set_feature_written. dispatch() must route it into
        // decoded.truncation (its own truncation_message member), NOT into a feature slot and
        // NOT into the unknown vector; a truncation-only buffer (no feature) is still dropped.
        {
            // feature + truncation -> buffer delivered; truncation captured separately
            cbor_metadata_buffer ctx{};   // default (4096) buffer
            ctx.reset();
            writeable& w = ctx.get_writer();
            cbor_object cbor_outer{w};
            cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
            outer.print_key_string(CBOR_METADATA_TRUNCATION_KEY, "truncated"); // not a feature
            exposed_creds_message::construct(exposed_creds_message::KEY_PLAINTEXT,
                datum{"http"}, datum{"basic"}, datum{"admin"}).template write<cbor_object>(outer);
            ctx.set_feature_written();
            outer.close();
            cbor_outer.close();
            report("truncation: has_data with feature", ctx.has_data());

            cbor_decoded_metadata decoded;
            decode_cbor_metadata(ctx.get_buffer(), ctx.get_length(), decoded);
            report("truncation: decode valid", decoded.valid);
            report("truncation: captured in decoded.truncation",
                   decoded.truncation.is_valid()
                   && decoded.truncation.status().match("truncated"));
            // The feature is still present, and truncation did NOT leak into the unknown
            // vector.
            report("truncation: feature intact, not in unknown",
                   decoded.unknown.size() == 1
                   && decoded.unknown[0].key().match("exposed_credentials_plaintext")
                   && !decoded.unknown[0].key().match(truncation_message::KEY));

            // truncation-only buffer (no feature written) -> dropped by the feature-written gate
            cbor_metadata_buffer ctx2{};
            ctx2.reset();
            writeable& w2 = ctx2.get_writer();
            cbor_object cbor_outer2{w2};
            cbor_object outer2{cbor_outer2, CBOR_METADATA_VERSION_KEY};
            outer2.print_key_string(CBOR_METADATA_TRUNCATION_KEY, "none");     // no set_feature_written
            outer2.close();
            cbor_outer2.close();
            report("truncation-only: has_data == false (dropped)", !ctx2.has_data());
            report("truncation-only: length == 0", ctx2.get_length() == 0);
        }
    }

    // ================================================================
    // Group B — SHIPPED container cbor_decoded_metadata = typed_decoder<>
    // (nothing registered: EVERY feature falls through to the unknown vector)
    // ================================================================

    // Test 8: a known feature (cnsa) with an EMPTY registration is NOT dropped — it is captured
    // in the unknown vector with its key and a CBOR span that renders back to JSON (the exact
    // path the inspector's harvest_cbor_metadata relies on).
    {
        data_buffer<1024> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        crypto_cnsa_tls_message msg;
        msg.set_policy("quantum_safe");
        msg.set_target("client");
        msg.set_cs_allowed("none");
        msg.set_valid();
        cbor::text_string(crypto_cnsa_tls_message::KEY).write(buf);
        msg.template write<cbor_object>(outer);
        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;                 // typed_decoder<>
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);
        report("shipped: valid on recognized version", decoded.valid);
        report("shipped: cnsa captured as unknown",
               decoded.unknown.size() == 1
               && decoded.unknown[0].is_valid()
               && decoded.unknown[0].key().match("cnsa_2_0_non_conformant"));
        if (decoded.unknown.size() == 1) {
            std::string js = render_json(decoded.unknown[0].cbor_span());
            report("shipped: cnsa span renders JSON", !js.empty());
            report("shipped: JSON has policy",
                   js.find("\"policy\":\"quantum_safe\"") != std::string::npos);
        }
    }

    // Test 9: several features (two known + one future-unknown) in one buffer ALL land in the
    // unknown vector, in order, each with its own key — count and keys verified.
    {
        data_buffer<2048> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        // known: exposed_creds
        exposed_creds_message::construct(exposed_creds_message::KEY_PLAINTEXT,
            datum{"http"}, datum{"basic"}, datum{"admin"}).template write<cbor_object>(outer);
        // known: nist
        crypto_nist_message nist;
        nist.set_policy("nist_sp_800_52_2");
        nist.set_has_negotiated_params();
        nist.set_non_compliant("tls_version_non_compliant", "TLSv1.0");
        nist.set_valid();
        cbor::text_string(crypto_nist_message::KEY).write(buf);
        nist.template write<cbor_object>(outer);
        // future / unregistered feature
        cbor_object fut{outer, "future_detection"};
        fut.print_key_string("severity", "high");
        fut.close();
        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);
        report("shipped multi: valid", decoded.valid);
        report("shipped multi: 3 unknowns in order",
               decoded.unknown.size() == 3
               && decoded.unknown[0].key().match("exposed_credentials_plaintext")
               && decoded.unknown[1].key().match("nist_sp_800_52_2_non_conformant")
               && decoded.unknown[2].key().match("future_detection"));
        report("shipped multi: future span renders JSON",
               decoded.unknown.size() == 3
               && render_json(decoded.unknown[2].cbor_span()).find("\"severity\":\"high\"") != std::string::npos);
    }

    // Test 10: empty buffer -> not valid, nothing captured.
    {
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(nullptr, 0, decoded);
        report("shipped empty: valid == false", !decoded.valid);
        report("shipped empty: unknown empty", decoded.unknown.empty());
    }

    // Test 11: unrecognized outer version wrapper -> early bail, not valid, nothing captured
    // (forward-compat: an old decoder must reject a future schema wrapper rather than mis-decode).
    {
        data_buffer<256> buf;
        cbor_object cbor_outer{buf};
        cbor_object cbor_inner{cbor_outer, "v99"};
        cbor_inner.print_key_string("some_key", "some_value");
        cbor_inner.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);
        report("shipped bad-version: valid == false", !decoded.valid);
        report("shipped bad-version: unknown empty", decoded.unknown.empty());
    }

    // Test 12: unknown vector reserve floor + grow-on-demand + capacity RETAINED across the
    // reset() that decode_cbor_metadata performs at entry (no per-packet reallocation churn).
    {
        cbor_decoded_metadata decoded;
        report("shipped: initial capacity == reserve floor",
               decoded.unknown.capacity() == cbor_decoded_metadata::unknown_reserve_count);

        // 6 unknowns (> reserve floor) forces a grow.
        data_buffer<4096> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        for (int i = 0; i < 6; i++) {
            char key_name[32];
            snprintf(key_name, sizeof(key_name), "future_feature_%d", i);
            cbor_object feat{outer, key_name};
            feat.print_key_string("data", "value");
            feat.close();
        }
        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);
        report("shipped: grew to 6 unknowns", decoded.unknown.size() == 6);
        size_t grown_capacity = decoded.unknown.capacity();
        report("shipped: capacity grew past floor", grown_capacity >= 6);

        // Re-decode a single-feature buffer on the SAME container: reset() clears size but
        // must retain the grown capacity.
        data_buffer<256> buf2;
        cbor_object cbor_outer2{buf2};
        cbor_object outer2{cbor_outer2, CBOR_METADATA_VERSION_KEY};
        exposed_creds_message::construct(exposed_creds_message::KEY_PLAINTEXT,
            datum{"http"}, datum{"basic"}, datum{"admin"}).template write<cbor_object>(outer2);
        outer2.close();
        cbor_outer2.close();

        datum encoded2 = buf2.contents();
        decode_cbor_metadata(encoded2.data, encoded2.length(), decoded);
        report("shipped: unknowns become 1 on re-decode", decoded.unknown.size() == 1);
        report("shipped: capacity retained across reset",
               decoded.unknown.capacity() == grown_capacity);
    }

    // Test 13: varied registration side-by-side. The SAME cnsa buffer decoded into a fully
    // registered decoder lands in its typed slot; decoded into the shipped typed_decoder<> it
    // flows to the unknown vector — still fully captured. Proves registration is a per-consumer
    // choice and that unregistered features degrade to the unknown path, never dropped.
    {
        data_buffer<1024> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        crypto_cnsa_tls_message msg;
        msg.set_policy("quantum_safe");
        msg.set_target("client");
        msg.set_cs_allowed("none");
        msg.set_valid();
        cbor::text_string(crypto_cnsa_tls_message::KEY).write(buf);
        msg.template write<cbor_object>(outer);
        outer.close();
        cbor_outer.close();
        datum encoded = buf.contents();

        full_decoder full;
        decode_cbor_metadata(encoded.data, encoded.length(), full);
        report("varied full: cnsa typed", full.get<cnsa_feature>().tls_if() != nullptr);
        report("varied full: unknown empty", full.unknown.empty());

        cbor_decoded_metadata none;                    // typed_decoder<>
        decode_cbor_metadata(encoded.data, encoded.length(), none);
        report("varied empty: valid", none.valid);
        report("varied empty: cnsa in unknown",
               none.unknown.size() == 1
               && none.unknown[0].is_valid()
               && none.unknown[0].key().match("cnsa_2_0_non_conformant"));
    }

    // ================================================================
    // Group C — duplicate keys, encode exhaustion, custom buffer size,
    // and decode-side robustness against short/truncated input.
    // ================================================================

    // Test 14: duplicate feature key.
    //   - Typed slot (full_decoder): the second occurrence OVERWRITES the first
    //     (decode_into does `*this = decode(...)`); unknown stays empty.
    //   - Shipped typed_decoder<>: both occurrences are preserved in the unknown
    //     vector (no overwrite) so harvest never silently drops a duplicate span.
    {
        data_buffer<1024> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        exposed_creds_message::construct(exposed_creds_message::KEY_PLAINTEXT,
            datum{"http"}, datum{"basic"}, datum{"alice"}).template write<cbor_object>(outer);
        exposed_creds_message::construct(exposed_creds_message::KEY_PLAINTEXT,
            datum{"http"}, datum{"basic"}, datum{"bob"}).template write<cbor_object>(outer);
        outer.close();
        cbor_outer.close();
        datum encoded = buf.contents();

        full_decoder d;
        decode_cbor_metadata(encoded.data, encoded.length(), d);
        auto &ec = d.get<exposed_creds_message>();
        report("dup typed: valid + slot", d.valid && ec.is_valid());
        report("dup typed: second overwrites first (username == bob)",
               ec.username().match("bob"));
        report("dup typed: unknown empty", d.unknown.empty());

        cbor_decoded_metadata shipped;                 // typed_decoder<>
        decode_cbor_metadata(encoded.data, encoded.length(), shipped);
        report("dup shipped: both preserved in unknown",
               shipped.valid && shipped.unknown.size() == 2
               && shipped.unknown[0].key().match("exposed_credentials_plaintext")
               && shipped.unknown[1].key().match("exposed_credentials_plaintext"));
    }

    // Test 15: buffer exhaustion during encode. A cnsa written into a tiny context
    // overruns the buffer; the writeable goes null. Asserts is_truncated() true,
    // get_length() == 0 (the is_null() gate), and that the point-14
    // growth check is overflow-safe: bytes_written() reports 0 after the overrun,
    // so (bytes_written() > before_features) is false and set_feature_written()
    // is NOT called (mirrors the orchestrator).
    {
        cbor_metadata_buffer ctx{64};   // tiny buffer, forces overrun
        ctx.reset();
        writeable& w = ctx.get_writer();
        cbor_object cbor_outer{w};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};

        const size_t before_features = ctx.bytes_written();

        crypto_cnsa_tls_message msg;
        msg.set_policy("quantum_safe");
        msg.set_target("client");
        for (int i = 0; i < 20; i++) { msg.add_cs_not_allowed("TLS_RSA_WITH_AES_128_CBC_SHA"); }
        msg.set_cs_allowed("some");
        msg.set_grp_allowed("all");
        msg.set_valid();
        cbor::text_string(crypto_cnsa_tls_message::KEY).write(w);
        msg.template write<cbor_object>(outer);

        // orchestrator's growth check: on overrun bytes_written() == 0 -> false
        report("exhaust: bytes_written == 0 after overrun", ctx.bytes_written() == 0);
        if (ctx.bytes_written() > before_features) { ctx.set_feature_written(); }

        outer.close();
        cbor_outer.close();
        report("exhaust: is_truncated() true", ctx.is_truncated());
        report("exhaust: has_data() false", !ctx.has_data());
        report("exhaust: get_length() == 0", ctx.get_length() == 0);
    }

    // Test 16: custom buffer size codepath. The SAME payload truncates at a small
    // configured size and fits at a larger one (8192) -- exercising the
    // constructor's size path on both sides of the boundary.
    {
        // encode a moderate cnsa (10 ciphersuites) into a context of the given
        // capacity; return it so the caller can inspect it.
        auto encode_cnsa = [](size_t cap) -> cbor_metadata_buffer {
            cbor_metadata_buffer ctx{cap};
            ctx.reset();
            writeable& w = ctx.get_writer();
            cbor_object cbor_outer{w};
            cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
            const size_t before = ctx.bytes_written();
            crypto_cnsa_tls_message msg;
            msg.set_policy("quantum_safe");
            msg.set_target("client");
            for (int i = 0; i < 10; i++) { msg.add_cs_not_allowed("TLS_RSA_WITH_AES_128_CBC_SHA"); }
            msg.set_cs_allowed("some");
            msg.set_grp_allowed("all");
            msg.set_valid();
            cbor::text_string(crypto_cnsa_tls_message::KEY).write(w);
            msg.template write<cbor_object>(outer);
            if (ctx.bytes_written() > before) { ctx.set_feature_written(); }
            outer.close();
            cbor_outer.close();
            return ctx;
        };

        cbor_metadata_buffer small = encode_cnsa(256);    // too small -> truncates
        report("custom-size: small (256) truncated", small.is_truncated());
        report("custom-size: small (256) no data", !small.has_data());

        cbor_metadata_buffer large = encode_cnsa(8192);   // fits
        report("custom-size: large (8192) not truncated", !large.is_truncated());
        report("custom-size: large (8192) has data", large.has_data());

        // the 8192 buffer decodes back to the cnsa feature (round-trip intact)
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(large.get_buffer(), large.get_length(), decoded);
        report("custom-size: large decodes valid", decoded.valid);
        report("custom-size: large -> cnsa unknown",
               decoded.unknown.size() == 1
               && decoded.unknown[0].key().match("cnsa_2_0_non_conformant"));
    }

    // Test 17: decode-side robustness -- a short/truncated buffer handed to
    // decode_cbor_metadata() must fail cleanly (valid == false, nothing captured,
    // no crash / no out-of-bounds read). Two flavors: cut mid-stream, and a
    // 2-byte stub.
    {
        // build a valid single-feature buffer, then feed a reduced length.
        data_buffer<512> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        exposed_creds_message::construct(exposed_creds_message::KEY_PLAINTEXT,
            datum{"http"}, datum{"basic"}, datum{"alice"}).template write<cbor_object>(outer);
        outer.close();
        cbor_outer.close();
        datum encoded = buf.contents();

        // cut 6 bytes off the end -> chops the final value / break
        cbor_decoded_metadata cut;
        decode_cbor_metadata(encoded.data, encoded.length() - 6, cut);
        report("trunc-decode: mid-stream cut -> valid false", !cut.valid);

        // 2-byte stub -> outer map can't parse
        cbor_decoded_metadata stub;
        decode_cbor_metadata(encoded.data, 2, stub);
        report("trunc-decode: 2-byte stub -> valid false", !stub.valid);
        report("trunc-decode: stub unknown empty", stub.unknown.empty());
    }

    return all_passed;
}

#endif // CBOR_DECODED_METADATA_TEST_HPP
