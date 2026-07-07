// cbor_decoded_metadata_test.hpp
//
// Unit tests for the CBOR metadata decode interface.
// This file is NOT copied to the inspector — tests only run in the mercury build.

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

    // Test 1: exposed_creds_plaintext round-trip
    {
        data_buffer<512> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        auto msg = exposed_creds_message::construct(exposed_creds_message::KEY_PLAINTEXT, 
            datum{"imap"}, datum{"LOGIN"}, datum{"alice"});
        msg.template write<cbor_object>(outer);
        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("exposed_creds_plaintext decode valid", decoded.valid);
        report("exposed_creds_plaintext count == 1", decoded.exposed_creds.is_valid() && !decoded.cnsa_tls.is_valid() && !decoded.cnsa_ssh.is_valid() && !decoded.nist.is_valid() && decoded.unknown.empty());

        if (true) {
            bool is_plaintext = decoded.exposed_creds.is_valid();
            report("exposed_creds_plaintext variant type", is_plaintext);
            if (is_plaintext) {
                auto &dec = decoded.exposed_creds;
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
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        auto msg = exposed_creds_message::construct(exposed_creds_message::KEY_TOKEN, 
            datum{"imap"}, datum{"OAUTHBEARER"}, datum{});
        msg.template write<cbor_object>(outer);
        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("exposed_creds_token decode valid", decoded.valid);
        report("exposed_creds_token count == 1", decoded.exposed_creds.is_valid() && !decoded.cnsa_tls.is_valid() && !decoded.cnsa_ssh.is_valid() && !decoded.nist.is_valid() && decoded.unknown.empty());
        if (true) {
            bool is_token = decoded.exposed_creds.is_valid();
            report("exposed_creds_token variant type", is_token);
            if (is_token) {
                auto &dec = decoded.exposed_creds;
                report("protocol == imap", dec.protocol().match("imap"));
                report("auth_method == OAUTHBEARER", dec.auth_method().match("OAUTHBEARER"));
                report("username is empty (not readable)", !dec.username().is_readable());
            }
        }
    }

    // Test 2b: exposed_creds_derived round-trip (LDAP DIGEST-MD5)
    {
        data_buffer<512> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        auto msg = exposed_creds_message::construct(exposed_creds_message::KEY_DERIVED, 
            datum{"ldap"}, datum{"DIGEST-MD5"}, datum{});
        msg.template write<cbor_object>(outer);
        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("exposed_creds_derived decode valid", decoded.valid);
        report("exposed_creds_derived count == 1", decoded.exposed_creds.is_valid() && !decoded.cnsa_tls.is_valid() && !decoded.cnsa_ssh.is_valid() && !decoded.nist.is_valid() && decoded.unknown.empty());
        if (true) {
            bool is_derived = decoded.exposed_creds.is_valid();
            report("exposed_creds_derived variant type", is_derived);
            if (is_derived) {
                auto &dec = decoded.exposed_creds;
                report("protocol == ldap", dec.protocol().match("ldap"));
                report("auth_method == DIGEST-MD5", dec.auth_method().match("DIGEST-MD5"));
                report("key == exposed_credentials_derived",
                       dec.key().match("exposed_credentials_derived"));
            }
        }
    }

    // Test 3: crypto_cnsa round-trip
    {
        data_buffer<1024> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};

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
        msg.template write<cbor_object>(outer);
        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("crypto_cnsa decode valid", decoded.valid);
        report("crypto_cnsa count == 1", decoded.cnsa_tls.is_valid() && !decoded.exposed_creds.is_valid() && !decoded.cnsa_ssh.is_valid() && !decoded.nist.is_valid() && decoded.unknown.empty());
        if (true) {
            bool is_cnsa = decoded.cnsa_tls.is_valid();
            report("crypto_cnsa variant type", is_cnsa);
            if (is_cnsa) {
                auto &dec = decoded.cnsa_tls;
                report("cnsa is_valid", dec.is_valid());
                report("cnsa key matches", dec.key().match("cnsa_2_0_non_conformant"));
            }
        }
    }

    // Test 3 hex: crypto_cnsa with hex cipher suite values (exercises print_uint16_hex)
    {
        data_buffer<1024> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};

        crypto_cnsa_message msg;
        msg.set_policy("quantum_safe");
        msg.set_target("client");
        msg.add_cs_not_allowed_hex(0xc02c);  // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        msg.add_cs_not_allowed_hex(0x0005);  // TLS_RSA_WITH_RC4_128_SHA
        msg.add_grp_not_allowed_hex(0x001d); // x25519
        msg.set_cs_allowed("some");
        msg.set_grp_allowed("some");
        msg.set_psk_mode(false);
        msg.set_valid();

        cbor::text_string(crypto_cnsa_message::KEY).write(buf);
        msg.template write<cbor_object>(outer);
        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("cnsa hex decode valid", decoded.valid);
        report("cnsa hex count == 1", decoded.cnsa_tls.is_valid() && !decoded.exposed_creds.is_valid() && !decoded.cnsa_ssh.is_valid() && !decoded.nist.is_valid() && decoded.unknown.empty());
        if (true) {
            bool is_cnsa = decoded.cnsa_tls.is_valid();
            report("cnsa hex variant type", is_cnsa);
            if (is_cnsa) {
                auto &dec = decoded.cnsa_tls;
                report("cnsa hex is_valid", dec.is_valid());
                report("cnsa hex cs_count == 2", dec.cs_not_allowed_count() == 2);
                if (dec.cs_not_allowed_count() >= 2) {
                    report("cnsa hex cs[0] == c02c",
                           dec.cs_not_allowed_at(0).value().match("c02c"));
                    report("cnsa hex cs[1] == 0005",
                           dec.cs_not_allowed_at(1).value().match("0005"));
                }
                report("cnsa hex grp_count == 1", dec.grp_not_allowed_count() == 1);
                if (dec.grp_not_allowed_count() >= 1) {
                    report("cnsa hex grp[0] == 001d",
                           dec.grp_not_allowed_at(0).value().match("001d"));
                }
            }
        }
    }

    // Test 3a: crypto_cnsa with multiple PSK non-compliant entries + unknown field
    {
        data_buffer<2048> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};

        crypto_cnsa_message msg;
        msg.set_policy("quantum_safe");
        msg.set_target("client");
        msg.set_cs_allowed("all");
        msg.set_grp_allowed("all");
        msg.set_psk_mode(true);
        msg.set_psk_non_compliant("tls_cert_with_extern_psk_non_compliant",
                                   "tls_cert_with_extern_psk requires pre_shared_key, psk_key_exchange_modes, and key_share");
        msg.set_psk_non_compliant("psk_key_exchange_modes_non_compliant",
                                   "psk_key_exchange_modes must include psk_dhe_ke and must not include psk_ke");
        msg.set_compliant(false);
        msg.set_valid();

        cbor::text_string(crypto_cnsa_message::KEY).write(buf);
        msg.template write<cbor_object>(outer);
        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("cnsa multi-psk decode valid", decoded.valid);
        report("cnsa multi-psk count == 1", decoded.cnsa_tls.is_valid() && !decoded.exposed_creds.is_valid() && !decoded.cnsa_ssh.is_valid() && !decoded.nist.is_valid() && decoded.unknown.empty());
        if (true) {
            bool is_cnsa = decoded.cnsa_tls.is_valid();
            report("cnsa multi-psk variant type", is_cnsa);
            if (is_cnsa) {
                auto &dec = decoded.cnsa_tls;
                report("cnsa multi-psk is_valid", dec.is_valid());
                report("cnsa multi-psk psk_count == 2", dec.psk_non_compliant_count() == 2);
                if (dec.psk_non_compliant_count() >= 2) {
                    report("cnsa psk[0] key",
                           dec.psk_non_compliant_key_at(0).value().match("tls_cert_with_extern_psk_non_compliant"));
                    report("cnsa psk[1] key",
                           dec.psk_non_compliant_key_at(1).value().match("psk_key_exchange_modes_non_compliant"));
                }
            }
        }
    }

    // Test 3a2: crypto_cnsa decode with unknown field in target map (forward compat)
    {
        // Manually encode a cnsa message with an extra unknown field in the target map
        data_buffer<2048> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};

        // Write the cnsa key
        cbor::text_string(crypto_cnsa_message::KEY).write(buf);
        // Write an anonymous map (the cnsa message body)
        cbor_object cnsa_body{outer};
        cnsa_body.print_key_string("policy", "quantum_safe");
        // Write target sub-map with an unknown field
        cbor_object target{cnsa_body, "client"};
        target.print_key_string("ciphersuites_allowed", "all");
        target.print_key_string("groups_allowed", "all");
        target.print_key_bool("tls_cert_with_extern_psk", false);
        // Unknown future field — should be skipped by decoder
        target.print_key_string("signature_algorithms_not_allowed", "rsa_pkcs1_sha256");
        target.close();
        cnsa_body.close();
        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("cnsa unknown-field decode valid", decoded.valid);
        report("cnsa unknown-field count == 1", decoded.cnsa_tls.is_valid() && !decoded.exposed_creds.is_valid() && !decoded.cnsa_ssh.is_valid() && !decoded.nist.is_valid() && decoded.unknown.empty());
        if (true) {
            bool is_cnsa = decoded.cnsa_tls.is_valid();
            report("cnsa unknown-field variant type", is_cnsa);
            if (is_cnsa) {
                auto &dec = decoded.cnsa_tls;
                report("cnsa unknown-field is_valid", dec.is_valid());
                report("cnsa unknown-field psk_count == 0", dec.psk_non_compliant_count() == 0);
                report("cnsa unknown-field cs_allowed", dec.cs_allowed_valid());
                report("cnsa unknown-field grp_allowed", dec.grp_allowed_valid());
            }
        }
    }

    // Test 3b: crypto_nist round-trip (TLS server hello non-compliant)
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
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("crypto_nist decode valid", decoded.valid);
        report("crypto_nist count == 1", decoded.nist.is_valid() && !decoded.exposed_creds.is_valid() && !decoded.cnsa_tls.is_valid() && !decoded.cnsa_ssh.is_valid() && decoded.unknown.empty());
        if (true) {
            bool is_nist = decoded.nist.is_valid();
            report("crypto_nist variant type", is_nist);
            if (is_nist) {
                auto &dec = decoded.nist;
                report("nist is_valid", dec.is_valid());
                report("nist key matches", dec.key().match("nist_sp_800_52_2_non_conformant"));
            }
        }
    }

    // Test 4: multiple features in one buffer
    {
        data_buffer<2048> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};

        exposed_creds_message::construct(exposed_creds_message::KEY_PLAINTEXT, 
            datum{"http"}, datum{"basic"}, datum{"admin"})
            .template write<cbor_object>(outer);

        crypto_cnsa_message cnsa;
        cnsa.set_policy("quantum_safe");
        cnsa.set_target("session");
        cnsa.set_cs_allowed("all");
        cnsa.set_grp_allowed("all");
        cnsa.set_psk_mode(false);
        cnsa.set_valid();
        cbor::text_string(crypto_cnsa_message::KEY).write(buf);
        cnsa.template write<cbor_object>(outer);

        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("multi-feature decode valid", decoded.valid);
        report("multi-feature count == 2", decoded.exposed_creds.is_valid() && decoded.cnsa_tls.is_valid() && !decoded.cnsa_ssh.is_valid() && !decoded.nist.is_valid() && decoded.unknown.empty());
        if (true) {
            report("entry[0] is exposed_creds_plaintext",
                   decoded.exposed_creds.is_valid());
            report("entry[1] is crypto_cnsa",
                   decoded.cnsa_tls.is_valid());
        }
    }

    // Test 5: empty buffer
    {
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(nullptr, 0, decoded);
        report("empty buffer valid == false", !decoded.valid);
        report("empty buffer count == 0", !decoded.exposed_creds.is_valid());
    }

    // Test 5a: unknown outer version key -> valid == false
    // A well-formed buffer with an unrecognized version wrapper must NOT be
    // reported as valid (forward-compat: old decoder, future schema).
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

        report("unknown version valid == false", !decoded.valid);
        report("unknown version no features populated",
               !decoded.exposed_creds.is_valid() && !decoded.cnsa_tls.is_valid()
               && !decoded.cnsa_ssh.is_valid() && !decoded.nist.is_valid());
    }

    // Test 5b: cbor_metadata_context reports no data when no feature written
    {
        cbor_metadata_context ctx;
        ctx.reset();
        writeable& w = ctx.get_writer();
        cbor_object cbor_outer{w};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        // No feature written — don't call set_feature_written()
        outer.close();
        cbor_outer.close();
        ctx.end_encode();
        report("no-feature has_data == false", !ctx.has_data());
        report("no-feature length == 0", ctx.get_length() == 0);
    }

    // Test 5c: cbor_metadata_context reports data when feature is written
    {
        cbor_metadata_context ctx;
        ctx.reset();
        writeable& w = ctx.get_writer();
        cbor_object cbor_outer{w};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        // Write a feature and set the flag
        exposed_creds_message::construct(exposed_creds_message::KEY_PLAINTEXT, 
            datum{"http"}, datum{"basic"}, datum{"admin"})
            .template write<cbor_object>(outer);
        ctx.set_feature_written();
        outer.close();
        cbor_outer.close();
        ctx.end_encode();
        report("with-feature has_data == true", ctx.has_data());
        report("with-feature length > 0", ctx.get_length() > 0);

        // Verify the buffer is decodable
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(ctx.get_buffer(), ctx.get_length(), decoded);
        report("with-feature decode valid", decoded.valid);
        report("with-feature decode count == 1", decoded.exposed_creds.is_valid() && !decoded.cnsa_tls.is_valid() && !decoded.cnsa_ssh.is_valid() && !decoded.nist.is_valid() && decoded.unknown.empty());
    }

    // Test 5d: cbor_metadata_context reset clears the flag
    {
        cbor_metadata_context ctx;
        ctx.reset();
        writeable& w = ctx.get_writer();
        cbor_object cbor_outer{w};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        ctx.set_feature_written();
        outer.close();
        cbor_outer.close();
        ctx.end_encode();
        report("before reset has_data == true", ctx.has_data());

        // Reset and encode again without setting the flag
        ctx.reset();
        writeable& w2 = ctx.get_writer();
        cbor_object cbor_outer2{w2};
        cbor_object outer2{cbor_outer2, CBOR_METADATA_VERSION_KEY};
        outer2.close();
        cbor_outer2.close();
        ctx.end_encode();
        report("after reset has_data == false", !ctx.has_data());
    }

    // Test 6: unknown feature with fields — verify cbor_span produces correct JSON
    {
        data_buffer<512> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        // Write a map value for the unknown key (simulates a future feature)
        cbor_object unknown_map{outer, "future_detection"};
        unknown_map.print_key_string("severity", "high");
        unknown_map.print_key_string("category", "malware");
        unknown_map.print_key_uint("confidence", 95);
        unknown_map.close();
        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("unknown feature decode valid", decoded.valid);
        report("unknown feature count == 1", decoded.unknown.size() == 1);
        if (true) {
            report("entry[0] is unknown_feature",
                   (!decoded.unknown.empty() && decoded.unknown[0].is_valid()));
            if ((!decoded.unknown.empty() && decoded.unknown[0].is_valid())) {
                auto &uf = decoded.unknown[0];
                report("unknown key matches", uf.key().match("future_detection"));

                // Verify cbor_span can be decoded to JSON
                datum span = uf.cbor_span();
                output_buffer<512> json_buf;
                bool json_ok = decode_cbor_map_to_json(span, json_buf, nullptr);
                report("unknown cbor_span decodes to JSON", json_ok);
                if (json_ok) {
                    // Check JSON contains expected fields
                    report("JSON contains severity",
                           std::string(json_buf.dstr, json_buf.length()).find("\"severity\":\"high\"") != std::string::npos);
                    report("JSON contains category",
                           std::string(json_buf.dstr, json_buf.length()).find("\"category\":\"malware\"") != std::string::npos);
                    report("JSON contains confidence",
                           std::string(json_buf.dstr, json_buf.length()).find("\"confidence\":95") != std::string::npos);
                }
            }
        }
    }

    // Test 7: multiple unknown features go into vector
    {
        data_buffer<4096> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};
        for (int i = 0; i < 10; i++) {
            char key_name[32];
            snprintf(key_name, sizeof(key_name), "future_feature_%d", i);
            cbor_object feat{outer, key_name};
            feat.print_key_string("data", "value");
            feat.close();
        }
        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("overflow decode valid", decoded.valid);
        report("unknown vector has 10 entries",
               decoded.unknown.size() == 10);
    }

    // Test 8: unknown vector grows on demand and RETAINS capacity across reset
    {
        cbor_decoded_metadata decoded;
        report("unknown initial capacity == reserve floor",
               decoded.unknown.capacity() == cbor_decoded_metadata::unknown_reserve_count);

        // Encode a buffer with 6 unknown features (6 > the reserve floor, so
        // the vector must grow).
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
        report("grew to 6 unknowns", decoded.unknown.size() == 6);
        size_t grown_capacity = decoded.unknown.capacity();
        report("capacity grew past floor", grown_capacity >= 6);

        // Re-decode a buffer with NO unknowns on the SAME container. reset()
        // (called inside decode_cbor_metadata) clears size to 0 but must
        // retain the grown capacity.
        data_buffer<256> buf2;
        cbor_object cbor_outer2{buf2};
        cbor_object outer2{cbor_outer2, CBOR_METADATA_VERSION_KEY};
        exposed_creds_message::construct(exposed_creds_message::KEY_PLAINTEXT,
            datum{"http"}, datum{"basic"}, datum{"admin"})
            .template write<cbor_object>(outer2);
        outer2.close();
        cbor_outer2.close();

        datum encoded2 = buf2.contents();
        decode_cbor_metadata(encoded2.data, encoded2.length(), decoded);
        report("unknowns cleared on re-decode", decoded.unknown.empty());
        report("capacity retained across reset",
               decoded.unknown.capacity() == grown_capacity);
    }

    // Test 9: crypto_cnsa SSH round-trip — routes to cnsa_ssh via the cnsa_variant
    // discriminator (the SSH path was previously untested).
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
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("cnsa ssh decode valid", decoded.valid);
        report("cnsa ssh routed to cnsa_ssh (not cnsa_tls)",
               decoded.cnsa_ssh.is_valid() && !decoded.cnsa_tls.is_valid()
               && !decoded.exposed_creds.is_valid() && !decoded.nist.is_valid()
               && decoded.unknown.empty());
        report("cnsa ssh key matches",
               decoded.cnsa_ssh.is_valid() && decoded.cnsa_ssh.key().match("cnsa_2_0_non_conformant"));
    }

    // Test 10: cnsa_variant routing is order-independent. Hand-build a cnsa TLS sub-map
    // whose "cnsa_variant" comes AFTER the "client" structural key — the old structural
    // peek (offered/client/session first-key inference) is not relied upon; the explicit
    // discriminator must still route to cnsa_tls.
    {
        data_buffer<1024> buf;
        cbor_object cbor_outer{buf};
        cbor_object outer{cbor_outer, CBOR_METADATA_VERSION_KEY};

        cbor::text_string(crypto_cnsa_tls_message::KEY).write(buf);
        {
            cbor_object cnsa{outer};
            cnsa.print_key_string("policy", "quantum_safe");
            {
                cbor_object tgt{cnsa, "client"};   // structural target BEFORE the discriminator
                tgt.print_key_string("ciphersuites_allowed", "none");
                tgt.print_key_bool("tls_cert_with_extern_psk", false);
                tgt.close();
            }
            cnsa.print_key_string("cnsa_variant", "tls");   // discriminator LAST
            cnsa.close();
        }
        outer.close();
        cbor_outer.close();

        datum encoded = buf.contents();
        cbor_decoded_metadata decoded;
        decode_cbor_metadata(encoded.data, encoded.length(), decoded);

        report("cnsa order-independent decode valid", decoded.valid);
        report("cnsa_variant after target still routes to cnsa_tls",
               decoded.cnsa_tls.is_valid() && !decoded.cnsa_ssh.is_valid());
    }

    return all_passed;
}

#endif // CBOR_DECODED_METADATA_TEST_HPP
