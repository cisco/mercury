// TLS, QUIC and X509/PKIX Crypto Security Assessment
//

#ifndef CRYPTO_ASSESS_H
#define CRYPTO_ASSESS_H

#include <cstdint>
#include <array>
#include <memory>
#include <optional>
#include "json_object.h"
#include "cbor_messages.hpp"
#include "cbor_object.hpp"
#include "tls_parameters.hpp"
#include "tls_extensions.hpp"
#include "tls.h"
#include "dtls.h"
#include "ssh.h"
#include "printf_err.hpp"

#define MAX_CRYPTO_ASSESSMENT_TYPES 2

using crypto_assess_result = std::bitset<MAX_CRYPTO_ASSESSMENT_TYPES>;

inline const char* tls_version_to_string(tls_version v) {
    switch (v) {
        case tls_version::sslv2_0:
            return "SSLv2.0";
        case tls_version::sslv3_0:
            return "SSLv3.0";
        case tls_version::tlsv1_0:
            return "TLSv1.0";
        case tls_version::tlsv1_1:
            return "TLSv1.1";
        case tls_version::tlsv1_2:
            return "TLSv1.2";
        case tls_version::tlsv1_3:
            return "TLSv1.3";
        default:
            ;
    }
    return "unknown";
}

namespace crypto_policy {

    // assessor is the base class representing a particular crypto assessment policy.
    //
    // Each message type has two virtuals, and the caller selects between them through the
    // constness of the pointer it holds, so no runtime mode flag is needed:
    //
    //  - assess(const T &) const : compliance-only. Returns a verdict and writes nothing.
    //    Defaults to true ("compliant", i.e. not-applicable) so a policy overrides only the
    //    message types it actually assesses.
    //  - assess(const T &)       : the FILL path, non-const because it populates the policy's
    //    owned feature message. The default forwards to the const overload, which yields a
    //    real verdict with no metadata -- correct for a policy/type pair with nothing to fill.
    //
    // To give every policy defaults for an additional message type, add one const and one
    // non-const overload below.
    //
    class assessor {
        public:

        virtual size_t get_result_idx() const = 0;

        virtual bool assess(const tls_client_hello &) const {
            return true;
        }

        virtual bool assess(const tls_server_hello &) const {
            return true;
        }

        virtual bool assess(const tls_server_hello_and_certificate &) const {
            return true;
        }

        virtual bool assess(const dtls_client_hello &) const {
            return true;
        }

        virtual bool assess(const dtls_server_hello &) const {
            return true;
        }

        virtual bool assess(const ssh_kex_init &) const {
            return true;
        }

        virtual bool assess(const tls_client_hello &m) {
            return static_cast<const assessor&>(*this).assess(m);
        }

        virtual bool assess(const tls_server_hello &m) {
            return static_cast<const assessor&>(*this).assess(m);
        }

        virtual bool assess(const tls_server_hello_and_certificate &m) {
            return static_cast<const assessor&>(*this).assess(m);
        }

        virtual bool assess(const dtls_client_hello &m) {
            return static_cast<const assessor&>(*this).assess(m);
        }

        virtual bool assess(const dtls_server_hello &m) {
            return static_cast<const assessor&>(*this).assess(m);
        }

        virtual bool assess(const ssh_kex_init &m) {
            return static_cast<const assessor&>(*this).assess(m);
        }

        // Clear any owned feature message(s) so a subsequent assessment of a
        // message type this policy does not fill cannot emit a stale finding.
        // Called by the orchestrator once per policy before each emitting
        // assessment; every policy that owns output state must implement it.
        virtual void reset_output() = 0;

        // Render this policy's owned message (if any) into the caller-opened JSON assessment array.
        virtual void emit(json_array &) { }

        // Render this policy's non-compliant finding (if any) as a top-level CBOR
        // feature: its KEY and body. Whether a feature was written is detected by
        // the orchestrator (buffer growth); emit() has no metadata-context knowledge.
        virtual void emit(cbor_object &) { }

        virtual ~assessor() { }

        static void create(const std::string &policy, std::vector<assessor*> &assessors);
    };

    static bool is_grease(uint16_t x) {
        switch(x) {
        case 0x0a0a:
        case 0x1a1a:
        case 0x2a2a:
        case 0x3a3a:
        case 0x4a4a:
        case 0x5a5a:
        case 0x6a6a:
        case 0x7a7a:
        case 0x8a8a:
        case 0x9a9a:
        case 0xaaaa:
        case 0xbaba:
        case 0xcaca:
        case 0xdada:
        case 0xeaea:
        case 0xfafa:
            return true;
            break;
        default:
            ;
        }
        return false;
    }

    class quantum_safe : public assessor {
        bool readable_output;

        // Owned feature messages; filled by the non-const assess(), read by emit(). One
        // TLS-family and one SSH message; only one is valid per packet. Cleared by
        // reset_output(), which the orchestrator calls before every emitting assessment.
        crypto_cnsa_message     cnsa_tls_msg_;
        crypto_cnsa_ssh_message cnsa_ssh_msg_;

        public:

        void reset_output() override { cnsa_tls_msg_ = {}; cnsa_ssh_msg_ = {}; }

        quantum_safe(bool readable=false) :
            readable_output{readable}
        { }

        ~quantum_safe() { }

        const static size_t result_idx = 0; // index for crypto_assess_result::quantum_safe bitset

        virtual size_t get_result_idx() const override {
            return quantum_safe::result_idx;
        }

        static inline std::unordered_set<uint16_t> allowed_ciphersuites {
            // tls::cipher_suites::code::TLS_PSK_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_PSK_WITH_AES_256_CBC_SHA,
            // tls::cipher_suites::code::TLS_PSK_WITH_AES_128_GCM_SHA256,
            tls::cipher_suites::code::TLS_PSK_WITH_AES_256_GCM_SHA384,
            // tls::cipher_suites::code::TLS_PSK_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_PSK_WITH_AES_256_CBC_SHA384,
            // tls::cipher_suites::code::TLS_PSK_WITH_AES_128_CCM,
            tls::cipher_suites::code::TLS_PSK_WITH_AES_256_CCM,
            //tls::cipher_suites::code::TLS_PSK_WITH_AES_128_CCM_8,
            tls::cipher_suites::code::TLS_PSK_WITH_AES_256_CCM_8,
            // tls::cipher_suites::code::TLS_AES_128_GCM_SHA256,
            tls::cipher_suites::code::TLS_AES_256_GCM_SHA384,
            // tls::cipher_suites::code::TLS_CHACHA20_POLY1305_SHA256,
            // tls::cipher_suites::code::TLS_AES_128_CCM_SHA256,
            // tls::cipher_suites::code::TLS_AES_128_CCM_8_SHA256,
        };

        static inline std::unordered_set<uint16_t> allowed_groups {
            tls::supported_groups::code::MLKEM512,
            tls::supported_groups::code::MLKEM768,
            tls::supported_groups::code::MLKEM1024,
            tls::supported_groups::code::SecP256r1MLKEM768,
            tls::supported_groups::code::X25519MLKEM768,
            tls::supported_groups::code::X25519Kyber768Draft00,
            tls::supported_groups::code::SecP256r1Kyber768Draft00,
            tls::supported_groups::code::SecP384r1MLKEM1024, // https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
            // tls::supported_groups::code::arbitrary_explicit_prime_curves,
            // tls::supported_groups::code::arbitrary_explicit_char2_curves,
        };

        /*
        * Common Two-Loop Assessment Pattern:
        *
        * All assessment functions (assess_tls_ciphersuites, assess_tls_extensions,
        * assess_ssh_kex_methods, assess_ssh_ciphers) use a similar two-loop approach:
        *
        * OUTER LOOP: Iterates through items sequentially checking if all are allowed.
        * As soon as it encounters a non-allowed item, it immediately enters the inner loop.
        *
        * INNER LOOP: Processes the remaining items in the vector/list starting from
        * the current non-allowed item. This ensures we complete the entire traversal
        * in a single pass while collecting all non-allowed items.
        *
        * Key Design Decisions:
        * 1. The JSON array (e.g., "ciphersuites_not_allowed") is created ONLY when the
        *    first non-allowed item is encountered, not beforehand. This prevents empty
        *    arrays from appearing in the output when all items are allowed.
        *
        * 2. Single-pass efficiency: We traverse the entire input vector/list exactly
        *    once, switching from the outer loop to the inner loop seamlessly when needed.
        *
        */

        bool assess_tls_ciphersuites(datum ciphersuite_vector, crypto_cnsa_message &msg) const {
            return assess_tls_ciphersuites_impl(ciphersuite_vector, &msg);
        }

        bool assess_tls_ciphersuites(datum ciphersuite_vector) const {
            return assess_tls_ciphersuites_impl(ciphersuite_vector, nullptr);
        }

        bool assess_tls_ciphersuites_impl(datum ciphersuite_vector, crypto_cnsa_message *msg) const {
            bool all_allowed = true;
            bool some_allowed = false;

            while (ciphersuite_vector.is_readable()) {
                tls::cipher_suites cs{ciphersuite_vector};

                if (is_grease(cs)) {
                    continue;
                }

                bool found = (allowed_ciphersuites.find(cs.value()) != allowed_ciphersuites.end());
                if (!found) {
                    all_allowed = false;

                    while (true) {
                        if (!is_grease(cs)) {
                            found = (allowed_ciphersuites.find(cs.value()) != allowed_ciphersuites.end());
                            if (!found) {
                                if (msg) {
                                    if (readable_output) {
                                        msg->add_cs_not_allowed(cs.get_name());
                                    } else {
                                        msg->add_cs_not_allowed_hex(cs.value());
                                    }
                                }
                            } else {
                                some_allowed = true;
                            }
                        }

                        if (!ciphersuite_vector.is_readable()) break;
                        cs = tls::cipher_suites{ciphersuite_vector};
                    }

                    break;
                } else {
                    some_allowed = true;
                }

            }

            if (msg) {
                const char *quantifier = "none";
                if (all_allowed) {
                    quantifier = "all";
                } else if (some_allowed) {
                    quantifier = "some";
                }
                msg->set_cs_allowed(quantifier);
            }

            return all_allowed;
        }

        bool assess_tls_extensions(const tls_extensions &extensions, crypto_cnsa_message &msg) const {
            return assess_tls_extensions_impl(extensions, &msg);
        }

        bool assess_tls_extensions(const tls_extensions &extensions) const {
            return assess_tls_extensions_impl(extensions, nullptr);
        }

        bool assess_tls_extensions_impl(const tls_extensions &extensions, crypto_cnsa_message *msg) const {
            bool all_allowed = true;
            bool some_allowed = false;

            datum named_groups = extensions.get_supported_groups();
            xtn named_groups_xtn{named_groups};
            encoded<uint16_t> named_groups_len{named_groups_xtn.value};

            if (named_groups_len & 1) {
                return false; // not a valid named groups length
            }

            while (named_groups_xtn.value.is_readable()) {
                tls::supported_groups named_group{named_groups_xtn.value};

                if (is_grease(named_group)) {
                    continue;
                }

                bool found = (allowed_groups.find(named_group.value()) != allowed_groups.end());
                if (!found) {
                    all_allowed = false;

                    while (true) {
                        if (!is_grease(named_group)) {
                            found = (allowed_groups.find(named_group.value()) != allowed_groups.end());
                            if (!found) {
                                if (msg) {
                                    if (readable_output) {
                                        msg->add_grp_not_allowed(named_group.get_name());
                                    } else {
                                        msg->add_grp_not_allowed_hex(named_group.value());
                                    }
                                }
                            } else {
                                some_allowed = true;
                            }
                        }

                        if(!named_groups_xtn.value.is_readable()) break;
                        named_group = tls::supported_groups{named_groups_xtn.value};
                    }

                    break;
                } else {
                    some_allowed = true;
                }

            }

            bool have_tls_cert_with_extern_psk = false;
            bool have_pre_shared_key = false;
            bool have_psk_key_exchange_modes = false;
            bool have_key_share = false;
            bool psk_modes_valid = true;
            bool psk_mode_has_psk_ke = false;
            bool psk_mode_has_psk_dhe_ke = false;
            bool pre_shared_key_valid = true;
            bool pre_shared_key_binders_min_256_bits = true;
            bool pre_shared_key_has_binder = false;
            bool key_share_valid = true;
            bool key_share_has_mlkem1024 = false;
            datum tmp = extensions;
            while (tmp.is_readable()) {
                xtn extension{tmp};
                switch (extension.type()) {
                case tls::extensions<uint16_t>::code::tls_cert_with_extern_psk:
                    have_tls_cert_with_extern_psk = true;
                    break;
                case tls::extensions<uint16_t>::code::pre_shared_key:
                    have_pre_shared_key = true;
                    {
                        datum psk_data = extension.value;
                        encoded<uint16_t> identities_len{psk_data};
                        if (psk_data.is_not_readable() || identities_len > psk_data.length()) {
                            pre_shared_key_valid = false;
                            pre_shared_key_binders_min_256_bits = false;
                            break;
                        }
                        if (!psk_data.skip(identities_len)) {
                            pre_shared_key_valid = false;
                            pre_shared_key_binders_min_256_bits = false;
                            break;
                        }

                        encoded<uint16_t> binders_len{psk_data};
                        if (psk_data.is_not_readable() || binders_len != psk_data.length()) {
                            pre_shared_key_valid = false;
                            pre_shared_key_binders_min_256_bits = false;
                            break;
                        }

                        datum binders = psk_data;
                        binders.parse(psk_data, binders_len);
                        if (binders.is_not_readable()) {
                            pre_shared_key_valid = false;
                            pre_shared_key_binders_min_256_bits = false;
                            break;
                        }

                        while (binders.is_readable()) {
                            encoded<uint8_t> binder_len{binders};
                            if (binders.is_not_readable() || binder_len > binders.length()) {
                                pre_shared_key_valid = false;
                                pre_shared_key_binders_min_256_bits = false;
                                break;
                            }
                            if (binder_len < 32) {
                                pre_shared_key_binders_min_256_bits = false;
                            }
                            pre_shared_key_has_binder = true;
                            if (!binders.skip(binder_len)) {
                                pre_shared_key_valid = false;
                                pre_shared_key_binders_min_256_bits = false;
                                break;
                            }
                        }
                    }
                    break;
                case tls::extensions<uint16_t>::code::psk_key_exchange_modes:
                    have_psk_key_exchange_modes = true;
                    {
                        datum mode_data = extension.value;
                        encoded<uint8_t> mode_vector_len{mode_data};
                        if (mode_data.is_not_readable() || mode_vector_len != mode_data.length()) {
                            psk_modes_valid = false;
                            break;
                        }
                        while (mode_data.is_readable()) {
                            encoded<uint8_t> mode{mode_data};
                            if (mode == 0) {
                                psk_mode_has_psk_ke = true;
                            } else if (mode == 1) {
                                psk_mode_has_psk_dhe_ke = true;
                            }
                        }
                    }
                    break;
                case tls::extensions<uint16_t>::code::key_share:
                    have_key_share = true;
                    {
                        datum key_share_data = extension.value;
                        encoded<uint16_t> client_shares_len{key_share_data};
                        if (key_share_data.is_not_readable() || client_shares_len != key_share_data.length()) {
                            key_share_valid = false;
                            break;
                        }

                        datum client_shares = key_share_data;
                        client_shares.parse(key_share_data, client_shares_len);
                        if (client_shares.is_not_readable()) {
                            key_share_valid = false;
                            break;
                        }

                        while (client_shares.is_readable()) {
                            encoded<uint16_t> named_group{client_shares};
                            encoded<uint16_t> key_exchange_len{client_shares};
                            if (client_shares.is_not_readable() || key_exchange_len > client_shares.length()) {
                                key_share_valid = false;
                                break;
                            }
                            if (named_group == tls::supported_groups::code::MLKEM1024) {
                                key_share_has_mlkem1024 = true;
                            }
                            if (!client_shares.skip(key_exchange_len)) {
                                key_share_valid = false;
                                break;
                            }
                        }
                    }
                    break;
                default:
                    ;
                }
            }

            // optional extern PSK extension is only compliant with the presence of pre_shared_key,
            // psk_key_exchange_modes and key_share extensions
            bool external_psk_with_cert_compliant =
                !have_tls_cert_with_extern_psk ||
                (have_pre_shared_key && have_psk_key_exchange_modes && have_key_share);
            bool psk_modes_compliant = !have_pre_shared_key ||
                                       (have_psk_key_exchange_modes && psk_modes_valid &&
                                        !psk_mode_has_psk_ke && psk_mode_has_psk_dhe_ke);
            bool psk_binders_compliant = !have_pre_shared_key ||
                                         (pre_shared_key_valid && pre_shared_key_has_binder &&
                                          pre_shared_key_binders_min_256_bits);
            bool psk_mlkem1024_required = have_pre_shared_key &&
                                          have_psk_key_exchange_modes &&
                                          psk_modes_valid &&
                                          psk_mode_has_psk_dhe_ke;
            bool psk_mlkem1024_compliant = !psk_mlkem1024_required ||
                                           (have_key_share && key_share_valid && key_share_has_mlkem1024);

            if (msg) {
                const char *quantifier = "none";
                if (all_allowed) {
                    quantifier = "all";
                } else if (some_allowed) {
                    quantifier = "some";
                }
                msg->set_grp_allowed(quantifier);
                msg->set_psk_mode(have_tls_cert_with_extern_psk);
                if (!external_psk_with_cert_compliant) {
                    msg->set_psk_non_compliant("tls_cert_with_extern_psk_non_compliant",
                                               "tls_cert_with_extern_psk requires pre_shared_key, psk_key_exchange_modes, and key_share");
                }
                if (!psk_modes_compliant) {
                    msg->set_psk_non_compliant("psk_key_exchange_modes_non_compliant",
                                               "psk_key_exchange_modes must include psk_dhe_ke and must not include psk_ke");
                }
                if (!psk_mlkem1024_compliant) {
                    msg->set_psk_non_compliant("psk_key_exchange_mlkem1024_non_compliant",
                                               "psk_dhe_ke requires key_share with MLKEM1024");
                }
                if (!psk_binders_compliant) {
                    msg->set_psk_non_compliant("pre_shared_key_non_compliant",
                                               "pre_shared_key binders must be present and each binder must be at least 256 bits");
                }
            }

            return all_allowed &&
                   external_psk_with_cert_compliant &&
                   psk_modes_compliant &&
                   psk_mlkem1024_compliant &&
                   psk_binders_compliant;
        }

        /*
        * SSH kex init parameters - key exchange methods and encryption algorithms
        */
        static inline const std::unordered_set<std::string_view> ssh_allowed_kex {
            "sntrup761x25519-sha512",    // not NIST approved, but considered PQ safe
            "mlkem768nistp256-sha256",
            "mlkem1024nistp384-sha384",
            "mlkem768x25519-sha256",
            "mlkem512-sha256",
            "mlkem768-sha256",
            "mlkem1024-sha384"
        };

        // TODO: mine for other cipher names
        // considering blowfish, ctr and cbc etc. to be weak
        static inline const std::unordered_set<std::string_view> ssh_allowed_ciphers {
            "AEAD_AES_128_GCM",
            "AEAD_AES_192_GCM",
            "AEAD_AES_256_GCM",
            "aes128-gcm@openssh.com",
            "aes192-gcm@openssh.com",
            "aes256-gcm@openssh.com",
            "aes256-gcm",
            "aes192-gcm",
            "aes128-gcm"
        };

        // Which SSH cipher direction a fill targets (selects the c2s vs s2c message field).
        enum class ssh_cipher_dir { client_to_server, server_to_client };

        bool assess_ssh_kex_methods(const name_list &kex_list) const {
            return assess_ssh_kex_methods_impl(kex_list, nullptr);
        }

        // Classify SSH kex methods against the allow-list. If msg != nullptr, record each
        // not-allowed method and the "allowed" quantifier into it; if nullptr, compliance-only.
        bool assess_ssh_kex_methods_impl(const name_list &kex_list, crypto_cnsa_ssh_message *msg) const {
            bool all_allowed = true;
            bool some_allowed = false;
            name_list tmp_list = kex_list;

            while (tmp_list.is_readable()) {
                datum tmp{};
                tmp.parse_up_to_delim(tmp_list, ',');
                std::string_view tmp_sv{(char*)tmp.data, (size_t)tmp.length()};
                if (tmp.end() == tmp_list.end()) {
                    tmp_list.set_null();
                } else {
                    tmp_list.skip(1);
                }
                bool found = (ssh_allowed_kex.find(tmp_sv) != ssh_allowed_kex.end());
                if (!found) {
                    all_allowed = false;
                    while (true) {
                        found = (ssh_allowed_kex.find(tmp_sv) != ssh_allowed_kex.end());
                        if (!found) {
                            if (msg != nullptr) { msg->add_kex_not_allowed(tmp); }
                        } else {
                            some_allowed = true;
                        }
                        if (!tmp_list.is_readable()) { break; }
                        tmp.set_null();
                        tmp.parse_up_to_delim(tmp_list, ',');
                        tmp_sv = {(char*)tmp.data, (size_t)tmp.length()};
                        if (tmp.end() == tmp_list.end()) {
                            tmp_list.set_null();
                        } else {
                            tmp_list.skip(1);
                        }
                    }
                    break;
                } else {
                    some_allowed = true;
                }
            }
            if (msg != nullptr) {
                const char *quantifier = "none";
                if (all_allowed) { quantifier = "all"; }
                else if (some_allowed) { quantifier = "some"; }
                msg->set_kex_allowed(quantifier);
            }
            return all_allowed;
        }

        bool assess_ssh_ciphers(const name_list &ciphers) const {
            return assess_ssh_ciphers_impl(ciphers, nullptr, ssh_cipher_dir::client_to_server);
        }

        // Classify SSH ciphers against the allow-list. If msg != nullptr, record each
        // not-allowed cipher and the "allowed" quantifier into the c2s or s2c field selected by
        // dir; if nullptr, compliance-only (dir unused).
        bool assess_ssh_ciphers_impl(const name_list &ciphers, crypto_cnsa_ssh_message *msg,
                                     ssh_cipher_dir dir) const {
            bool all_allowed = true;
            bool some_allowed = false;
            name_list tmp_list = ciphers;

            while (tmp_list.is_readable()) {
                datum tmp{};
                tmp.parse_up_to_delim(tmp_list, ',');
                std::string_view tmp_sv{(char*)tmp.data, (size_t)tmp.length()};
                if (tmp.end() == tmp_list.end()) {
                    tmp_list.set_null();
                } else {
                    tmp_list.skip(1);
                }
                bool found = ssh_allowed_ciphers.find(tmp_sv) != ssh_allowed_ciphers.end();
                if (!found) {
                    all_allowed = false;
                    while (true) {
                        found = ssh_allowed_ciphers.find(tmp_sv) != ssh_allowed_ciphers.end();
                        if (!found) {
                            if (msg != nullptr) {
                                if (dir == ssh_cipher_dir::client_to_server) { msg->add_c2s_cs_not_allowed(tmp); }
                                else                                         { msg->add_s2c_cs_not_allowed(tmp); }
                            }
                        } else {
                            some_allowed = true;
                        }
                        if (!tmp_list.is_readable()) { break; }
                        tmp.set_null();
                        tmp.parse_up_to_delim(tmp_list, ',');
                        tmp_sv = {(char*)tmp.data, (size_t)tmp.length()};
                        if (tmp.end() == tmp_list.end()) {
                            tmp_list.set_null();
                        } else {
                            tmp_list.skip(1);
                        }
                    }
                    break;
                } else {
                    some_allowed = true;
                }
            }
            if (msg != nullptr) {
                const char *quantifier = "none";
                if (all_allowed) { quantifier = "all"; }
                else if (some_allowed) { quantifier = "some"; }
                if (dir == ssh_cipher_dir::client_to_server) { msg->set_c2s_cs_allowed(quantifier); }
                else                                         { msg->set_s2c_cs_allowed(quantifier); }
            }
            return all_allowed;
        }

        // --- compliance-only (NO_OUTPUT) path: const, fills nothing ---

        bool assess(const tls_client_hello &ch) const override {
            return assess_tls_ciphersuites(ch.ciphersuite_vector) &&
                   assess_tls_extensions(ch.extensions);
        }

        bool assess(const tls_server_hello &ch) const override {
            return assess_tls_ciphersuites(ch.ciphersuite_vector) &&
                   assess_tls_extensions(ch.extensions);
        }

        bool assess(const tls_server_hello_and_certificate &hello_and_cert) const override {
            if (hello_and_cert.is_not_empty()) {
                return assess(hello_and_cert.get_server_hello());
            }
            return true;
        }

        bool assess(const ssh_kex_init &ssh_kex) const override {
            return assess_ssh_kex_methods(ssh_kex.kex_algorithms) &&
                   assess_ssh_ciphers(ssh_kex.encryption_algorithms_client_to_server) &&
                   assess_ssh_ciphers(ssh_kex.encryption_algorithms_server_to_client);
        }

        bool assess(const dtls_client_hello &dtls_ch) const override {
            const tls_client_hello &ch = dtls_ch.get_tls_client_hello();
            return assess_tls_ciphersuites(ch.ciphersuite_vector) &&
                   assess_tls_extensions(ch.extensions);
        }

        bool assess(const dtls_server_hello &dtls_sh) const override {
            const tls_server_hello &sh = dtls_sh.get_tls_server_hello();
            return assess_tls_ciphersuites(sh.ciphersuite_vector) &&
                   assess_tls_extensions(sh.extensions);
        }

        // Fill path: populates the owned message and returns the compliance bit.
        // These overloads are selected by being non-const; adding const here would
        // silently route callers to the compliance-only version.

        bool assess(const tls_client_hello &ch) override {
            cnsa_tls_msg_.set_policy("quantum_safe");
            cnsa_tls_msg_.set_target("client");
            bool suites = assess_tls_ciphersuites(ch.ciphersuite_vector, cnsa_tls_msg_);
            bool exts   = assess_tls_extensions(ch.extensions, cnsa_tls_msg_);
            cnsa_tls_msg_.set_compliant(suites && exts);
            cnsa_tls_msg_.set_valid();
            return suites && exts;
        }

        bool assess(const tls_server_hello &ch) override {
            cnsa_tls_msg_.set_policy("quantum_safe");
            cnsa_tls_msg_.set_target("session");
            bool suites = assess_tls_ciphersuites(ch.ciphersuite_vector, cnsa_tls_msg_);
            bool exts   = assess_tls_extensions(ch.extensions, cnsa_tls_msg_);
            cnsa_tls_msg_.set_compliant(suites && exts);
            cnsa_tls_msg_.set_valid();
            return suites && exts;
        }

        bool assess(const tls_server_hello_and_certificate &hello_and_cert) override {
            if (hello_and_cert.is_not_empty()) {
                return assess(hello_and_cert.get_server_hello());
            }
            return true;
        }

        bool assess(const ssh_kex_init &ssh_kex) override {
            cnsa_ssh_msg_.set_policy("quantum_safe");
            bool kex_compliant = assess_ssh_kex_methods_impl(ssh_kex.kex_algorithms, &cnsa_ssh_msg_);
            bool c2s_compliant = assess_ssh_ciphers_impl(ssh_kex.encryption_algorithms_client_to_server, &cnsa_ssh_msg_,
                                                         ssh_cipher_dir::client_to_server);
            bool s2c_compliant = assess_ssh_ciphers_impl(ssh_kex.encryption_algorithms_server_to_client, &cnsa_ssh_msg_,
                                                         ssh_cipher_dir::server_to_client);
            cnsa_ssh_msg_.set_compliant(kex_compliant && c2s_compliant && s2c_compliant);
            cnsa_ssh_msg_.set_valid();
            return kex_compliant && c2s_compliant && s2c_compliant;
        }

        bool assess(const dtls_client_hello &dtls_ch) override {
            return assess(dtls_ch.get_tls_client_hello());
        }

        bool assess(const dtls_server_hello &dtls_sh) override {
            return assess(dtls_sh.get_tls_server_hello());
        }

        // --- emit the owned message in the requested format ---

        void emit(json_array &record) override {
            if (cnsa_tls_msg_.is_valid())      { cnsa_tls_msg_.write<json_object>(record); }
            else if (cnsa_ssh_msg_.is_valid()) { cnsa_ssh_msg_.write<json_object>(record); }
        }

        void emit(cbor_object &out) override {
            if (cnsa_tls_msg_.is_valid() && !cnsa_tls_msg_.is_compliant()) {
                cbor::text_string(crypto_cnsa_tls_message::KEY).write(out.get_writeable());
                cnsa_tls_msg_.write<cbor_object>(out);
            } else if (cnsa_ssh_msg_.is_valid() && !cnsa_ssh_msg_.is_compliant()) {
                cbor::text_string(crypto_cnsa_ssh_message::KEY).write(out.get_writeable());
                cnsa_ssh_msg_.write<cbor_object>(out);
            }
        }

    };


    // TLS Server Hello required extensions to check for NIST SP 800-52 Rev 2 non compliance
    //
    typedef struct required_extensions{
        std::unordered_set<uint16_t> supported_extensions;
        uint16_t negotiated_supported_group = 0x0000;
        tls_version supported_version = tls_version::none;
        bool ec_points_format = false;
        bool encrypt_then_mac = false;
    } required_extensions;

    class nist_sp_800_52 : public assessor {

    const bool verbose_output = false;

    // Owned feature message; filled by the non-const assess(), read by emit(). Cleared by
    // reset_output(), which the orchestrator calls before every emitting assessment.
    crypto_nist_message nist_msg_;

    public:
        void reset_output() override { nist_msg_ = {}; }

        const static size_t result_idx = 1; // bitset index for nist assessment

        nist_sp_800_52() { }
        nist_sp_800_52(bool verbose) : verbose_output(verbose) { }
        ~nist_sp_800_52() { }

        virtual size_t get_result_idx() const override {
            return nist_sp_800_52::result_idx;
        }

        uint16_t get_negotiated_cipher_suite(const datum &ciphersuite_vector) const {
            datum cs_datum = ciphersuite_vector;
            if (cs_datum.is_not_readable() || cs_datum.length() != 2) {
                return 0;
            }
            encoded<uint16_t> cs{cs_datum};
            return cs.value();
        }

        bool assess_impl(const tls_server_hello &sh, crypto_nist_message *msg) const {

            bool non_compliant = false;
            tls_version protocol_version = sh.get_version();
            required_extensions exts = sh.extensions.get_required_extensions();
            uint16_t ciphersuite = get_negotiated_cipher_suite(sh.ciphersuite_vector);

            if (msg) {
                msg->set_policy("nist_sp_800_52_2");

                if (verbose_output) {
                    msg->set_has_negotiated_params();
                    if (exts.supported_version != tls_version::none) {
                        msg->set_protocol_version(tls_version_to_string(exts.supported_version));
                    } else {
                        msg->set_protocol_version(tls_version_to_string(protocol_version));
                    }

                    for (const auto &ext : exts.supported_extensions) {
                        if (!is_grease(ext)) {
                            tls::extensions<uint16_t> extn{ext};
                            msg->add_extension(extn.get_name());
                        }
                    }

                    msg->set_cipher_suite(tls::cipher_suites{ciphersuite}.get_name());
                    msg->set_supported_group(tls::supported_groups{exts.negotiated_supported_group}.get_name());
                }
            }

            // NIST SP 800-52 Rev 2 Compliance Rules
            //
            if (!non_compliant && protocol_version == tls_version::tlsv1_3 && exts.supported_version != tls_version::tlsv1_3) {
                if (msg) {
                    msg->set_non_compliant("tls_version_non_compliant", "TLSv1.3 negotiated but supported_versions extension missing or invalid");
                }
                non_compliant = true;
            }

            if (!non_compliant && sh.compression_method.is_readable() &&
                sh.compression_method.is_not_empty() && sh.compression_method.data[0] != 0x00) {
                if (msg) {
                    msg->set_non_compliant("compression_method_non_compliant", "non-zero compression method");
                }
                non_compliant = true;
            }

            if (!non_compliant && exts.supported_extensions.count(type_supported_versions)) {
                if (exts.supported_version == tls_version::tlsv1_3) {
                    if (!non_compliant && !v1_3_allowed_ciphersuites.count(ciphersuite)) {
                        if (msg) {
                            msg->set_non_compliant("cipher_suite_non_compliant", "disallowed cipher suite for TLSv1.3");
                        }
                        non_compliant = true;
                    }
                }
                else {
                    if (msg) {
                        msg->set_non_compliant("tls_version_non_compliant", "supported_versions extension invalid");
                    }
                    non_compliant = true;
                }
            }
            else if (!non_compliant) {
                if (ecdhe_ciphersuites.count(ciphersuite) && !exts.supported_extensions.count(type_supported_groups)) {
                    if (msg) {
                        msg->set_non_compliant("supported_groups_missing", "supported_groups extension missing for ECDHE cipher suite");
                    }
                    non_compliant = true;
                }

                if (!non_compliant && ec_ciphersuites.count(ciphersuite)) {
                    if (!non_compliant && !exts.ec_points_format) {
                        if (msg) {
                            msg->set_non_compliant("ec_points_format_non_compliant", "ec_points_format extension missing but EC cipher suite negotiated");
                        }
                        non_compliant = true;
                    }
                    if (!non_compliant && !(exts.negotiated_supported_group == tls::supported_groups::code::secp256r1 ||
                        exts.negotiated_supported_group == tls::supported_groups::code::secp384r1)) {
                        if (msg) {
                            msg->set_non_compliant("supported_group_non_compliant", "disallowed supported group for EC cipher suite");
                        }
                        non_compliant = true;
                    }
                }

                if (!non_compliant && cbc_ciphersuites.count(ciphersuite) && !exts.encrypt_then_mac) {
                    if (msg) {
                        msg->set_non_compliant("encrypt_then_mac_non_compliant", "encrypt_then_mac extension missing for CBC cipher suite");
                    }
                    non_compliant = true;
                }

                if (protocol_version == tls_version::tlsv1_2) {
                    if (!non_compliant && !v1_2_allowed_ciphersuites.count(ciphersuite)) {
                        if (msg) {
                            msg->set_non_compliant("cipher_suite_non_compliant", "disallowed cipher suite for TLSv1.2");
                        }
                        non_compliant = true;
                    }
                }
                else if (protocol_version == tls_version::tlsv1_1) {
                    if (!non_compliant && !v1_1_allowed_ciphersuites.count(ciphersuite)) {
                        if (msg) {
                            msg->set_non_compliant("cipher_suite_non_compliant", "disallowed cipher suite for TLSv1.1");
                        }
                        non_compliant = true;
                    }
                }
                else if (!non_compliant) {
                    if (msg) {
                        msg->set_non_compliant("tls_version_non_compliant", tls_version_to_string(protocol_version));
                    }
                    non_compliant = true;
                }
            }

            if (msg) {
                msg->set_valid();
            }

            return !non_compliant;
        }

        // compliance-only (NO_OUTPUT) path: const, fills nothing.
        bool assess(const tls_server_hello& sh) const override {
            return assess_impl(sh, nullptr);
        }

        bool assess(const tls_server_hello_and_certificate &hello_and_cert) const override {
            if (hello_and_cert.is_not_empty()) {
                return assess(hello_and_cert.get_server_hello());
            }
            return true;
        }

        // FILL path: non-const, populates the owned message via assess_impl(&msg), returns the
        // compliance bit. The non-constness selects these overloads; never add const here.
        bool assess(const tls_server_hello &sh) override {
            return assess_impl(sh, &nist_msg_);
        }

        bool assess(const tls_server_hello_and_certificate &hello_and_cert) override {
            if (hello_and_cert.is_not_empty()) {
                return assess(hello_and_cert.get_server_hello());
            }
            return true;
        }

        void emit(json_array &record) override {
            if (nist_msg_.is_valid()) { nist_msg_.write<json_object>(record); }
        }

        void emit(cbor_object &out) override {
            if (nist_msg_.is_valid() && !nist_msg_.is_compliant()) {
                cbor::text_string(crypto_nist_message::KEY).write(out.get_writeable());
                nist_msg_.write<cbor_object>(out);
            }
        }

        static inline std::unordered_set<uint16_t> cbc_ciphersuites = {
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            tls::cipher_suites::code::TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
            tls::cipher_suites::code::TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
            tls::cipher_suites::code::TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
            tls::cipher_suites::code::TLS_DH_DSS_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_DH_DSS_WITH_AES_256_CBC_SHA,
            tls::cipher_suites::code::TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
            tls::cipher_suites::code::TLS_DH_RSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_DH_RSA_WITH_AES_256_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            tls::cipher_suites::code::TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        };

        static inline std::unordered_set<uint16_t> ecdhe_ciphersuites {
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        };

        static inline std::unordered_set<uint16_t> ec_ciphersuites {
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
        };

        static inline std::unordered_set<uint16_t> v1_3_allowed_ciphersuites {
            tls::cipher_suites::code::TLS_AES_128_GCM_SHA256,
            tls::cipher_suites::code::TLS_AES_256_GCM_SHA384,
            tls::cipher_suites::code::TLS_AES_128_CCM_SHA256,
            tls::cipher_suites::code::TLS_AES_128_CCM_8_SHA256
        };

        static inline std::unordered_set<uint16_t> v1_2_allowed_ciphersuites {
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,

            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,

            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_128_CCM,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_256_CCM,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_128_CCM_8,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_256_CCM_8,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,

            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,

            tls::cipher_suites::code::TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
            tls::cipher_suites::code::TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
            tls::cipher_suites::code::TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,

            tls::cipher_suites::code::TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_DHE_DSS_WITH_AES_256_CBC_SHA,

            tls::cipher_suites::code::TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
            tls::cipher_suites::code::TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
            tls::cipher_suites::code::TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_DH_DSS_WITH_AES_256_CBC_SHA256,

            tls::cipher_suites::code::TLS_DH_DSS_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_DH_DSS_WITH_AES_256_CBC_SHA,

            tls::cipher_suites::code::TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
            tls::cipher_suites::code::TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
            tls::cipher_suites::code::TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_DH_RSA_WITH_AES_256_CBC_SHA256,

            tls::cipher_suites::code::TLS_DH_RSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_DH_RSA_WITH_AES_256_CBC_SHA,

            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,

            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,

            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,

            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
        };

        static inline std::unordered_set<uint16_t> v1_1_allowed_ciphersuites {
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,

            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,

            tls::cipher_suites::code::TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_DHE_DSS_WITH_AES_256_CBC_SHA,

            tls::cipher_suites::code::TLS_DH_DSS_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_DH_DSS_WITH_AES_256_CBC_SHA,

            tls::cipher_suites::code::TLS_DH_RSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_DH_RSA_WITH_AES_256_CBC_SHA,

            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,

            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
            tls::cipher_suites::code::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
        };

        // Allowed supported groups for NIST SP 800-52 Rev 2
        // Currently we are not checking if disallowed supported group is used
        //
        static inline std::unordered_set<uint16_t> allowed_groups {
            tls::supported_groups::code::secp224r1,
            tls::supported_groups::code::secp256r1,
            tls::supported_groups::code::secp384r1,
            tls::supported_groups::code::secp521r1,
            tls::supported_groups::code::sect233k1,
            tls::supported_groups::code::sect283k1,
            tls::supported_groups::code::sect409k1,
            tls::supported_groups::code::sect571k1,
            tls::supported_groups::code::sect233r1,
            tls::supported_groups::code::sect283r1,
            tls::supported_groups::code::sect409r1,
            tls::supported_groups::code::sect571r1
        };

    };

    inline void assessor::create(const std::string &policy, std::vector<assessor*> &assessors) {

        if (policy == "default") {
            assessors.push_back(new crypto_policy::quantum_safe{true});
            assessors.push_back(new crypto_policy::nist_sp_800_52{true});
            return;
        }

        std::unordered_set<std::string> parsed_policies;
        std::string delim = ",";
        std::string policy_str = policy;
        auto pos = std::string::npos;

        do {
            std::string token;
            pos = policy_str.find(delim);

            if (pos != std::string::npos) {
                token = policy_str.substr(0, pos);
                policy_str.erase(0, pos + delim.length());
            } else {
                token = policy_str;
            }

            if (parsed_policies.count(token) != 0) {
                printf_err(log_err, "Cryptographic security assessment policy '%s' specified multiple times\n", token.c_str());
                continue;
            }

            if (token == "quantum_safe") {
                assessors.push_back(new crypto_policy::quantum_safe{true});
            } else if (token == "nist_sp_800_52") {
                assessors.push_back(new crypto_policy::nist_sp_800_52{true});
            } else {
                printf_err(log_err, "Unknown cryptographic security assessment policy '%s' specified\n", token.c_str());
            }
            parsed_policies.insert(token);

        } while (pos != std::string::npos);
    }

    // LCOV_EXCL_START
    [[maybe_unused]] static bool unit_test() {
        quantum_safe assessor{true};
        char buff[1024];

        // --------------- TLS EXTENSIONS AND CIPHERSUITES ---------------
        // TEST-1
        //
        uint8_t tls_ciphers[] = {
            0x00, 0x8D, // TLS_PSK_WITH_AES_256_CBC_SHA (allowed)
            0xC0, 0xA9, // TLS_PSK_WITH_AES_256_CCM_8 (allowed)
            0x7A, 0x7A, // grease
            0xC0, 0x06  // TLS_ECDHE_ECDSA_WITH_NULL_SHA (not allowed)
        };
        datum ciphersuites_vector{tls_ciphers, tls_ciphers + sizeof(tls_ciphers)};
        crypto_cnsa_message cs_msg;
        assessor.assess_tls_ciphersuites(ciphersuites_vector, cs_msg);
        buffer_stream tls_cphrs_buff_strm{buff, 1024};
        json_object c{&tls_cphrs_buff_strm};
        if (cs_msg.cs_not_allowed_count() > 0 || cs_msg.cs_allowed_valid()) {
            // write just the ciphersuite fields for comparison
            if (cs_msg.cs_not_allowed_count() > 0) {
                json_array cs_arr{c, "ciphersuites_not_allowed"};
                for (size_t i = 0; i < cs_msg.cs_not_allowed_count(); i++)
                    cs_arr.print_string(cs_msg.cs_not_allowed_at(i).value());
                cs_arr.close();
            }
            if (cs_msg.cs_allowed_valid()) {
                c.print_key_string("ciphersuites_allowed", cs_msg.cs_allowed_value().value());
            }
        }
        c.close();

        std::string tls_ciphers_output_str = "{\"ciphersuites_not_allowed\":[\"TLS_ECDHE_ECDSA_WITH_NULL_SHA\"],\"ciphersuites_allowed\":\"some\"}";

        if (tls_ciphers_output_str.length() != c.b->length() || memcmp(tls_ciphers_output_str.c_str(), c.b->dstr, tls_ciphers_output_str.length()) != 0) {
            return false;
        }

        // TEST-2
        //
        uint8_t tls_ciphers_all_allowed[] = {
            0x00, 0x8D, // TLS_PSK_WITH_AES_256_CBC_SHA (allowed)
            0xC0, 0xA9, // TLS_PSK_WITH_AES_256_CCM_8 (allowed)
            0x7A, 0x7A, // grease
        };
        datum ciphersuites_vector_all_allowed{tls_ciphers_all_allowed, tls_ciphers_all_allowed + sizeof(tls_ciphers_all_allowed)};
        crypto_cnsa_message cs_msg_all;
        assessor.assess_tls_ciphersuites(ciphersuites_vector_all_allowed, cs_msg_all);
        buffer_stream tls_cphrs_buff_strm_all_allowed{buff, 1024};
        json_object c_all_allowed{&tls_cphrs_buff_strm_all_allowed};
        if (cs_msg_all.cs_allowed_valid()) {
            c_all_allowed.print_key_string("ciphersuites_allowed", cs_msg_all.cs_allowed_value().value());
        }
        c_all_allowed.close();

        std::string tls_ciphers_all_allowed_output_str = "{\"ciphersuites_allowed\":\"all\"}";

        if (tls_ciphers_all_allowed_output_str.length() != c_all_allowed.b->length() || memcmp(tls_ciphers_all_allowed_output_str.c_str(), c_all_allowed.b->dstr, tls_ciphers_all_allowed_output_str.length()) != 0) {
            return false;
        }

        // TEST-3
        uint8_t tls_ciphers_none_allowed[] = {
            0xC0, 0x06, // TLS_ECDHE_ECDSA_WITH_NULL_SHA (not allowed)
            0x7A, 0x7A, // grease
            0xC0, 0x07  // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA (not allowed)
        };
        datum ciphersuites_vector_none_allowed{tls_ciphers_none_allowed, tls_ciphers_none_allowed + sizeof(tls_ciphers_none_allowed)};
        crypto_cnsa_message cs_msg_none;
        assessor.assess_tls_ciphersuites(ciphersuites_vector_none_allowed, cs_msg_none);
        buffer_stream tls_cphrs_buff_strm_none_allowed{buff, 1024};
        json_object c_none_allowed{&tls_cphrs_buff_strm_none_allowed};
        if (cs_msg_none.cs_not_allowed_count() > 0) {
            json_array cs_arr{c_none_allowed, "ciphersuites_not_allowed"};
            for (size_t i = 0; i < cs_msg_none.cs_not_allowed_count(); i++)
                cs_arr.print_string(cs_msg_none.cs_not_allowed_at(i).value());
            cs_arr.close();
        }
        if (cs_msg_none.cs_allowed_valid()) {
            c_none_allowed.print_key_string("ciphersuites_allowed", cs_msg_none.cs_allowed_value().value());
        }
        c_none_allowed.close();

        std::string tls_ciphers_none_allowed_output_str = "{\"ciphersuites_not_allowed\":[\"TLS_ECDHE_ECDSA_WITH_NULL_SHA\",\"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA\"],\"ciphersuites_allowed\":\"none\"}";
        if (tls_ciphers_none_allowed_output_str.length() != c_none_allowed.b->length() || memcmp(tls_ciphers_none_allowed_output_str.c_str(), c_none_allowed.b->dstr, tls_ciphers_none_allowed_output_str.length()) != 0) {
            return false;
        }


        // TEST-4
        //
        uint8_t tls_extensions_data[] = {
            0x00, 0x0A, // type (supported group)
            0x00, 0x08, // length
            0x00, 0x06, // named groups length
            0x02, 0x00, // MLKEM512 (allowed)
            0x0A, 0x0A, // grease
            0x00, 0x01  // sect163k1 (not allowed)
        };

        tls_extensions extensions{tls_extensions_data, tls_extensions_data + sizeof(tls_extensions_data)};
        crypto_cnsa_message ext_msg;
        assessor.assess_tls_extensions(extensions, ext_msg);
        buffer_stream tls_extn_buff_strm{buff, 1024};
        json_object d{&tls_extn_buff_strm};
        if (ext_msg.grp_not_allowed_count() > 0) {
            json_array grp_arr{d, "groups_not_allowed"};
            for (size_t i = 0; i < ext_msg.grp_not_allowed_count(); i++)
                grp_arr.print_string(ext_msg.grp_not_allowed_at(i).value());
            grp_arr.close();
        }
        if (ext_msg.grp_allowed_valid()) {
            d.print_key_string("groups_allowed", ext_msg.grp_allowed_value().value());
        }
        d.print_key_bool("tls_cert_with_extern_psk", ext_msg.psk_mode());
        for (size_t i = 0; i < ext_msg.psk_non_compliant_count(); i++)
            d.print_key_string(ext_msg.psk_non_compliant_key_at(i).value(), ext_msg.psk_non_compliant_reason_at(i).value());
        d.close();

        std::string tls_extensions_output_str = "{\"groups_not_allowed\":[\"sect163k1\"],\"groups_allowed\":\"some\",\"tls_cert_with_extern_psk\":false}";

        if (tls_extensions_output_str.length() != d.b->length() || memcmp(tls_extensions_output_str.c_str(), d.b->dstr, tls_extensions_output_str.length()) != 0) {
            return false;
        }

        // TEST-5
        //
        uint8_t tls_extensions_data_invalid[] = {
            0x00, 0x0A, // type (supported group)
            0x00, 0x08, // length
            0x00, 0x07, // named groups length (invalid length - odd number)
            0x02, 0x00, // MLKEM512 (allowed)
            0x0A, 0x0A, // grease
            0x00, 0x01  // sect163k1 (not allowed)
        };

        tls_extensions extensions_invalid{tls_extensions_data_invalid, tls_extensions_data_invalid + sizeof(tls_extensions_data_invalid)};
        crypto_cnsa_message ext_msg_invalid;
        if (assessor.assess_tls_extensions(extensions_invalid, ext_msg_invalid)) {
            return false;
        }

        // TEST-6
        //
        uint8_t tls_extensions_data_all_allowed[] = {
            0x00, 0x0A, // type (supported group)
            0x00, 0x08, // length
            0x00, 0x06, // named groups length
            0x02, 0x00, // MLKEM512 (allowed)
            0x0A, 0x0A, // grease
            0x02, 0x01  // MLKEM768 (allowed)
        };

        tls_extensions extensions_all_allowed{tls_extensions_data_all_allowed, tls_extensions_data_all_allowed + sizeof(tls_extensions_data_all_allowed)};
        crypto_cnsa_message ext_msg_all;
        assessor.assess_tls_extensions(extensions_all_allowed, ext_msg_all);
        buffer_stream tls_extn_buff_strm_all_allowed{buff, 1024};
        json_object d_all_allowed{&tls_extn_buff_strm_all_allowed};
        if (ext_msg_all.grp_allowed_valid()) {
            d_all_allowed.print_key_string("groups_allowed", ext_msg_all.grp_allowed_value().value());
        }
        d_all_allowed.print_key_bool("tls_cert_with_extern_psk", ext_msg_all.psk_mode());
        d_all_allowed.close();

        std::string tls_extensions_all_allowed_output_str = "{\"groups_allowed\":\"all\",\"tls_cert_with_extern_psk\":false}";

        if (tls_extensions_all_allowed_output_str.length() != d_all_allowed.b->length() || memcmp(tls_extensions_all_allowed_output_str.c_str(), d_all_allowed.b->dstr, tls_extensions_all_allowed_output_str.length()) != 0) {
            return false;
        }

        // TEST-7
        //
        uint8_t tls_extensions_data_no_allowed[] = {
            0x00, 0x0A, // type (supported group)
            0x00, 0x08, // length
            0x00, 0x06, // named groups length
            0x00, 0x01, // sect163k1 (not allowed)
            0x0A, 0x0A, // grease
            0x00, 0x02  // sect163r1 (not allowed)
        };

        tls_extensions extensions_no_allowed{tls_extensions_data_no_allowed, tls_extensions_data_no_allowed + sizeof(tls_extensions_data_no_allowed)};
        crypto_cnsa_message ext_msg_no;
        assessor.assess_tls_extensions(extensions_no_allowed, ext_msg_no);
        buffer_stream tls_extn_buff_strm_no_allowed{buff, 1024};
        json_object d_no_allowed{&tls_extn_buff_strm_no_allowed};
        if (ext_msg_no.grp_not_allowed_count() > 0) {
            json_array grp_arr{d_no_allowed, "groups_not_allowed"};
            for (size_t i = 0; i < ext_msg_no.grp_not_allowed_count(); i++)
                grp_arr.print_string(ext_msg_no.grp_not_allowed_at(i).value());
            grp_arr.close();
        }
        if (ext_msg_no.grp_allowed_valid()) {
            d_no_allowed.print_key_string("groups_allowed", ext_msg_no.grp_allowed_value().value());
        }
        d_no_allowed.print_key_bool("tls_cert_with_extern_psk", ext_msg_no.psk_mode());
        d_no_allowed.close();

        std::string tls_extensions_no_allowed_output_str = "{\"groups_not_allowed\":[\"sect163k1\",\"sect163r1\"],\"groups_allowed\":\"none\",\"tls_cert_with_extern_psk\":false}";

        if (tls_extensions_no_allowed_output_str.length() != d_no_allowed.b->length() || memcmp(tls_extensions_no_allowed_output_str.c_str(), d_no_allowed.b->dstr, tls_extensions_no_allowed_output_str.length()) != 0) {
            return false;
        }

        // --------------- SSH KEX METHODS AND CIPHERSUITES ---------------
        // TEST-8
        //
        uint8_t kex_algorithms[] = {
            0x00, 0x00, 0x00, 0x30, // length 48
            0x6D, 0x6C, 0x6B, 0x65, 0x6D, 0x31, 0x30, 0x32, //
            0x34, 0x6E, 0x69, 0x73, 0x74, 0x70, 0x33, 0x38, //
            0x34, 0x2D, 0x73, 0x68, 0x61, 0x33, 0x38, 0x34, // mlkem1024nistp384-sha384,mlkem768-sha256,abc,xyz
            0x2C, 0x6D, 0x6c, 0x6B, 0x65, 0x6D, 0x37, 0x36, //
            0x38, 0x2D, 0x73, 0x68, 0x61, 0x32, 0x35, 0x36, //
            0x2C, 0x61, 0x62, 0x63, 0x2C, 0x78, 0x79, 0x7A  //
        };

        datum kex_algo_dtm{kex_algorithms, kex_algorithms + sizeof(kex_algorithms)};
        name_list kex_algorithms_data{};
        kex_algorithms_data.parse(kex_algo_dtm);

        // assess into a message via the fill path, then verify the rendered JSON contains the
        // expected kex classification (nested under "offered").
        {
            crypto_cnsa_ssh_message kex_msg;
            bool kex_compliant = assessor.assess_ssh_kex_methods_impl(kex_algorithms_data, &kex_msg);
            buffer_stream kex_bs{buff, 1024};
            json_object kex_jo{&kex_bs};
            kex_msg.write<json_object>(kex_jo);
            kex_jo.close();
            std::string kex_out{kex_bs.dstr, (size_t)kex_bs.length()};
            if (kex_compliant
                || kex_out.find("\"kex_not_allowed\":[\"abc\",\"xyz\"]") == std::string::npos
                || kex_out.find("\"kex_allowed\":\"some\"") == std::string::npos) {
                return false;
            }
        }

        // TEST-9
        //
        uint8_t kex_algorithms_all_allowed[] = {
            0x00, 0x00, 0x00, 0x28, // length 40
            0x6D, 0x6C, 0x6B, 0x65, 0x6D, 0x31, 0x30, 0x32, //
            0x34, 0x6E, 0x69, 0x73, 0x74, 0x70, 0x33, 0x38, //
            0x34, 0x2D, 0x73, 0x68, 0x61, 0x33, 0x38, 0x34, // mlkem1024nistp384-sha384,mlkem768-sha256
            0x2C, 0x6D, 0x6c, 0x6B, 0x65, 0x6D, 0x37, 0x36, //
            0x38, 0x2D, 0x73, 0x68, 0x61, 0x32, 0x35, 0x36  //
        };

        datum kex_algo_all_allowed_dtm{kex_algorithms_all_allowed, kex_algorithms_all_allowed + sizeof(kex_algorithms_all_allowed)};
        name_list kex_algorithms_all_allowed_data{};
        kex_algorithms_all_allowed_data.parse(kex_algo_all_allowed_dtm);

        {
            crypto_cnsa_ssh_message kex_msg;
            bool kex_compliant = assessor.assess_ssh_kex_methods_impl(kex_algorithms_all_allowed_data, &kex_msg);
            buffer_stream kex_bs{buff, 1024};
            json_object kex_jo{&kex_bs};
            kex_msg.write<json_object>(kex_jo);
            kex_jo.close();
            std::string kex_out{kex_bs.dstr, (size_t)kex_bs.length()};
            if (!kex_compliant
                || kex_out.find("\"kex_not_allowed\"") != std::string::npos
                || kex_out.find("\"kex_allowed\":\"all\"") == std::string::npos) {
                return false;
            }
        }

        // TEST-10
        //
        uint8_t kex_algorithms_none_allowed[] = {
            0x00, 0x00, 0x00, 0x0F, // length 15
            0x61, 0x62, 0x63, 0x2C, //
            0x78, 0x79, 0x7A, 0x2C, //
            0x61, 0x62, 0x63, 0x2C, // abc,xyz,abc,xyz
            0x78, 0x79, 0x7A        //
        };

        datum kex_algo_none_allowed_dtm{kex_algorithms_none_allowed, kex_algorithms_none_allowed + sizeof(kex_algorithms_none_allowed)};
        name_list kex_algorithms_none_allowed_data{};
        kex_algorithms_none_allowed_data.parse(kex_algo_none_allowed_dtm);

        {
            crypto_cnsa_ssh_message kex_msg;
            bool kex_compliant = assessor.assess_ssh_kex_methods_impl(kex_algorithms_none_allowed_data, &kex_msg);
            buffer_stream kex_bs{buff, 1024};
            json_object kex_jo{&kex_bs};
            kex_msg.write<json_object>(kex_jo);
            kex_jo.close();
            std::string kex_out{kex_bs.dstr, (size_t)kex_bs.length()};
            if (kex_compliant
                || kex_out.find("\"kex_not_allowed\":[\"abc\",\"xyz\",\"abc\",\"xyz\"]") == std::string::npos
                || kex_out.find("\"kex_allowed\":\"none\"") == std::string::npos) {
                return false;
            }
        }

        // TEST-11
        //
        uint8_t ssh_ciphers[] = {
            0x00, 0x00, 0x00, 0x23, // length 35
            0x41, 0x45, 0x41, 0x44, 0x5F, 0x41, 0x45, 0x53, //
            0x5F, 0x31, 0x32, 0x38, 0x5F, 0x47, 0x43, 0x4D, //
            0x2C, 0x61, 0x65, 0x73, 0x32, 0x35, 0x36, 0x2D, // AEAD_AES_128_GCM,aes256-gcm,abc,xyz
            0x67, 0x63, 0x6D, 0x2C, 0x61, 0x62, 0x63, 0x2C, //
            0x78, 0x79, 0x7A                                //
        };

        datum ssh_ciphers_dtm{ssh_ciphers, ssh_ciphers + sizeof(ssh_ciphers)};
        name_list ssh_ciphers_data{};
        ssh_ciphers_data.parse(ssh_ciphers_dtm);

        {
            crypto_cnsa_ssh_message cs_msg;
            bool cs_compliant = assessor.assess_ssh_ciphers_impl(ssh_ciphers_data, &cs_msg,
                                                                 quantum_safe::ssh_cipher_dir::client_to_server);
            buffer_stream cs_bs{buff, 1024};
            json_object cs_jo{&cs_bs};
            cs_msg.write<json_object>(cs_jo);
            cs_jo.close();
            std::string cs_out{cs_bs.dstr, (size_t)cs_bs.length()};
            if (cs_compliant
                || cs_out.find("\"ciphersuites_not_allowed\":[\"abc\",\"xyz\"]") == std::string::npos
                || cs_out.find("\"ciphersuites_allowed\":\"some\"") == std::string::npos) {
                return false;
            }
        }

        // TEST-12
        //
        uint8_t ssh_ciphers_all_allowed[] = {
            0x00, 0x00, 0x00, 0x1B, // length 27
            0x41, 0x45, 0x41, 0x44, 0x5F, 0x41, 0x45, 0x53, //
            0x5F, 0x31, 0x32, 0x38, 0x5F, 0x47, 0x43, 0x4D, // AEAD_AES_128_GCM,aes256-gcm
            0x2C, 0x61, 0x65, 0x73, 0x32, 0x35, 0x36, 0x2D, //
            0x67, 0x63, 0x6D                                //
        };

        datum ssh_ciphers_all_allowed_dtm{ssh_ciphers_all_allowed, ssh_ciphers_all_allowed + sizeof(ssh_ciphers_all_allowed)};
        name_list ssh_ciphers_all_allowed_data{};
        ssh_ciphers_all_allowed_data.parse(ssh_ciphers_all_allowed_dtm);

        {
            crypto_cnsa_ssh_message cs_msg;
            bool cs_compliant = assessor.assess_ssh_ciphers_impl(ssh_ciphers_all_allowed_data, &cs_msg,
                                                                 quantum_safe::ssh_cipher_dir::client_to_server);
            buffer_stream cs_bs{buff, 1024};
            json_object cs_jo{&cs_bs};
            cs_msg.write<json_object>(cs_jo);
            cs_jo.close();
            std::string cs_out{cs_bs.dstr, (size_t)cs_bs.length()};
            if (!cs_compliant
                || cs_out.find("\"ciphersuites_not_allowed\"") != std::string::npos
                || cs_out.find("\"ciphersuites_allowed\":\"all\"") == std::string::npos) {
                return false;
            }
        }

        // TEST-13
        //
        uint8_t ssh_ciphers_none_allowed[] = {
            0x00, 0x00, 0x00, 0x0F, // length 15
            0x61, 0x62, 0x63, 0x2C, //
            0x78, 0x79, 0x7A, 0x2C, //
            0x61, 0x62, 0x63, 0x2C, // abc,xyz,abc,xyz
            0x78, 0x79, 0x7A        //
        };

        datum ssh_ciphers_none_allowed_dtm{ssh_ciphers_none_allowed, ssh_ciphers_none_allowed + sizeof(ssh_ciphers_none_allowed)};
        name_list ssh_ciphers_none_allowed_data{};
        ssh_ciphers_none_allowed_data.parse(ssh_ciphers_none_allowed_dtm);

        {
            crypto_cnsa_ssh_message cs_msg;
            bool cs_compliant = assessor.assess_ssh_ciphers_impl(ssh_ciphers_none_allowed_data, &cs_msg,
                                                                 quantum_safe::ssh_cipher_dir::client_to_server);
            buffer_stream cs_bs{buff, 1024};
            json_object cs_jo{&cs_bs};
            cs_msg.write<json_object>(cs_jo);
            cs_jo.close();
            std::string cs_out{cs_bs.dstr, (size_t)cs_bs.length()};
            if (cs_compliant
                || cs_out.find("\"ciphersuites_not_allowed\":[\"abc\",\"xyz\",\"abc\",\"xyz\"]") == std::string::npos
                || cs_out.find("\"ciphersuites_allowed\":\"none\"") == std::string::npos) {
                return false;
            }
        }

        // TEST-14
        //
        uint8_t ssh_ciphers_malformed[] = {
            0x00, 0x00, 0x00, 0x3D, // length 61
            0x2C, 0x2C, 0x61, 0x62, 0x63, 0x2D, 0x61, 0x62, //
            0x63, 0x28, 0x61, 0x62, 0x63, 0x29, 0x40, 0x78, //
            0x79, 0x7A, 0x2E, 0x63, 0x6F, 0x6D, 0x2C, 0x2C, //
            0x61, 0x22, 0x62, 0x63, 0x22, 0x78, 0x79, 0x7A, // ,,abc-abc(abc)@xyz.com,,a"bc"xyz@abc.com,abc\-/xyz@domain.org
            0x40, 0x61, 0x62, 0x63, 0x2E, 0x63, 0x6F, 0x6D, //
            0x2C, 0x61, 0x62, 0x63, 0x5C, 0x2D, 0x2F, 0x78, //
            0x79, 0x7A, 0x40, 0x64, 0x6F, 0x6D, 0x61, 0x69, //
            0x6E, 0x2E, 0x6F, 0x72, 0x67                    //
        };

        datum ssh_ciphers_malformed_dtm{ssh_ciphers_malformed, ssh_ciphers_malformed + sizeof(ssh_ciphers_malformed)};
        name_list ssh_ciphers_malformed_data{};
        ssh_ciphers_malformed_data.parse(ssh_ciphers_malformed_dtm);

        {
            crypto_cnsa_ssh_message cs_msg;
            bool cs_compliant = assessor.assess_ssh_ciphers_impl(ssh_ciphers_malformed_data, &cs_msg,
                                                                 quantum_safe::ssh_cipher_dir::client_to_server);
            buffer_stream cs_bs{buff, 1024};
            json_object cs_jo{&cs_bs};
            cs_msg.write<json_object>(cs_jo);
            cs_jo.close();
            std::string cs_out{cs_bs.dstr, (size_t)cs_bs.length()};
            // malformed input: none allowed; the not-allowed list records the non-empty parsed
            // tokens verbatim (embedded quotes/backslashes included).
            if (cs_compliant
                || cs_out.find("\"ciphersuites_not_allowed\":[\"abc-abc(abc)@xyz.com\",\"a\\\"bc\\\"xyz@abc.com\",\"abc\\\\-/xyz@domain.org\"]") == std::string::npos
                || cs_out.find("\"ciphersuites_allowed\":\"none\"") == std::string::npos) {
                return false;
            }
        }

        // A reused nist_sp_800_52 must not emit a ServerHello finding on a later
        // ClientHello it does not assess. Drives the policy objects through the same
        // reset_output -> assess -> emit sequence as an emitting assessment pass.
        {
            std::vector<crypto_policy::assessor *> policies;
            policies.push_back(new nist_sp_800_52{true});

            // one emitting crypto-assessment pass, mirroring the pkt_proc.cc
            // CBOR block; returns the number of bytes emitted into the v1 map.
            auto emitted_bytes = [&](auto &&hello) -> ssize_t {
                data_buffer<1024> buf;
                cbor_object outer{buf};
                cbor_object v1{outer, CBOR_METADATA_VERSION_KEY};
                const ssize_t before = buf.readable_length();
                for (auto *p : policies) {
                    p->reset_output();
                    p->assess(hello);
                }
                for (auto *p : policies) { p->emit(v1); }
                const ssize_t after_features = buf.readable_length();
                v1.close();
                outer.close();
                return after_features - before;   // >0 iff a feature was emitted
            };

            // --- packet A: non-compliant TLS ServerHello ---
            uint8_t verA[]  = { 0x03, 0x03 };   // TLS 1.2
            uint8_t csA[]   = { 0x00, 0x3d };   // TLS_RSA_WITH_AES_256_CBC_SHA256
            uint8_t compA[] = { 0x01 };         // non-zero compression -> non-compliant
            tls_server_hello sh;
            sh.protocol_version   = datum{verA,  verA  + sizeof(verA)};
            sh.ciphersuite_vector = datum{csA,   csA   + sizeof(csA)};
            sh.compression_method = datum{compA, compA + sizeof(compA)};

            ssize_t bytes_A = emitted_bytes(sh);

            // --- packet B: ClientHello (NIST inherits the default fill path) ---
            uint8_t verB[]  = { 0x03, 0x03 };
            uint8_t csB[]   = { 0x13, 0x01 };   // TLS_AES_128_GCM_SHA256
            uint8_t compB[] = { 0x00 };
            tls_client_hello ch;
            ch.protocol_version    = datum{verB,  verB  + sizeof(verB)};
            ch.ciphersuite_vector  = datum{csB,   csB   + sizeof(csB)};
            ch.compression_methods = datum{compB, compB + sizeof(compB)};

            ssize_t bytes_B = emitted_bytes(ch);

            for (auto *p : policies) { delete p; }

            // A (non-compliant ServerHello) must emit; B (ClientHello, not
            // assessed by NIST) must NOT emit. bytes_B > 0 is the bug.
            if (bytes_A <= 0) { return false; }   // the ServerHello must emit
            if (bytes_B  > 0) { return false; }   // the ClientHello must not emit
        }

        // The emitting loop must reach each policy's non-const assess() override.
        // The overloads differ only in const-ness, so one written const by mistake
        // compiles cleanly and emits nothing.
        {
            std::vector<crypto_policy::assessor *> policies;
            policies.push_back(new quantum_safe{true});
            policies.push_back(new nist_sp_800_52{true});

            // one emitting pass through a non-const assessor*, as the orchestrator does
            auto emitted_bytes = [&](auto &&hello) -> ssize_t {
                data_buffer<1024> buf;
                cbor_object outer{buf};
                cbor_object v1{outer, CBOR_METADATA_VERSION_KEY};
                const ssize_t before = buf.readable_length();
                for (auto *p : policies) {
                    p->reset_output();
                    p->assess(hello);       // must select the non-const overload
                }
                for (auto *p : policies) { p->emit(v1); }
                const ssize_t after_features = buf.readable_length();
                v1.close();
                outer.close();
                return after_features - before;
            };

            // non-compliant TLS ServerHello: quantum_safe and nist both fill and emit
            uint8_t ver[]  = { 0x03, 0x03 };   // TLS 1.2
            uint8_t cs[]   = { 0x00, 0x3d };   // TLS_RSA_WITH_AES_256_CBC_SHA256
            uint8_t comp[] = { 0x01 };         // non-zero compression -> non-compliant
            tls_server_hello sh;
            sh.protocol_version   = datum{ver,  ver  + sizeof(ver)};
            sh.ciphersuite_vector = datum{cs,   cs   + sizeof(cs)};
            sh.compression_method = datum{comp, comp + sizeof(comp)};
            ssize_t sh_bytes = emitted_bytes(sh);

            // non-compliant TLS ClientHello: quantum_safe fills; nist has no
            // ClientHello override and correctly emits nothing
            uint8_t ccomp[] = { 0x00 };
            tls_client_hello ch;
            ch.protocol_version    = datum{ver,   ver   + sizeof(ver)};
            ch.ciphersuite_vector  = datum{cs,    cs    + sizeof(cs)};
            ch.compression_methods = datum{ccomp, ccomp + sizeof(ccomp)};
            ssize_t ch_bytes = emitted_bytes(ch);

            for (auto *p : policies) { delete p; }

            // zero bytes means the non-const override was never reached
            if (sh_bytes <= 0) { return false; }
            if (ch_bytes <= 0) { return false; }
        }

        return true;
    }
    // LCOV_EXCL_STOP

}; // namespace crypto_policy


// Implementation of tls_extensions::get_required_extensions()
//
inline crypto_policy::required_extensions tls_extensions::get_required_extensions() const {

    crypto_policy::required_extensions req_exts;

    datum ext_parser{*this};

    while (ext_parser.length() > 0) {
        uint64_t tmp_len = 0;
        uint64_t tmp_type;

        const uint8_t *data = ext_parser.data;
        if (ext_parser.read_uint(&tmp_type, L_ExtensionType) == false) {
            break;
        }
        if (ext_parser.read_uint(&tmp_len, L_ExtensionLength) == false) {
            break;
        }
        if (ext_parser.skip(tmp_len) == false) {
            break;
        }

        const uint8_t* data_end = ext_parser.data;
        if (tmp_type == type_supported_groups) {
            req_exts.negotiated_supported_group = 0x0000;   // initialize to unknown in case of invalid extension
            datum named_groups = get_supported_groups();
            xtn named_groups_xtn{named_groups};
            encoded<uint16_t> named_groups_len{named_groups_xtn.value};
            if (named_groups_len != 2) {
                continue; // invalid length
            }
            if (named_groups_xtn.value.is_readable()) {
                tls::supported_groups named_group{named_groups_xtn.value};
                if (crypto_policy::is_grease(named_group)) {
                    continue;
                }
                req_exts.negotiated_supported_group = named_group.value();
            }
        }
        else if (tmp_type == type_supported_versions) {
            datum ext{data, data_end};
            ext.skip(L_ExtensionType + L_ExtensionLength);
            if (ext.is_readable() == false || ext.length() < 2) {
                continue; // invalid length
            }
            encoded<uint16_t> version{(uint16_t)(ext.data[0] << 8 | ext.data[1])};
            req_exts.supported_version = (tls_version)version.value();
        }
        else if (tmp_type == type_encrypt_then_mac) {
            req_exts.encrypt_then_mac = true;
        }
        else if (tmp_type == type_ec_points_format) {
            req_exts.ec_points_format = true;
        }

        req_exts.supported_extensions.insert(tmp_type);
    }

    return req_exts;
}


#endif // CRYPTO_ASSESS_H
