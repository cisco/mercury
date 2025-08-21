// TLS, QUIC and X509/PKIX Crypto Security Assessment
//

#ifndef CRYPTO_ASSESS_H
#define CRYPTO_ASSESS_H

#include <cstdint>
#include <array>
#include "json_object.h"
#include "tls_parameters.hpp"
#include "tls_extensions.hpp"
#include "tls.h"
#include "dtls.h"
#include "ssh.h"

namespace crypto_policy {

    // assessor is the base class representing a particular crypto
    // assessment policy
    //
    class assessor {
    public:

        virtual bool assess(const tls_client_hello &) const {
            return true;
        };

        virtual bool assess(const tls_client_hello &, json_object &) const {
            return true;
        };

        virtual bool assess(const tls_server_hello &, json_object &) const {
            return true;
        };

        virtual bool assess(const tls_server_hello_and_certificate &, json_object &) const {
            return true;
        };

        virtual bool assess(const dtls_client_hello &, json_object &) const {
            return true;
        }

        virtual bool assess(const dtls_server_hello &, json_object &) const {
            return true;
        }

        virtual bool assess(const ssh_kex_init &, json_object &) const {
            return true;
        }

        virtual ~assessor() { }

        static const assessor *create(const std::string &policy);
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

    public:

        quantum_safe(bool readable=false) :
            readable_output{readable}
        { }

        ~quantum_safe() { }

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
            // tls::supported_groups::code::arbitrary_explicit_prime_curves,
            // tls::supported_groups::code::arbitrary_explicit_char2_curves,
        };

        bool assess_tls_ciphersuites(datum ciphersuite_vector, json_object &a) const {
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

                    // Initialize json array for "ciphersuites_not_allowed" inside the if block
                    json_array cs_array(a, "ciphersuites_not_allowed");

                    // Inner while loop through remaining ciphersuite vector, writing out json array
                    while (true) {
                        if (!is_grease(cs)) {
                            found = (allowed_ciphersuites.find(cs.value()) != allowed_ciphersuites.end());
                            if (!found) {
                                all_allowed = false;
                                if (readable_output) {
                                    cs_array.print_string(cs.get_name());
                                } 
                                else {
                                    cs_array.print_uint16_hex(cs);
                                }
                            }
                            else {
                                some_allowed = true;
                            }
                        }
                        if (!ciphersuite_vector.is_readable()) break;
                        cs = tls::cipher_suites{ciphersuite_vector};
                    }

                    cs_array.close();
                    break; // Break out of the outer while loop
                }
                else {
                    some_allowed = true;
                }

            }

            const char *quantifier = "none";
            if (all_allowed) {
                quantifier = "all";
            } 
            else if (some_allowed) {
                quantifier = "some";
            }
            a.print_key_string("ciphersuites_allowed", quantifier);

            return true;
        }
        
        bool assess_tls_extensions(const tls_extensions &extensions, json_object &a) const {
            bool all_allowed = true;
            bool some_allowed = false;

            datum named_groups = extensions.get_supported_groups();
            xtn named_groups_xtn{named_groups};
            encoded<uint16_t> named_groups_len{named_groups_xtn.value};

            while (named_groups_xtn.value.is_readable()) {
                tls::supported_groups named_group{named_groups_xtn.value};

                if (is_grease(named_group)) {
                    continue;
                }

                bool found = (allowed_groups.find(named_group.value()) != allowed_groups.end());
                if (!found) {
                    all_allowed = false;
                    json_array ng_array(a, "groups_not_allowed");

                    while (true) {
                        if (!is_grease(named_group)) {
                            found = (allowed_groups.find(named_group.value()) != allowed_groups.end());
                            if (!found) {
                                all_allowed = false;
                                if (readable_output) {
                                    ng_array.print_string(named_group.get_name());
                                } else {
                                    ng_array.print_uint16_hex(named_group);
                                }
                            }
                            else {
                                some_allowed = true;
                            }
                        }
                        if(!named_groups_xtn.value.is_readable()) break;
                        named_group = tls::supported_groups{named_groups_xtn.value};
                    }

                    ng_array.close();
                    break;
                }
                else {
                    some_allowed = true;
                }

            }

            const char *quantifier = "none";
            if (all_allowed) {
                quantifier = "all";
            } 
            else if (some_allowed) {
                quantifier = "some";
            }
            a.print_key_string("groups_allowed", quantifier);

            // required extensions
            bool have_tls_cert_with_extern_psk = false;
            datum tmp = extensions;
            while (tmp.is_readable()) {
                xtn extension{tmp};
                switch (extension.type()) {
                case tls::extensions<uint16_t>::code::tls_cert_with_extern_psk:
                    have_tls_cert_with_extern_psk = true;
                    break;
                default:
                    ;
                }
            }
            
            a.print_key_bool("tls_cert_with_extern_psk", have_tls_cert_with_extern_psk);
            
            return true;

        }

        /*
        * SSH kex init paramaters - key exchange methods and encryption algorithms
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

        bool assess_ssh_kex_methods(const name_list &kex_list, json_object &a) const {
            bool all_allowed = true;
            bool some_allowed = false;
            name_list tmp_list = kex_list;

            while (tmp_list.is_readable()) {
                datum tmp{};
                tmp.parse_up_to_delim(tmp_list, ',');
                std::string_view tmp_sv{(char*)tmp.data, (size_t)tmp.length()};
                if (tmp.end() == tmp_list.end()) {
                    tmp_list.set_null();
                }
                tmp_list.skip(1); // skip ','

                bool found = (ssh_allowed_kex.find(tmp_sv) != ssh_allowed_kex.end());
                if (!found) {
                    all_allowed = false;
                    json_array cs_array(a, "kex_not_allowed");
                    
                    while (true) {
                        
                        found = (ssh_allowed_kex.find(tmp_sv) != ssh_allowed_kex.end());
                        if (!found) {
                            all_allowed = false;
                            cs_array.print_string(tmp_sv.data(), tmp_sv.length());
                        }
                        else {
                            some_allowed = true;
                        }

                        if (!tmp_list.is_readable()) {
                            break;
                        }

                        tmp.set_null();
                        tmp.parse_up_to_delim(tmp_list, ',');
                        tmp_sv = {(char*)tmp.data, (size_t)tmp.length()};
                        if (tmp.end() == tmp_list.end()) {
                            tmp_list.set_null();
                        }
                        tmp_list.skip(1); // skip ','
                    }
                    cs_array.close();
                    break;
                }
                else {
                    some_allowed = true;
                }
            }

            const char *quantifier = "none";
            if (all_allowed) {
                quantifier = "all";
            } 
            else if (some_allowed) {
                quantifier = "some";
            }

            a.print_key_string("kex_allowed", quantifier);

            return true;
        }

        bool assess_ssh_ciphers(const name_list &ciphers, json_object &a) const {
            bool all_allowed = true;
            bool some_allowed = false;
            name_list tmp_list = ciphers;

            while (tmp_list.is_readable()) {
                datum tmp{};
                tmp.parse_up_to_delim(tmp_list, ',');
                std::string_view tmp_sv{(char*)tmp.data, (size_t)tmp.length()};
                if (tmp.end() == tmp_list.end()) {
                    tmp_list.set_null();
                }
                tmp_list.skip(1); // skips ','

                bool found = ssh_allowed_ciphers.find(tmp_sv) != ssh_allowed_ciphers.end();
                if (!found) {
                    all_allowed = false;
                    json_array cs_array(a, "ciphersuites_not_allowed");

                    while (true) {
                        found = ssh_allowed_ciphers.find(tmp_sv) != ssh_allowed_ciphers.end();
                        if (!found) {
                            all_allowed = false;
                            cs_array.print_string(tmp_sv.data(), tmp_sv.length());
                        }
                        else {
                            some_allowed = true;
                        }

                        if (!tmp_list.is_readable()) {
                            break;
                        }

                        tmp.set_null();
                        tmp.parse_up_to_delim(tmp_list, ',');
                        tmp_sv = {(char*)tmp.data, (size_t)tmp.length()};
                        if (tmp.end() == tmp_list.end()) {
                            tmp_list.set_null();
                        }
                        tmp_list.skip(1); // skips ','

                    }
                    cs_array.close();
                    break;
                }
                else {
                    some_allowed = true;
                }
            }

            const char *quantifier = "none";
            if (all_allowed) {
                quantifier = "all";
            } 
            else if (some_allowed) {
                quantifier = "some";
            }

            a.print_key_string("ciphersuites_allowed", quantifier);

            return true;
        }

        bool assess(const tls_client_hello &ch, json_object &o) const override {

            json_object a{o, "cryptographic_security_assessment"};
            a.print_key_string("policy", "quantum_safe");
            json_object assessment{a, "client"};
            assess_tls_ciphersuites(ch.ciphersuite_vector, assessment);
            assess_tls_extensions(ch.extensions, assessment);
            assessment.close();
            a.close();

            return true;
        }

        bool assess(const tls_server_hello &ch, json_object &o) const override {

            json_object a{o, "cryptographic_security_assessment"};
            a.print_key_string("policy", "quantum_safe");
            json_object assessment{a, "session"};
            assess_tls_ciphersuites(ch.ciphersuite_vector, assessment);
            assess_tls_extensions(ch.extensions, assessment);
            assessment.close();
            a.close();

            return true;
        }

        bool assess(const tls_server_hello_and_certificate &hello_and_cert, json_object &o) const override {
            if (hello_and_cert.is_not_empty()) {
                return assess(hello_and_cert.get_server_hello(), o);
            }
            return false;
        };

        bool assess(const ssh_kex_init &ssh_kex, json_object &o) const override {
            json_object a{o, "cryptographic_security_assessment"};
            a.print_key_string("policy", "quantum_safe");
            json_object assessment{a, "offered"};
            assess_ssh_kex_methods(ssh_kex.kex_algorithms,assessment);
            json_object client_server{assessment, "client_to_server"};
            assess_ssh_ciphers(ssh_kex.encryption_algorithms_client_to_server,client_server);
            client_server.close();
            json_object server_client{assessment,"server_to_client"};
            assess_ssh_ciphers(ssh_kex.encryption_algorithms_server_to_client,server_client);
            server_client.close();
            assessment.close();
            a.close();
            return true;
        }
        
        bool assess(const dtls_client_hello &dtls_ch, json_object &o) const override {

            const tls_client_hello &ch = dtls_ch.get_tls_client_hello();
            json_object a{o, "cryptographic_security_assessment"};
            a.print_key_string("policy", "quantum_safe");
            a.print_key_string("target", "client");
            assess_tls_ciphersuites(ch.ciphersuite_vector, a);
            assess_tls_extensions(ch.extensions, a);
            a.close();

            return true;
        }

        bool assess(const dtls_server_hello &dtls_sh, json_object &o) const override {

            const tls_server_hello &sh = dtls_sh.get_tls_server_hello();
            json_object a{o, "cryptographic_security_assessment"};
            a.print_key_string("policy", "quantum_safe");
            a.print_key_string("target", "session");
            assess_tls_ciphersuites(sh.ciphersuite_vector, a);
            assess_tls_extensions(sh.extensions, a);
            a.close();

            return true;
        }

    };

    inline const assessor* assessor::create(const std::string &policy) {
        if (policy == "quantum_safe" or policy == "default") {
            return new crypto_policy::quantum_safe{true};
        } else if (policy == "quantum_safe_compact") {
            return new crypto_policy::quantum_safe{false};
        }
        return nullptr;   // error: policy not found
    }

}; // namespace crypto_policiy

// #include "nist_sp800_52.hpp"

#endif // CRYPTO_ASSESS_H
