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
                    json_array cs_array(a, "ciphersuites_not_allowed");

                    while (true) {
                        if (!is_grease(cs)) {
                            found = (allowed_ciphersuites.find(cs.value()) != allowed_ciphersuites.end());
                            if (!found) {
                                all_allowed = false;
                                if (readable_output) {
                                    cs_array.print_string(cs.get_name());
                                } else {
                                    cs_array.print_uint16_hex(cs);
                                }
                            } else {
                                some_allowed = true;
                            }
                        }

                        if (!ciphersuite_vector.is_readable()) break;
                        cs = tls::cipher_suites{ciphersuite_vector};
                    }

                    cs_array.close();
                    break;
                } else {
                    some_allowed = true;
                }

            }

            const char *quantifier = "none";
            if (all_allowed) {
                quantifier = "all";
            } else if (some_allowed) {
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
                            } else {
                                some_allowed = true;
                            }
                        }

                        if(!named_groups_xtn.value.is_readable()) break;
                        named_group = tls::supported_groups{named_groups_xtn.value};
                    }

                    ng_array.close();
                    break;
                } else {
                    some_allowed = true;
                }

            }

            const char *quantifier = "none";
            if (all_allowed) {
                quantifier = "all";
            } else if (some_allowed) {
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
                } else {
                    tmp_list.skip(1); // skip ','
                }

                bool found = (ssh_allowed_kex.find(tmp_sv) != ssh_allowed_kex.end());
                if (!found) {
                    all_allowed = false;
                    json_array kex_array(a, "kex_not_allowed");
                    
                    while (true) {
                        found = (ssh_allowed_kex.find(tmp_sv) != ssh_allowed_kex.end());
                        if (!found) {
                            all_allowed = false;
                            kex_array.print_string(tmp_sv.data(), tmp_sv.length());
                        } else {
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
                        } else {
                            tmp_list.skip(1); // skip ','
                        }
                    }
                    kex_array.close();
                    break;
                } else {
                    some_allowed = true;
                }
            }

            const char *quantifier = "none";
            if (all_allowed) {
                quantifier = "all";
            } else if (some_allowed) {
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
                } else {
                    tmp_list.skip(1); // skips ','
                }

                bool found = ssh_allowed_ciphers.find(tmp_sv) != ssh_allowed_ciphers.end();
                if (!found) {
                    all_allowed = false;
                    json_array cs_array(a, "ciphersuites_not_allowed");

                    while (true) {
                        found = ssh_allowed_ciphers.find(tmp_sv) != ssh_allowed_ciphers.end();
                        if (!found) {
                            all_allowed = false;
                            cs_array.print_string(tmp_sv.data(), tmp_sv.length());
                        } else {
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
                        } else {
                            tmp_list.skip(1); // skips ','
                        }

                    }
                    cs_array.close();
                    break;
                } else {
                    some_allowed = true;
                }
            }

            const char *quantifier = "none";
            if (all_allowed) {
                quantifier = "all";
            } else if (some_allowed) {
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
    
    [[maybe_unused]] static bool unit_test() {
        quantum_safe assessor{true};
        char buff[1024];

        // test-1
        // 
        // 0x008D0xC0A90x7a7a0xffff
        // 
        uint8_t tls_ciphers[] = {
            0x00, 0x8d,
            0xc0, 0xa9,
            0x7a, 0x7a,
            0xc0, 0x06
        };
        datum ciphersuites_vector{tls_ciphers, tls_ciphers + sizeof(tls_ciphers)};
        buffer_stream tls_cphrs_buff_strm{buff, 1024};
        json_object c{&tls_cphrs_buff_strm};
        assessor.assess_tls_ciphersuites(ciphersuites_vector, c);
        c.close();

        // {"ciphersuites_not_allowed":["TLS_ECDHE_ECDSA_WITH_NULL_SHA"],"ciphersuites_allowed":"some"}
        // 
        uint8_t tls_ciphers_output[] = {
            0x7B, 0x22, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72,
            0x73, 0x75, 0x69, 0x74, 0x65, 0x73, 0x5F, 0x6E,
            0x6F, 0x74, 0x5F, 0x61, 0x6C, 0x6C, 0x6F, 0x77,
            0x65, 0x64, 0x22, 0x3A, 0x5B, 0x22, 0x54, 0x4C,
            0x53, 0x5F, 0x45, 0x43, 0x44, 0x48, 0x45, 0x5F,
            0x45, 0x43, 0x44, 0x53, 0x41, 0x5F, 0x57, 0x49,
            0x54, 0x48, 0x5F, 0x4E, 0x55, 0x4C, 0x4C, 0x5F,
            0x53, 0x48, 0x41, 0x22, 0x5D, 0x2C, 0x22, 0x63,
            0x69, 0x70, 0x68, 0x65, 0x72, 0x73, 0x75, 0x69,
            0x74, 0x65, 0x73, 0x5F, 0x61, 0x6C, 0x6C, 0x6F,
            0x77, 0x65, 0x64, 0x22, 0x3A, 0x22, 0x73, 0x6F,
            0x6D, 0x65, 0x22, 0x7D
        };

        if (memcmp(tls_ciphers_output, c.b->dstr, 92) != 0) {
            return false;
        }


        // test-2
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
        buffer_stream tls_extn_buff_strm{buff, 1024};
        json_object d{&tls_extn_buff_strm};
        assessor.assess_tls_extensions(extensions, d);
        d.close();

        // {"groups_not_allowed":["sect163k1"],"groups_allowed":"some","tls_cert_with_extern_psk":false}
        // 
        uint8_t tls_extensions_output[] = {
            0x7B, 0x22, 0x67, 0x72, 0x6F, 0x75, 0x70, 0x73,
            0x5F, 0x6E, 0x6F, 0x74, 0x5F, 0x61, 0x6C, 0x6C, 
            0x6F, 0x77, 0x65, 0x64, 0x22, 0x3A, 0x5B, 0x22, 
            0x73, 0x65, 0x63, 0x74, 0x31, 0x36, 0x33, 0x6B, 
            0x31, 0x22, 0x5D, 0x2C, 0x22, 0x67, 0x72, 0x6F, 
            0x75, 0x70, 0x73, 0x5F, 0x61, 0x6C, 0x6C, 0x6F, 
            0x77, 0x65, 0x64, 0x22, 0x3A, 0x22, 0x73, 0x6F, 
            0x6D, 0x65, 0x22, 0x2C, 0x22, 0x74, 0x6C, 0x73, 
            0x5F, 0x63, 0x65, 0x72, 0x74, 0x5F, 0x77, 0x69, 
            0x74, 0x68, 0x5F, 0x65, 0x78, 0x74, 0x65, 0x72, 
            0x6E, 0x5F, 0x70, 0x73, 0x6B, 0x22, 0x3A, 0x66, 
            0x61, 0x6C, 0x73, 0x65, 0x7D
        };

        if (memcmp(tls_extensions_output, d.b->dstr, 93) != 0) {
            return false;
        }

        // test-3
        // 
        // mlkem1024nistp384-sha384,mlkem768-sha256,abc,xyz
        // 
        uint8_t kex_alogorithms[] = {
            0x00, 0x00, 0x00, 0x30,
            0x6D, 0x6C, 0x6B, 0x65, 0x6D, 0x31, 0x30, 0x32,
            0x34, 0x6E, 0x69, 0x73, 0x74, 0x70, 0x33, 0x38,
            0x34, 0x2D, 0x73, 0x68, 0x61, 0x33, 0x38, 0x34,
            0x2C, 0x6D, 0x6c, 0x6B, 0x65, 0x6D, 0x37, 0x36,
            0x38, 0x2D, 0x73, 0x68, 0x61, 0x32, 0x35, 0x36,
            0x2C, 0x61, 0x62, 0x63, 0x2C, 0x78, 0x79, 0x7A
        };

        datum data{kex_alogorithms, kex_alogorithms + sizeof(kex_alogorithms)};
        name_list kex_alogorithms_data{};
        kex_alogorithms_data.parse(data);
        buffer_stream buff_strm{buff, 1024};
        json_object a{&buff_strm};

        assessor.assess_ssh_kex_methods(kex_alogorithms_data, a);
        a.close();

        // {"kex_not_allowed":["abc,"xyz"],"kex_allowed":"some"}
        // 
        uint8_t json_output[] = {
            0x7B, 0x22, 0x6B, 0x65, 0x78, 0x5F, 0x6E, 0x6F,
            0x74, 0x5F, 0x61, 0x6C, 0x6C, 0x6F, 0x77, 0x65, 
            0x64, 0x22, 0x3A, 0x5B, 0x22, 0x61, 0x62, 0x63, 
            0x22, 0x2C, 0x22, 0x78, 0x79, 0x7A, 0x22, 0x5D, 
            0x2C, 0x22, 0x6B, 0x65, 0x78, 0x5F, 0x61, 0x6C, 
            0x6C, 0x6F, 0x77, 0x65, 0x64, 0x22, 0x3A, 0x22, 
            0x73, 0x6F, 0x6D, 0x65, 0x22, 0x7D
        };

        if (memcmp(json_output, a.b->dstr, 54) != 0) {
            return false;
        }

        // test-4
        // 
        // AEAD_AES_128_GCM,aes256-gcm,abc,xyz
        // 
        uint8_t ssh_ciphers[] = {
            0x00, 0x00, 0x00, 0x23,
            0x41, 0x45, 0x41, 0x44, 0x5F, 0x41, 0x45, 0x53,
            0x5F, 0x31, 0x32, 0x38, 0x5F, 0x47, 0x43, 0x4D, 
            0x2C, 0x61, 0x65, 0x73, 0x32, 0x35, 0x36, 0x2D, 
            0x67, 0x63, 0x6D, 0x2C, 0x61, 0x62, 0x63, 0x2C, 
            0x78, 0x79, 0x7A
        };

        data.data = ssh_ciphers;
        data.data_end = ssh_ciphers + sizeof(ssh_ciphers);
        name_list ssh_ciphers_data{};
        ssh_ciphers_data.parse(data);
        buffer_stream ssh_buff_strm{buff, 1024};
        json_object b{&ssh_buff_strm};

        assessor.assess_ssh_ciphers(ssh_ciphers_data, b);
        b.close();

        // {"ciphersuites_not_allowed":["abc","xyz"],"ciphersuites_allowed":"some"}
        // 
        uint8_t ssh_ciphers_output[] = {
            0x7B, 0x22, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72,
            0x73, 0x75, 0x69, 0x74, 0x65, 0x73, 0x5F, 0x6E, 
            0x6F, 0x74, 0x5F, 0x61, 0x6C, 0x6C, 0x6F, 0x77, 
            0x65, 0x64, 0x22, 0x3A, 0x5B, 0x22, 0x61, 0x62, 
            0x63, 0x22, 0x2C, 0x22, 0x78, 0x79, 0x7A, 0x22, 
            0x5D, 0x2C, 0x22, 0x63, 0x69, 0x70, 0x68, 0x65, 
            0x72, 0x73, 0x75, 0x69, 0x74, 0x65, 0x73, 0x5F, 
            0x61, 0x6C, 0x6C, 0x6F, 0x77, 0x65, 0x64, 0x22, 
            0x3A, 0x22, 0x73, 0x6F, 0x6D, 0x65, 0x22, 0x7D
        };

        if (memcmp(ssh_ciphers_output, b.b->dstr, 72) != 0) {
            return false;
        }

        return true;
    }

}; // namespace crypto_policiy

// #include "nist_sp800_52.hpp"

#endif // CRYPTO_ASSESS_H
