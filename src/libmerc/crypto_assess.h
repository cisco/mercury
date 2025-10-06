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
            if (!all_allowed) {
                json_array cs_array{a, "kex_not_allowed"};
                name_list tmp_list = kex_list;
                while (tmp_list.is_readable()) {
                    datum tmp{};
                    tmp.parse_up_to_delim(tmp_list,',');
                    if (tmp.end() == tmp_list.end()) {
                       // end of list
                        tmp_list.set_null();
                    }
                    tmp_list.skip(1);    // skip ','
                    if (ssh_allowed_kex.find(std::string{(char*)tmp.data,(size_t)tmp.length()}) == ssh_allowed_kex.end()) {
                        cs_array.print_string(std::string{(char*)tmp.data,(size_t)tmp.length()}.c_str());
                    }
                }
                cs_array.close();
            }

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
            if (!all_allowed) {
                json_array cs_array{a, "ciphersuites_not_allowed"};
                name_list tmp_list = ciphers;
                while (tmp_list.is_readable()) {
                    datum tmp{};
                    tmp.parse_up_to_delim(tmp_list,',');
                    if (tmp.end() == tmp_list.end()) {
                       // end of list
                        tmp_list.set_null();
                    }
                    tmp_list.skip(1);    // skip ','
                    if (ssh_allowed_ciphers.find(std::string{(char*)tmp.data,(size_t)tmp.length()}) == ssh_allowed_ciphers.end()) {
                        cs_array.print_string(std::string{(char*)tmp.data,(size_t)tmp.length()}.c_str());
                    }
                }
                cs_array.close();
            }

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

        // --------------- TLS EXTENSIONS AND CIPHERSUITES ---------------
        // TEST-1
        // 
        uint8_t tls_ciphers[] = {
            0x00, 0x8d, // TLS_PSK_WITH_AES_256_CBC_SHA (allowed)
            0xc0, 0xa9, // TLS_PSK_WITH_AES_256_CCM_8 (allowed)
            0x7a, 0x7a, // grease
            0xc0, 0x06  // TLS_ECDHE_ECDSA_WITH_NULL_SHA (not allowed)
        };
        datum ciphersuites_vector{tls_ciphers, tls_ciphers + sizeof(tls_ciphers)};
        buffer_stream tls_cphrs_buff_strm{buff, 1024};
        json_object c{&tls_cphrs_buff_strm};
        assessor.assess_tls_ciphersuites(ciphersuites_vector, c);
        c.close();

        std::string tls_ciphers_output_str = "{\"ciphersuites_not_allowed\":[\"TLS_ECDHE_ECDSA_WITH_NULL_SHA\"],\"ciphersuites_allowed\":\"some\"}";

        if (tls_ciphers_output_str.length() > (unsigned long)c.b->dlen || memcmp(tls_ciphers_output_str.c_str(), c.b->dstr, tls_ciphers_output_str.length()) != 0) {
            return false;
        }

        // TEST-2
        // 
        uint8_t tls_ciphers_all_allowed[] = {
            0x00, 0x8d, // TLS_PSK_WITH_AES_256_CBC_SHA (allowed)
            0xc0, 0xa9, // TLS_PSK_WITH_AES_256_CCM_8 (allowed)
            0x7a, 0x7a, // grease
        };
        datum ciphersuites_vector_all_allowed{tls_ciphers_all_allowed, tls_ciphers_all_allowed + sizeof(tls_ciphers_all_allowed)};
        buffer_stream tls_cphrs_buff_strm_all_allowed{buff, 1024};
        json_object c_all_allowed{&tls_cphrs_buff_strm_all_allowed};
        assessor.assess_tls_ciphersuites(ciphersuites_vector_all_allowed, c_all_allowed);
        c_all_allowed.close();

        std::string tls_ciphers_all_allowed_output_str = "{\"ciphersuites_allowed\":\"all\"}";

        if (tls_ciphers_all_allowed_output_str.length() > (unsigned long)c_all_allowed.b->dlen || memcmp(tls_ciphers_all_allowed_output_str.c_str(), c_all_allowed.b->dstr, tls_ciphers_all_allowed_output_str.length()) != 0) {
            return false;
        }

        // TEST-3
        uint8_t tls_ciphers_none_allowed[] = {
            0xc0, 0x06, // TLS_ECDHE_ECDSA_WITH_NULL_SHA (not allowed)
            0x7a, 0x7a, // grease
            0xc0, 0x07  // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA (not allowed)
        };
        datum ciphersuites_vector_none_allowed{tls_ciphers_none_allowed, tls_ciphers_none_allowed + sizeof(tls_ciphers_none_allowed)};
        buffer_stream tls_cphrs_buff_strm_none_allowed{buff, 1024};
        json_object c_none_allowed{&tls_cphrs_buff_strm_none_allowed};
        assessor.assess_tls_ciphersuites(ciphersuites_vector_none_allowed, c_none_allowed);
        c_none_allowed.close();

        std::string tls_ciphers_none_allowed_output_str = "{\"ciphersuites_not_allowed\":[\"TLS_ECDHE_ECDSA_WITH_NULL_SHA\",\"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA\"],\"ciphersuites_allowed\":\"none\"}";
        if (tls_ciphers_none_allowed_output_str.length() > (unsigned long)c_none_allowed.b->dlen || memcmp(tls_ciphers_none_allowed_output_str.c_str(), c_none_allowed.b->dstr, tls_ciphers_none_allowed_output_str.length()) != 0) {
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
        buffer_stream tls_extn_buff_strm{buff, 1024};
        json_object d{&tls_extn_buff_strm};
        assessor.assess_tls_extensions(extensions, d);
        d.close();

        std::string tls_extensions_output_str = "{\"groups_not_allowed\":[\"sect163k1\"],\"groups_allowed\":\"some\",\"tls_cert_with_extern_psk\":false}";

        if (tls_extensions_output_str.length() > (unsigned long)d.b->dlen || memcmp(tls_extensions_output_str.c_str(), d.b->dstr, tls_extensions_output_str.length()) != 0) {
            return false;
        }

        // TEST-5
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
        buffer_stream tls_extn_buff_strm_all_allowed{buff, 1024};
        json_object d_all_allowed{&tls_extn_buff_strm_all_allowed};
        assessor.assess_tls_extensions(extensions_all_allowed, d_all_allowed);
        d_all_allowed.close();

        std::string tls_extensions_all_allowed_output_str = "{\"groups_allowed\":\"all\",\"tls_cert_with_extern_psk\":false}";

        if (tls_extensions_all_allowed_output_str.length() > (unsigned long)d_all_allowed.b->dlen || memcmp(tls_extensions_all_allowed_output_str.c_str(), d_all_allowed.b->dstr, tls_extensions_all_allowed_output_str.length()) != 0) {
            return false;
        }

        // TEST-6
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
        buffer_stream tls_extn_buff_strm_no_allowed{buff, 1024};
        json_object d_no_allowed{&tls_extn_buff_strm_no_allowed};
        assessor.assess_tls_extensions(extensions_no_allowed, d_no_allowed);
        d_no_allowed.close();

        std::string tls_extensions_no_allowed_output_str = "{\"groups_not_allowed\":[\"sect163k1\",\"sect163r1\"],\"groups_allowed\":\"none\",\"tls_cert_with_extern_psk\":false}";

        if (tls_extensions_no_allowed_output_str.length() > (unsigned long)d_no_allowed.b->dlen || memcmp(tls_extensions_no_allowed_output_str.c_str(), d_no_allowed.b->dstr, tls_extensions_no_allowed_output_str.length()) != 0) {
            return false;
        }

        // --------------- SSH KEX METHODS AND CIPHERSUITES ---------------
        // TEST-7
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
        buffer_stream buff_strm{buff, 1024};
        json_object a{&buff_strm};

        assessor.assess_ssh_kex_methods(kex_algorithms_data, a);
        a.close();

        std::string kex_algorithms_output_str = "{\"kex_not_allowed\":[\"abc\",\"xyz\"],\"kex_allowed\":\"some\"}";

        if (kex_algorithms_output_str.length() > (unsigned long)a.b->dlen || memcmp(kex_algorithms_output_str.c_str(), a.b->dstr, kex_algorithms_output_str.length()) != 0) {
            return false;
        }

        // TEST-8
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
        buffer_stream buff_strm_all_allowed{buff, 1024};
        json_object a_all_allowed{&buff_strm_all_allowed};

        assessor.assess_ssh_kex_methods(kex_algorithms_all_allowed_data, a_all_allowed);
        a_all_allowed.close();

        std::string kex_algorithms_all_allowed_output_str = "{\"kex_allowed\":\"all\"}";

        if (kex_algorithms_all_allowed_output_str.length() > (unsigned long)a_all_allowed.b->dlen || memcmp(kex_algorithms_all_allowed_output_str.c_str(), a_all_allowed.b->dstr, kex_algorithms_all_allowed_output_str.length()) != 0) {
            return false;
        }

        // TEST-9
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
        buffer_stream buff_strm_none_allowed{buff, 1024};
        json_object a_none_allowed{&buff_strm_none_allowed};

        assessor.assess_ssh_kex_methods(kex_algorithms_none_allowed_data, a_none_allowed);
        a_none_allowed.close();

        std::string kex_algorithms_none_allowed_output_str = "{\"kex_not_allowed\":[\"abc\",\"xyz\",\"abc\",\"xyz\"],\"kex_allowed\":\"none\"}";
        
        if (kex_algorithms_none_allowed_output_str.length() > (unsigned long)a_none_allowed.b->dlen || memcmp(kex_algorithms_none_allowed_output_str.c_str(), a_none_allowed.b->dstr, kex_algorithms_none_allowed_output_str.length()) != 0) {
            return false;
        }

        // TEST-10
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
        buffer_stream ssh_buff_strm{buff, 1024};
        json_object b{&ssh_buff_strm};

        assessor.assess_ssh_ciphers(ssh_ciphers_data, b);
        b.close();

        std::string ssh_ciphers_output_str = "{\"ciphersuites_not_allowed\":[\"abc\",\"xyz\"],\"ciphersuites_allowed\":\"some\"}";

        if (ssh_ciphers_output_str.length() > (unsigned long)b.b->dlen || memcmp(ssh_ciphers_output_str.c_str(), b.b->dstr, ssh_ciphers_output_str.length()) != 0) {
            return false;
        }

        // TEST-11
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
        buffer_stream ssh_buff_strm_all_allowed{buff, 1024};
        json_object b_all_allowed{&ssh_buff_strm_all_allowed};

        assessor.assess_ssh_ciphers(ssh_ciphers_all_allowed_data, b_all_allowed);
        b_all_allowed.close();

        std::string ssh_ciphers_all_allowed_output_str = "{\"ciphersuites_allowed\":\"all\"}";

        if (ssh_ciphers_all_allowed_output_str.length() > (unsigned long)b_all_allowed.b->dlen || memcmp(ssh_ciphers_all_allowed_output_str.c_str(), b_all_allowed.b->dstr, ssh_ciphers_all_allowed_output_str.length()) != 0) {
            return false;
        }

        // TEST-12
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
        buffer_stream ssh_buff_strm_none_allowed{buff, 1024};
        json_object b_none_allowed{&ssh_buff_strm_none_allowed};

        assessor.assess_ssh_ciphers(ssh_ciphers_none_allowed_data, b_none_allowed);
        b_none_allowed.close();

        std::string ssh_ciphers_none_allowed_output_str = "{\"ciphersuites_not_allowed\":[\"abc\",\"xyz\",\"abc\",\"xyz\"],\"ciphersuites_allowed\":\"none\"}";

        if (ssh_ciphers_none_allowed_output_str.length() > (unsigned long)b_none_allowed.b->dlen || memcmp(ssh_ciphers_none_allowed_output_str.c_str(), b_none_allowed.b->dstr, ssh_ciphers_none_allowed_output_str.length()) != 0) {
            return false;
        }

        // TEST-13
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
        buffer_stream ssh_buff_strm_malformed{buff, 1024};
        json_object b_malformed{&ssh_buff_strm_malformed};

        assessor.assess_ssh_ciphers(ssh_ciphers_malformed_data, b_malformed);
        b_malformed.close();

        std::string ssh_ciphers_malformed_output_str = "{\"ciphersuites_not_allowed\":[\"\",\"\",\"abc-abc(abc)@xyz.com\",\"\",\"a\"bc\"xyz@abc.com\",\"abc\\-/xyz@domain.org\"],\"ciphersuites_allowed\":\"none\"}";

        if (ssh_ciphers_malformed_output_str.length() > (unsigned long)b_malformed.b->dlen || memcmp(ssh_ciphers_malformed_output_str.c_str(), b_malformed.b->dstr, ssh_ciphers_malformed_output_str.length()) != 0) {
            return false;
        }

        return true;
    }

}; // namespace crypto_policy

// #include "nist_sp800_52.hpp"

#endif // CRYPTO_ASSESS_H
