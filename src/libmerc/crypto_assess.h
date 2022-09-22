// TLS, QUIC and X509/PKIX Crypto Security Assessment
//

#ifndef CRYPTO_ASSESS_H
#define CRYPTO_ASSESS_H

#include <cstdint>
#include <array>
#include "json_object.h"
#include "tls_parameters.h"
#include "tls.h"

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

        virtual ~assessor() { }
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
    public:

        ~quantum_safe() { }

        static inline std::unordered_set<uint16_t> allowed_ciphersuites {
            tls::TLS_PSK_WITH_AES_128_CBC_SHA,
            tls::TLS_PSK_WITH_AES_256_CBC_SHA,
            tls::TLS_PSK_WITH_AES_128_GCM_SHA256,
            tls::TLS_PSK_WITH_AES_256_GCM_SHA384,
            tls::TLS_PSK_WITH_AES_128_CBC_SHA256,
            tls::TLS_PSK_WITH_AES_256_CBC_SHA384,
            tls::TLS_PSK_WITH_AES_128_CCM,
            tls::TLS_PSK_WITH_AES_256_CCM,
            tls::TLS_PSK_WITH_AES_128_CCM_8,
            tls::TLS_PSK_WITH_AES_256_CCM_8,
            tls::TLS_AES_128_GCM_SHA256,
            tls::TLS_AES_256_GCM_SHA384,
            tls::TLS_CHACHA20_POLY1305_SHA256,
            tls::TLS_AES_128_CCM_SHA256,
            tls::TLS_AES_128_CCM_8_SHA256,
        };

        static inline std::unordered_set<uint16_t> allowed_groups {
            tls::p256_kyber512,
            tls::p384_kyber768,
            tls::p521_kyber1024,
            tls::kyber90s512,
            tls::kyber90s768,
            tls::kyber90s1024,
        };

        bool assess(const tls_client_hello &ch, json_object &o) const override {

            json_object a{o, "quantum_security_assessment"};

            bool all_allowed = true;
            bool some_allowed = false;
            datum tmp = ch.ciphersuite_vector;
            while (tmp.is_readable()) {
                encoded<uint16_t> cs{tmp};
                if (!is_grease(cs) || allowed_ciphersuites.find(cs.value()) != allowed_ciphersuites.end()) {
                    some_allowed = true;
                } else {
                    all_allowed = false;
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
                datum tmp = ch.ciphersuite_vector;
                while (tmp.is_readable()) {
                    encoded<uint16_t> cs{tmp};
                    if (!is_grease(cs) && allowed_ciphersuites.find(cs.value()) == allowed_ciphersuites.end()) {
                        cs_array.print_uint(cs);
                    }
                }
                cs_array.close();
            }

            all_allowed = true;
            some_allowed = false;
            datum named_groups = ch.extensions.get_supported_groups();
            xtn named_groups_xtn{named_groups};
            encoded<uint16_t> named_groups_len{named_groups_xtn.value};
            while (named_groups_xtn.value.is_readable()) {
                encoded<uint16_t> named_group{named_groups_xtn.value};
                if (!is_grease(named_group) || allowed_groups.find(named_group.value()) != allowed_groups.end()) {
                    all_allowed = false;
                } else {
                    some_allowed = true;
                }
            }
            quantifier = "none";
            if (all_allowed) {
                quantifier = "all";
            } else if (some_allowed) {
                quantifier = "some";
            }
            a.print_key_string("groups_allowed", quantifier);
            if (!all_allowed) {
                json_array ng_array{a, "groups_not_allowed"};
                datum named_groups = ch.extensions.get_supported_groups();
                xtn named_groups_xtn{named_groups};
                encoded<uint16_t> named_groups_len{named_groups_xtn.value};
                while (named_groups_xtn.value.is_readable()) {
                    encoded<uint16_t> named_group{named_groups_xtn.value};
                    if (!is_grease(named_group) || allowed_groups.find(named_group.value()) != allowed_groups.end()) {
                        ng_array.print_uint(named_group);
                    } else {
                    }
                }
                ng_array.close();
            }

            // required extensions
            //
            bool have_tls_cert_with_extern_psk = false;
            tmp = ch.extensions;
            while (tmp.is_readable()) {
                xtn extension{tmp};
                switch(extension.type()) {
                case tls::tls_cert_with_extern_psk:
                    have_tls_cert_with_extern_psk = true;
                    break;
                default:
                    ;
                }
            }
            a.print_key_bool("tls_cert_with_extern_psk", have_tls_cert_with_extern_psk);
            a.close();

            return true;
        }

    };

}; // namespace crypto_policiy

#endif // CRYPTO_ASSESS_H
