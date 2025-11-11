/*
 * crypto_engine.h
 *
 * Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

/**
 * \file crypto_engine.h
 *
 * \brief core crypto interfaces
 */
#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#ifndef OPENSSL_V1_1
#ifndef OPENSSL_LEGACY
// OpenSSL 3.0+ is default
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif
#endif
#include <stdexcept>
#include <cstring>

#define pt_buf_len 2048

class crypto_engine {

    EVP_CIPHER_CTX *gcm_ctx = nullptr;
    EVP_CIPHER_CTX *ecb_ctx = nullptr;

    static constexpr size_t max_label_len = 2048;

public:

    crypto_engine()
                    : gcm_ctx{EVP_CIPHER_CTX_new()}
                    , ecb_ctx{EVP_CIPHER_CTX_new()}
    {
        if (gcm_ctx == nullptr or ecb_ctx == nullptr) {
            throw std::runtime_error("could not create EVP_CIPHER_CTX");
        }
    }

    ~crypto_engine() {
        if (gcm_ctx) {
            EVP_CIPHER_CTX_free(gcm_ctx);
        }
        if (ecb_ctx){
            EVP_CIPHER_CTX_free(ecb_ctx);
        }
    }

    void ecb_encrypt(unsigned char *key,
                    uint8_t *ciphertext,
                    const unsigned char *plaintext,
                    const int plaintext_len)
    {
        int len;
        int ciphertext_len;

        if(!EVP_EncryptInit_ex(ecb_ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
            throw std::runtime_error("could not initialize EVP_CIPHER_CTX");
        }

        if (!EVP_EncryptUpdate(ecb_ctx, ciphertext, &len, plaintext, plaintext_len)) {
            return;
        }
        ciphertext_len = len;

        if (!EVP_EncryptFinal_ex(ecb_ctx, ciphertext + len, &len)) {
            return;
        }
        ciphertext_len += len;
        (void)ciphertext_len;  // not currently used

        return;
    }

    // gcm_decrypt() is adapted from openSSL documentation; see "GCM Mode" at
    // https://github.com/majek/openssl/blob/master/doc/crypto/EVP_EncryptInit.pod and
    // https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
    //
    int gcm_decrypt(const uint8_t *ad,
                    unsigned int ad_len,
                    const unsigned char *ciphertext,
                    int ciphertext_len,
                    unsigned char *key,
                    unsigned char *iv,
                    unsigned char *plaintext)
    {
        int len;
        int plaintext_len;

        // trim ciphertext length so that plaintext length fits in buffer, if needed
        //
        ciphertext_len = (ciphertext_len < pt_buf_len) ? ciphertext_len : pt_buf_len;

        static constexpr size_t tag_len = 16;

        ciphertext_len -= tag_len;  // final 16 bytes of ciphertext is auth tag
        if (ciphertext_len < 0) {
            return -1;              // too short
        }
        const uint8_t *tag = ciphertext + ciphertext_len;

        // initialize cipher & context with key and iv
        //
        if(!EVP_DecryptInit_ex(gcm_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
            throw std::runtime_error("could not initialize EVP_CIPHER_CTX");
        }
        if(!EVP_DecryptInit_ex(gcm_ctx, NULL, NULL, key, iv)) {
            return -1;
        }

        // set the associated data
        //
        EVP_DecryptUpdate(gcm_ctx, NULL, &len, ad, ad_len);

        // decrypt ciphertext into plaintext buffer
        //
        // TODO: move length bound check here
        //
        if(!EVP_DecryptUpdate(gcm_ctx, plaintext, &len, ciphertext, ciphertext_len)) {
            return -1;
        }
        plaintext_len = len;

        // set the expected tag value
        //
        EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void *)tag);

        // finalize decryption, and check for an authentication failure
        //
        int retval = EVP_DecryptFinal_ex(gcm_ctx, plaintext + len, &len);
        if (retval <= 0) {
            return -1;     // authentication check failed
        }

        plaintext_len += len;

        return plaintext_len;
    }

private:
    // HMAC wrapper class - abstracts OpenSSL version differences
    class hmac_wrapper {
        const EVP_MD *evp_md;
        // Version-specific members
#ifdef OPENSSL_LEGACY
        HMAC_CTX hmac;
        bool initialized;
#elif defined(OPENSSL_V1_1)
        HMAC_CTX *hmac;
#else
        // OpenSSL 3.0+ (default)
        EVP_MAC *mac;
        EVP_MAC_CTX *mac_ctx;
#endif

    public:
        // Constructor
        hmac_wrapper(const EVP_MD *md)
            : evp_md(md)
#ifdef OPENSSL_LEGACY
            , initialized(false)
#elif defined(OPENSSL_V1_1)
            , hmac(nullptr)
#else
            // OpenSSL 3.0+ (default)
            , mac(nullptr), mac_ctx(nullptr)
#endif
        {}

        // Prevent copying to avoid double-free
        hmac_wrapper(const hmac_wrapper&) = delete;
        hmac_wrapper& operator=(const hmac_wrapper&) = delete;

        // Destructor
        ~hmac_wrapper() {
#ifdef OPENSSL_LEGACY
            if (initialized) HMAC_CTX_cleanup(&hmac);
#elif defined(OPENSSL_V1_1)
            if (hmac) HMAC_CTX_free(hmac);
#else
            // OpenSSL 3.0+ (default)
            if (mac_ctx) EVP_MAC_CTX_free(mac_ctx);
            if (mac) EVP_MAC_free(mac);
#endif
        }

        // Initialize HMAC with secret
        bool init(const uint8_t *secret, unsigned int secret_length) {
#ifdef OPENSSL_LEGACY
            HMAC_CTX_init(&hmac);
            initialized = true;
            return HMAC_Init(&hmac, secret, secret_length, evp_md);
#elif defined(OPENSSL_V1_1)
            hmac = HMAC_CTX_new();
            if (!hmac) return false;
            return HMAC_Init_ex(hmac, secret, secret_length, evp_md, NULL);
#else
            // OpenSSL 3.0+ (default)
            mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
            if (!mac) return false;

            mac_ctx = EVP_MAC_CTX_new(mac);
            if (!mac_ctx) return false;

            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string("digest", (char*)EVP_MD_get0_name(evp_md), 0),
                OSSL_PARAM_construct_end()
            };

            return EVP_MAC_init(mac_ctx, secret, secret_length, params);
#endif
        }

        // Re-initialize for next iteration
        bool reinit() {
#ifdef OPENSSL_LEGACY
            return HMAC_Init(&hmac, NULL, 0, NULL);
#elif defined(OPENSSL_V1_1)
            return HMAC_Init_ex(hmac, NULL, 0, NULL, NULL);
#else
            // OpenSSL 3.0+ (default)
            return EVP_MAC_init(mac_ctx, NULL, 0, NULL);
#endif
        }

        // Update HMAC with data
        bool update(const uint8_t *data, size_t len) {
#ifdef OPENSSL_LEGACY
            return HMAC_Update(&hmac, data, len);
#elif defined(OPENSSL_V1_1)
            return HMAC_Update(hmac, data, len);
#else
            // OpenSSL 3.0+ (default)
            return EVP_MAC_update(mac_ctx, data, len);
#endif
        }

        // Finalize and get HMAC result
        bool finalize(uint8_t *out, size_t out_len) {
#ifdef OPENSSL_LEGACY
            (void)out_len;  // unused in this version
            return HMAC_Final(&hmac, out, NULL);
#elif defined(OPENSSL_V1_1)
            (void)out_len;  // unused in this version
            return HMAC_Final(hmac, out, NULL);
#else
            // OpenSSL 3.0+ (default)
            return EVP_MAC_final(mac_ctx, out, NULL, out_len);
#endif
        }
    };

public:
    void kdf_tls13(uint8_t *secret, unsigned int secret_length,
                   const uint8_t *label, const unsigned int label_len,
                   uint8_t length, uint8_t *out_, unsigned int *out_len) {

        // Prepare HKDF-Expand-Label per RFC 8446:
        // Note: label parameter should already include "tls13 " prefix
        // e.g., "tls13 quic key" for QUIC key derivation
        uint8_t new_label[max_label_len] = {0};
        new_label[1] = length;
        new_label[2] = label_len;
        for (size_t i = 0; i < label_len; i++) {
            new_label[3+i] = label[i];
        }
        size_t new_label_len = 4 + label_len;
        *out_len = length;

        // Calculate digest parameters
        const EVP_MD *evp_md = EVP_sha256();
        int md_sz = EVP_MD_size(evp_md);
        if (md_sz <= 0 || out_ == NULL) {
            return;
        }
        size_t dig_len = (size_t)md_sz;

        // Calculate number of iterations needed
        size_t n = length / dig_len;
        if (length % dig_len) {
            n++;
        }
        if (n > 255) {
            return;  // Too many iterations
        }

        // Initialize HMAC wrapper
        hmac_wrapper hmac(evp_md);
        if (!hmac.init(secret, secret_length)) {
            return;
        }

        // HKDF-Expand-Label loop: T(i) = HMAC(T(i-1) || label || i)
        unsigned char buf[2048];
        size_t done_len = 0;

        for (size_t i = 1; i <= n; i++) {
            const unsigned char iteration = i;

            if (i > 1) {
                if (!hmac.reinit() || !hmac.update(buf, dig_len)) {
                    return;
                }
            }

            if (!hmac.update(new_label, new_label_len) ||
                !hmac.update(&iteration, 1) ||
                !hmac.finalize(buf, sizeof(buf))) {
                return;
            }

            // Copy appropriate amount to output
            size_t copy_len = (done_len + dig_len > length) ? (length - done_len) : dig_len;
            memcpy(out_ + done_len, buf, copy_len);
            done_len += copy_len;
        }
    }

#ifndef NDEBUG
    /// unit_test() tests the kdf_tls13() function using test vectors from
    /// RFC 9001 Appendix A - QUIC Sample Packet Protection.
    /// Returns true if all tests pass, false otherwise.
    ///
    static bool unit_test() {
        crypto_engine engine;
        bool all_passed = true;

        // QUIC Initial secrets from RFC 9001 Appendix A
        uint8_t client_initial_secret[32] = {
            0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75,
            0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
            0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a,
            0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea
        };

        uint8_t server_initial_secret[32] = {
            0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd,
            0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81,
            0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d,
            0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b
        };

        // Test 1: QUIC client "tls13 quic key" derivation (16 bytes)
        {
            uint8_t label[] = {'t', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'k', 'e', 'y'};
            uint8_t expected[16] = {
                0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
                0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d
            };

            uint8_t output[16];
            unsigned int out_len = 0;

            engine.kdf_tls13(client_initial_secret, sizeof(client_initial_secret),
                           label, sizeof(label),
                           16, output, &out_len);

            if (out_len != 16 || memcmp(output, expected, 16) != 0) {
                all_passed = false;
            }
        }

        // Test 2: QUIC client "tls13 quic iv" derivation (12 bytes)
        {
            uint8_t label[] = {'t', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'i', 'v'};
            uint8_t expected[12] = {
                0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
                0x46, 0xfb, 0x25, 0x5c
            };

            uint8_t output[12];
            unsigned int out_len = 0;

            engine.kdf_tls13(client_initial_secret, sizeof(client_initial_secret),
                           label, sizeof(label),
                           12, output, &out_len);

            if (out_len != 12 || memcmp(output, expected, 12) != 0) {
                all_passed = false;
            }
        }

        // Test 3: QUIC client "tls13 quic hp" derivation (16 bytes)
        {
            uint8_t label[] = {'t', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'h', 'p'};
            uint8_t expected[16] = {
                0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
                0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2
            };

            uint8_t output[16];
            unsigned int out_len = 0;

            engine.kdf_tls13(client_initial_secret, sizeof(client_initial_secret),
                           label, sizeof(label),
                           16, output, &out_len);

            if (out_len != 16 || memcmp(output, expected, 16) != 0) {
                all_passed = false;
            }
        }

        // Test 4: QUIC server "tls13 quic key" derivation (16 bytes)
        {
            uint8_t label[] = {'t', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'k', 'e', 'y'};
            uint8_t expected[16] = {
                0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c,
                0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37
            };

            uint8_t output[16];
            unsigned int out_len = 0;

            engine.kdf_tls13(server_initial_secret, sizeof(server_initial_secret),
                           label, sizeof(label),
                           16, output, &out_len);

            if (out_len != 16 || memcmp(output, expected, 16) != 0) {
                all_passed = false;
            }
        }

        // Test 5: QUIC server "tls13 quic iv" derivation (12 bytes)
        {
            uint8_t label[] = {'t', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'i', 'v'};
            uint8_t expected[12] = {
                0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53,
                0xb0, 0xbb, 0xa0, 0x3e
            };

            uint8_t output[12];
            unsigned int out_len = 0;

            engine.kdf_tls13(server_initial_secret, sizeof(server_initial_secret),
                           label, sizeof(label),
                           12, output, &out_len);

            if (out_len != 12 || memcmp(output, expected, 12) != 0) {
                all_passed = false;
            }
        }

        // Test 6: QUIC server "tls13 quic hp" derivation (16 bytes)
        {
            uint8_t label[] = {'t', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'h', 'p'};
            uint8_t expected[16] = {
                0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76,
                0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14
            };

            uint8_t output[16];
            unsigned int out_len = 0;

            engine.kdf_tls13(server_initial_secret, sizeof(server_initial_secret),
                           label, sizeof(label),
                           16, output, &out_len);

            if (out_len != 16 || memcmp(output, expected, 16) != 0) {
                all_passed = false;
            }
        }

        // Test 7: Deterministic output - same inputs produce same output
        {
            uint8_t label[] = {'t', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'k', 'e', 'y'};

            uint8_t output1[16];
            uint8_t output2[16];
            unsigned int out_len1 = 0;
            unsigned int out_len2 = 0;

            // Call twice with same inputs
            engine.kdf_tls13(client_initial_secret, sizeof(client_initial_secret),
                           label, sizeof(label), 16, output1, &out_len1);
            engine.kdf_tls13(client_initial_secret, sizeof(client_initial_secret),
                           label, sizeof(label), 16, output2, &out_len2);

            // Outputs must be identical
            if (out_len1 != 16 || out_len2 != 16 || memcmp(output1, output2, 16) != 0) {
                all_passed = false;
            }
        }

        return all_passed;
    }
#endif

};

class hasher {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md = nullptr;

public:

    hasher(const char *type) : mdctx{nullptr} {

        if (type == nullptr) {
            throw std::runtime_error{"nullptr passed to hasher"};
        }
        if (strcmp(type, "sha256") == 0) {
            md = EVP_sha256();
        } else if (strcmp(type, "sha1") == 0) {
            md = EVP_sha1();
        } else if (strcmp(type, "md5") == 0) {
            md = EVP_md5();
        } else {
            throw std::runtime_error{std::string{"unknown hash function "} + type};
        }
    }

    ~hasher() {
        // EVP_MD_CTX_free() is preferred in v1.1.1, but unavailable in earlier versions
        EVP_MD_CTX_destroy(mdctx);
    }

    size_t output_size() const { return EVP_MD_size(md); }

    void hash_buffer(const unsigned char *message, size_t message_len, unsigned char *digest, unsigned int digest_len) {

        if ((unsigned int)EVP_MD_size(md) > digest_len) {
            handleErrors();
        }

        if (mdctx == NULL) {
            // EVP_MD_CTX_new() is preferred in v1.1.1, but unavailable in earlier versions
            if ((mdctx = EVP_MD_CTX_create()) == NULL) {
                handleErrors();
            }
        }

        if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
            handleErrors();
        }

        if (1 != EVP_DigestUpdate(mdctx, message, message_len)) {
            handleErrors();
        }

        unsigned int tmp_len;
        if (1 != EVP_DigestFinal_ex(mdctx, digest, &tmp_len)) {
            handleErrors();
        }

    }

    [[noreturn]] void handleErrors() {
        throw std::runtime_error("EVP hash failure");
    }
};

#endif /* CRYPTO_ENGINE_H */
