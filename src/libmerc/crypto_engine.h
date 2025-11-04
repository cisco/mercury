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
#ifdef OPENSSL_V3_0
#include <openssl/core_names.h>
#include <openssl/params.h>
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
#ifdef OPENSSL_V3_0
        EVP_MAC *mac;
        EVP_MAC_CTX *mac_ctx;
#elif defined(OPENSSL_V1_1)
        HMAC_CTX *hmac;
#else
        HMAC_CTX hmac;
        bool initialized;
#endif

    public:
        // Constructor
        hmac_wrapper(const EVP_MD *md)
            : evp_md(md)
#ifdef OPENSSL_V3_0
            , mac(nullptr), mac_ctx(nullptr)
#elif defined(OPENSSL_V1_1)
            , hmac(nullptr)
#else
            , initialized(false)
#endif
        {}

        // Destructor
        ~hmac_wrapper() {
#ifdef OPENSSL_V3_0
            if (mac_ctx) EVP_MAC_CTX_free(mac_ctx);
            if (mac) EVP_MAC_free(mac);
#elif defined(OPENSSL_V1_1)
            if (hmac) HMAC_CTX_free(hmac);
#else
            if (initialized) HMAC_CTX_cleanup(&hmac);
#endif
        }

        // Initialize HMAC with secret
        bool init(const uint8_t *secret, unsigned int secret_length) {
#ifdef OPENSSL_V3_0
            mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
            if (!mac) return false;

            mac_ctx = EVP_MAC_CTX_new(mac);
            if (!mac_ctx) return false;

            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string("digest", (char*)EVP_MD_get0_name(evp_md), 0),
                OSSL_PARAM_construct_end()
            };

            return EVP_MAC_init(mac_ctx, secret, secret_length, params);
#elif defined(OPENSSL_V1_1)
            hmac = HMAC_CTX_new();
            if (!hmac) return false;
            return HMAC_Init_ex(hmac, secret, secret_length, evp_md, NULL);
#else
            HMAC_CTX_init(&hmac);
            initialized = true;
            return HMAC_Init(&hmac, secret, secret_length, evp_md);
#endif
        }

        // Re-initialize for next iteration
        bool reinit() {
#ifdef OPENSSL_V3_0
            return EVP_MAC_init(mac_ctx, NULL, 0, NULL);
#elif defined(OPENSSL_V1_1)
            return HMAC_Init_ex(hmac, NULL, 0, NULL, NULL);
#else
            return HMAC_Init(&hmac, NULL, 0, NULL);
#endif
        }

        // Update HMAC with data
        bool update(const uint8_t *data, size_t len) {
#ifdef OPENSSL_V3_0
            return EVP_MAC_update(mac_ctx, data, len);
#elif defined(OPENSSL_V1_1)
            return HMAC_Update(hmac, data, len);
#else
            return HMAC_Update(&hmac, data, len);
#endif
        }

        // Finalize and get HMAC result
        bool finalize(uint8_t *out, size_t out_len) {
#ifdef OPENSSL_V3_0
            return EVP_MAC_final(mac_ctx, out, NULL, out_len);
#elif defined(OPENSSL_V1_1)
            (void)out_len;  // unused in this version
            return HMAC_Final(hmac, out, NULL);
#else
            (void)out_len;  // unused in this version
            return HMAC_Final(&hmac, out, NULL);
#endif
        }
    };

public:
    // Unified KDF TLS 1.3 implementation - readable algorithm logic
    void kdf_tls13(uint8_t *secret, unsigned int secret_length,
                   const uint8_t *label, const unsigned int label_len,
                   uint8_t length, uint8_t *out_, unsigned int *out_len) {

        // Prepare TLS 1.3 HKDF label format: [0x00][length][label_len][label][0x00]
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
