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

#ifdef SSLNEW
    void kdf_tls13(uint8_t *secret, unsigned int secret_length, const uint8_t *label, const unsigned int label_len,
                   uint8_t length, uint8_t *out_, unsigned int *out_len) {

        uint8_t new_label[max_label_len] = {0};
        new_label[1] = length;
        new_label[2] = label_len;
        for (size_t i = 0; i < label_len; i++) {
            new_label[3+i] = label[i];
        }
        size_t new_label_len = 4 + label_len;
        *out_len = length;

        HMAC_CTX *hmac;
        int md_sz;
        unsigned char buf[2048];
        size_t done_len = 0, dig_len, n;

        const EVP_MD *evp_md = EVP_sha256();

        md_sz = EVP_MD_size(evp_md);
        if (md_sz <= 0) {
            return;
        }
        dig_len = (size_t)md_sz;

        n = length / dig_len;
        if (length % dig_len) {
            n++;
        }

        if (n > 255 || out_ == NULL || ((hmac = HMAC_CTX_new()) == NULL)) {
            return;
        }

        if (!HMAC_Init_ex(hmac, secret, secret_length, evp_md, NULL)) {
            HMAC_CTX_free(hmac);
            return;
        }

        for (size_t i = 1; i <= n; i++) {
            size_t copy_len;
            const unsigned char ind = i;
            if (i > 1) {
                if (!HMAC_Init_ex(hmac, NULL, 0, NULL, NULL)) {
                    HMAC_CTX_free(hmac);
                    return;
                }
                if (!HMAC_Update(hmac, buf, dig_len)) {
                    HMAC_CTX_free(hmac);
                    return;
                }
            }

            if (!HMAC_Update(hmac, new_label, new_label_len)) {
                HMAC_CTX_free(hmac);
                return;
            }
            if (!HMAC_Update(hmac, &ind, 1)) {
                HMAC_CTX_free(hmac);
                return;
            }
            if (!HMAC_Final(hmac, buf, NULL)) {
                HMAC_CTX_free(hmac);
                return;
            }

            copy_len = (done_len + dig_len > length) ? (length-done_len) : dig_len;
            memcpy(out_ + done_len, buf, copy_len);

            done_len += copy_len;
        }

        HMAC_CTX_free(hmac);
    }
#else
    void kdf_tls13(uint8_t *secret, unsigned int secret_length, const uint8_t *label, const unsigned int label_len,
                   uint8_t length, uint8_t *out_, unsigned int *out_len) {

        uint8_t new_label[max_label_len] = {0};
        new_label[1] = length;
        new_label[2] = label_len;
        for (size_t i = 0; i < label_len; i++) {
            new_label[3+i] = label[i];
        }
        size_t new_label_len = 4 + label_len;
        *out_len = length;

        HMAC_CTX hmac;
	    HMAC_CTX_init(&hmac);
        int md_sz;
        unsigned char buf[2048];
        size_t done_len = 0, dig_len, n;

        const EVP_MD *evp_md = EVP_sha256();

        md_sz = EVP_MD_size(evp_md);
        if (md_sz <= 0) {
            return;
        }
        dig_len = (size_t)md_sz;

        n = length / dig_len;
        if (length % dig_len) {
            n++;
        }

        if (n > 255 || out_ == NULL) {
            return;
        }

        if (!HMAC_Init(&hmac, secret, secret_length, evp_md)) {
            HMAC_CTX_cleanup(&hmac);
            return;
        }

        for (size_t i = 1; i <= n; i++) {
            size_t copy_len;
            const unsigned char ind = i;
            if (i > 1) {
                if (!HMAC_Init(&hmac, NULL, 0, NULL)) {
                    HMAC_CTX_cleanup(&hmac);
                    return;
                }
                if (!HMAC_Update(&hmac, buf, dig_len)) {
                    HMAC_CTX_cleanup(&hmac);
                    return;
                }
            }

            if (!HMAC_Update(&hmac, new_label, new_label_len)) {
                HMAC_CTX_cleanup(&hmac);
                return;
            }
            if (!HMAC_Update(&hmac, &ind, 1)) {
                HMAC_CTX_cleanup(&hmac);
                return;
            }
            if (!HMAC_Final(&hmac, buf, NULL)) {
                HMAC_CTX_cleanup(&hmac);
                return;
            }

            copy_len = (done_len + dig_len > length) ? (length-done_len) : dig_len;
            memcpy(out_ + done_len, buf, copy_len);

            done_len += copy_len;
        }

        HMAC_CTX_cleanup(&hmac);
    }
#endif

};

#endif /* CRYPTO_ENGINE_H */
