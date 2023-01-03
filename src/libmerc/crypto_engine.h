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
#include <openssl/kdf.h>

#define pt_buf_len 2048

class crypto_engine {

    EVP_CIPHER_CTX *gcm_ctx = nullptr;
    EVP_CIPHER_CTX *ecb_ctx = nullptr;

    static constexpr size_t max_label_len = 32;

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

    void kdf_tls13(uint8_t *secret, unsigned int secret_length, const uint8_t *label, const unsigned int label_len,
                   uint8_t length, uint8_t *out_, unsigned int *out_len) {

        uint8_t new_label[max_label_len] = {0};
        new_label[1] = length;
        new_label[2] = label_len;
        for (uint i = 0; i < label_len; i++) {
            new_label[3+i] = label[i];
        }

        uint8_t ind = 0;
        uint8_t block[EVP_MAX_MD_SIZE];
        uint8_t new_block[512] = {0};
        unsigned int block_len = 0;
        while (*out_len < length) {
            ind++;

            for (unsigned int i = 0; i < block_len; i++) {
                new_block[i] = block[i];
            }
            for (unsigned int i = block_len; i < block_len+label_len+4; i++) {
                new_block[i] = new_label[i];
            }
            new_block[block_len+label_len+4] = ind;

            HMAC(EVP_sha256(), secret, secret_length, new_block, block_len+label_len+5, block, &block_len);

            for (unsigned int i = 0; i < block_len; i++) {
                out_[*out_len] = block[i];
                (*out_len)++;
                if (*out_len >= length) {
                    return ;
                }
            }
        }
    }

    void quic_kdf_expand(uint8_t *secret, unsigned int secret_length, const uint8_t *label, const unsigned int label_len,
                   uint8_t *out_, size_t *out_len, size_t len) {

        unsigned char hkdf_label[256], *in;
        *out_len = len;
        in = hkdf_label;
        *in++ = len >> 8;
        *in++ = len & 0xff;
        *in++ = label_len;
        memcpy(in, label, label_len);
        in += label_len;
        *in++ = '\0';
        size_t hkdf_label_len = in - hkdf_label;

        EVP_PKEY_CTX *ctx;
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
        if (!ctx) {
            return;
        }
        if (EVP_PKEY_derive_init(ctx) <= 0 ||
            EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0 ||
            EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, secret_length) <= 0 ||
            EVP_PKEY_CTX_add1_hkdf_info(ctx, hkdf_label, hkdf_label_len) <= 0 ||
            EVP_PKEY_derive(ctx, out_, &len) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return;
        }
        EVP_PKEY_CTX_free(ctx);
    }

};

#endif /* CRYPTO_ENGINE_H */
