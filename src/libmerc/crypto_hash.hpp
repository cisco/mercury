// crypto_hash.hpp
//

#ifndef CRYPTO_HASH_HPP
#define CRYPTO_HASH_HPP

#include <openssl/evp.h>

class hasher {
    EVP_MD_CTX *mdctx;

public:

    hasher() : mdctx{nullptr} { }

    ~hasher() {
        // EVP_MD_CTX_free() is preferred in v1.1.1, but unavailable in earlier versions
        EVP_MD_CTX_destroy(mdctx);
    }

    constexpr static size_t output_size = 20;

    void hash_buffer(const unsigned char *message, size_t message_len, unsigned char *digest, unsigned int digest_len) {

        if ((unsigned int)EVP_MD_size(EVP_sha1()) > digest_len) {
            handleErrors();
        }

        if (mdctx == NULL) {
            // EVP_MD_CTX_new() is preferred in v1.1.1, but unavailable in earlier versions
            if ((mdctx = EVP_MD_CTX_create()) == NULL) {
                handleErrors();
            }
        }

        if (1 != EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL)) {
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

    void handleErrors() {
        fprintf(stderr, "error: EVP hash failure\n");
    }
};


[[maybe_unused]] static void fprint_sha1_hash(FILE *f, const void *buffer, unsigned int len) {

    class hasher h;
    uint8_t output_buffer[h.output_size];

    h.hash_buffer((uint8_t *)buffer, len, output_buffer, sizeof(output_buffer));

    for (size_t i = 0; i < sizeof(output_buffer); i++) {
        fprintf(f, "%.2x", output_buffer[i]);
    }
    fputc('\n', f);

}

#include <string>

static std::basic_string<uint8_t> sha1_hash(const void *buffer, unsigned int len) {

    class hasher h;
    std::basic_string<uint8_t> output;
    output.resize(h.output_size);

    h.hash_buffer((uint8_t *)buffer, len, (uint8_t *)output.data(), h.output_size);

    return output;
}

[[maybe_unused]] static std::basic_string<uint8_t> sha1_hash(datum d) {

    class hasher h;
    std::basic_string<uint8_t> output;
    output.resize(h.output_size);

    h.hash_buffer(d.data, d.length(), (uint8_t *)output.data(), h.output_size);

    return output;
}

#endif // CRYPTO_HASH_HPP
