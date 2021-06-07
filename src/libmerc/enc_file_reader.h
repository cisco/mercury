// enc_file_reader.h
//
// (AES-CBC-128) encrypted file reader

#ifndef ENC_FILE_READER_H
#define ENC_FILE_READER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/types.h>

#include <openssl/evp.h>

// The encrypted_file class decrypts and reads files that are
// encrypted in AES-128-CBC mode, with the Initialization Vector (IV)
// included as the first 16 bytes of the file.  To encrypt a file
// $FILE in that way using openssl, for instance:
//
//   openssl rand 16 > tmpfile
//   cat $FILE >> tmpfile
//   openssl enc -aes128 -in tmpfile -out $FILE.enc -nosalt -p -K $KEY -iv 00000000000000000000000000000000 >/dev/null

template <size_t N>
class cryptovar {

public:

    unsigned char value[N];

    cryptovar(const unsigned char *in) {
        //fprintf(stderr, "sizeof(value): %zu\n", sizeof(value));
        if (in) {
            memcpy(value, in, N);
        } else {
            memset(value, 0, N);
        }
    }

    cryptovar(const char *null_terminated_hex_string) {
        if (null_terminated_hex_string) {
            size_t raw_bytes = hex_to_raw(value, N, null_terminated_hex_string);
            if (raw_bytes != N) {
                fprintf(stderr, "error: expected %zu bytes in key, only got %zu\n", N, raw_bytes);
                throw "too few bytes in key initialization";
            }
        } else {
            memset(value, 0, N);
        }
    }

    ~cryptovar() {
        // use volatile to prevent compiler optimization from eliding this function
        volatile unsigned char *p = &value[0];
        for (size_t i=0; i < N; i++) {
            *p++ = 0x00;
        }
    }

    bool is_null() const {
        for ( const auto & c: value) {
            if (c != 0) {
                return false;
            }
        }
        return true;
    }

};

class encrypted_file {
    FILE *file;
    cryptovar<16> key;
    cryptovar<16> iv;
    EVP_CIPHER_CTX *ctx;

    unsigned char ct_buffer[512] = { 0, };     // ciphertext
    unsigned char pt_buffer[512+16] = { 0, };  // plaintext
    ssize_t bytes_in_ct_buffer = 0;
    ssize_t bytes_in_pt_buffer = 0;
    bool err;

    // the function fill_pt_buffer() reads ciphertext data from the
    // file, then decrypts it into the plaintext buffer.  It returns
    // true if there is no more plaintext, and returns false
    // otherwise.
    //
    bool fill_pt_buffer() {

        //fprintf(stderr, "%s\n", __func__);

        bool no_more_ciphertext = false;

        // fill ciphertext buffer
        //
        if (bytes_in_ct_buffer == 0) {
            if (file == nullptr) {
                return true;    // no file to read from
            }
            ssize_t bytes_read = fread(ct_buffer, sizeof(unsigned char), sizeof(ct_buffer), file);
            if (bytes_read < 0) {
                fprintf(stderr, "error: could not read data from file\n");
                return true;    // could not read ciphertext from file
            }
            //fprintf(stderr, "read %zd bytes of ciphertext from file\n", bytes_read);
            bytes_in_ct_buffer = bytes_read;
        }

        // decrypt ciphertext buffer into plaintext buffer
        //
        int retval = decrypt_update(ct_buffer, bytes_in_ct_buffer, pt_buffer);
        if (retval < 0) {
            err = true;
            return true;  // error in decrypt_update
        }
        if (retval == 0) {
            // at end of ciphertext, time to finalize
            //
            retval = decrypt_final(pt_buffer);
            no_more_ciphertext = true;
        }
        bytes_in_pt_buffer = retval;
        bytes_in_ct_buffer = 0;  // indicate that ciphertext buffer is empty
        //fprintf(stderr, "%s: bytes_in_pt_buffer: %d\n", __func__, retval);

        if (no_more_ciphertext) {
            fclose(file);
            file = nullptr;
        }

        return false;
    }

    ssize_t decrypt_update(unsigned char *ciphertext,
                           int ciphertext_len,
                           unsigned char *plaintext)  {

        if (ctx == nullptr) {
            fprintf(stderr, "error: nullptr in decrypt_update\n");
            return -1;  // error: decryption context not initialized
        }

        // decrypt data in ciphertext buffer into plaintext buffer
        //
        int num_plaintext_bytes;  // used to report the number of bytes of plaintext output
        int retcode = EVP_DecryptUpdate(ctx, plaintext, &num_plaintext_bytes, ciphertext, ciphertext_len);
        if(retcode != 1) {
            fprintf(stderr, "error: decrypt_update failed\n");
            return -1;
        }
        return num_plaintext_bytes;
    }

    ssize_t decrypt_final(unsigned char *plaintext) {

        if (ctx == nullptr) {
            fprintf(stderr, "error: nullptr in decrypt_final\n");
            return -1;  // error: decryption context not initialized
        }

        // finalize decryption by processing the trailing block(s) of ciphertext
        //
        int num_plaintext_bytes;  // used to report the number of bytes of plaintext output
        int retcode = EVP_DecryptFinal_ex(ctx, plaintext, &num_plaintext_bytes);
        if (retcode != 1) {
            fprintf(stderr, "error: decrypted plaintext has incorrect padding\n");
            return -1; // error
        }
        return num_plaintext_bytes;
    }

public:

    FILE * get_file() const { return file; }

    encrypted_file(const char *filename,
                   const unsigned char *key_in,
                   const unsigned char *iv_in) : file{nullptr}, key{key_in}, iv{iv_in}, ctx{nullptr}, err{false} {


        file = fopen(filename, "r");
        if (file == nullptr) {
            fprintf(stderr, "error: could not open file %s\n", filename);
            throw "error: cannot open file";
        }

        if (key.is_null()) {
            // fprintf(stderr, "note: key is null, no decryption will be performed\n");
            return;   // leave ctx null
        }

        // create and initialize decryption context
        ctx = EVP_CIPHER_CTX_new();
        if(!ctx) {
            throw "error: cannot allocate EVP_CIPHER_CTX";
        }

        // Initialise the decryption context, using a key and IV size
        // appropriate for AES-128, which has a 16-byte key and a
        // 16-byte IV
        //
        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.value, iv.value)) {
            throw "error: cannot initialize EVP_CIPHER_CTX";
        }

        // if no initialization vector (iv) has been provided, it was
        // included in the encrypted file, and thus we need to discard
        // the first block of plaintext
        if (iv.is_null()) {
            uint8_t aes_block[16];
            ssize_t bytes_read = read(aes_block, sizeof(aes_block));
            if (bytes_read != 16) {
                throw "error: could not read first block from encrypted file";
            }
        }
    }

    ~encrypted_file() {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
            ctx = nullptr;
        }
        if (file) {
            fclose(file);
            file = nullptr;
        }
    }


    ssize_t read(void *buf, size_t count) {

        //fprintf(stderr, "%s\n", __func__);

        if (key.is_null() && file != nullptr) {
            return fread(buf, sizeof(char), count, file);
        }

        err = false;
        uint8_t *outbuf = (uint8_t *)buf;
        ssize_t pt_bytes_needed = count;
        bool no_more_plaintext = false;

        int plaintext_length = 0;
        while (pt_bytes_needed > 0) {

            if (bytes_in_pt_buffer == 0) {
                no_more_plaintext = fill_pt_buffer();
            }

            //fprintf(stderr, "bytes in pt buffer: %zd\n", bytes_in_pt_buffer);

            if (bytes_in_pt_buffer > 0) {

                // copy plaintext into destination buffer
                ssize_t outbytes = bytes_in_pt_buffer > pt_bytes_needed ? pt_bytes_needed : bytes_in_pt_buffer;
                memcpy(outbuf, pt_buffer, outbytes);
                outbuf += outbytes;
                plaintext_length += outbytes;
                pt_bytes_needed -= outbytes;

                if (outbytes < bytes_in_pt_buffer) {
                    // move remaining plaintext to the initial position inside the plaintext buffer
                    ssize_t bytes_remaining = bytes_in_pt_buffer - outbytes;
                    memmove(pt_buffer, pt_buffer + outbytes, bytes_remaining);
                    bytes_in_pt_buffer = bytes_remaining;
                } else {
                    // indicate that plaintext buffer is empty
                    bytes_in_pt_buffer = 0;
                }
            }

            if (no_more_plaintext) {
                break;
            }
        }

        if (err) {
            return -1;  // indicate error
        }
        return plaintext_length;
    }


    bool is_readable() const {
        if (file == nullptr && (bytes_in_pt_buffer == 0)) {
            return false;
        }
        return true;
    }
};

#endif // ENC_FILE_READER_H
