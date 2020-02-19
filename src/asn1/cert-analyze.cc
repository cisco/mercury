/*
 * cert-analyze.cc
 *
 * analyze X509 certificates
 */

#include <stdio.h>
#include <string.h>
#include <string>
#include <unordered_map>

#include "x509.h"




/*
 * START base64
 */

/*
* Base64 encoding/decoding (RFC1341)
* Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
*
* This software may be distributed under the terms of the BSD license.
* See README for more details.
*/

// 2016-12-12 - Gaspard Petit : Slightly modified to return a std::string 
// instead of a buffer allocated with malloc.

#include <string>

static const unsigned char base64_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
* base64_encode - Base64 encode
* @src: Data to be encoded
* @len: Length of the data to be encoded
* @out_len: Pointer to output length variable, or %NULL if not used
* Returns: Allocated buffer of out_len bytes of encoded data,
* or empty string on failure
*/
std::string base64_encode(const unsigned char *src, size_t len)
{
    unsigned char *out, *pos;
    const unsigned char *end, *in;

    size_t olen;

    olen = 4*((len + 2) / 3); /* 3-byte blocks to 4-byte */

    if (olen < len)
        return std::string(); /* integer overflow */

    std::string outStr;
    outStr.resize(olen);
    out = (unsigned char*)&outStr[0];

    end = src + len;
    in = src;
    pos = out;
    while (end - in >= 3) {
        *pos++ = base64_table[in[0] >> 2];
        *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = base64_table[in[2] & 0x3f];
        in += 3;
    }

    if (end - in) {
        *pos++ = base64_table[in[0] >> 2];
        if (end - in == 1) {
            *pos++ = base64_table[(in[0] & 0x03) << 4];
            *pos++ = '=';
        }
        else {
            *pos++ = base64_table[((in[0] & 0x03) << 4) |
                (in[1] >> 4)];
            *pos++ = base64_table[(in[1] & 0x0f) << 2];
        }
        *pos++ = '=';
    }

    return outStr;
}

static const int B64index[256] = {
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0, 62, 63, 62, 62, 63,
    52, 53, 54, 55, 56, 57, 58, 59,
    60, 61,  0,  0,  0,  0,  0,  0,
     0,  0,  1,  2,  3,  4,  5,  6,
     7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22,
    23, 24, 25,  0,  0,  0,  0, 63,
     0, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48,
     49, 50, 51, 0,  0,  0,  0,  0
};

std::string b64decode(const void* data, const size_t len) {
    unsigned char* p = (unsigned char*)data;
    int pad = len > 0 && (len % 4 || p[len - 1] == '=');
    const size_t L = ((len + 3) / 4 - pad) * 4;
    std::string str(L / 4 * 3 + pad, '\0');

    for (size_t i = 0, j = 0; i < L; i += 4)  {
        int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
        str[j++] = n >> 16;
        str[j++] = n >> 8 & 0xFF;
        str[j++] = n & 0xFF;
    }
    if (pad) {
        int n = B64index[p[L]] << 18 | B64index[p[L + 1]] << 12;
        str[str.size() - 1] = n >> 16;

        if (len > L + 2 && p[L + 2] != '=') {
            n |= B64index[p[L + 2]] << 6;
            str.push_back(n >> 8 & 0xFF);
        }
    }
    return str;
}

void print_as_ascii_with_dots(const void *string, size_t len) {
    const char *s = (const char *)string;
    for (size_t i=0; i < len; i++) {
        if (isprint(s[i])) {
            printf("%c", s[i]);
        } else {
            printf(".");
        }
    }
    printf("\n");
}


void fprintf_parser_as_string(FILE *f, struct parser *p) {
    fprintf(f, "%.*s", (int) (p->data_end - p->data), p->data);
}

// for debugging, compare to the output of 
//  $ openssl x509 -in first.pem -text -noout
//

#if 0 // omit hashing for now

#include <mhash.h>
void sha256_hash(const void *buffer,
                 unsigned int len) {
    int i;
    MHASH td;
    unsigned char hash[32]; 

    hashid hash_type = MHASH_SHA1;
    td = mhash_init(hash_type);
    if (td == MHASH_FAILED) {
        return;
    }

    mhash(td, buffer, len);

    mhash_deinit(td, hash);

    printf("%s: ", mhash_get_hash_name(hash_type));
    for (i = 0; i < mhash_get_block_size(hash_type); i++) {
        printf("%.2x", hash[i]);
    }
    printf("\n");

}

#endif

// std::unordered_map<std::string, std::string> cert_dict;

int main(int argc, char *argv[]) {
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    stream = fopen(argv[1], "r");
    if (stream == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    while ((nread = getline(&line, &len, stream)) != -1) {
        // printf("got line of length %zu:\n", nread);
        // fwrite(line, nread, 1, stdout);

        // advance just past the comma
        int i = 0;
        for (i=0; i<nread; i++) {
            if (line[i] == ',') {
                break;
            }
        }
        char *b64_line = line + (i+1);
        std::string cert = b64decode(b64_line, nread-(i+1));
        //fprintf(stdout, "parsed base64 (len: %zu)\n", cert.length());

        // sha256_hash(cert.c_str(), cert.length());

        // fprintf(stderr, "parsing cert\n");
        try{
            // parse certificate, then print as JSON
            struct x509_cert c;
            c.parse(cert.c_str(), cert.length());
            c.print_as_json(stdout);

            // parse certificate prefix, then print as JSON 
            struct x509_cert_prefix p;
            p.parse(cert.c_str(), cert.length());
            p.print_as_json_hex(stdout);
            // fprintf(stderr, "prefix length: %zu\n", p.get_length());
        }
        catch (const char *msg) {
            fprintf(stderr, "error: %s\n", msg);
            return EXIT_FAILURE;
        }

        //        cert_dict[key] = cert;
    }

    // fprintf(stderr, "loaded %lu certs\n", cert_dict.size());

    free(line);
    fclose(stream);

    exit(EXIT_SUCCESS);

}
