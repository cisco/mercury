/*
 *
 */

#ifndef BASE64_H
#define BASE64_H


std::string hex_encode(const unsigned char *src, size_t len) {
    char hex_table[] =
        {
         '0', '1', '2', '3',
         '4', '5', '6', '7',
         '8', '9', 'a', 'b',
         'c', 'd', 'e', 'f'
    };
    std::string out;

    for (size_t i = 0; i < len; i++) {
        out += hex_table[(src[i] & 0xf0) >> 4];
        out += hex_table[src[i] & 0x0f];
    }
    return out;
}

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

static const unsigned char base64url_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
* base64_encode - Base64 encode
* @src: Data to be encoded
* @len: Length of the data to be encoded
*/
std::string base64_encode(const unsigned char *src, size_t len, const unsigned char table[65]=base64_table)
{
    unsigned char *out, *pos;
    const unsigned char *end, *in;

    size_t olen;

    olen = 4*((len + 2) / 3);  // 3-byte blocks to 4-byte
    if (olen < len) {
        return std::string();  // error
    }

    std::string out_str;
    out_str.resize(olen);
    out = (unsigned char*)&out_str[0];

    end = src + len;
    in = src;
    pos = out;
    while (end - in >= 3) {
        *pos++ = table[in[0] >> 2];
        *pos++ = table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = table[in[2] & 0x3f];
        in += 3;
    }

    if (end - in) {
        *pos++ = table[in[0] >> 2];
        if (end - in == 1) {
            *pos++ = table[(in[0] & 0x03) << 4];
            if (table != base64url_table) {
                *pos++ = '=';
            } else {
                out_str.pop_back();
            }
        } else {
            *pos++ = table[((in[0] & 0x03) << 4) |
                (in[1] >> 4)];
            *pos++ = table[(in[1] & 0x0f) << 2];
        }
        if (table != base64url_table) {
            *pos++ = '=';
        } else {
            out_str.pop_back();
        }
    }

    return out_str;
}

namespace base64 {

static const int index[256] = {
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
        int n = index[p[i]] << 18 | index[p[i + 1]] << 12 | index[p[i + 2]] << 6 | index[p[i + 3]];
        str[j++] = n >> 16;
        str[j++] = n >> 8 & 0xFF;
        str[j++] = n & 0xFF;
    }
    if (pad) {
        int n = index[p[L]] << 18 | index[p[L + 1]] << 12;
        str[str.size() - 1] = n >> 16;

        if (len > L + 2 && p[L + 2] != '=') {
            n |= index[p[L + 2]] << 6;
            str.push_back(n >> 8 & 0xFF);
        }
    }
    return str;
}

bool invalid[256] =  {
     1, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 0, 1, 1, 1, 0,
     0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 1, 1, 1, 0, 1, 1,
     1, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 1, 1, 1, 1, 1,
     1, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1
};

/*
 * base64::decode(outbuf, outlen, data, len) performs a base-64
 * decoding of the data buffer with length len, and writes the
 * resulting data into outbuf, if there is enough room in that buffer.
 * If the decoding is successful, then the length of the decoded data
 * in outbuf is returned.  Otherwise, a zero is returned to indicate
 * that there is not enough room in the buffer, or a negative number
 * is returned to indicate that the input data was not in base64
 * format.
 */
int decode(void *outbuf, const size_t outlen, const void* data, const size_t len) {
    unsigned char* p = (unsigned char*)data;
    int pad = len > 0 && (len % 4 || p[len - 1] == '=');
    const size_t L = ((len + 3) / 4 - pad) * 4;
    uint8_t *str = (uint8_t *)outbuf;
    size_t str_size = L / 4 * 3 + pad;

    if (outlen < str_size) {
        fprintf(stderr, "len: %zu", len);
        fprintf(stderr, "L: %zu", L);
        fprintf(stderr, "error: base64 decode needs %zu bytes, only has room for %zu\n", str_size, outlen);
        return 0;  // not enough room for output
    }
    size_t i, j;
    for (i = 0, j = 0; i < L; i += 4)  {
        if (invalid[p[i]] | invalid[p[i+1]] | invalid[p[i+2]] | invalid[p[i+3]]) {
            return -(i+1);
        }
        int n = index[p[i]] << 18 | index[p[i + 1]] << 12 | index[p[i + 2]] << 6 | index[p[i + 3]];
        str[j++] = n >> 16;
        str[j++] = n >> 8 & 0xFF;
        str[j++] = n & 0xFF;
    }
    if (pad) {
        int n = index[p[L]] << 18 | index[p[L + 1]] << 12;
        str[j++] = n >> 16;

        if (len > L + 2 && p[L + 2] != '=') {
            n |= index[p[L + 2]] << 6;
            str[j++] = n >> 8 & 0xFF;
        }
    }
    return j;
}

} // namespace base64


#endif // BASE64_H
