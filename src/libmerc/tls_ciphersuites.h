#include "tls.h"

inline bool is_faketls_util(const datum ciphersuite_vector) {
    size_t len = ciphersuite_vector.length();

    if (len % 2) {
        len--;    // forces length to be a multiple of 2
    }

    uint16_t *x = (uint16_t *)ciphersuite_vector.data;
    uint16_t *x_end = x + (len/2);

    size_t invalid_ciphers = 0;

    while (x < x_end) {
        uint16_t tmp = hton(degrease_uint16(*x++));
        if (tls::cipher_suites_list.find(tmp) != tls::cipher_suites_list.end())    // cipher suite found in IANA list
            continue;
        else if (tls::faketls_cipher_suite_exceptions.find(tmp) == tls::faketls_cipher_suite_exceptions.end())    // cipher suite not found in IANA and exception list
            invalid_ciphers++;
    }

    // flag for faketls only when all the cipher suites used are outside of IANA/exception list
    //
    if (invalid_ciphers == len/2) {
        return true;
    }

    return false;
}
