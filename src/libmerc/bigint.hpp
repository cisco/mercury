// bigint.hpp
//
// classes for encoding and decoding large integers in ASN.1

#ifndef BIGINT_HPP
#define BIGINT_HPP

#include <gmp.h>
#include "datum.h"

// class bigint holds a big-endian octet string suitable for output or
// ASN.1 encoding
//
class bigint {
    size_t count;      // octets in buffer
    uint8_t *mpz_buf;  // buffer

    static constexpr int bigendian = 1;

public:

    bigint(mpz_t x) :
        count{(mpz_sizeinbase(x, 2) + 8-1) / 8},
        mpz_buf{(uint8_t *)mpz_export(nullptr, &count, bigendian, 1, 1, 0, x)} {
        if (mpz_buf == nullptr) {
            throw std::runtime_error{"could not allocate mpz buffer"};
        }
        // fprintf(stdout, "bytes in mpz_buf: %zu\n", count);
        // fprintf(stdout, "mpz_buf: %x%x%x%x\n", mpz_buf[0], mpz_buf[1], mpz_buf[2], mpz_buf[3]);
    }

    ~bigint() { free(mpz_buf); }

    datum get_datum() const { return { mpz_buf, mpz_buf + count }; }
    //    std::pair<uint8_t *, uint8_t *> get_datum() const { return { mpz_buf, mpz_buf + count }; }

    size_t octets() const { return count; }
};


// mpz_init_set_datum(mpz, d) initializes an mpz_t integer and then
// sets it to the vaule of the datum
//
static inline int mpz_init_set_datum(mpz_t mod, datum mod_tmp) {
    char mod_buf[2048];
    ssize_t chars_written = mod_tmp.write_hex(mod_buf, sizeof(mod_buf), true);
    if (chars_written < 0) {
        mpz_init(mod);
        return -1;      // error: cannot set integer from datum
    }
    return mpz_init_set_str(mod, mod_buf, 16);
}

#endif // BIGINT_HPP
