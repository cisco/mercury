// tofsee.hpp
//
// initial message de-obfuscation and parsing

#ifndef TOFSEE_HPP
#define TOFSEE_HPP

#include "datum.h"
#include "json_object.h"
#include "utils.h"

template <size_t bits, typename T>
inline T rotl(T &x) {
    return (x << bits )|(x >> (sizeof(T)*8 - bits));
}

class tofsee_initial_message {

    static void decrypt(const uint8_t *ciphertext, uint8_t *plaintext, size_t data_len) {
        uint8_t res = 198;
        for (size_t i=0; i<data_len; i++) {
            uint8_t c = *ciphertext++;
            *plaintext++ = res ^ rotl<5>(c);
            res = c ^ 0xc6;
        }
    }

    class plaintext : public datum {
        uint8_t buffer[200];
    public:
        plaintext(datum &d) {
            if (d.length() != sizeof(buffer)) {
                d.set_null(); // error: ciphertext has wrong length
            }
            decrypt(d.data, buffer, sizeof(buffer));
            data = buffer;
            data_end = buffer + sizeof(buffer);
        }
    };

    plaintext pt;
    datum key;
    datum unknown_1;
    datum ipv4;
    datum srv_time;
    datum unknown_2;

public:

    tofsee_initial_message(datum &ct) :
        pt{ct},
        key{pt, 128},
        unknown_1{pt, 16},
        ipv4{pt, 4},
        srv_time{pt, 4},
        unknown_2{pt, 48} { }

    void write_json(json_object &o, bool=true) const {
        if (!is_not_empty()) {
            return;
        }
        o.print_key_hex("key", key.data, key.length());
        o.print_key_hex("unknown_1", unknown_1.data, unknown_1.length());
        o.print_key_ipv4_addr("ipv4_addr", ipv4.data);
        o.print_key_hex("srv_time", srv_time.data, srv_time.length());
        o.print_key_hex("unknown_2", unknown_2.data, unknown_2.length());
    }

    bool is_not_empty() const {
        return unknown_2.is_not_null();
    }
};

#endif // TOFSEE_HPP
