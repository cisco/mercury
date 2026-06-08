/*
 * wireguard.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include "datum.h"
#include "protocol.h"
#include "match.h"
#include "json_object.h"

struct wireguard_handshake_initiation {
    uint8_t  message_type;                       // 1
    uint8_t  reserved_zero[3];                   // { 0, 0, 0 }
    uint32_t sender_index;                       // random
    uint8_t  unencrypted_ephemeral[32];          // random
    uint8_t  encrypted_static[32 + 16];          // random
    uint8_t  encrypted_timestamp[12 + 16];       // random
    uint8_t  mac1[16];                           // random
    uint8_t  mac2[16];                           // random or { 0, 0, ... }
};

struct wireguard_handshake_init : public base_protocol {
    struct datum sender_index;
    struct datum unencrypted_ephemeral;
    bool valid;

    wireguard_handshake_init(datum &p) : sender_index{NULL, NULL}, unencrypted_ephemeral{NULL, NULL}, valid{false} { parse(p); }

    void parse(struct datum &p) {
        valid = false;
        if (p.length() != sizeof(struct wireguard_handshake_initiation)) {
            // fprintf(stderr, "%s: wrong size (got %zu, expected %zu)\n", __func__, p.length(), sizeof(struct wireguard_handshake_initiation));
            return;
        }
        p.skip(sizeof(wireguard_handshake_initiation::message_type) +
               sizeof(wireguard_handshake_initiation::reserved_zero));

        sender_index.parse(p, sizeof(wireguard_handshake_initiation::sender_index));
        unencrypted_ephemeral.parse(p, sizeof(wireguard_handshake_initiation::unencrypted_ephemeral));
        valid = true;
    }

    void write_json(struct json_object &o, bool write_metadata=false);

    bool is_not_empty() { return valid; }

    constexpr static mask_and_value<8> matcher = {
       { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 },
       { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
    };

};

// we report wireguard's 32-bit sender index in hexadecimal, as a
// little-endian number, since that's what wireshark does.  The
// uint32_hbo represents a uint32_t that can write itself to a
// buffer_stream in host byte order.
//
class uint32_hbo {
    uint64_t value=0;
public:
    uint32_hbo(datum d) { d.read_uint(&value, 4); }

    /// write a textual representation of this uint32 into \param b
    ///
    void write(buffer_stream &b) { b.write_hex_uint(ntoh(value)); }
};

inline void wireguard_handshake_init::write_json(struct json_object &o, bool write_metadata) {
    (void)write_metadata;

    if (sender_index.is_not_readable()) {
        return;
    }
    struct json_object wg{o, "wireguard"};
    uint32_hbo si{sender_index};
    wg.print_key_value("sender_index", si);
    wg.close();

}

[[maybe_unused]] inline int wireguard_handshake_init_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<wireguard_handshake_init>(data, size);
}

namespace wireguard_unit_test {
#ifndef NDEBUG
    inline bool unit_test() {
        char buffer[512];

        uint8_t valid[148] = {0};
        valid[0] = 0x01;
        valid[4] = 0x12; valid[5] = 0x34; valid[6] = 0x56; valid[7] = 0x78;
        datum d1{valid, valid + sizeof(valid)};
        wireguard_handshake_init msg1{d1};
        if (!msg1.is_not_empty()) return false;
        {
            buffer_stream buf{buffer, sizeof(buffer)};
            json_object json{&buf};
            msg1.write_json(json, false);
            json.close();
            buf.write_char('\0');
            if (!strstr(buffer, "wireguard")) return false;
            if (!strstr(buffer, "sender_index")) return false;
        }

        uint8_t wrong_size[100] = {0};
        wrong_size[0] = 0x01;
        datum d2{wrong_size, wrong_size + sizeof(wrong_size)};
        wireguard_handshake_init msg2{d2};
        if (msg2.is_not_empty()) return false;

        uint8_t too_short[] = { 0x01, 0x00, 0x00, 0x00 };
        datum d3{too_short, too_short + sizeof(too_short)};
        wireguard_handshake_init msg3{d3};
        if (msg3.is_not_empty()) return false;

        return true;
    }
#endif
} // namespace wireguard_unit_test

#endif /* WIREGUARD_H */
