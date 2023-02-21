/*
 * wireguard.cc
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include "wireguard.h"
#include "json_object.h"

// we report wireguard's 32-bit sender index in hexadecimal, as a
// little-endian number, since that's what wireshark does.  The
// uint32_hbo represents a uint32_t that can write itself to a
// buffer_stream in host byte order.
//
class uint32_hbo {
    uint64_t value=0;
public:
    uint32_hbo(datum d) { d.read_uint(&value, 4); }
    void fingerprint(buffer_stream &b) { b.write_hex_uint(ntoh(value)); }
};

void wireguard_handshake_init::write_json(struct json_object &o, bool write_metadata) {
    (void)write_metadata;

    if (sender_index.is_not_readable()) {
        return;
    }
    struct json_object wg{o, "wireguard"};
    uint32_hbo si{sender_index};
    wg.print_key_value("sender_index", si);
    wg.close();

}
