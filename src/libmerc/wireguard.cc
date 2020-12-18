/*
 * wireguard.c
 */

#include "wireguard.h"
#include "json_object.h"

void wireguard_handshake_init::write_json(struct json_object &o) {

    if (sender_index.is_not_readable()) {
        return;
    }
    struct json_object wg{o, "wireguard"};
    uint32_t tmp = ntohl(*(const uint32_t *)sender_index.data);
    struct datum si{(uint8_t *)&tmp, (uint8_t *)&tmp + sizeof(uint32_t)};
    wg.print_key_hex("sender_index", si);
    wg.close();

}
