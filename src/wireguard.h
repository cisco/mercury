/*
 * wireguard.h
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include "parser.h"

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

struct wireguard_handshake_init {
    struct parser sender_index;
    struct parser unencrypted_ephemeral;

    wireguard_handshake_init() : sender_index{NULL, NULL}, unencrypted_ephemeral{NULL, NULL} {}

    void parse(struct parser &p) {
        if (p.length() != sizeof(struct wireguard_handshake_initiation)) {
            return;
        }
        p.skip(sizeof(wireguard_handshake_initiation::message_type) +
               sizeof(wireguard_handshake_initiation::reserved_zero));

        sender_index.parse(p, sizeof(wireguard_handshake_initiation::sender_index));
        unencrypted_ephemeral.parse(p, sizeof(wireguard_handshake_initiation::unencrypted_ephemeral));
    }

    void write_json(struct json_object &o);
};

#endif /* WIREGUARD_H */
