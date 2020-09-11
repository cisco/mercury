/*
 * wireguard.c
 */

#include "wireguard.h"
#include "json_object.h"
#include "extractor.h"

unsigned int parser_extractor_process_wireguard(struct parser *p, struct extractor *x) {
    (void)x;
    
    extractor_debug("%s: processing packet\n", __func__);

    if (p->length() != sizeof(struct wireguard_handshake_initiation)) {
        return 0;   // not wireguard handshake initial message
    }

    // set sender_index as packet_data

    return 0;
}

void wireguard_handshake_init::write_json(struct json_object &o) {

    if (sender_index.is_not_readable()) {
        return;
    }
    struct json_object wg{o, "wireguard"};
    uint32_t tmp = ntohl(*(const uint32_t *)sender_index.data);
    struct parser si{(uint8_t *)&tmp, (uint8_t *)&tmp + sizeof(uint32_t)};
    wg.print_key_hex("sender_index", si);
    wg.close();

}
