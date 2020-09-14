/*
 * udp.h
 *
 * UDP protocol processing
 */

#ifndef UDP_H
#define UDP_H

#include "extractor.h"

unsigned int packet_filter_process_udp(struct packet_filter *pf, struct key *k);

struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__ ((__packed__));

struct udp_packet {
    const struct udp_header *header;

    udp_packet() : header{NULL} {};

    void parse(struct datum &d) {
        if (d.length() < (int)sizeof(struct udp_header)) {
            return;
        }
        header = (const struct udp_header *)d.data;
        d.skip(sizeof(struct udp_header));
    }

    void set_key(struct key &k) {
        if (header) {
            k.src_port = ntohs(header->src_port);
            k.dst_port = ntohs(header->dst_port);
            k.protocol = 17; // udp
        }
    }

};

enum msg_type udp_get_message_type(const uint8_t *udp_data,
                                   unsigned int len);

#endif

