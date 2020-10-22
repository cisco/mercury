/*
 * quic.h
 *
 * Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

/**
 * \file quic.h
 *
 * \brief interface file for QUIC code
 */
#ifndef QUIC_H
#define QUIC_H

#include <string>
#include "json_object.h"
#include "util_obj.h"


typedef struct {
    uint8_t connection_info;
} __attribute__((__packed__)) quic_hdr;


struct quic_packet {
    quic_hdr *header;
    struct datum version;
    struct datum dcid;
    struct datum scid;
    struct datum token;
    struct datum data;
    uint8_t dcid_length;
    uint8_t scid_length;
    uint8_t token_length;
    uint16_t length;

    quic_packet() : header{NULL}, dcid{NULL, NULL}, scid{NULL, NULL}, token{NULL, NULL}, data{NULL, NULL} {  }

    quic_packet(struct datum &d) : header{NULL}, dcid{NULL, NULL}, scid{NULL, NULL}, token{NULL, NULL}, data{NULL, NULL} {
        parse(d);
    }

    void parse(struct datum &d) {
        if (d.length() < (int)sizeof(quic_hdr)) {
            return;  // too short
        }
        header = (quic_hdr *)d.data;
        d.skip(sizeof(quic_hdr));

        if ((header->connection_info & 0x30) != 0) {
            header = NULL;  // not an initial packet
            return;
        }

        version.parse(d, 4);

        d.read_uint8(&dcid_length);
        dcid.parse(d, dcid_length);

        d.read_uint8(&scid_length);
        scid.parse(d, scid_length);

        d.read_uint8(&token_length);
        token.parse(d, token_length);

        // @TODO: need to handle actually handle QUIC's variable length encoding
        d.read_uint16(&length);
        length = length & 0x3FFF;
        data.parse(d, length);

        if ((data.is_not_empty() == false) || (version.is_not_empty() == false) ||
            (dcid.is_not_empty() == false) || (scid.is_not_empty() == false) ||
            (data.length() < 32)) {
            header = NULL;
            version.set_null();
            dcid.set_null();
            scid.set_null();
            token.set_null();
            data.set_null();
        }
    }

    bool is_not_empty() {
        return (header != NULL);
    }

    void write_json(struct json_object &o) const {
        if (header == NULL) {
            return;
        }

        o.print_key_uint8("connection_info",header->connection_info);
        o.print_key_hex("version",version);
        o.print_key_hex("dcid",dcid);
        o.print_key_hex("scid",scid);
        o.print_key_hex("token",token);
        o.print_key_hex("data",data);

    }
};

#endif /* QUIC_H */
