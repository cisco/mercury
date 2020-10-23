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

/*
 * QUIC header format (from draft-ietf-quic-transport-32):
 *
 *    Long Header Packet {
 *       Header Form (1) = 1,
 *       Fixed Bit (1) = 1,
 *       Long Packet Type (2),
 *       Type-Specific Bits (4),
 *       Version (32),
 *       Destination Connection ID Length (8),
 *       Destination Connection ID (0..160),
 *       Source Connection ID Length (8),
 *       Source Connection ID (0..160),
 *    }
 *
 *    Short Header Packet {
 *       Header Form (1) = 0,
 *       Fixed Bit (1) = 1,
 *       Spin Bit (1),
 *       Reserved Bits (2),
 *       Key Phase (1),
 *       Packet Number Length (2),
 *       Destination Connection ID (0..160),
 *       Packet Number (8..32),
 *       Packet Payload (..),
 *    }
 *
 */

struct uint8_bitfield {
    uint8_t value;

    uint8_bitfield(uint8_t x) : value{x} {}

    void operator()(struct buffer_stream &b) {
        b.write_char('\"');
        for (uint8_t x = 0x80; x > 0; x=x>>1) {
            if (x & value) {
                b.write_char('1');
            } else {
                b.write_char('0');
            }
        }
        b.write_char('\"');
    }
};

struct quic_initial_packet {
    uint8_t connection_info;
    struct datum version;
    struct datum dcid;
    struct datum scid;
    struct datum token;
    struct datum data;
    bool valid;

    //    quic_initial_packet() : connection_info{0}, dcid{NULL, NULL}, scid{NULL, NULL}, token{NULL, NULL}, data{NULL, NULL}, valid{false} {  }

    quic_initial_packet(struct datum &d) : connection_info{0}, dcid{NULL, NULL}, scid{NULL, NULL}, token{NULL, NULL}, data{NULL, NULL}, valid{false} {
        parse(d);
    }

    void parse(struct datum &d) {

        d.read_uint8(&connection_info);
        if ((connection_info & 0x30) != 0) {
            return;
        }

        version.parse(d, 4);

        uint8_t dcid_length;
        d.read_uint8(&dcid_length);
        dcid.parse(d, dcid_length);

        uint8_t scid_length;
        d.read_uint8(&scid_length);
        scid.parse(d, scid_length);

        uint8_t token_length;
        d.read_uint8(&token_length);
        token.parse(d, token_length);

        // @TODO: need to handle actually handle QUIC's variable length encoding
        uint16_t data_length;
        d.read_uint16(&data_length);
        data_length = data_length & 0x3FFF;
        data.parse(d, data_length);

        if ((data.is_not_empty() == false) || (data_length < 32)) {
            return;  // invalid or incomplete packet
        }
        valid = true;
    }

    bool is_not_empty() {
        return valid;
    }

    void write_json(struct json_object &o) const {
        if (!valid) {
            return;
        }

        //        o.print_key_uint8("connection_info", connection_info);
        struct uint8_bitfield bitfield{connection_info};
        o.print_key_value("connection_info", bitfield);
        o.print_key_hex("version", version);
        o.print_key_hex("dcid", dcid);
        o.print_key_hex("scid", scid);
        o.print_key_hex("token", token);
        o.print_key_hex("data", data);

    }
};

#endif /* QUIC_H */
