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
#include <openssl/aes.h>
#include <openssl/hmac.h>
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

// 22: {'salt': bytes.fromhex('7fbcdb0e7c66bbe9193a96cd21519ebd7a02644a')},
// 23: {'salt': bytes.fromhex('c3eef712c72ebb5a11a7d2432bb46365bef9f502')},
// 24: {'salt': bytes.fromhex('c3eef712c72ebb5a11a7d2432bb46365bef9f502')},
// 25: {'salt': bytes.fromhex('c3eef712c72ebb5a11a7d2432bb46365bef9f502')},
// 26: {'salt': bytes.fromhex('c3eef712c72ebb5a11a7d2432bb46365bef9f502')},
// 27: {'salt': bytes.fromhex('c3eef712c72ebb5a11a7d2432bb46365bef9f502')},
// 28: {'salt': bytes.fromhex('c3eef712c72ebb5a11a7d2432bb46365bef9f502')},
// 29: {'salt': bytes.fromhex('afbfec289993d24c9e9786f19c6111e04390a899')},
// 30: {'salt': bytes.fromhex('afbfec289993d24c9e9786f19c6111e04390a899')},
// 31: {'salt': bytes.fromhex('afbfec289993d24c9e9786f19c6111e04390a899')},


struct quic_initial_packet_crypto {
    AES_KEY dec_key;
    constexpr static const uint8_t client_in[] = "tls13 client in";
    constexpr static const uint8_t quic_key[]  = "tls13 quic key";
    constexpr static const uint8_t quic_iv[]   = "tls13 quic iv";

    quic_initial_packet_crypto(const uint8_t *dcid, size_t dcid_len) {
        uint8_t salt_v31[] = {
            0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c,
            0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
            0x43, 0x90, 0xa8, 0x99
        };

        uint8_t initial_secret[EVP_MAX_MD_SIZE];
        unsigned int initial_secret_len = 0;
        HMAC(EVP_sha256(), salt_v31, sizeof(salt_v31), dcid, dcid_len, initial_secret, &initial_secret_len);

        //        AES_set_decrypt_key(dec_key_v31, 192, &dec_key);

        fprintf(stderr, "set decryption key\n");
    }

    void decrypt(void *data) {
    }

    void kdf_tls13() {

    }
    // def kdf_tls13(secret, label, length):
    //     digest_type = SHA256()
    //     key = b''
    //     block = b''

    //     label = b'tls13 ' + label
    //     len_ = struct.pack('!H', length)
    //     label = b'%s%s%s%s' % (len_, struct.pack('B', len(label)), label, b'\x00')

    //     ind = 0
    //     while len(key) < length:
    //         ind += 1
    //         block = IQUIC.hmac(secret, digest_type, b'%s%s%s' % (block, label, struct.pack('B',ind)))
    //         key += block

    //     return bytearray(key[:length])

};

struct quic_initial_packet {
    uint8_t connection_info;
    struct datum version;
    struct datum dcid;
    struct datum scid;
    struct datum token;
    struct datum data;
    bool valid;

    static struct quick_initial_packet_crypto decrypter;

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

        if ((data.is_not_empty() == false) || (data_length < 32) || (scid.is_not_empty() == false)) {
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
