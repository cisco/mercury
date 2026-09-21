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

#include <array>
#include <cstdint>
#include <string>
#include <tuple>
#include <unordered_map>
#include <variant>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "tls.h"
#include "flow_key.h"
#include "json_object.h"
#include "match.h"
#include "crypto_engine.h"
#include "quic_vli.hpp"

#define type_quic_user_agent 0x3129
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

    /// write a textual representation of this bitfield into \param b
    ///
    void write(buffer_stream &b) {
        for (uint8_t x = 0x80; x > 0; x=x>>1) {
            if (x & value) {
                b.write_char('1');
            } else {
                b.write_char('0');
            }
        }
    }
};

// quic frames are defined by a set of classes and the std::variant
// quic_frame, defined below
//

// PADDING Frame {
//   Type (i) = 0x00,
// }
//
// PING Frame {
//   Type (i) = 0x01,
// }
//
//
// ACK Range {
//   Gap (i),
//   ACK Range Length (i),
// }
//
class ack_range {
    variable_length_integer gap;
    variable_length_integer length;
public:

    ack_range(datum &d) : gap{d}, length{d} { }
};

// ACK Frame {
//   Type (i) = 0x02..0x03,
//   Largest Acknowledged (i),
//   ACK Delay (i),
//   ACK Range Count (i),
//   First ACK Range (i),
//   ACK Range (..) ...,
//   [ECN Counts (..)],
// }
//
class ack {
    variable_length_integer largest_acked;
    variable_length_integer ack_delay;
    variable_length_integer ack_range_count;
    variable_length_integer first_ack_range;
    bool valid;

public:
    ack(datum &d) : largest_acked{d}, ack_delay{d}, ack_range_count{d}, first_ack_range{d}, valid{false} {
        // rough estimate: considering 2k byte pkt, and min ack range size as 2 bytes, max ack range count is 1000
        // exit if range count exceeds this or datum is empty
        if (ack_range_count.value() > 1000) {
            d.set_null();
            return;
        }
        for (unsigned i=0; i<ack_range_count.value() && d.is_not_empty(); i++) {
            ack_range range{d};
        }
        if (d.is_null()) {
            return;
        }
        valid = true;
    }

    bool is_valid() const { return valid; }

    void write_json(json_object &o) {
        if (is_valid()) {
            json_object a{o, "ack"};
            a.print_key_uint("largest_acked", largest_acked.value());
            a.print_key_uint("ack_delay", ack_delay.value());
            a.print_key_uint("ack_range_count", ack_range_count.value());
            a.print_key_uint("first_ack_range", first_ack_range.value());
            a.close();
        }
    }

	void write(FILE *f) {
    	if (is_valid()) {
        	fprintf(f, "ack.largest_acked: %" PRIu64 "\n", largest_acked.value());
        	fprintf(f, "ack.ack_delay: %" PRIu64 "\n", ack_delay.value());
        	fprintf(f, "ack.ack_range_count: %" PRIu64 "\n", ack_range_count.value());
        	fprintf(f, "ack.first_ack_range: %" PRIu64 "\n", first_ack_range.value());
        } else {
        	fprintf(f, "ack.not valid\n");
        }
    }

};
class ack_ecn {
    ack ack_frame;
    variable_length_integer ect0;
    variable_length_integer ect1;
    variable_length_integer ecn_ce;
    bool valid = false;

public:

    ack_ecn(datum &d) : ack_frame{d}, ect0{d}, ect1{d}, ecn_ce{d}, valid{d.is_not_null()&&ack_frame.is_valid()} {}

    bool is_valid() { return valid; }

    void write_json(json_object &o) {
        if (is_valid()) {
            json_object a{o, "ack_ecn"};
            a.print_key_uint("ect0", ect0.value());
            a.print_key_uint("ect1", ect1.value());
            a.print_key_uint("ecn_ce", ecn_ce.value());
            ack_frame.write_json(a);
            a.close();
        }
    }

    void write(FILE *f) {
    	if (is_valid()) {
            ack_frame.write(f);
        	fprintf(f, "ack.ect0: %" PRIu64 "\n", ect0.value());
            fprintf(f, "ack.ect1: %" PRIu64 "\n", ect1.value());
            fprintf(f, "ack.ecn_ce: %" PRIu64 "\n", ecn_ce.value());
        } else {
        	fprintf(f, "ack_ecn.not valid\n");
        }
    }
};

//
// ECN Counts {
//   ECT0 Count (i),
//   ECT1 Count (i),
//   ECN-CE Count (i),
// }
//
// RESET_STREAM Frame {
//   Type (i) = 0x04,
//   Stream ID (i),
//   Application Protocol Error Code (i),
//   Final Size (i),
// }
//
// STOP_SENDING Frame {
//   Type (i) = 0x05,
//   Stream ID (i),
//   Application Protocol Error Code (i),
// }
//
// CRYPTO Frame {
//   Type (i) = 0x06,
//   Offset (i),
//   Length (i),
//   Crypto Data (..),
// }
//
class crypto {
    variable_length_integer _offset;
    variable_length_integer _length;
    datum _data;

public:
    crypto(datum &p) : _offset{p}, _length{p}, _data{p, (ssize_t)_length.value()} {    }

    crypto(const crypto &c) : _offset{c._offset}, _length{c._length}, _data{c._data} {   }

    crypto() : _offset{0}, _length{0}, _data{} {   }

    void operator =(const crypto &c) {
        _offset = c._offset;
        _length = c._length;
        _data = c._data;
    }

    bool is_valid() const { return _data.is_not_empty(); }

    datum &data() { return _data; } // note: function is not const

    uint64_t offset() const
    {
        return _offset.value();
    }

    uint64_t length() const
    {
        return _length.value();
    }

    void write(FILE *f) {
        if (is_valid()) {
            fprintf(f, "crypto.offset: %" PRIu64 "\n", _offset.value());
            fprintf(f, "crypto.length: %" PRIu64 "\n", _length.value());
        } else {
            fprintf(f, "crypto.not valid\n");
        }
    }
};

// NEW_TOKEN Frame {
//   Type (i) = 0x07,
//   Token Length (i),
//   Token (..),
// }
//
// STREAM Frame {
//   Type (i) = 0x08..0x0f,
//   Stream ID (i),
//   [Offset (i)],
//   [Length (i)],
//   Stream Data (..),
// }
//
// MAX_DATA Frame {
//   Type (i) = 0x10,
//   Maximum Data (i),
// }
//
// MAX_STREAM_DATA Frame {
//   Type (i) = 0x11,
//   Stream ID (i),
//   Maximum Stream Data (i),
// }
//
// MAX_STREAMS Frame {
//   Type (i) = 0x12..0x13,
//   Maximum Streams (i),
// }
//
// DATA_BLOCKED Frame {
//   Type (i) = 0x14,
//   Maximum Data (i),
// }
//
// STREAM_DATA_BLOCKED Frame {
//   Type (i) = 0x15,
//   Stream ID (i),
//   Maximum Stream Data (i),
// }
//
// STREAMS_BLOCKED Frame {
//   Type (i) = 0x16..0x17,
//   Maximum Streams (i),
// }
//
// NEW_CONNECTION_ID Frame {
//   Type (i) = 0x18,
//   Sequence Number (i),
//   Retire Prior To (i),
//   Length (8),
//   Connection ID (8..160),
//   Stateless Reset Token (128),
// }
//
// RETIRE_CONNECTION_ID Frame {
//   Type (i) = 0x19,
//   Sequence Number (i),
// }
//
// PATH_CHALLENGE Frame {
//   Type (i) = 0x1a,
//   Data (64),
// }
//
// PATH_RESPONSE Frame {
//   Type (i) = 0x1b,
//   Data (64),
// }
//
// CONNECTION_CLOSE Frame {
//   Type (i) = 0x1c..0x1d,
//   Error Code (i),
//   [Frame Type (i)],
//   Reason Phrase Length (i),
//   Reason Phrase (..),
// }
//
class connection_close {
    variable_length_integer error_code{0};
    variable_length_integer frame_type{0};
    variable_length_integer reason_phrase_length{0};
    datum reason_phrase;
    bool application_variant{false};   // type 0x1d omits the Frame Type field
    bool valid{false};

public:
    // is_application selects the 0x1d layout (no Frame Type field).
    connection_close(datum &p, bool is_application = false) : application_variant{is_application} {
        error_code = variable_length_integer{p};
        if (!application_variant) {
            frame_type = variable_length_integer{p};
        }
        reason_phrase_length = variable_length_integer{p};
        reason_phrase.parse(p, (ssize_t)reason_phrase_length.value());
        valid = p.is_not_null();   // fields parsed; a zero-length reason phrase is valid
    }

    bool is_valid() const { return valid; }

	void write_json(json_object &o) {
        if (is_valid()) {
            json_object cc{o, "connection_close"};
            cc.print_key_uint("error_code", error_code.value());
            if (!application_variant) {
                cc.print_key_uint("frame_type", frame_type.value());
            }
            cc.print_key_json_string("reason_phrase", reason_phrase);
            cc.close();
        }
    }

	void write(FILE *f) {
    	if (is_valid()) {
        	fprintf(f, "connection_close.error_code: %" PRIu64 "\n", error_code.value());
            if (!application_variant) {
                fprintf(f, "connection_close.frame_type: %" PRIu64 "\n", frame_type.value());
            }
        	fprintf(f, "connection_close.reason_phrase_length: %" PRIu64 "\n", reason_phrase_length.value());
        	fprintf(f, "connection_close.reason_phrase: %s\n", reason_phrase.get_string().c_str());
        } else {
        	fprintf(f, "connection_close.not valid\n");
        }
    }
};


// HANDSHAKE_DONE Frame {
//   Type (i) = 0x1e,
// }



//   Initial Packet {
//     Header Form (1) = 1,
//     Fixed Bit (1) = 1,
//     Long Packet Type (2) = 0,
//     Reserved Bits (2),
//     Packet Number Length (2),
//     Version (32),
//     Destination Connection ID Length (8),
//     Destination Connection ID (0..160),
//     Source Connection ID Length (8),
//     Source Connection ID (0..160),
//     Token Length (i),
//     Token (..),
//     Length (i),
//     Packet Number (8..32),
//     Packet Payload (8..),
//   }
//
// QUIC v2 version numbers.  These must have V2 salt/mask/label entries in
// quic_parameters and drive is_v2_version() (which renumbers Long Packet Type).
static constexpr uint32_t quic_version_2       = 0x6b3343cf;   // RFC 9369
static constexpr uint32_t quic_version_2_draft = 0x709a50c4;   // v2 draft1-7

struct quic_initial_packet {
    uint8_t connection_info;
    struct datum version;  // TODO: encoded<uint32_t>
    struct datum dcid;
    struct datum scid;
    struct datum token;
    struct datum payload;
    bool valid;
    const uint8_t *aad_start = nullptr;
    const uint8_t *aad_end = nullptr;
    struct datum raw_packet;  // full packet for raw_packet_data output

    // require_min_datagram_len enforces the datagram minimum length; set it
    // false for coalesced packets after the first, which may be smaller.
    quic_initial_packet(struct datum &d, bool require_min_datagram_len = true) : connection_info{0}, dcid{}, scid{}, token{}, payload{}, valid{false}, raw_packet{} {
        parse(d, require_min_datagram_len);
    }

    // v2 renumbers the Long Packet Type; keep in sync with V2 entries in quic_parameters
    static bool is_v2_version(uint32_t v) {
        return v == quic_version_2 || v == quic_version_2_draft;
    }

    void parse(struct datum &d, bool require_min_datagram_len = true) {

        raw_packet = d;

        // additional authenticated data (aad) is used in authenticated decryption
        //
        aad_start = d.data;

        // The 1184-byte minimum is a datagram-level requirement (the client's
        // first flight). Coalesced packets after the first may be smaller, so
        // the caller disables this check for them.
        if (require_min_datagram_len && d.length() < min_len_pdu) {
            return;  // packet too short to be valid
        }

        // connection information octet for initial packets:
        //
        // Header Form        (1)        1
        // Fixed Bit          (1)        ?
        // Long Packet Type   (2)        00
        // Type-Specific Bits (4)        ??
        //
        d.read_uint8(&connection_info);

        version.parse(d, 4);
        if (!version.is_not_empty()) {
            return;  // truncated packet: no version; avoid null-datum lookahead
        }

        // process non-standard QUIC versions, unless compile-time
        // configuration says not to do so
        //
        constexpr bool process_non_standard_versions = true;
        if (!process_non_standard_versions) {
            uint64_t v = 0;
            version.lookahead_uint(4, &v);
            switch(v) {
            case 4207849473:   // faceb001
            case 4207849474:   // faceb002
            case 4207849486:   // faceb00e
            case 4207849488:   // faceb010
            case 4207849489:   // faceb011
            case 4207849490:   // faceb012
            case 4207849491:   // faceb013
            case 4278190102:   // draft-22
            case 4278190103:   // draft-23
            case 4278190104:   // draft-24
            case 4278190105:   // draft-25
            case 4278190106:   // draft-26
            case 4278190107:   // draft-27
            case 4278190108:   // draft-28
            case 4278190109:   // draft-29
            case 4278190110:   // draft-30
            case 4278190111:   // draft-31
            case 4278190112:   // draft-32
            case 4278190113:   // draft-33
            case 4278190114:   // draft-34
            case 1:            // version-1
            case 1889161412:   // draft1_draft7_v2
            case 1798521807:   // version-2
                break;
            case 0x51303433:   // Google QUIC Q043
            case 0x51303436:   // Google QUIC Q046
            case 0x51303530:   // Google QUIC Q050
                ;              // note: could report gquic
                break;
            default:
                return;
            }
        }

        // Non-Initial long-header types are rejected by quic_init, which has
        // access to the per-version Long Packet Type mapping in
        // quic_parameters.  Gating here would have to hardcode one version's
        // mapping and would drop unknown versions before trial decryption.

        uint8_t dcid_length = 0;
        d.read_uint8(&dcid_length);
        if (dcid_length > 20) {
            return;  // dcid too long
        }
        dcid.parse(d, dcid_length);

        uint8_t scid_length = 0;
        d.read_uint8(&scid_length);
        if (scid_length > 20) {
            return;  // scid too long
        }
        scid.parse(d, scid_length);

        variable_length_integer token_length{d};
        token.parse(d, token_length.value());

        variable_length_integer length{d}; // length of packet number and packet payload
        //fprintf(stderr, "length: %08lu\td.length(): %08zu\tversion: %08lx\n", length.value(), d.length(), v);
        if (d.length() < (ssize_t)length.value() || length.value() < min_len_pn_and_payload) {
            //fprintf(stderr, "invalid\n");
            return;
        }

        // remember where aad ends
        //
        aad_end = d.data;

        payload.parse(d, length.value());

        if ((payload.is_not_empty() == false)) {
            //fprintf(stderr, "invalid\n");
            return;  // invalid or incomplete packet
        }

        // Now that the packet's extent is known, bound raw_packet to it.  It
        // was set to the whole remaining datagram on entry, because the length
        // is not known until the header has been parsed; leaving it that way
        // would make the raw_packet_data fallback dump any coalesced packets
        // that follow, rather than the one packet this record describes.
        //
        raw_packet = datum{aad_start, d.data};

        // fprintf(stderr, "VALID\n");
        valid = true;
    }

	// Min Length: header-protection samples 16 bytes at payload offset 4
	// (RFC 9001 S5.4.2), so payload >= 20; this also covers the AEAD tag.
	static constexpr size_t min_len_pn_and_payload = 20;
	static constexpr ssize_t min_len_pdu = 1184;          // TODO: determine best length bound

    bool is_not_empty() const {
        return valid;
    }

    void write_json(struct json_object &json_quic, bool =false) const {
        if (!valid) {
            return;
        }

        struct uint8_bitfield bitfield{connection_info};
        json_quic.print_key_value("connection_info", bitfield);
        json_quic.print_key_hex("version", version);
        json_quic.print_key_hex("dcid", dcid);
        json_quic.print_key_hex("scid", scid);
        json_quic.print_key_hex("token", token);
    }

    constexpr static mask_and_value<8> matcher = {
       { 0b10000000, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x00, 0x00 },
       { 0b10000000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
    };

};

class quic_parameters {
public:

    // salt_enum acts as an index for the array of salts
    //
    enum class salt_enum {
        D22      = 0,
        D23_D28  = 1,
        D29_D32  = 2,
        D33_V1   = 3,
        D1_D7_V2 = 4,
        V2       = 5
    };

    // init_pkt_mask_enum acts as an index for the array of initial pkt type masks
    //
    enum class init_pkt_mask_enum {
        D22_V1     = 0,
        V2         = 1,
    };

    // hkdf_label_enum acts as an index for the array of HKDF labels
    //
    enum class hkdf_label_enum {
        D22_V1     = 0,
        V2         = 1,
    };

    // class salt holds a salt value and the printable name associated
    // with it
    //
    class salt {
        std::array<uint8_t, 20> value;
        const char *name;

    public:

        salt(std::array<uint8_t, 20> v, const char *n) : value{v}, name{n} { }

        const uint8_t *data() const { return value.data(); }

        const char *get_name() const { return name; }
    };

    std::array<salt, 6> salts{
        salt{{0x7f,0xbc,0xdb,0x0e,0x7c,0x66,0xbb,0xe9,0x19,0x3a,0x96,0xcd,0x21,0x51,0x9e,0xbd,0x7a,0x02,0x64,0x4a}, "d22"},
        salt{{0xc3,0xee,0xf7,0x12,0xc7,0x2e,0xbb,0x5a,0x11,0xa7,0xd2,0x43,0x2b,0xb4,0x63,0x65,0xbe,0xf9,0xf5,0x02}, "d23_d28"},
        salt{{0xaf,0xbf,0xec,0x28,0x99,0x93,0xd2,0x4c,0x9e,0x97,0x86,0xf1,0x9c,0x61,0x11,0xe0,0x43,0x90,0xa8,0x99}, "d29_d32"},
        salt{{0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a}, "d33_v1"},
        salt{{0xa7,0x07,0xc2,0x03,0xa5,0x9b,0x47,0x18,0x4a,0x1d,0x62,0xca,0x57,0x04,0x06,0xea,0x7a,0xe3,0xe5,0xd3}, "d1_d7_v2"},
        salt{{0x0d,0xed,0xe3,0xde,0xf7,0x00,0xa6,0xdb,0x81,0x93,0x81,0xbe,0x6e,0x26,0x9d,0xcb,0xf9,0xbd,0x2e,0xd9}, "v2"}
    };

    // KDF labels
    constexpr static const uint8_t client_in_label_d22_v1[] = "tls13 client in";
    constexpr static const uint8_t quic_key_label_d22_v1[]  = "tls13 quic key";
    constexpr static const uint8_t quic_iv_label_d22_v1[]   = "tls13 quic iv";
    constexpr static const uint8_t quic_hp_label_d22_v1[]   = "tls13 quic hp";

    constexpr static const uint8_t client_in_label_v2[] = "tls13 client in";
    constexpr static const uint8_t quic_key_label_v2[]  = "tls13 quicv2 key";
    constexpr static const uint8_t quic_iv_label_v2[]   = "tls13 quicv2 iv";
    constexpr static const uint8_t quic_hp_label_v2[]   = "tls13 quicv2 hp";

    // class kdf_label holds the HKDF lables for the QUIC versions
    //
    class kdf_label {
        const uint8_t *client_in_label;
        const uint8_t *quic_key_label;
        const uint8_t *quic_iv_label;
        const uint8_t *quic_hp_label;
        const unsigned int client_in_label_size;
        const unsigned int quic_key_label_size;
        const unsigned int quic_iv_label_size;
        const unsigned int quic_hp_label_size;
    public:

        kdf_label(const uint8_t *client, const uint8_t *key, const uint8_t *iv, const uint8_t *hp, const unsigned int client_size, const unsigned int key_size, const unsigned int iv_size, const unsigned int hp_size) :
        client_in_label{client},
        quic_key_label{key},
        quic_iv_label{iv},
        quic_hp_label{hp},
        client_in_label_size{client_size},
        quic_key_label_size{key_size},
        quic_iv_label_size{iv_size},
        quic_hp_label_size{hp_size}
        {}

        const uint8_t* get_client_label() const { return client_in_label;}
        const uint8_t* get_key_label() const { return quic_key_label;}
        const uint8_t* get_iv_label() const { return quic_iv_label;}
        const uint8_t* get_hp_label() const { return quic_hp_label;}
        unsigned int get_client_label_size() const { return client_in_label_size;}
        unsigned int get_key_label_size() const { return quic_key_label_size;}
        unsigned int get_iv_label_size() const { return quic_iv_label_size;}
        unsigned int get_hp_label_size() const { return quic_hp_label_size;}

    };

    std::array<kdf_label, 2> kdf_labels {
        kdf_label{client_in_label_d22_v1,quic_key_label_d22_v1,quic_iv_label_d22_v1,quic_hp_label_d22_v1, sizeof(client_in_label_d22_v1),sizeof(quic_key_label_d22_v1),sizeof(quic_iv_label_d22_v1),sizeof(quic_hp_label_d22_v1)},
        kdf_label{client_in_label_v2,quic_key_label_v2,quic_iv_label_v2,quic_hp_label_v2,sizeof(client_in_label_v2),sizeof(quic_key_label_v2),sizeof(quic_iv_label_v2),sizeof(quic_hp_label_v2)},
    };

    // class init_pkt_mask_value holds the bitmask and value for initial pkt type for long header
    //

    class init_pkt_mask_value {
        const std::pair<uint8_t,uint8_t> pkt_mask_value;

    public:

        init_pkt_mask_value (uint8_t mask, uint8_t value) : pkt_mask_value{mask,value} {}

        const std::pair<uint8_t,uint8_t> *get_mask_value() const {return &pkt_mask_value;}
    };

    std::array<init_pkt_mask_value, 2> init_pkt_masks_values {
        init_pkt_mask_value{0b10110000,0b10000000},
        init_pkt_mask_value{0b10110000,0b10010000}
    };

private:

    // WARNING: this map is shared via a process-wide singleton
    // (quic_parameters::create()) and is NOT thread-safe for concurrent
    // read+write.  It is safest to treat it as immutable after construction.
    // Do not call add_param_mapping() from multi-threaded contexts.
    //
    // To re-enable runtime mutation, either:
    //   (a) guard with a std::shared_mutex (read-lock on find/iterate,
    //       write-lock on emplace), or
    //   (b) make the map thread-local (one copy per worker), or
    //   (c) use a ping-pong swap: build a new map in a background
    //       thread, then atomically swap pointers.
    //
    std::unordered_map<uint32_t, const std::tuple<salt_enum, init_pkt_mask_enum, hkdf_label_enum> > quic_initial_params;

public:

    static constexpr size_t MAX_QUIC_VERSIONS{30};  // limit memory usage

    quic_parameters() {

        quic_initial_params = std::unordered_map<uint32_t, const std::tuple<salt_enum, init_pkt_mask_enum, hkdf_label_enum>>{
            {0xfaceb001, {salt_enum::D22, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}},     // facebook
            {0xfaceb002, {salt_enum::D23_D28, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}}, // facebook
            {0xfaceb00e, {salt_enum::D23_D28, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}}, // facebook
            {0xfaceb010, {salt_enum::D23_D28, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}}, // facebook
            {0xfaceb011, {salt_enum::D23_D28, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}}, // facebook
            {0xfaceb012, {salt_enum::D23_D28, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}}, // facebook
            {0xfaceb013, {salt_enum::D23_D28, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}}, // facebook
            {0xfacefeed, {salt_enum::D33_V1, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}},  // facebook
            {0xff000016, {salt_enum::D22, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}},     // draft-22
            {0xff000017, {salt_enum::D23_D28, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}}, // draft-23
            {0xff000018, {salt_enum::D23_D28, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}}, // draft-24
            {0xff000019, {salt_enum::D23_D28, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}}, // draft-25
            {0xff00001a, {salt_enum::D23_D28, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}}, // draft-26
            {0xff00001b, {salt_enum::D23_D28, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}}, // draft-27
            {0xff00001c, {salt_enum::D23_D28, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}}, // draft-28
            {0xff00001d, {salt_enum::D29_D32, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}}, // draft-29
            {0xff00001e, {salt_enum::D29_D32, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}}, // draft-30
            {0xff00001f, {salt_enum::D29_D32, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}}, // draft-31
            {0xff000020, {salt_enum::D29_D32, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}}, // draft-32
            {0xff000021, {salt_enum::D33_V1, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}},  // draft-33
            {0xff000022, {salt_enum::D33_V1, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}},  // draft-34
            {0x00000001, {salt_enum::D33_V1, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}},  // version-1 (RFC 9000)
            {quic_version_2_draft, {salt_enum::D1_D7_V2, init_pkt_mask_enum::V2, hkdf_label_enum::V2}},  // v2-draft1_draft7
            {quic_version_2, {salt_enum::V2, init_pkt_mask_enum::V2, hkdf_label_enum::V2}},              // version-2 (RFC 9369)
            {0xd4000400, {salt_enum::D33_V1, init_pkt_mask_enum::D22_V1, hkdf_label_enum::D22_V1}},  // empirical - tencent?
        };
        quic_initial_params.reserve(MAX_QUIC_VERSIONS);
    }

    // WARNING: NOT THREAD-SAFE.  Calling this while other threads read
    // quic_initial_params is undefined behavior and has caused production
    // crashes.  Only safe in single-threaded contexts (e.g. cython offline
    // analysis).
    //
    void add_param_mapping(uint32_t version, const std::tuple<quic_parameters::salt_enum, quic_parameters::init_pkt_mask_enum, quic_parameters::hkdf_label_enum> param) {
        if (quic_initial_params.size() >= MAX_QUIC_VERSIONS) {
            return;
        }
        quic_initial_params.emplace(version, param);
    }

    const quic_parameters::salt *get_initial_salt(salt_enum salt_num) {
        return &salts[static_cast<size_t>(salt_num)];
    }

    const quic_parameters::kdf_label *get_kdf(hkdf_label_enum label_num) {
        return &kdf_labels[static_cast<size_t>(label_num)];
    }

    const quic_parameters::init_pkt_mask_value *get_init_pkt_mask_value(init_pkt_mask_enum mask_value_num) {
        return &init_pkt_masks_values[static_cast<size_t>(mask_value_num)];
    }

    const std::tuple<salt_enum, init_pkt_mask_enum, hkdf_label_enum> *get_initial_params(uint32_t version) {
        auto pair = quic_initial_params.find(version);
        if (pair != quic_initial_params.end()) {
            return &pair->second;
        } else {
            return nullptr;
        }
    }

    const std::unordered_map<uint32_t, const std::tuple<salt_enum, init_pkt_mask_enum, hkdf_label_enum> > &get_params_map() {return quic_initial_params;}

    // Returns the (mask, value) pair that identifies an Initial packet for
    // this version, or nullptr when the version is unknown.
    //
    // Long Packet Type bits are version-specific -- v2 renumbers Initial from
    // 0b00 to 0b01 -- so a caller must not assume v1's mapping.  A null return
    // means "layout unknown, do not gate", which leaves unknown and
    // experimental versions free to reach trial decryption.
    //
    const std::pair<uint8_t,uint8_t> *get_initial_pkt_mask_value(uint32_t version) {
        const std::tuple<salt_enum, init_pkt_mask_enum, hkdf_label_enum> *params = get_initial_params(version);
        if (params == nullptr) {
            return nullptr;
        }
        return get_init_pkt_mask_value(std::get<1>(*params))->get_mask_value();
    }

    static quic_parameters &create() {
        static quic_parameters quic_params;
        return quic_params;
    }
};

class quic_crypto_engine {

    crypto_engine core_crypto;

    size_t salt_length = 20;

    uint8_t quic_key[EVP_MAX_MD_SIZE] = {0};
    unsigned int quic_key_len = 0;

    uint8_t quic_iv[EVP_MAX_MD_SIZE] = {0};
    unsigned int quic_iv_len = 0;

    uint8_t quic_hp[EVP_MAX_MD_SIZE] = {0};
    unsigned int quic_hp_len = 0;

    uint8_t pn_length = 0;

    unsigned char plaintext[pt_buf_len] = {0};
    int plaintext_len = 0;   // gcm_decrypt() returns int (<= pt_buf_len)

    const char *salt_str = nullptr;
    bool quic_trial_decryption = false;

public:

    explicit quic_crypto_engine(bool quic_trial_decryption=false) : quic_trial_decryption{quic_trial_decryption} {}
    /// Attempt to decrypt a QUIC Initial packet.
    ///
    /// When quic_trial_decryption is false (the default), only the known
    /// version->salt mapping is tried.  This path is thread-safe only
    /// when there are no concurrent trial-decryption callers mutating
    /// the shared quic_initial_params map.
    ///
    /// When quic_trial_decryption is true, every known salt is tried in a
    /// brute-force loop.  On success the discovered mapping is cached
    /// via add_param_mapping(), which writes to the shared
    /// quic_initial_params map.  This is NOT thread-safe and must
    /// only be used in single-threaded contexts (e.g., cython offline
    /// analysis).
    ///
    datum decrypt(quic_initial_packet &quic_pkt) {
        if (!quic_pkt.is_not_empty()) {
            return {nullptr, nullptr};
        }

        data_buffer<1024> aad;
        // Read the 4-byte version big-endian; avoids an unaligned, strict-
        // aliasing uint32_t* load (version.data points mid-buffer at offset 1).
        uint64_t version_be = 0;
        quic_pkt.version.lookahead_uint(4, &version_be);
        uint32_t version = (uint32_t)version_be;
        // NOTE: quic_params is a process-wide singleton (initialized on
        // first use); safe for concurrent reads, but NOT for concurrent
        // reads + writes.
        //
        static quic_parameters &quic_params = quic_parameters::create();
        const std::tuple<quic_parameters::salt_enum, quic_parameters::init_pkt_mask_enum, quic_parameters::hkdf_label_enum> *params = quic_params.get_initial_params(version);

        if (params) {
            const quic_parameters::salt *initial_salt = quic_params.get_initial_salt(std::get<0>(*params));
            const std::pair<uint8_t,uint8_t> *mask_value = quic_params.get_init_pkt_mask_value(std::get<1>(*params))->get_mask_value();

            if (mask_value) {
                if ((quic_pkt.connection_info & mask_value->first) != mask_value->second) {
                    // the initial pkt bits do not match
                    quic_pkt.valid = false;
                    return {nullptr,nullptr};
                }
            }

            const uint8_t *client_in_label = (quic_params.get_kdf(std::get<2>(*params))->get_client_label());
            const uint8_t *quic_key_label  = (quic_params.get_kdf(std::get<2>(*params))->get_key_label());
            const uint8_t *quic_iv_label   = (quic_params.get_kdf(std::get<2>(*params))->get_iv_label());
            const uint8_t *quic_hp_label   = (quic_params.get_kdf(std::get<2>(*params))->get_hp_label());
            const unsigned int client_in_label_size = (quic_params.get_kdf(std::get<2>(*params))->get_client_label_size());
            const unsigned int quic_key_label_size  = (quic_params.get_kdf(std::get<2>(*params))->get_key_label_size());
            const unsigned int quic_iv_label_size   = (quic_params.get_kdf(std::get<2>(*params))->get_iv_label_size());
            const unsigned int quic_hp_label_size   = (quic_params.get_kdf(std::get<2>(*params))->get_hp_label_size());

            if (initial_salt) {
                salt_str = initial_salt->get_name();
                if (process_initial_packet(aad, quic_pkt, initial_salt->data(), client_in_label, quic_key_label, quic_iv_label, quic_hp_label,
                                            client_in_label_size, quic_key_label_size, quic_iv_label_size, quic_hp_label_size) == false) {
                    if (!quic_trial_decryption) {
                        return {nullptr, nullptr};
                    }
                    aad.reset();
                    // fall through to trial decryption
                }
                else {
                    decrypt__(aad.buffer, aad.readable_length(),
                          quic_pkt.payload.data, quic_pkt.payload.length());
                    if (plaintext_len) {
                        return {plaintext, plaintext+plaintext_len};
                    }
                    // decryption failed, fall through to trial decryption if enabled
                    if (!quic_trial_decryption) {
                        return {plaintext, plaintext+plaintext_len};
                    }
                    aad.reset();
                }
            }
            else if (!quic_trial_decryption) {
                return {nullptr, nullptr};
            }
        }
        if (quic_trial_decryption) {
            // try every salt to decrypt, most likely a version negotiation pkt
            for (const auto &params_kv : quic_params.get_params_map()) {
                const std::tuple<quic_parameters::salt_enum, quic_parameters::init_pkt_mask_enum, quic_parameters::hkdf_label_enum> param = params_kv.second;
                const quic_parameters::salt *initial_salt = quic_params.get_initial_salt(std::get<0>(param));
                const uint8_t *client_in_label = (quic_params.get_kdf(std::get<2>(param))->get_client_label());
                const uint8_t *quic_key_label  = (quic_params.get_kdf(std::get<2>(param))->get_key_label());
                const uint8_t *quic_iv_label   = (quic_params.get_kdf(std::get<2>(param))->get_iv_label());
                const uint8_t *quic_hp_label   = (quic_params.get_kdf(std::get<2>(param))->get_hp_label());
                const unsigned int client_in_label_size = (quic_params.get_kdf(std::get<2>(param))->get_client_label_size());
                const unsigned int quic_key_label_size  = (quic_params.get_kdf(std::get<2>(param))->get_key_label_size());
                const unsigned int quic_iv_label_size   = (quic_params.get_kdf(std::get<2>(param))->get_iv_label_size());
                const unsigned int quic_hp_label_size   = (quic_params.get_kdf(std::get<2>(param))->get_hp_label_size());
                if (process_initial_packet(aad, quic_pkt, initial_salt->data(), client_in_label, quic_key_label, quic_iv_label, quic_hp_label,
                                        client_in_label_size, quic_key_label_size, quic_iv_label_size, quic_hp_label_size) == false) {
                    reset_buffers();
                    aad.reset();
                    continue;
                }
                decrypt__(aad.buffer, aad.readable_length(),
                  quic_pkt.payload.data, quic_pkt.payload.length());

                if (plaintext_len) {
                    salt_str = initial_salt->get_name();
                    // WARNING: not thread-safe.  This write is only
                    // reachable when quic_trial_decryption is true, so
                    // callers must ensure single-threaded execution.
                    quic_params.add_param_mapping(version, param);
                    return {plaintext, plaintext+plaintext_len};
                }
                aad.reset();
            }
            return {nullptr, nullptr};
        }
        return {nullptr, nullptr};
    }

    void write_json(struct json_object &record) {
        record.print_key_string("salt_string", salt_str);
    }

    const char *get_salt_str() const {
        return salt_str;
    }

private:

    //bool process_initial_packet(data_buffer<1024> &aad, const quic_initial_packet &quic_pkt, const uint8_t* salt) {
    bool process_initial_packet(data_buffer<1024> &aad, const quic_initial_packet &quic_pkt, const uint8_t* salt,
                            const uint8_t *client_in_label, const uint8_t *quic_key_label, const uint8_t *quic_iv_label, const uint8_t *quic_hp_label,
                            const unsigned int client_in_label_size, const unsigned int quic_key_label_size, const unsigned int quic_iv_label_size, const unsigned int quic_hp_label_size) {
        if (!quic_pkt.is_not_empty()) {
            return false;
        }
        const uint8_t *dcid = quic_pkt.dcid.data;
        size_t dcid_len = quic_pkt.dcid.length();

        uint8_t initial_secret[EVP_MAX_MD_SIZE];
        unsigned int initial_secret_len = 0;
        HMAC(EVP_sha256(), salt, salt_length, dcid, dcid_len, initial_secret, &initial_secret_len);

        uint8_t c_initial_secret[EVP_MAX_MD_SIZE] = {0};
        unsigned int c_initial_secret_len = 0;
        core_crypto.kdf_tls13(initial_secret, initial_secret_len, client_in_label, client_in_label_size-1, 32, c_initial_secret, &c_initial_secret_len);
        core_crypto.kdf_tls13(c_initial_secret, c_initial_secret_len, quic_key_label, quic_key_label_size-1, 16, quic_key, &quic_key_len);
        core_crypto.kdf_tls13(c_initial_secret, c_initial_secret_len, quic_iv_label, quic_iv_label_size-1, 12, quic_iv, &quic_iv_len);
        core_crypto.kdf_tls13(c_initial_secret, c_initial_secret_len, quic_hp_label, quic_hp_label_size-1, 16, quic_hp, &quic_hp_len);

        // remove header protection (RFC9001, Section 5.4.1)
        //
        static constexpr size_t sample_offset = 4;
        uint8_t mask[32] = {0};
        core_crypto.ecb_encrypt(quic_hp,mask,quic_pkt.payload.data + sample_offset,16);

        uint8_t unmasked_conn_info;
        unmasked_conn_info = quic_pkt.connection_info ^ (mask[0] & 0x0f);
        /*
         * Reference from RFC 9000:
         *
         * Reserved Bits:  Two bits (those with a mask of 0x0c) of byte 0 are
         * reserved across multiple packet types.  These bits are protected
         * using header protection. The value included prior to protection MUST be
         * set to 0.  An endpoint MUST treat receipt of a packet that has a
         * non-zero value for these bits after removing both packet and header
         * protection as a connection error of type PROTOCOL_VIOLATION.
         * Discarding such a packet after only removing header protection can
         * expose the endpoint to attacks;
         *
         * Refer to RFC 9001 for details on the above mentioned attack(section 9.5)
         * https://www.rfc-editor.org/info/rfc9001
         *
         * Timing attacks are not applicable in the context of mercury
         * Hence we can safely rely on checking if the reserved bit is zero after
         * removing header protection.
         */
        if ((unmasked_conn_info & 0x0c) != 0) {
            return false;
        }

        pn_length = (unmasked_conn_info & 0x03) + 1;

        aad.copy(quic_pkt.connection_info ^ (mask[0] & 0x0f));
        aad.copy(quic_pkt.aad_start + 1, (quic_pkt.aad_end - quic_pkt.aad_start) - 1);

        // reconstruct packet number
        //
        uint32_t packet_number = 0;
        for (int i=0; i<pn_length; i++) {
            packet_number *= 256;
            packet_number += mask[i+1] ^ quic_pkt.payload.data[i];
            aad.copy(quic_pkt.payload.data[i] ^ mask[i+1]);
        }
        (void)packet_number;  // not currently used

        if (aad.is_null()) {
            return false;     // data was too long to fit into AAD buffer
        }

        // construct AEAD iv
        //
        for (uint8_t i = quic_iv_len-pn_length; i < quic_iv_len; i++) {
            quic_iv[i] ^= (mask[(i-(quic_iv_len-pn_length))+1] ^ *(quic_pkt.payload.data + (i-(quic_iv_len-pn_length))));
        }

        return true;
    }

    void reset_buffers() {
        quic_key_len = 0;
        quic_iv_len = 0;
        quic_hp_len = 0;
        pn_length = 0;
    }

    void decrypt__(const uint8_t *ad, unsigned int ad_len, const uint8_t *data, unsigned int length) {

        uint16_t cipher_len = length - pn_length;
        plaintext_len = core_crypto.gcm_decrypt(ad, ad_len, data+pn_length, cipher_len, quic_key, quic_iv, plaintext);
        if (plaintext_len == -1) {
            plaintext_len = 0;  // error; indicate that there is no plaintext in buffer
        }

        // reset buffer states after decryption
        //
        reset_buffers();
    }
};

//   Version Negotiation Packet {
//     Header Form (1) = 1,
//     Unused (7),
//     Version (32) = 0,
//     Destination Connection ID Length (8),
//     Destination Connection ID (0..2040),
//     Source Connection ID Length (8),
//     Source Connection ID (0..2040),
//     Supported Version (32) ...,
//   }
//
struct quic_version_negotiation {
    uint8_t connection_info;
    struct datum dcid;
    struct datum scid;
    struct datum version_list;
    bool valid;

    quic_version_negotiation(struct datum &d) : connection_info{0}, dcid{}, scid{}, version_list{}, valid{false} {
        parse(d);
    }

    void parse(struct datum &d) {
        d.read_uint8(&connection_info);
        if ((connection_info & 0x80) != 0x80) {
            return;
        }
        d.skip(4);  // skip version, it's 00000000

        uint8_t dcid_length = 0;
        d.read_uint8(&dcid_length);
        dcid.parse(d, dcid_length);

        uint8_t scid_length = 0;
        d.read_uint8(&scid_length);
        scid.parse(d, scid_length);

        version_list = d;  // TODO: member function to get remainder

        if ((version_list.is_not_empty() == false) || (dcid.is_not_empty() == false)) {
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

        struct uint8_bitfield bitfield{connection_info};
        o.print_key_value("connection_info", bitfield);
        o.print_key_hex("dcid", dcid);
        o.print_key_hex("scid", scid);
        json_array array{o, "versions"};
        datum tmp = version_list;
        while (tmp.is_not_empty()) {
            datum version;
            version.parse(version, 4);
            array.print_hex(version);
        }
        array.close();
    }

};

class padding {

public:
	padding(datum &) {
    }

	void write(FILE *f) {
		fprintf(f, "padding\n");
	}

private:

    // the function parse_consecutive_padding() reads consecutive padding
    // frames and reports their number; it might be handy if you want to
    // print out frames.
    //
    size_t parse_consecutive_padding(datum &d) {
        size_t pad_len = 0;
        while (true) {
            uint8_t type = 0;
            d.lookahead_uint8(&type);
            if (type != 0 || !d.is_not_empty()) {
                break;
            }
            d.skip(1);
            ++pad_len;
        }
        return pad_len;
    }
};

class ping {
public:
	ping(datum &) {}

	void write(FILE *f) {
		fprintf(f, "ping\n");
	}
};

class quic_frame {
    std::variant<std::monostate, padding, ping, ack, ack_ecn, crypto, connection_close> frame;

public:

    quic_frame(datum &d) {
        // Frame Type is a varint (RFC 9000 S12.4/S16); decode it so
        // non-minimal encodings of known types (e.g. 0x4006 CRYPTO) are kept.
        variable_length_integer type{d};
        if (d.is_null()) {
            frame.emplace<std::monostate>();   // truncated type field
        } else if (type.value() == 0x06) {
            frame.emplace<crypto>(d);
        } else if (type.value() == 0x1c) {
            frame.emplace<connection_close>(d, false);   // transport (has Frame Type)
        } else if (type.value() == 0x1d) {
            frame.emplace<connection_close>(d, true);    // application (no Frame Type)
        } else if (type.value() == 0x00) {
            frame.emplace<padding>(d);
        } else if (type.value() == 0x01) {
            frame.emplace<ping>(d);
        } else if (type.value() == 0x02) {
            frame.emplace<ack>(d);
        } else if (type.value() == 0x03) {
            frame.emplace<ack_ecn>(d);
        }
        else {
            // fprintf(stderr, "unknown frame type %02x\n", type);  // TODO: report through JSON
            frame.emplace<std::monostate>();
        }
    }

    quic_frame() : frame{} { }

    bool is_valid() const {
        return std::holds_alternative<std::monostate>(frame) == false;
    }

    template <typename T>
    bool has_type() const {
        return std::holds_alternative<T>(frame) == true;
    }

    template <typename T>
    T *get_if() {
        return std::get_if<T>(&frame);
    }

    class write_visitor {
        FILE *f_;
    public:
        write_visitor(FILE *f) : f_{f} { }

        template <typename T> void operator()(T &x) { x.write(f_); }

        void operator()(std::monostate &) { }
    };

    void write(FILE *f) {
        std::visit(write_visitor{f}, frame);
    }

    class write_json_visitor {
        json_object &o;
    public:
        write_json_visitor(json_object &json) : o{json} { }

        template <typename T> void operator()(T &x) { x.write_json(o); }

        void operator()(padding &) { }
        void operator()(ping &) { }
        void operator()(crypto &) { }
        void operator()(std::monostate &) { }
    };

    void write_json(json_object &o) {
        std::visit(write_json_visitor{o}, frame);
    }

};

// Per-frame metadata retained for CRYPTO reassembly. We deliberately do NOT
// store the frame's datum: its bytes live in a decryption buffer that later
// (coalesced) packets overwrite, so a retained datum would dangle. The bytes
// are copied into cryptographic_buffer::buffer; consumers reconstruct data
// from buffer + offset() using these lengths.
struct crypto_frame_meta {
    uint64_t frame_offset = 0;    // CRYPTO frame stream offset
    uint64_t frame_length = 0;    // declared CRYPTO Length field
    uint64_t bytes_captured = 0;  // bytes actually copied into the buffer

    uint64_t offset() const { return frame_offset; }
    uint64_t length() const { return frame_length; }
    uint64_t captured_length() const { return bytes_captured; }
};

struct cryptographic_buffer
{
    uint64_t buf_len = 0;
    static constexpr uint32_t crypto_buf_len = 8192;
    static constexpr uint32_t min_crypto_data_len = 10;   // minimum number of bytes needed to discover TLS handshake size
    unsigned char buffer[crypto_buf_len] = {}; // pt_buf_len - decryption buffer trim size for gcm_decrypt

    std::pair<uint64_t,uint64_t> min_frame {UINT64_MAX,UINT64_MAX};     // <offset,len>
    std::pair<uint64_t,uint64_t> max_frame {0,0};                       // <offset,len>
    uint32_t total_data = 0;
    static constexpr uint16_t max_frames = 20;
    static constexpr uint16_t invalid_first_frame_index = UINT16_MAX;
    crypto_frame_meta crypto_frames[max_frames];
    uint16_t crypto_frames_count = 0;
    uint16_t first_frame_index = invalid_first_frame_index;
    bool missing_crypto_frames = false;
    bool min_crypto_data = false;

    cryptographic_buffer() {}

    // returns true if the crypto frame contributed to extending the buffer
    // This function completely discards frames with even a single byte over the limit
    // to keep logic simple
    bool extend(crypto& d)
    {
        // Check for integer overflow first
        if (d.offset() > sizeof(buffer) || d.length() > sizeof(buffer)) {
            return false;  // Invalid offset or length
        }

        if (d.offset() + d.length() <= sizeof(buffer)) {
            memcpy(buffer + d.offset(), d.data().data, d.length());
            if (d.offset() + d.length() > buf_len) {
                buf_len = d.offset() + d.length();
            }
            return true;
        }
        // TODO: track segments to verify that all are present
        return false;
    }

    void update_crypto_frames (crypto *c) {
        // update min
        if (c->offset() <= min_frame.first) {
            min_frame.first = c->offset();
            min_frame.second = c->length();
        }
        // update max
        if (c->offset() >= max_frame.first) {
            max_frame.first = c->offset();
            max_frame.second = c->length();
        }
        // update total
        total_data += c->length();
        // update frame array (store metadata only; the frame's datum would
        // dangle once a later coalesced packet overwrites the decryption buffer).
        // Record first_frame_index only for frames we actually store, so it
        // never points past crypto_frames_count (avoids OOB in consumers).
        if (crypto_frames_count < max_frames) {
            if (c->offset() == 0) {
                first_frame_index = crypto_frames_count;
            }
            crypto_frames[crypto_frames_count] = crypto_frame_meta{c->offset(), c->length(), (uint64_t)c->data().length()};
            crypto_frames_count++;
        }
    }

    void check_missing_crypto_frames () {
        if (total_data != (max_frame.first + max_frame.second - min_frame.first) ) {
            // soomething messed up in crypto frames ordering
            missing_crypto_frames = true;
        }
    }

    bool is_valid()
    {
        return buf_len > 0;
    }

    bool has_first_frame() const {
        return first_frame_index != invalid_first_frame_index &&
               first_frame_index < crypto_frames_count;
    }

    void reset() {
        buf_len = 0;
        min_frame = {UINT64_MAX,UINT64_MAX};
        max_frame = {0,0};
        total_data = 0;
        crypto_frames_count = 0;
        first_frame_index = invalid_first_frame_index;
        missing_crypto_frames = false;
        min_crypto_data = false;
    }
};

struct quic_hdr_fp {
    const datum &version;

    quic_hdr_fp(const datum &version_) : version{version_} {};

    void fingerprint(struct buffer_stream &buf) const {
        //add version
        //
        buf.write_char('(');
        buf.raw_as_hex(version.data, version.length());
        buf.write_char(')');
    }
};

// quic_client_hello represents the tls client hello in a quic_init;
// it is defined so that we can specialize the fingerprinting function
//
class quic_client_hello : public tls_client_hello {
public:
    void fingerprint(struct buffer_stream &buf, size_t format_version) const {
        if (is_not_empty() == false) {
            return;
        }

        /*
         * copy clientHello.ProtocolVersion
         */
        buf.write_char('(');
        buf.raw_as_hex(protocol_version.data, protocol_version.length());
        buf.write_char(')');

        /* copy ciphersuite offer vector */
        buf.write_char('(');
        raw_as_hex_degrease(buf, ciphersuite_vector.data, ciphersuite_vector.length());
        buf.write_char(')');

        /*
         * copy extensions vector
         */
        if (format_version == 1) {
            extensions.fingerprint_format2(buf, tls_role::client);
        } else {
            extensions.fingerprint_quic_tls(buf, tls_role::client);
        }
    }
};

// class quic_init_decry represents an initial quic message which is already decrypted
//
class quic_init_decry {
    const quic_initial_packet &initial_packet;
    cryptographic_buffer &crypto_buffer;
    quic_client_hello hello;
    datum plaintext;
    bool valid;
    // We report at most one ACK/ACK_ECN and one CONNECTION_CLOSE per packet,
    // the first of each seen, under distinct JSON keys.
    quic_frame ack_frame;   // first ACK / ACK_ECN frame
    quic_frame close;       // first CONNECTION_CLOSE frame
    uint8_t pkt_num_len;
    uint32_t more_bytes_needed;
    uint32_t min_crypto_offset;

public:
    quic_init_decry (quic_initial_packet &pkt, cryptographic_buffer& buffer) : initial_packet{pkt}, crypto_buffer{buffer}, hello{}, plaintext{}, valid{false}, ack_frame{}, close{}, pkt_num_len{0}, more_bytes_needed{0}, min_crypto_offset{UINT32_MAX} {}

    void parse() {
        if (!initial_packet.is_not_empty()) {
            return;
        }

        pkt_num_len = (initial_packet.connection_info & 0x03) + 1;
        plaintext = datum{initial_packet.payload.data + pkt_num_len, initial_packet.payload.data_end};

        // parse plaintext as a sequence of frames
        //
        datum plaintext_copy = plaintext;
        while (plaintext_copy.is_not_empty()) {
            quic_frame frame{plaintext_copy};
            //frame.write(stderr);
            if (!frame.is_valid() || plaintext_copy.is_null()) {
                valid = false;
                return;
            }

            crypto *c = frame.get_if<crypto>();
            if (c && c->is_valid()) {
                if (crypto_buffer.extend(*c)) {
                    crypto_buffer.update_crypto_frames(c);
                    // update min offset
                    if (c->offset() <= min_crypto_offset)
                        min_crypto_offset = (uint32_t)c->offset();
                }
            }
            if (frame.has_type<connection_close>()) {
                if (!close.is_valid()) {
                    close = frame;   // keep first close
                }
            } else if (frame.has_type<ack>() || frame.has_type<ack_ecn>()) {
                if (!ack_frame.is_valid()) {
                    ack_frame = frame;   // keep first ack
                }
            }
        }
        valid = true;
        if(crypto_buffer.is_valid()){
            crypto_buffer.check_missing_crypto_frames();

            if (!crypto_buffer.missing_crypto_frames) {
                struct datum d{crypto_buffer.buffer, crypto_buffer.buffer + crypto_buffer.buf_len};
                tls_handshake tls{d};
                more_bytes_needed = tls.additional_bytes_needed;
                hello.parse(tls.body);
                hello.is_quic_hello = true;
            }
            else {
                // some frames might be missing. Two possibilities:
                // 1. min crypto offset is 0, parse the first frame as tls handshake. Ideally the first frame should be big
                // enough to figure out total bytes needed.
                // 2. min crypto offset > 0. Pass on all the frames for reassembly
                if (!crypto_buffer.has_first_frame()) {
                    return;
                }
                if (crypto_buffer.crypto_frames[crypto_buffer.first_frame_index].captured_length() < 10) {
                    // directly pick first 10 bytes from buffer
                    crypto_buffer.min_crypto_data = true;
                    struct datum d{crypto_buffer.buffer, crypto_buffer.buffer + 10};
                    tls_handshake tls{d};
                    more_bytes_needed = tls.additional_bytes_needed;
                    hello.parse(tls.body);
                    hello.is_quic_hello = true;
                }
                else {
                    // Read the frame from the owned crypto_buffer (extend copied
                    // it there); the engine's plaintext buffer may have been
                    // overwritten by a coalesced packet's decryption.
                    const crypto_frame_meta &f = crypto_buffer.crypto_frames[crypto_buffer.first_frame_index];
                    uint64_t f_off = f.offset();
                    uint64_t f_len = f.captured_length();   // bytes actually copied into the buffer
                    if (f_off + f_len > crypto_buffer.buf_len) {
                        return;   // inconsistent offsets; avoid reading past the buffer
                    }
                    struct datum d{crypto_buffer.buffer + f_off,
                                   crypto_buffer.buffer + f_off + f_len};
                    tls_handshake tls{d};
                    more_bytes_needed = tls.additional_bytes_needed;
                    hello.parse(tls.body);
                    hello.is_quic_hello = true;
                }
            }
        }
    }

    bool is_valid() {return valid;}

    bool hello_is_not_empty() const {return hello.is_not_empty();}

    const quic_client_hello &get_tls_client_hello() const {return hello;}

    void write_json(struct json_object &record, bool metadata_output=false) {
        if (hello.is_not_empty()) {
            hello.write_json(record, metadata_output);
        }
        json_object quic_record{record, "quic"};
        initial_packet.write_json(quic_record);
        if (close.is_valid()) {
            close.write_json(quic_record);
        }
        if (ack_frame.is_valid()) {
            ack_frame.write_json(quic_record);
        }
        if (plaintext.is_not_empty()) {
            quic_record.print_key_hex("plaintext", plaintext);
        } else {
            quic_record.print_key_hex("raw_packet_data", initial_packet.raw_packet);
        }
        quic_record.close();
    }

    void compute_fingerprint(class fingerprint &fp) const {
        if (hello.is_not_empty()) {
            fp.set_type(fingerprint_type_quic);
            quic_hdr_fp hdr_fp(initial_packet.version);
            fp.add(hdr_fp);
            fp.add(hello, 0); // note: using quic format=0
            fp.final();
        }
    }

    bool do_analysis(const struct key &k_, struct analysis_context &analysis_, classifier *c_) {
        struct datum sn{NULL, NULL};
        struct datum user_agent {NULL, NULL};
        datum alpn;

        hello.extensions.set_meta_data(sn, user_agent, alpn);
        analysis_.destination.init(sn, user_agent, alpn, k_);

        if (c_ == nullptr) {
            return false;
        }

        bool ret = c_->analyze_fingerprint_and_destination_context(analysis_);

        // QUIC FakeTLS detection - re-enable when suffcient data is available
        //
        // if (analysis_.result.status == fingerprint_status_randomized) {    // check for faketls on randomized connections only
        //     if (!analysis_.result.attr.is_initialized() && c_) {
        //         analysis_.result.attr.initialize(&(c_->get_common_data().attr_name.value()),c_->get_common_data().attr_name.get_names_char());
        //     }
        //     if (hello.is_faketls()) {
        //         analysis_.result.attr.set_attr(c_->get_common_data().faketls_idx, 1.0);
        //     }
        // }

        return ret;
    }

    uint32_t get_more_bytes_needed() const { return more_bytes_needed; }
    uint32_t get_min_crypto_offset() const { return min_crypto_offset; }
};

// class quic_init represents an initial quic message
//
class quic_init : public base_protocol {
    quic_initial_packet initial_packet;
    quic_crypto_engine &quic_crypto;
    cryptographic_buffer crypto_buffer;
    quic_client_hello hello;
    datum plaintext;
    // We report at most one ACK/ACK_ECN and one CONNECTION_CLOSE, the first of
    // each seen in the last decrypted packet, under distinct JSON keys.
    quic_frame ack_frame;   // first ACK / ACK_ECN frame
    quic_frame close;       // first CONNECTION_CLOSE frame
    quic_init_decry decry_pkt;
    bool pre_decrypted;
    uint32_t more_bytes_needed;
    uint32_t min_crypto_offset;

    // Coalesced-packet handling (RFC 9000 S12.2): cap decrypt attempts per
    // datagram to bound work (DoS); further Initials are counted, not decrypted.
    static constexpr uint32_t max_decrypt_pkts = 3;
    // Hard cap on total coalesced packets examined per datagram (defense in
    // depth); bounds the skip/count loop even if packets keep parsing.
    static constexpr uint32_t max_coalesced_pkts = 8;
    uint32_t decrypt_attempts = 0;        // decrypt() calls made (bounds DoS)
    uint32_t decrypted_pkt_count = 0;     // decrypt() calls that produced plaintext
    uint32_t failed_decrypt_count = 0;    // decrypt() calls that returned empty
    uint32_t undecrypted_pkt_count = 0;   // coalesced Initials skipped past the cap
    uint32_t total_frame_count = 0;       // non-PADDING frames across decrypted packets
    uint32_t total_padding_count = 0;     // PADDING frames (one per padding byte)

    // Harvest one decrypted packet: merge CRYPTO into crypto_buffer, count
    // frames, and capture the first CONNECTION_CLOSE and ACK.  CRYPTO bytes
    // are copied into crypto_buffer as we go, so they outlive the packet.
    //
    // close and ack_frame have different lifetimes:
    //
    //   - connection_close holds a datum for the reason phrase, pointing into
    //     the engine's decryption buffer.  Every decrypt attempt overwrites
    //     that buffer, including a failed one: gcm_decrypt() writes the
    //     unauthenticated plaintext with EVP_DecryptUpdate() before
    //     EVP_DecryptFinal_ex() checks the tag.  We therefore reset close on
    //     every call and report only the packet whose plaintext is still live
    //     at write_json, rather than a reason phrase that has been clobbered.
    //
    //   - ack / ack_ecn decode into variable-length integers held by value,
    //     so they stay valid across buffer reuse.  ack_frame is not reset:
    //     the first ACK seen anywhere in the datagram is reported.
    //
    void harvest_frames(datum pt) {
        close = quic_frame{};
        datum plaintext_copy = pt;
        while (plaintext_copy.is_not_empty()) {
            quic_frame frame{plaintext_copy};
            if (!frame.is_valid()) {
                break;
            }
            // PADDING is one frame per 0x00 byte and dominates the count; track
            // it separately so total_frame_count reflects meaningful frames.
            if (frame.has_type<padding>()) {
                total_padding_count++;
            } else {
                total_frame_count++;
            }

            crypto *c = frame.get_if<crypto>();
            if (c && c->is_valid()) {
                if (crypto_buffer.extend(*c)) {
                    crypto_buffer.update_crypto_frames(c);
                    if (c->offset() <= min_crypto_offset)
                        min_crypto_offset = (uint32_t)c->offset();
                }
            }
            if (frame.has_type<connection_close>()) {
                if (!close.is_valid()) {
                    close = frame;   // keep first close
                }
            } else if (frame.has_type<ack>() || frame.has_type<ack_ecn>()) {
                if (!ack_frame.is_valid()) {
                    ack_frame = frame;   // keep first ack
                }
            }
        }
    }

    // true if other belongs to the same connection as the first packet,
    // that is, it carries the same QUIC version and the same Destination
    // Connection ID.
    //
    // RFC 9000 Section 12.2 requires every packet coalesced into a datagram
    // to carry the same DCID, and Initial keys are derived from the DCID of
    // the packet itself.  Without the DCID check an appended Initial from a
    // different connection decrypts successfully and its offset-0 CRYPTO
    // frame overwrites the ClientHello of the first packet, while the record
    // still reports the first packet's dcid.
    //
    bool same_connection(const quic_initial_packet &other) const {
        datum va = initial_packet.version;
        datum vb = other.version;
        if (va.is_null() || vb.is_null()) {
            return false;
        }
        uint64_t a = 0, b = 0;
        va.lookahead_uint(4, &a);
        vb.lookahead_uint(4, &b);
        if (a != b) {
            return false;
        }
        return initial_packet.dcid == other.dcid;
    }

public:

    quic_init(struct datum &d, quic_crypto_engine &quic_crypto_) : initial_packet{d}, quic_crypto{quic_crypto_}, crypto_buffer{}, hello{}, plaintext{}, decry_pkt{initial_packet,crypto_buffer}, pre_decrypted{false}, more_bytes_needed{0}, min_crypto_offset{UINT32_MAX} {

        // Reject non-Initial long-header packets: only an Initial carries a
        // Token field and the ClientHello, so parsing a 0-RTT, Handshake or
        // Retry packet Initial-style produces a forged record.
        //
        // The Long Packet Type encoding is version-specific, so take the
        // mask from quic_parameters rather than assuming v1's mapping.  An
        // unknown version yields no mask and is left ungated, so it still
        // reaches trial decryption.  decrypt() applies the same mask, but
        // only for packets that get that far -- the pre-decrypted path below
        // returns first -- so the check is made here as well.
        //
        static quic_parameters &quic_params = quic_parameters::create();
        uint64_t version_value = 0;
        initial_packet.version.lookahead_uint(4, &version_value);
        const std::pair<uint8_t,uint8_t> *mask_value =
            quic_params.get_initial_pkt_mask_value((uint32_t)version_value);
        if (mask_value != nullptr &&
            (initial_packet.connection_info & mask_value->first) != mask_value->second) {
            initial_packet.valid = false;
            return;
        }

        // check reserved bits, if 0, try for decrypted quic packet
        //
        // The reserved bits are header-protected in a genuine Initial, so
        // this heuristic runs on attacker-influenced input: a malformed first
        // packet whose protected bytes happen to parse as PADDING would be
        // accepted as cleartext.  Require that nothing follows in the
        // datagram, so a crafted first packet cannot suppress a valid
        // coalesced Initial behind it.  Genuine pre-decrypted input is a
        // single packet, so this does not narrow the intended use.
        //
        if ((initial_packet.connection_info & 0x0c) == 0) {
            decry_pkt.parse();
            if (decry_pkt.is_valid() && d.is_empty()) {
                pre_decrypted = true;
                return;
            }
        }

        // reset crypto buffer
        //
        crypto_buffer.reset();

        // Decrypt the first Initial. plaintext points at the engine buffer
        // (holds the last decrypted packet, valid until write_json); a failed
        // decrypt is a no-op in harvest and does not abort coalesced processing.
        plaintext = quic_crypto.decrypt(initial_packet);
        harvest_frames(plaintext);
        decrypt_attempts = 1;
        if (plaintext.is_not_empty()) { decrypted_pkt_count++; } else { failed_decrypt_count++; }

        // Process coalesced Initial packets in the same datagram: decrypt up to
        // max_decrypt_pkts total, then count any remaining without decrypting.
        // Cap total iterations (max_coalesced_pkts) for defense in depth.
        datum coalesced = d;   // d has advanced past the first Initial
        uint32_t examined = 1;
        // Only walk coalesced packets when the first Initial parsed; otherwise
        // its version datum is null and same_connection has nothing to compare.
        while (initial_packet.is_not_empty() && coalesced.is_not_empty() && examined < max_coalesced_pkts) {
            quic_initial_packet next{coalesced, false};   // coalesced packets may be < datagram min
            if (!next.is_not_empty() || !same_connection(next)) {
                break;
            }
            examined++;
            if (decrypt_attempts < max_decrypt_pkts) {
                plaintext = quic_crypto.decrypt(next);
                harvest_frames(plaintext);
                decrypt_attempts++;
                if (plaintext.is_not_empty()) { decrypted_pkt_count++; } else { failed_decrypt_count++; }
            } else {
                undecrypted_pkt_count++;
            }
        }

        if(crypto_buffer.is_valid()){
            crypto_buffer.check_missing_crypto_frames();

            if (!crypto_buffer.missing_crypto_frames) {
                struct datum d{crypto_buffer.buffer, crypto_buffer.buffer + crypto_buffer.buf_len};
                tls_handshake tls{d};
                more_bytes_needed = tls.additional_bytes_needed;
                hello.parse(tls.body);
                hello.is_quic_hello = true;
            }
            else {
                // some frames might be missing. Two possibilities:
                // 1. min crypto offset is 0, parse the first frame as tls handshake. Ideally the first frame should be big
                // enough to figure out total bytes needed.
                // 2. min crypto offset > 0. Pass on all the frames for reassembly
                if (!crypto_buffer.has_first_frame()) {
                    return;
                }
                if (crypto_buffer.crypto_frames[crypto_buffer.first_frame_index].captured_length() < 10) {
                    // directly pick first 10 bytes from buffer
                    crypto_buffer.min_crypto_data = true;
                    struct datum d{crypto_buffer.buffer, crypto_buffer.buffer + 10};
                    tls_handshake tls{d};
                    more_bytes_needed = tls.additional_bytes_needed;
                    hello.parse(tls.body);
                    hello.is_quic_hello = true;
                }
                else {
                    // Read the frame from the owned crypto_buffer (extend copied
                    // it there); the engine's plaintext buffer may have been
                    // overwritten by a coalesced packet's decryption.
                    const crypto_frame_meta &f = crypto_buffer.crypto_frames[crypto_buffer.first_frame_index];
                    uint64_t f_off = f.offset();
                    uint64_t f_len = f.captured_length();   // bytes actually copied into the buffer
                    if (f_off + f_len > crypto_buffer.buf_len) {
                        return;   // inconsistent offsets; avoid reading past the buffer
                    }
                    struct datum d{crypto_buffer.buffer + f_off,
                                   crypto_buffer.buffer + f_off + f_len};
                    tls_handshake tls{d};
                    more_bytes_needed = tls.additional_bytes_needed;
                    hello.parse(tls.body);
                    hello.is_quic_hello = true;
                }
            }
        }
    }

    void reparse_crypto_buf(datum crypto_buf) {
            tls_handshake tls{crypto_buf};
            hello.parse(tls.body);
            more_bytes_needed = tls.additional_bytes_needed;
            hello.is_quic_hello = true;
    }

    const uint8_t *get_crypto_buf (uint32_t *buf_len) const {
        uint32_t offset = pre_decrypted ? decry_pkt.get_min_crypto_offset() : min_crypto_offset;
        if (!crypto_buffer.buf_len || offset == UINT32_MAX || offset > crypto_buffer.buf_len) {
            *buf_len = 0;
        }
        else {
            *buf_len = crypto_buffer.buf_len - offset;
        }
        return (const uint8_t*)crypto_buffer.buffer;
    }

    const datum &get_cid() const {
        // return first non empty cid in order dcid, scid
        if (initial_packet.dcid.is_not_empty())
            return initial_packet.dcid;
        else
            return initial_packet.scid;
    }

    // bool cid_matches (datum cid) const {
    //     return cid == initial_packet.scid;
    // }

    bool is_not_empty() {
        return initial_packet.is_not_empty();
        //return plaintext.is_not_empty();
    }

    uint32_t additional_bytes_needed() const {
        return (pre_decrypted ? (decry_pkt.get_more_bytes_needed()) : more_bytes_needed);
    }

    bool missing_crypto_frames() const {
        return crypto_buffer.missing_crypto_frames;
    }

    const crypto_frame_meta *get_crypto_frames(uint16_t &frame_count, uint16_t &first_frame_idx) const {
        frame_count = crypto_buffer.crypto_frames_count;
        first_frame_idx = crypto_buffer.first_frame_index;
        return crypto_buffer.crypto_frames;
    }

    bool min_crypto_data() { return crypto_buffer.min_crypto_data; }

    uint32_t get_min_crypto_offset() const {
        return (pre_decrypted ? (decry_pkt.get_min_crypto_offset()) : min_crypto_offset);
    }

    bool has_tls() const {
        if (pre_decrypted) {
            return decry_pkt.hello_is_not_empty();
        }
        return hello.is_not_empty();
    }

    const quic_client_hello &get_tls_client_hello() const {
        if (pre_decrypted) {
            return decry_pkt.get_tls_client_hello();
        }
        return hello;
    }

    void write_json(struct json_object &record, bool metadata_output=false) {
        if(pre_decrypted) {
            decry_pkt.write_json(record,metadata_output);
            return;
        }

        if (hello.is_not_empty()) {
            hello.write_json(record, metadata_output);
        }
        json_object quic_record{record, "quic"};
        initial_packet.write_json(quic_record);
        // Coalesced-datagram telemetry (RFC 9000 S12.2): extra metadata, emitted
        // only under the metadata flag when the datagram held >1 QUIC packet.
        if (metadata_output && (decrypt_attempts + undecrypted_pkt_count > 1)) {
            quic_record.print_key_uint("decrypted_packets", decrypted_pkt_count);
            if (failed_decrypt_count > 0) {
                quic_record.print_key_uint("decrypt_failures", failed_decrypt_count);
            }
            if (undecrypted_pkt_count > 0) {
                quic_record.print_key_uint("undecrypted_packets", undecrypted_pkt_count);
            }
            quic_record.print_key_uint("decrypted_frames", total_frame_count);
            quic_record.print_key_uint("padding_frames", total_padding_count);
        }
        if (close.is_valid()) {
            close.write_json(quic_record);
        }
        if (ack_frame.is_valid()) {
            ack_frame.write_json(quic_record);
        }
        if (plaintext.is_not_empty()) {
            quic_crypto.write_json(quic_record);
            quic_record.print_key_hex("plaintext", plaintext);
        } else if (decrypted_pkt_count == 0) {
            // Report the undecrypted bytes only when nothing in the datagram
            // decrypted.  plaintext tracks the most recent attempt, so a
            // datagram whose trailing packet failed would otherwise claim
            // that no packet was readable.
            quic_record.print_key_hex("raw_packet_data", initial_packet.raw_packet);
        }
        // json_object frame_dump{record, "frame_dump"};
        // datum plaintext_copy = plaintext;
        // while (plaintext_copy.is_not_empty()) {
        //     quic_frame frame{plaintext_copy};
        //     frame.write_json(frame_dump);
        // }
        // frame_dump.close();
        quic_record.close();
    }

    void write_l7_metadata(cbor_object &o, bool) {
        cbor_array protocols{o, "protocols"};
        protocols.print_string("quic");
        protocols.close();

        if (hello.is_not_empty()) {
            hello.write_l7_metadata_detail(o);
        }
    }

    void compute_fingerprint(class fingerprint &fp, size_t format_version) const {

        // fingerprint format:  quic:(quic_version)(tls fingerprint)
        //
        // TODO: do we want to report anything if !hello.is_not_empty() ?

        if(pre_decrypted) {
            decry_pkt.compute_fingerprint(fp);
            return;
        }

        if (hello.is_not_empty()) {
            fp.set_type(fingerprint_type_quic, format_version);
            quic_hdr_fp hdr_fp(initial_packet.version);
            fp.add(hdr_fp);
            fp.add(hello, format_version);
            fp.final();
        }
    }

    bool do_analysis(const struct key &k_, struct analysis_context &analysis_, classifier *c_) {
        if(pre_decrypted) {
            return decry_pkt.do_analysis(k_, analysis_, c_);
        }

        struct datum sn{NULL, NULL};
        struct datum user_agent {NULL, NULL};
        datum alpn;

        hello.extensions.set_meta_data(sn, user_agent, alpn);
        analysis_.destination.init(sn, user_agent, alpn, k_);

        if (c_ == nullptr) {
            return false;
        }

        bool ret = c_->analyze_fingerprint_and_destination_context(analysis_);

        // QUIC FakeTLS detection - re-enable when suffcient data is available
        //
        // if (analysis_.result.status == fingerprint_status_randomized) {    // check for faketls on randomized connections only
        //     if (!analysis_.result.attr.is_initialized() && c_) {
        //         analysis_.result.attr.initialize(&(c_->get_common_data().attr_name.value()),c_->get_common_data().attr_name.get_names_char());
        //     }
        //     if (hello.is_faketls()) {
        //         analysis_.result.attr.set_attr(c_->get_common_data().faketls_idx, 1.0);
        //     }
        // }

        return ret;
    }
};

namespace {

    /// \brief Adapter that lets json_output_fuzzer exercise quic_init.
    ///
    /// quic_init needs a quic_crypto_engine reference in addition to the
    /// fuzzed datum, while json_output_fuzzer<T> constructs T from only a
    /// datum &.  This wrapper owns the crypto engine for the lifetime of the
    /// quic_init instance and forwards JSON output to the real parser.
    ///
    class quic_init_json_output {
        quic_crypto_engine quic_crypto;
        quic_init quic_pkt;

    public:

        quic_init_json_output(datum &d) :
            quic_crypto{},
            quic_pkt{d, quic_crypto}
        { }

        void write_json(struct json_object &record, bool metadata_output) {
            if (quic_pkt.is_not_empty()) {
                quic_pkt.write_json(record, metadata_output);
            }
        }
    };

    [[maybe_unused]] inline int quic_init_fuzz_test(const uint8_t *data, size_t size) {
        return json_output_fuzzer<quic_init_json_output>(data, size);
    }

}; //end of namespace

/// Attempt trial decryption on raw QUIC Initial packet bytes and return
/// the salt name that successfully decrypted the packet.
///
/// @param data pointer to raw QUIC Initial packet bytes (starting from connection_info byte)
/// @param len  length of the packet data
/// @return     salt name string if decryption succeeded, nullptr otherwise
///
/// WARNING: This function is NOT thread-safe because it mutates the
/// process-wide quic_parameters singleton on successful decryption.
/// Only use in single-threaded contexts.
///
inline const char *quic_trial_decrypt_get_salt(const uint8_t *data, size_t len) {
    if (data == nullptr || len == 0) {
        return nullptr;
    }
    datum d{data, data + len};
    static quic_crypto_engine crypto{true};  // enable trial decryption
    quic_initial_packet pkt{d};
    if (!pkt.is_not_empty()) {
        return nullptr;
    }
    datum plaintext = crypto.decrypt(pkt);
    if (plaintext.is_not_empty()) {
        return crypto.get_salt_str();
    }
    return nullptr;
}

#ifndef NDEBUG
// LCOV_EXCL_START
namespace quic_packet_safety_unit_test {

    static constexpr size_t quic_initial_packet_len = static_cast<size_t>(quic_initial_packet::min_len_pdu);

    inline bool is_aligned_to(const void *ptr, size_t alignment) {
        return reinterpret_cast<std::uintptr_t>(ptr) % alignment == 0;
    }

    template <size_t StorageSize, size_t PacketSize>
    inline const uint8_t *copy_with_unaligned_field(std::array<uint8_t, StorageSize> &storage,
                                                    const std::array<uint8_t, PacketSize> &packet,
                                                    size_t field_offset,
                                                    size_t alignment) {
        if (alignment <= 1 || field_offset >= packet.size() || packet.size() + alignment > storage.size()) {
            return nullptr;
        }

        for (size_t offset = 1; offset <= alignment; offset++) {
            uint8_t *candidate = storage.data() + offset;
            if (!is_aligned_to(candidate + field_offset, alignment)) {
                storage.fill(0);
                for (size_t i = 0; i < packet.size(); i++) {
                    candidate[i] = packet[i];
                }
                return candidate;
            }
        }
        return nullptr;
    }

    inline std::array<uint8_t, quic_initial_packet_len> make_quic_initial() {
        std::array<uint8_t, quic_initial_packet_len> packet{};

        packet[0] = 0xc0;      // long-header Initial
        packet[4] = 0x01;      // version 1
        packet[5] = 0x08;      // DCID length
        for (size_t i = 0; i < 8; i++) {
            packet[6 + i] = static_cast<uint8_t>(i + 1);
        }
        packet[14] = 0x00;     // SCID length
        packet[15] = 0x00;     // token length
        packet[16] = 0x40;     // protected payload length 64
        packet[17] = 0x40;

        return packet;
    }

    // number of bytes a packet written by write_initial() occupies
    static constexpr size_t initial_pkt_len = 18 + 64;   // header + payload

    // Writes a minimal long-header Initial into buf: version 1, an 8-byte
    // Destination Connection ID of repeated dcid_byte, and a 64-byte payload.
    // conn_info selects the first octet, so callers can set the reserved bits
    // to steer the packet away from the pre-decrypted fast path.  Returns the
    // number of bytes written, so coalesced packets can be appended.
    //
    inline size_t write_initial(uint8_t *buf, uint8_t dcid_byte, uint8_t conn_info = 0xc8) {
        buf[0] = conn_info;
        buf[1] = 0x00;
        buf[2] = 0x00;
        buf[3] = 0x00;
        buf[4] = 0x01;         // version 1
        buf[5] = 0x08;         // DCID length
        for (size_t i = 0; i < 8; i++) {
            buf[6 + i] = dcid_byte;
        }
        buf[14] = 0x00;        // SCID length
        buf[15] = 0x00;        // token length
        buf[16] = 0x40;        // protected payload length 64 (2-byte varint)
        buf[17] = 0x40;
        return initial_pkt_len;
    }

    inline bool initial_version_decode_unit_test() {
        static constexpr size_t version_offset = 1;
        auto packet = make_quic_initial();
        std::array<uint8_t, quic_initial_packet_len + alignof(uint32_t)> storage{};

        const uint8_t *data = copy_with_unaligned_field(storage,
                                                        packet,
                                                        version_offset,
                                                        alignof(uint32_t));
        if (data == nullptr) {
            return false;
        }

        datum d{data, data + packet.size()};
        quic_initial_packet initial{d};
        if (!initial.is_not_empty()) {
            return false;
        }

        quic_crypto_engine crypto{};
        datum plaintext = crypto.decrypt(initial);
        (void)plaintext;
        return true;
    }

    // Known frame types with non-minimal varint encoding must still parse.
    inline bool frame_type_varint_unit_test() {
        static const uint8_t crypto_data[5] = {0xde, 0xad, 0xbe, 0xef, 0x01};

        auto parse_crypto = [](const uint8_t *buf, size_t len) -> bool {
            datum d{buf, buf + len};
            quic_frame f{d};
            if (!f.is_valid() || !f.has_type<crypto>()) {
                return false;
            }
            crypto *c = f.get_if<crypto>();
            if (c == nullptr || !c->is_valid()) {
                return false;
            }
            if (c->offset() != 0 || c->length() != sizeof(crypto_data)) {
                return false;
            }
            datum &cd = c->data();
            if (cd.length() != (ssize_t)sizeof(crypto_data)) {
                return false;
            }
            for (size_t i = 0; i < sizeof(crypto_data); i++) {
                if (cd.data[i] != crypto_data[i]) {
                    return false;
                }
            }
            return true;
        };

        // CRYPTO body: type, Offset (0), Length (5), Data. Type in 1/2/4 bytes.
        static const uint8_t crypto_1b[] = {0x06, 0x00, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x01};
        if (!parse_crypto(crypto_1b, sizeof(crypto_1b))) {
            return false;
        }
        static const uint8_t crypto_2b[] = {0x40, 0x06, 0x00, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x01};
        if (!parse_crypto(crypto_2b, sizeof(crypto_2b))) {
            return false;
        }
        static const uint8_t crypto_4b[] = {0x80, 0x00, 0x00, 0x06, 0x00, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x01};
        if (!parse_crypto(crypto_4b, sizeof(crypto_4b))) {
            return false;
        }

        // non-minimal PING (0x4001)
        {
            static const uint8_t ping_2b[] = {0x40, 0x01};
            datum d{ping_2b, ping_2b + sizeof(ping_2b)};
            quic_frame f{d};
            if (!f.is_valid() || !f.has_type<ping>()) {
                return false;
            }
        }

        // CONNECTION_CLOSE transport 0x1c: Error Code, Frame Type, Reason.
        {
            static const uint8_t cc_1c[] = {0x1c, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63};
            datum d{cc_1c, cc_1c + sizeof(cc_1c)};
            quic_frame f{d};
            if (!f.is_valid() || !f.has_type<connection_close>() || d.is_not_empty()) {
                return false;
            }
        }

        // CONNECTION_CLOSE application 0x1d: Error Code, Reason (no Frame Type).
        {
            static const uint8_t cc_1d[] = {0x1d, 0x00, 0x03, 0x61, 0x62, 0x63};
            datum d{cc_1d, cc_1d + sizeof(cc_1d)};
            quic_frame f{d};
            if (!f.is_valid() || !f.has_type<connection_close>() || d.is_not_empty()) {
                return false;
            }
        }

        // truncated type -> invalid
        {
            static const uint8_t trunc[] = {0x40};
            datum d{trunc, trunc + sizeof(trunc)};
            quic_frame f{d};
            if (f.is_valid()) {
                return false;
            }
        }

        return true;
    }

    // Only Initial packets are accepted; other long-header types are
    // rejected.  The Long Packet Type mapping is taken from quic_parameters,
    // so v2's renumbering is honoured and an unknown version -- whose header
    // layout we cannot assume -- is left ungated for trial decryption.
    inline bool initial_packet_type_gate_unit_test() {
        auto build = [](uint8_t conn_info, uint32_t version) {
            auto packet = make_quic_initial();
            packet[0] = conn_info;
            packet[1] = (uint8_t)(version >> 24);
            packet[2] = (uint8_t)(version >> 16);
            packet[3] = (uint8_t)(version >> 8);
            packet[4] = (uint8_t)version;
            return packet;
        };
        auto parses = [](std::array<uint8_t, quic_initial_packet_len> &packet) {
            datum d{packet.data(), packet.data() + packet.size()};
            quic_crypto_engine engine{};
            quic_init quic{d, engine};
            return quic.is_not_empty();
        };

        struct { uint8_t conn_info; uint32_t version; bool expect_initial; } cases[] = {
            {0xc0, 0x00000001, true},   // v1 Initial (type 0b00)
            {0xd0, 0x00000001, false},  // v1 0-RTT
            {0xe0, 0x00000001, false},  // v1 Handshake
            {0xf0, 0x00000001, false},  // v1 Retry
            {0xd0, 0x6b3343cf, true},   // v2 Initial (type 0b01)
            {0xc0, 0x6b3343cf, false},  // v2 Retry (type 0b00)
            {0xd0, 0xdeadbeef, true},   // unknown version: layout unknown, not gated
            {0xe0, 0xdeadbeef, true},   // likewise; trial decryption decides
        };
        for (auto &c : cases) {
            auto p = build(c.conn_info, c.version);
            if (parses(p) != c.expect_initial) {
                return false;
            }
        }
        return true;
    }

    // A CONNECTION_CLOSE with an empty reason phrase is spec-compliant and valid.
    inline bool connection_close_validity_unit_test() {
        auto check = [](const uint8_t *bytes, size_t len, bool expect_valid) {
            datum d{bytes, bytes + len};
            quic_frame f{d};
            if (!f.has_type<connection_close>()) {
                return false;
            }
            return f.get_if<connection_close>()->is_valid() == expect_valid;
        };
        static const uint8_t transport_empty[]  = {0x1c, 0x00, 0x00, 0x00};            // reason len 0
        static const uint8_t transport_reason[] = {0x1c, 0x00, 0x00, 0x02, 'h', 'i'};
        static const uint8_t application_empty[] = {0x1d, 0x00, 0x00};                 // 0x1d has no frame type
        static const uint8_t truncated[]        = {0x1c, 0x00};                        // fields cut short
        return check(transport_empty, sizeof(transport_empty), true)
            && check(transport_reason, sizeof(transport_reason), true)
            && check(application_empty, sizeof(application_empty), true)
            && check(truncated, sizeof(truncated), false);
    }

    // A CONNECTION_CLOSE must survive a following ACK_ECN, and ACK_ECN must
    // be captured on the pre-decrypted path.
    inline bool connection_close_frame_walk_unit_test() {
        auto packet = make_quic_initial();   // conn_info 0xc0 -> reserved bits 0 -> pre-decrypted path
        static const uint8_t frames[] = {
            0x1c, 0x00, 0x00, 0x03, 'a', 'b', 'c',            // CONNECTION_CLOSE, reason "abc"
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // ACK_ECN, all-zero fields
        };
        const size_t off = 19;   // payload starts at 18, plus 1-byte packet number
        for (size_t i = 0; i < sizeof(frames); i++) {
            packet[off + i] = frames[i];
        }

        datum d{packet.data(), packet.data() + packet.size()};
        quic_initial_packet ip{d};
        if (!ip.is_not_empty()) {
            return false;
        }
        cryptographic_buffer crypto_buffer{};
        quic_init_decry decry{ip, crypto_buffer};
        decry.parse();

        char buf[8192];
        buffer_stream bs{buf, sizeof(buf)};
        json_object record{&bs};
        decry.write_json(record);
        record.close();
        std::string out(buf, bs.doff > 0 ? (size_t)bs.doff : 0);

        return out.find("connection_close") != std::string::npos   // close not clobbered by ACK
            && out.find("abc") != std::string::npos
            && out.find("ack_ecn") != std::string::npos;            // ack_ecn handled on this path
    }

    // Length at min_len_pn_and_payload is accepted; one byte below is rejected.
    inline bool min_payload_length_unit_test() {
        auto build = [](uint16_t length_field) {
            auto packet = make_quic_initial();
            packet[16] = 0x40 | ((length_field >> 8) & 0x3f);   // 2-byte varint
            packet[17] = (uint8_t)(length_field & 0xff);
            return packet;
        };
        auto parses = [](std::array<uint8_t, quic_initial_packet_len> &packet) {
            datum d{packet.data(), packet.data() + packet.size()};
            quic_initial_packet ip{d};
            return ip.is_not_empty();
        };
        auto at_min = build(quic_initial_packet::min_len_pn_and_payload);
        auto below  = build(quic_initial_packet::min_len_pn_and_payload - 1);
        return parses(at_min) && !parses(below);
    }

    // A late offset-0 CRYPTO frame (arriving after the crypto_frames array is
    // full) must not set first_frame_index past crypto_frames_count; otherwise
    // consumers index one past the array (OOB read).
    inline bool crypto_frame_index_bounds_unit_test() {
        cryptographic_buffer cb{};
        auto feed = [&cb](uint8_t offset) {
            uint8_t body[3] = {offset, 0x01, 0xab};   // offset(<64), length 1, 1 data byte
            datum d{body, body + sizeof(body)};
            crypto c{d};
            if (!c.is_valid()) { return; }
            if (cb.extend(c)) { cb.update_crypto_frames(&c); }
        };
        // Fill the array with nonzero-offset frames, then add an offset-0 frame.
        for (uint8_t off = 1; off <= cryptographic_buffer::max_frames; off++) {
            feed(off);
        }
        feed(0);   // would set first_frame_index = max_frames without the fix
        // No stored offset-0 frame, so there is no usable first frame, and the
        // index (if set) must stay within the populated range.
        if (cb.has_first_frame()) {
            return false;
        }
        if (cb.first_frame_index != cryptographic_buffer::invalid_first_frame_index &&
            cb.first_frame_index >= cb.crypto_frames_count) {
            return false;
        }
        return true;
    }

    // raw_packet must describe the one packet the record is about.  With
    // coalescing the rest of the datagram can be several further packets, and
    // dumping those as raw_packet_data both misattributes them and inflates
    // the record.
    //
    inline bool raw_packet_extent_unit_test() {
        std::array<uint8_t, quic_initial_packet_len> datagram{};
        size_t off = write_initial(datagram.data(), 0x01);
        write_initial(datagram.data() + off, 0x01);

        datum d{datagram.data(), datagram.data() + datagram.size()};
        quic_initial_packet ip{d};
        if (!ip.is_not_empty()) {
            return false;
        }
        return ip.raw_packet.length() == (ssize_t)initial_pkt_len;
    }

    // The pre-decrypted fast path infers "already decrypted" from reserved
    // bits that are header-protected in a genuine Initial, so it runs on
    // attacker-influenced input.  It must not return before the coalesced
    // walk: otherwise a crafted first packet that happens to parse as PADDING
    // suppresses a valid coalesced Initial behind it.
    //
    // A pre-decrypted record reports "plaintext" and no coalesced telemetry;
    // taking the normal path on this input fails to decrypt and reports
    // "raw_packet_data" plus telemetry, so the two are distinguishable.
    //
    inline bool pre_decrypted_coalesced_unit_test() {
        auto record_for = [](const std::array<uint8_t, quic_initial_packet_len> &datagram) {
            datum d{datagram.data(), datagram.data() + datagram.size()};
            quic_crypto_engine engine{};
            quic_init quic{d, engine};

            char buf[16384];
            buffer_stream bs{buf, sizeof(buf)};
            json_object record{&bs};
            quic.write_json(record, true);   // metadata_output
            record.close();
            return std::string(buf, bs.doff > 0 ? (size_t)bs.doff : 0);
        };

        // One cleartext-looking Initial that fills the datagram: the fast
        // path still applies, since nothing follows it.
        std::array<uint8_t, quic_initial_packet_len> single{};
        write_initial(single.data(), 0x01, 0xc0);   // reserved bits 0
        single[16] = 0x44;   // payload length 1166, so the packet fills the datagram
        single[17] = 0x8e;
        std::string single_out = record_for(single);
        if (single_out.find("plaintext") == std::string::npos ||
            single_out.find("decrypted_packets") != std::string::npos) {
            return false;
        }

        // The same first packet with a coalesced Initial behind it must not
        // short-circuit; the walk has to examine the second packet.
        std::array<uint8_t, quic_initial_packet_len> coalesced{};
        size_t off = write_initial(coalesced.data(), 0x01, 0xc0);
        write_initial(coalesced.data() + off, 0x01, 0xc0);
        std::string coalesced_out = record_for(coalesced);
        return coalesced_out.find("decrypted_packets") != std::string::npos;
    }

    // A coalesced Initial carrying a different Destination Connection ID must
    // not be examined.  Initial keys derive from each packet's own DCID, so a
    // foreign-DCID packet decrypts successfully and its offset-0 CRYPTO frame
    // would overwrite the first packet's ClientHello while the record still
    // reports the first packet's dcid (RFC 9000 Section 12.2).
    //
    // Coalesced telemetry is emitted only when more than one packet was
    // examined, so its presence tells us whether the walk continued.
    //
    inline bool coalesced_dcid_gate_unit_test() {
        auto examined_second_packet = [](uint8_t second_dcid_byte) {
            std::array<uint8_t, quic_initial_packet_len> datagram{};
            size_t off = write_initial(datagram.data(), 0x01);
            write_initial(datagram.data() + off, second_dcid_byte);

            datum d{datagram.data(), datagram.data() + datagram.size()};
            quic_crypto_engine engine{};
            quic_init quic{d, engine};

            char buf[8192];
            buffer_stream bs{buf, sizeof(buf)};
            json_object record{&bs};
            quic.write_json(record, true);   // metadata_output
            record.close();
            std::string out(buf, bs.doff > 0 ? (size_t)bs.doff : 0);
            return out.find("decrypted_packets") != std::string::npos;
        };

        return examined_second_packet(0x01)       // same DCID: walk continues
            && !examined_second_packet(0x02);     // foreign DCID: walk stops
    }

    // A long header cut off before its 4-byte version must not parse (guards a
    // null-datum lookahead); the datagram-min-length check is disabled so the
    // truncation, not the length gate, is what rejects it.
    inline bool truncated_version_unit_test() {
        static const uint8_t buf[] = {0xc0, 0x00, 0x01};   // conn_info + only 2 version bytes
        datum d{buf, buf + sizeof(buf)};
        quic_initial_packet ip{d, false};
        return !ip.is_not_empty();
    }

    // Gapped CRYPTO frames (offset-0 frame present, but a later frame leaves a
    // hole) set missing_crypto_frames and drive the reassembly-fallback
    // ClientHello extraction. Two cases: first frame captures < 10 bytes and
    // >= 10 bytes, exercising both fallback branches.
    inline bool missing_crypto_frame_fallback_unit_test() {
        auto run = [](const uint8_t *frames, size_t flen, bool &missing, bool &first) -> bool {
            auto packet = make_quic_initial();
            const size_t off = 19;   // payload at 18, plus 1-byte packet number
            if (off + flen > packet.size()) { return false; }
            for (size_t i = 0; i < flen; i++) { packet[off + i] = frames[i]; }
            datum d{packet.data(), packet.data() + packet.size()};
            quic_initial_packet ip{d};
            if (!ip.is_not_empty()) { return false; }
            cryptographic_buffer cb{};
            quic_init_decry decry{ip, cb};
            decry.parse();
            missing = cb.missing_crypto_frames;
            first = cb.has_first_frame();
            return true;
        };
        // CRYPTO off 0 len 5, then CRYPTO off 100 len 5 (gap): first captures 5 (< 10)
        static const uint8_t small_first[] = {
            0x06, 0x00, 0x05, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
            0x06, 0x40, 0x64, 0x05, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
        };
        // CRYPTO off 0 len 12, then CRYPTO off 100 len 5 (gap): first captures 12 (>= 10)
        static const uint8_t large_first[] = {
            0x06, 0x00, 0x0c, 0x16, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x06, 0x40, 0x64, 0x05, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
        };
        bool m1 = false, f1 = false, m2 = false, f2 = false;
        if (!run(small_first, sizeof(small_first), m1, f1)) { return false; }
        if (!run(large_first, sizeof(large_first), m2, f2)) { return false; }
        return m1 && f1 && m2 && f2;
    }

    inline bool unit_test() {
        return initial_version_decode_unit_test()
            && frame_type_varint_unit_test()
            && initial_packet_type_gate_unit_test()
            && connection_close_validity_unit_test()
            && connection_close_frame_walk_unit_test()
            && min_payload_length_unit_test()
            && crypto_frame_index_bounds_unit_test()
            && raw_packet_extent_unit_test()
            && pre_decrypted_coalesced_unit_test()
            && coalesced_dcid_gate_unit_test()
            && truncated_version_unit_test()
            && missing_crypto_frame_fallback_unit_test();
    }

} // namespace quic_packet_safety_unit_test
// LCOV_EXCL_STOP
#endif // NDEBUG

#endif /* QUIC_H */
