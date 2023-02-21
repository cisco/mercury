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
#include <unordered_map>
#include <variant>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "tls.h"
#include "json_object.h"
#include "util_obj.h"
#include "match.h"
#include "crypto_engine.h"

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

    void fingerprint(struct buffer_stream &b) {
        for (uint8_t x = 0x80; x > 0; x=x>>1) {
            if (x & value) {
                b.write_char('1');
            } else {
                b.write_char('0');
            }
        }
    }
};

// class variable_length_integer implements the QUIC variable-length
// integer encoding (following RFC9000, Section 16).  If there is a
// parse error, i.e. the datum being parsed is too short, then the datum
// reference passed to the constructor will be set to NULL state.  The
// value of the variable length integer is returned by the member function
// value().
//
//          +======+========+=============+=======================+
//          | 2MSB | Length | Usable Bits | Range                 |
//          +======+========+=============+=======================+
//          | 00   | 1      | 6           | 0-63                  |
//          +------+--------+-------------+-----------------------+
//          | 01   | 2      | 14          | 0-16383               |
//          +------+--------+-------------+-----------------------+
//          | 10   | 4      | 30          | 0-1073741823          |
//          +------+--------+-------------+-----------------------+
//          | 11   | 8      | 62          | 0-4611686018427387903 |
//          +------+--------+-------------+-----------------------+
//
class variable_length_integer {
    uint64_t value_;

public:

    variable_length_integer(datum &d) : value_{0} {
        uint8_t b;
        d.read_uint8(&b);
        int len=0;
        switch (b & 0xc0) {
        case 0xc0:
            len = 8;
            break;
        case 0x80:
            len = 4;
            break;
        case 0x40:
            len = 2;
            break;
        case 0x00:
            len = 1;
        }
        value_ = (b & 0x3f);
        for (int i=1; i<len; i++) {
            value_ *= 256;
            d.read_uint8(&b);
            value_ += b;
        }
    }

    uint64_t value() const { return value_; }

};

class variable_length_integer_datum : public datum {

public:

    variable_length_integer_datum(datum &d) {
        uint8_t b;
        d.lookahead_uint8(&b);
        int len=0;
        switch (b & 0xc0) {
        case 0xc0:
            len = 8;
            break;
        case 0x80:
            len = 4;
            break;
        case 0x40:
            len = 2;
            break;
        case 0x00:
            len = 1;
        }
        datum::parse(d, len);
    }

    void write(buffer_stream &b) const {
        b.raw_as_hex(data, length());
    }

    bool is_grease() const {
        datum tmp = *this;               // copy to avoid changing *this
        variable_length_integer v{tmp};
        return v.value() % 31 == 27;
    }

    uint64_t value() const {
        datum tmp = *this;               // copy to avoid changing *this
        variable_length_integer v{tmp};
        return v.value();
    }
};

// quic_transport_parameters are carried in a TLS extension; see
// https://datatracker.ietf.org/doc/html/rfc9000#section-18 and
// https://www.iana.org/assignments/quic/quic.xhtml#quic-transport
//
//   Transport Parameter {
//     Transport Parameter ID (i),
//     Transport Parameter Length (i),
//     Transport Parameter Value (..),
//   }
//
class quic_transport_parameter {
    variable_length_integer_datum _id;
    variable_length_integer _length;
    datum _value;

public:

    quic_transport_parameter(datum &d) : _id{d}, _length{d}, _value{d, _length.value()} { }

    bool is_not_empty() const {
        return _value.is_not_null(); // note: zero-length value is possible
    }

    void write_id(buffer_stream &b) const {
        if (!_id.is_grease()) {
            _id.write(b);
        } else {
            // write out the smallest GREASE value (0x1b == 27)
            b.write_char('1');
            b.write_char('b');
        }
    }
    variable_length_integer_datum get_id() const { return _id; }
    datum  get_value() const { return _value; }

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
        	fprintf(f, "ack.largest_acked: %lu\n", largest_acked.value());
        	fprintf(f, "ack.ack_delay: %lu\n", ack_delay.value());
        	fprintf(f, "ack.ack_range_count: %lu\n", ack_range_count.value());
        	fprintf(f, "ack.first_ack_range: %lu\n", first_ack_range.value());
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
        	fprintf(f, "ack.ect0: %lu\n", ect0.value());
            fprintf(f, "ack.ect1: %lu\n", ect1.value());
            fprintf(f, "ack.ecn_ce: %lu\n", ecn_ce.value());
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
    crypto(datum &p) : _offset{p}, _length{p}, _data{p, _length.value()} {    }

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
            fprintf(f, "crypto.offset: %lu\n", _offset.value());
            fprintf(f, "crypto.length: %lu\n", _length.value());
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
    variable_length_integer error_code;
    variable_length_integer frame_type;
    variable_length_integer reason_phrase_length;
    datum reason_phrase;

public:
    connection_close(datum &p) : error_code{p}, frame_type{p}, reason_phrase_length{p}, reason_phrase{p, reason_phrase_length.value()} { }

    bool is_valid() const { return reason_phrase.is_not_empty(); }

	void write_json(json_object &o) {
        if (is_valid()) {
            json_object cc{o, "connection_close"};
            cc.print_key_uint("error_code", error_code.value());
            cc.print_key_uint("frame_type", frame_type.value());
            cc.print_key_json_string("reason_phrase", reason_phrase);
            cc.close();
        }
    }

	void write(FILE *f) {
    	if (is_valid()) {
        	fprintf(f, "connection_close.error_code: %lu\n", error_code.value());
        	fprintf(f, "connection_close.frame_type: %lu\n", frame_type.value());
        	fprintf(f, "connection_close.reason_phrase_length: %lu\n", reason_phrase_length.value());
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

    quic_initial_packet(struct datum &d) : connection_info{0}, dcid{}, scid{}, token{}, payload{}, valid{false} {
        parse(d);
    }

    void parse(struct datum &d) {

        // additional authenticated data (aad) is used in authenticated decryption
        //
        aad_start = d.data;

        if (d.length() < min_len_pdu) {
            return;  // packet too short to be valid
        }

        // connection information octet for initial packets:
        //
        // Header Form        (1)        1
        // Fixed Bit          (1)        ?
        // Long Packet Type   (2)        00
        // Type-Specific Bits (4)        ??
        //
        uint8_t conn_info_mask  = 0b10110000;
        uint8_t conn_info_value = 0b10000000;
        d.read_uint8(&connection_info);
        if ((connection_info & conn_info_mask) != conn_info_value) {
            return;
        }

        version.parse(d, 4);

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

        uint8_t dcid_length;
        d.read_uint8(&dcid_length);
        if (dcid_length > 20) {
            return;  // dcid too long
        }
        dcid.parse(d, dcid_length);

        uint8_t scid_length;
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
        // fprintf(stderr, "VALID\n");
        valid = true;
    }

	static constexpr size_t min_len_pn_and_payload = 64;  // TODO: determine best length bound
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
        json_quic.print_key_hex("data", payload);

    }

    constexpr static mask_and_value<8> matcher = {
       { 0b10110000, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x00, 0x00 },
       { 0b10000000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
    };

};

class quic_parameters {
public:

    // salt_enum acts as an index for the array of salts
    //
    enum salt_enum {
        D22     = 0,
        D23_D28 = 1,
        D29_D32 = 2,
        D33_V1  = 3
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

    std::array<salt, 4> salts{
        salt{{0x7f,0xbc,0xdb,0x0e,0x7c,0x66,0xbb,0xe9,0x19,0x3a,0x96,0xcd,0x21,0x51,0x9e,0xbd,0x7a,0x02,0x64,0x4a}, "d22"},
        salt{{0xc3,0xee,0xf7,0x12,0xc7,0x2e,0xbb,0x5a,0x11,0xa7,0xd2,0x43,0x2b,0xb4,0x63,0x65,0xbe,0xf9,0xf5,0x02}, "d23_d28"},
        salt{{0xaf,0xbf,0xec,0x28,0x99,0x93,0xd2,0x4c,0x9e,0x97,0x86,0xf1,0x9c,0x61,0x11,0xe0,0x43,0x90,0xa8,0x99}, "d29_d32"},
        salt{{0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a}, "d33_v1"}
    };

private:

    std::unordered_map<uint32_t, salt_enum> quic_initial_salt;

public:

    static constexpr size_t MAX_QUIC_VERSIONS{30};  // limit memory usage

    quic_parameters() {

        quic_initial_salt.reserve(MAX_QUIC_VERSIONS);
        quic_initial_salt = {
            {4207849473, salt_enum::D22},     // faceb001
            {4207849474, salt_enum::D23_D28}, // faceb002
            {4207849486, salt_enum::D23_D28}, // faceb00e
            {4207849488, salt_enum::D23_D28}, // faceb010
            {4207849489, salt_enum::D23_D28}, // faceb011
            {4207849490, salt_enum::D23_D28}, // faceb012
            {4207849491, salt_enum::D23_D28}, // faceb013
            {4278190102, salt_enum::D22},     // draft-22
            {4278190103, salt_enum::D23_D28}, // draft-23
            {4278190104, salt_enum::D23_D28}, // draft-24
            {4278190105, salt_enum::D23_D28}, // draft-25
            {4278190106, salt_enum::D23_D28}, // draft-26
            {4278190107, salt_enum::D23_D28}, // draft-27
            {4278190108, salt_enum::D23_D28}, // draft-28
            {4278190109, salt_enum::D29_D32}, // draft-29
            {4278190110, salt_enum::D29_D32}, // draft-30
            {4278190111, salt_enum::D29_D32}, // draft-31
            {4278190112, salt_enum::D29_D32}, // draft-32
            {4278190113, salt_enum::D33_V1},  // draft-33
            {4278190114, salt_enum::D33_V1},  // draft-34
            {1,          salt_enum::D33_V1},  // version-1
        };
    }

    void add_salt_mapping(uint32_t version, salt_enum salt_num) {
        if (quic_initial_salt.size() > MAX_QUIC_VERSIONS) {
            return;
        }
        quic_initial_salt.emplace(version, salt_num);
    }

    const salt *get_initial_salt(uint32_t version) {
        auto pair = quic_initial_salt.find(version);
        if (pair != quic_initial_salt.end()) {
            return &salts[pair->second];
        } else {
            return nullptr;
        }
    }

    static quic_parameters &create() {
        static quic_parameters quic_params;
        return quic_params;
    }
};

class quic_crypto_engine {

    crypto_engine core_crypto;

    constexpr static const uint8_t client_in_label[] = "tls13 client in";
    constexpr static const uint8_t quic_key_label[]  = "tls13 quic key";
    constexpr static const uint8_t quic_iv_label[]   = "tls13 quic iv";
    constexpr static const uint8_t quic_hp_label[]   = "tls13 quic hp";

    size_t salt_length = 20;

    uint8_t quic_key[EVP_MAX_MD_SIZE] = {0};
    unsigned int quic_key_len = 0;

    uint8_t quic_iv[EVP_MAX_MD_SIZE] = {0};
    unsigned int quic_iv_len = 0;

    uint8_t quic_hp[EVP_MAX_MD_SIZE] = {0};
    unsigned int quic_hp_len = 0;

    uint8_t pn_length = 0;

    unsigned char plaintext[pt_buf_len] = {0};
    int16_t plaintext_len = 0;

    const char *salt_str = nullptr;

public:

    datum decrypt(const quic_initial_packet &quic_pkt) {
        if (!quic_pkt.is_not_empty()) {
            return {nullptr, nullptr};
        }

        data_buffer<1024> aad;
        uint32_t version = ntoh(*((uint32_t*)quic_pkt.version.data));
        static quic_parameters &quic_params = quic_parameters::create();  // initialize on first use
        const quic_parameters::salt *initial_salt = quic_params.get_initial_salt(version);

        if (initial_salt) {
            salt_str = initial_salt->get_name();
            if (process_initial_packet(aad, quic_pkt, initial_salt->data()) == false) {
                return {nullptr, nullptr};
            }
            decrypt__(aad.buffer, aad.readable_length(),
                  quic_pkt.payload.data, quic_pkt.payload.length());
            return {plaintext, plaintext+plaintext_len};
        } else {

            for (size_t i = 0; i < quic_params.salts.size(); i++) {
                if (process_initial_packet(aad, quic_pkt, quic_params.salts[i].data()) == false) {
                    reset_buffers();
                    continue;
                }
                decrypt__(aad.buffer, aad.readable_length(),
                  quic_pkt.payload.data, quic_pkt.payload.length());

                if (plaintext_len) {
                    salt_str = quic_params.salts[i].get_name();
                    quic_params.add_salt_mapping(version, (quic_parameters::salt_enum)i);
                    return {plaintext, plaintext+plaintext_len};
                }
                aad.reset();
            }
            return {nullptr, nullptr};
        }
    }

    void write_json(struct json_object &record) {
        record.print_key_string("salt_string", salt_str);
    }

private:

    bool process_initial_packet(data_buffer<1024> &aad, const quic_initial_packet &quic_pkt, const uint8_t* salt) {
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
        core_crypto.kdf_tls13(initial_secret, initial_secret_len, client_in_label, sizeof(client_in_label)-1, 32, c_initial_secret, &c_initial_secret_len);
        core_crypto.kdf_tls13(c_initial_secret, c_initial_secret_len, quic_key_label, sizeof(quic_key_label)-1, 16, quic_key, &quic_key_len);
        core_crypto.kdf_tls13(c_initial_secret, c_initial_secret_len, quic_iv_label, sizeof(quic_iv_label)-1, 12, quic_iv, &quic_iv_len);
        core_crypto.kdf_tls13(c_initial_secret, c_initial_secret_len, quic_hp_label, sizeof(quic_hp_label)-1, 16, quic_hp, &quic_hp_len);

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

        uint8_t dcid_length;
        d.read_uint8(&dcid_length);
        dcid.parse(d, dcid_length);

        uint8_t scid_length;
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
        uint8_t type = 0;
        if (d.read_uint8(&type) == false) {
            frame.emplace<std::monostate>();   // invalid; no data to read
        } else if (type == 0x06) {
            frame.emplace<crypto>(d);
        } else if (type == 0x1c) {
            frame.emplace<connection_close>(d);
        } else if (type == 0x00) {
            frame.emplace<padding>(d);
        } else if (type == 0x01) {
            frame.emplace<ping>(d);
        } else if (type == 0x02) {
            frame.emplace<ack>(d);
        } else if (type == 0x03) {
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

struct cryptographic_buffer
{
    uint64_t buf_len = 0;
    unsigned char buffer[pt_buf_len] = {}; // pt_buf_len - decryption buffer trim size for gcm_decrypt

    void extend(crypto& d)
    {
        if (d.offset() + d.length() <= sizeof(buffer)) {
            memcpy(buffer + d.offset(), d.data().data, d.length());
            if (d.offset() + d.length() > buf_len) {
                buf_len = d.offset() + d.length();
            }
        }
        // TODO: track segments to verify that all are present
    }

    bool is_valid()
    {
        return buf_len > 0;
    }

    void reset() {buf_len = 0;}
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
        (void)format_version;
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
        extensions.fingerprint_quic_tls(buf, tls_role::client);

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
    quic_frame cc;
    uint8_t pkt_num_len;

public:
    quic_init_decry (quic_initial_packet &pkt, cryptographic_buffer& buffer) : initial_packet{pkt}, crypto_buffer{buffer}, hello{}, plaintext{}, valid{false}, cc{}, pkt_num_len{0} {}

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
                crypto_buffer.extend(*c);
            }
            if (frame.has_type<connection_close>() || frame.has_type<ack>()) {
                cc = frame;
            }
        }
        valid = true;
        if(crypto_buffer.is_valid()){
            struct datum d{crypto_buffer.buffer, crypto_buffer.buffer + crypto_buffer.buf_len};
            tls_handshake tls{d};
            hello.parse(tls.body);
            hello.is_quic_hello = true;
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
        if (cc.is_valid()) {
            cc.write_json(quic_record);
        }
        if (plaintext.is_not_empty()) {
            //quic_crypto.write_json(quic_record);
            quic_record.print_key_hex("plaintext", plaintext);
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

        return c_->analyze_fingerprint_and_destination_context(analysis_.fp, analysis_.destination, analysis_.result);
    }
};

// class quic_init represents an initial quic message
//
class quic_init {
    quic_initial_packet initial_packet;
    quic_crypto_engine &quic_crypto;
    cryptographic_buffer crypto_buffer;
    quic_client_hello hello;
    datum plaintext;
    quic_frame cc;
    quic_init_decry decry_pkt;
    bool pre_decrypted;

public:

    quic_init(struct datum &d, quic_crypto_engine &quic_crypto_) : initial_packet{d}, quic_crypto{quic_crypto_}, crypto_buffer{}, hello{}, plaintext{}, decry_pkt{initial_packet,crypto_buffer}, pre_decrypted{false} {

        // check reserved bits, if 0, try for decrypted quic packet
        //
        if ((initial_packet.connection_info & 0x0c) == 0) {
            decry_pkt.parse();
            if (decry_pkt.is_valid()) {
                pre_decrypted = true;
                return;
            }
        }

        // reset crypto buffer
        //
        crypto_buffer.reset();
        plaintext = quic_crypto.decrypt(initial_packet);

        // parse plaintext as a sequence of frames
        //
        datum plaintext_copy = plaintext;
        while (plaintext_copy.is_not_empty()) {
            quic_frame frame{plaintext_copy};
            //frame.write(stderr);
            if (!frame.is_valid()) {
                break;
            }

            crypto *c = frame.get_if<crypto>();
            if (c && c->is_valid()) {
                crypto_buffer.extend(*c);
            }
            if (frame.has_type<connection_close>() || frame.has_type<ack>() || frame.has_type<ack_ecn>()) {
                cc = frame;
            }
        }
        if(crypto_buffer.is_valid()){
            struct datum d{crypto_buffer.buffer, crypto_buffer.buffer + crypto_buffer.buf_len};
            tls_handshake tls{d};
            hello.parse(tls.body);
            hello.is_quic_hello = true;
        }
    }

    bool is_not_empty() {
        return initial_packet.is_not_empty();
        //return plaintext.is_not_empty();
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
        if (cc.is_valid()) {
            cc.write_json(quic_record);
        }
        if (plaintext.is_not_empty()) {
            quic_crypto.write_json(quic_record);
            quic_record.print_key_hex("plaintext", plaintext);
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

    void compute_fingerprint(class fingerprint &fp) const {

        // fingerprint format:  quic:(quic_version)(tls fingerprint)
        //
        // TODO: do we want to report anything if !hello.is_not_empty() ?

        if(pre_decrypted) {
            decry_pkt.compute_fingerprint(fp);
            return;
        }

        if (hello.is_not_empty()) {
            fp.set_type(fingerprint_type_quic);
            quic_hdr_fp hdr_fp(initial_packet.version);
            fp.add(hdr_fp);
            fp.add(hello, 0); // note: using quic format=0
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

        return c_->analyze_fingerprint_and_destination_context(analysis_.fp, analysis_.destination, analysis_.result);
    }
};

namespace {

    [[maybe_unused]] int quic_init_fuzz_test(const uint8_t *data, size_t size) {
        datum pkt_data{data, data+size};
        quic_crypto_engine quic_crypto{};
        quic_init quic_pkt{pkt_data, quic_crypto};
        return 0;
    }

}; //end of namespace

#endif /* QUIC_H */
