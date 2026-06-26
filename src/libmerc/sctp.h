// sctp.h
//

#ifndef SCTP_H
#define SCTP_H

#include "datum.h"
#include "protocol.h"

namespace sctp {

    //     The SCTP Common Header Format (following RFC 4960, Sec. 3.1)
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |     Source Port Number        |     Destination Port Number   |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                      Verification Tag                         |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                           Checksum                            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    class common_header {
        encoded<uint16_t> source_port;
        encoded<uint16_t> destination_port;
        encoded<uint32_t> verification_tag; // zero for INIT chunk
        encoded<uint32_t> checksum;
        bool is_valid;

    public:

        common_header(datum &d) :
            source_port{d},
            destination_port{d},
            verification_tag{d},
            checksum{d},
            is_valid{d.is_not_empty()}
        { }

        explicit operator bool() const { return is_valid; }

        void write_json(json_object &o, bool metadata_output) const {
            (void)metadata_output;
            o.print_key_uint("src_port", source_port);
            o.print_key_uint("dst_port", destination_port);
            // o.print_key_uint("verification_tag", verification_tag);
            // o.print_key_uint("checksum", checksum);
        }

        bool is_init() const { return is_valid && verification_tag == 0; }
    };

        enum chunk_type : uint8_t {
        DATA              = 0,
        INIT              = 1,
        INIT_ACK          = 2,
        SACK              = 3,
        HEARTBEAT         = 4,
        HEARTBEAT_ACK     = 5,
        ABORT             = 6,
        SHUTDOWN          = 7,
        SHUTDOWN_ACK      = 8,
        ERROR             = 9,
        COOKIE_ECHO       = 10,
        COOKIE_ACK        = 11,
        ECNE              = 12,
        CWR               = 13,
        SHUTDOWN_COMPLETE = 14,
        AUTH              = 15,
        I_DATA            = 64,
        ASCONF_ACK        = 128,
        RE_CONFIG         = 130,
        PAD               = 132,
        TSN               = 192,
        ASCONF            = 193,
        I_FORWARD_TSN     = 194
    };

    inline const char *chunk_type_get_string(uint8_t type) {
        switch (type) {
        case DATA:              return "DATA";
        case INIT:              return "INIT";
        case INIT_ACK:          return "INIT_ACK";
        case SACK:              return "SACK";
        case HEARTBEAT:         return "HEARTBEAT";
        case HEARTBEAT_ACK:     return "HEARTBEAT_ACK";
        case ABORT:             return "ABORT";
        case SHUTDOWN:          return "SHUTDOWN";
        case SHUTDOWN_ACK:      return "SHUTDOWN_ACK";
        case ERROR:             return "ERROR";
        case COOKIE_ECHO:       return "COOKIE_ECHO";
        case COOKIE_ACK:        return "COOKIE_ACK";
        case ECNE:              return "ECNE";
        case CWR:               return "CWR";
        case SHUTDOWN_COMPLETE: return "SHUTDOWN_COMPLETE";
        case AUTH:              return "AUTH";
        case I_DATA:            return "I_DATA";
        case ASCONF_ACK:        return "ASCONF_ACK";
        case RE_CONFIG:         return "RE_CONFIG";
        case PAD:               return "PAD";
        case TSN:               return "TSN";
        case ASCONF:            return "ASCONF";
        case I_FORWARD_TSN:     return "I_FORWARD_TSN";
        default:
            ;
        };
        return "unkown";
    }

    //    Chunk Header Format (following RFC 4960 Sec. 3.2)
    //
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |   Chunk Type  | Chunk  Flags  |        Chunk Length           |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    ~                                                               ~
    //    ~                          Chunk Value                          ~
    //    ~                                                               ~
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //    Chunk Length (RFC 4960): 16-bit unsigned integer representing
    //    the size of the chunk in bytes, including Type (1), Flags (1),
    //    Length (2), and Value fields. Minimum valid length is 4.
    //
    class chunk_header {
        static constexpr size_t header_size = 4;  // type + flags + length
        encoded<uint8_t> type;
        encoded<uint8_t> flags;
        encoded<uint16_t> length;
        datum value;
        bool valid;

        static datum parse_value(datum &d, uint16_t len) {
            if (len < header_size) {
                d.set_null();  // invalid length as per RFC 4960
                return datum{};
            }
            return datum{d, static_cast<ssize_t>(len - header_size)};
        }

    public:

        chunk_header(datum &d) :
            type{d},
            flags{d},
            length{d},
            value{parse_value(d, length)},
            valid{d.is_not_null()}
        { }

        bool is_type(chunk_type t) const { return valid && type == t; }
        bool has_min_length(uint16_t min_len) const { return valid && length >= min_len; }

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata;
            json_object json{o, "chunk"};
            json.print_key_string("type", chunk_type_get_string(type));
            json.print_key_uint("flags", flags);
            json.print_key_uint("length", length);
            json.print_key_hex("value", value);
            json.close();
        }
    };

}

// sctp_init represents the initial message of the SCTP protocol
//
// As currently implemented, only the initial (INIT) message of the
// protocol is reported through write_json(), so that the port numbers
// associated with the SCTP session are reported.
//
class sctp_init : public base_protocol {
    sctp::common_header header;
    sctp::chunk_header chunk;
    bool is_valid;

public:

    sctp_init(datum &d) :
        header{d},
        chunk{d},
        is_valid{header.is_init()
                 && chunk.is_type(sctp::INIT)
                 && chunk.has_min_length(20)}  // 4-byte header + 16-byte fixed INIT fields
    { }

    explicit operator bool() const { return is_valid; }

    bool is_not_empty() const { return is_valid; }

    void write_json(json_object &o, bool metadata_output) const {
        if (is_valid) {
            json_object json{o, "sctp"};
            header.write_json(json, metadata_output);
            chunk.write_json(json, metadata_output);
            json.close();
        }
    }
};

[[maybe_unused]] inline int sctp_init_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<sctp_init>(data, size);
}

namespace sctp_unit_test {
#ifndef NDEBUG
    inline bool unit_test() {
        char buffer[1024];

        // valid INIT: 12-byte common header + 20-byte INIT chunk (4 header + 16 value)
        uint8_t init[] = {
            0x00, 0x50, 0x00, 0x51,  // src_port=80, dst_port=81
            0x00, 0x00, 0x00, 0x00,  // verification_tag=0
            0x00, 0x00, 0x00, 0x00,  // checksum
            0x01, 0x00,              // chunk type=INIT, flags=0
            0x00, 0x14,              // chunk length=20
            0xde, 0xad, 0xbe, 0xef,  // initiate tag
            0x00, 0x01, 0x00, 0x00,  // a_rwnd
            0x00, 0x0a, 0x00, 0x0a,  // outbound/inbound streams
            0x01, 0x02, 0x03, 0x04   // initial TSN
        };
        datum d1{init, init + sizeof(init)};
        sctp_init msg1{d1};
        if (!msg1.is_not_empty()) return false;
        {
            buffer_stream buf{buffer, sizeof(buffer)};
            json_object json{&buf};
            msg1.write_json(json, false);
            json.close();
            buf.write_char('\0');
            if (!strstr(buffer, "sctp")) return false;
            if (!strstr(buffer, "INIT")) return false;
            if (!strstr(buffer, "src_port")) return false;
            if (!strstr(buffer, "dst_port")) return false;
            if (!strstr(buffer, "deadbeef")) return false;
        }

        uint8_t non_init[] = {
            0x00, 0x50, 0x00, 0x51,
            0x12, 0x34, 0x56, 0x78,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x08
        };
        datum d2{non_init, non_init + sizeof(non_init)};
        sctp_init msg2{d2};
        if (msg2.is_not_empty()) return false;

        uint8_t too_short[] = { 0x00, 0x50, 0x00, 0x51 };
        datum d3{too_short, too_short + sizeof(too_short)};
        sctp_init msg3{d3};
        if (msg3.is_not_empty()) return false;

        // zero verification tag but non-INIT chunk type (DATA=0x00)
        uint8_t zero_tag_non_init[] = {
            0x00, 0x50, 0x00, 0x51,
            0x00, 0x00, 0x00, 0x00,  // verification_tag = 0
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,              // chunk type = DATA (not INIT)
            0x00, 0x08
        };
        datum d4{zero_tag_non_init, zero_tag_non_init + sizeof(zero_tag_non_init)};
        sctp_init msg4{d4};
        if (msg4.is_not_empty()) return false;

        // invalid chunk length (< 4)
        uint8_t invalid_chunk_len[] = {
            0x00, 0x50, 0x00, 0x51,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x01, 0x00,              // chunk type = INIT
            0x00, 0x03               // length = 3 (invalid, minimum is 4)
        };
        datum d5{invalid_chunk_len, invalid_chunk_len + sizeof(invalid_chunk_len)};
        sctp_init msg5{d5};
        if (msg5.is_not_empty()) return false;

        // INIT chunk with length < 20 (missing fixed fields)
        uint8_t init_too_short[] = {
            0x00, 0x50, 0x00, 0x51,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x01, 0x00,              // chunk type = INIT
            0x00, 0x10,              // length = 16 (< 20 required for INIT)
            0xde, 0xad, 0xbe, 0xef,
            0x00, 0x01, 0x00, 0x00,
            0x00, 0x0a, 0x00, 0x0a
        };
        datum d6{init_too_short, init_too_short + sizeof(init_too_short)};
        sctp_init msg6{d6};
        if (msg6.is_not_empty()) return false;

        return true;
    }
#endif
} // namespace sctp_unit_test

// TODO: move sctp_init into SCTP namespace
//
// TODO: integrate SCTP into flow key functionality, so that it can be
// a full-rank peer of TCP and UDP within mercury's packet processing

#endif // SCTP_H
