// sctp.h
//

#ifndef SCTP_H
#define SCTP_H

#include "datum.h"

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
    class chunk_header {
        encoded<uint8_t> type;
        encoded<uint8_t> flags;
        encoded<uint8_t> length;
        datum value;

    public:

        chunk_header(datum &d) :
            type{d},
            flags{d},
            length{d},
            value{d, length}
        { }

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
        is_valid{header.is_init()}
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

// TODO: move sctp_init into SCTP namespace
//
// TODO: integrate SCTP into flow key functionality, so that it can be
// a full-rank peer of TCP and UDP within mercury's packet processing

#endif // SCTP_H
