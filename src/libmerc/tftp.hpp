// tftp.hpp
//
// trivial file transfer protocol

#ifndef TFTP_HPP
#define TFTP_HPP

#include "protocol.h"

namespace tftp {

    // TFTP packet formats (following RFC 1350)
    //
    //    Type   Op #     Format without header
    //
    //           2 bytes    string   1 byte     string   1 byte
    //           -----------------------------------------------
    //    RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
    //    WRQ    -----------------------------------------------
    //           2 bytes    2 bytes       n bytes
    //           ---------------------------------
    //    DATA  | 03    |   Block #  |    Data    |
    //           ---------------------------------
    //           2 bytes    2 bytes
    //           -------------------
    //    ACK   | 04    |   Block #  |
    //           --------------------
    //           2 bytes  2 bytes        string    1 byte
    //           ----------------------------------------
    //    ERROR | 05    |  ErrorCode |   ErrMsg   |   0  |
    //           ----------------------------------------
    //
    //          +-------+---~~---+---+---~~---+---+
    //    OACK  |  opc  |  opt1  | 0 | value1 | 0 |
    //          +-------+---~~---+---+---~~---+---+
    //

    class option_extension {
        datum option;
        datum value;

    public:

        option_extension(datum &d) {
            option.parse_up_to_delim(d, '\0');
            value.parse_up_to_delim(d, '\0');
        }

        void write_json(json_array &a) const {
            json_object opt{a};
            opt.print_key_json_string("option", option);
            opt.print_key_json_string("value", value);
            opt.close();
        }

    };

    // tftp::packet reports the filename and mode for read requests
    // and write requests
    //
    class packet : public base_protocol {
        encoded<uint16_t> opcode;
        datum body;

    public:

        packet(datum &d) : opcode{d}, body{d} { }

        bool is_not_empty() const { return body.is_not_null(); }

        void write_json(json_object &o, bool) const {
            datum d{body};
            if (opcode.value() == 1 or opcode.value() == 2) {
                datum filename;
                filename.parse_up_to_delim(d, '\0');
                d.accept('\0');
                datum mode;
                mode.parse_up_to_delim(d, '\0');
                d.accept('\0');
                if (d.is_not_null()) {
                    json_object tftp_json(o, "tftp");
                    tftp_json.print_key_string("opcode", opcode.value() == 1 ? "read" : "write");
                    tftp_json.print_key_json_string("filename", filename);
                    tftp_json.print_key_json_string("mode", mode);
                    json_array options_json{tftp_json, "options"};
                    // for (const auto & opt : sequence<option_extension>{d}) {
                    //     opt.write_json(options_json);
                    // }
                    options_json.close();
                    tftp_json.close();
                }
            }
        }

    };

    // registered port: 69


} // namespace tftp

#endif // TFTP_HPP
