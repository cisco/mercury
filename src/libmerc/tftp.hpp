// tftp.hpp
//
// trivial file transfer protocol

#ifndef TFTP_HPP
#define TFTP_HPP

#include "protocol.h"

namespace tftp {

    // TFTP packet formats (following RFCs 1350 and 2347)
    //
    //    Type   Op #     Format without header
    //
    //           2 bytes    string   1 byte     string   1 byte
    //           -----------------------------------------------
    //    RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
    //    WRQ    -----------------------------------------------
    //
    //           2 bytes    2 bytes       n bytes
    //           ---------------------------------
    //    DATA  | 03    |   Block #  |    Data    |
    //           ---------------------------------
    //
    //           2 bytes    2 bytes
    //           -------------------
    //    ACK   | 04    |   Block #  |
    //           --------------------
    //
    //           2 bytes  2 bytes        string    1 byte
    //           ----------------------------------------
    //    ERROR | 05    |  ErrorCode |   ErrMsg   |   0  |
    //           ----------------------------------------
    //
    //           2 bytes  string  1b   string  1b   string  1b   string  1b
    //          +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
    //    OACK  |  06   |  opt1  | 0 | value1 | 0 |  opt2  | 0 | value2 | 0 | ...
    //          +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
    //

    /// an option_extension object consists of two null-terminated strings
    ///
    class option_extension {
        datum option;
        datum value;

    public:

        option_extension(datum &d) {
            option.parse_up_to_delim(d, '\0');
            d.accept('\0');
            value.parse_up_to_delim(d, '\0');
            d.accept('\0');
        }

        void write_json(json_array &a) const {
            json_object opt{a};
            opt.print_key_json_string("option", option);
            opt.print_key_json_string("value", value);
            opt.close();
        }

    };

    /// an error object consists of a numerical code followed by a
    /// printable null-terminated string
    ///
    class error {
        encoded<uint16_t> code;
        datum err_msg;
        bool valid;

    public:

        error(datum &d) : code{d} {
            err_msg.parse_up_to_delim(d, '\0');
            valid = d.is_not_null();
        }

        bool is_not_empty() const { return valid; }

        void write_json(json_object &o) const {
            json_object tftp_json{o, "tftp"};
            json_object error_json{tftp_json, "error"};
            error_json.print_key_uint("code", code.value());
            error_json.close();
            tftp_json.close();
        }

    };

    /// tftp::packet reports the filename and mode for read requests
    /// and write requests
    ///
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
                    for (const auto & opt : sequence<option_extension>{d}) {
                        opt.write_json(options_json);
                    }
                    options_json.close();
                    tftp_json.close();
                }
            } else if (opcode.value() == 5) {        // this type should not actually appear on port 69
                if (lookahead<error> err_msg{d}) {
                    err_msg.value.write_json(o);
                }
            }
        }

    };

    // registered port: 69


} // namespace tftp

#endif // TFTP_HPP
