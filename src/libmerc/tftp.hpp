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

        void write_json(json_object &o, bool metadata=false) const {
            (void)metadata;
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

        void write_l7_metadata(writeable &buf, bool) {
            cbor_object o{buf, false};
            cbor_object tftp{o, "tftp"};
            tftp.close();
            o.close();
        }
    };

    /// runs unit tests on tftp::packet and returns true if all pass, and false otherwise
    ///
    [[maybe_unused]] static bool unit_test() {
        uint8_t read_request[] = {
            0x00, 0x01, 0x6d, 0x66, 0x73, 0x62, 0x73, 0x64,
            0x2d, 0x73, 0x65, 0x2d, 0x31, 0x30, 0x2e, 0x31,
            0x2d, 0x52, 0x45, 0x4c, 0x45, 0x41, 0x53, 0x45,
            0x2d, 0x61, 0x6d, 0x64, 0x36, 0x34, 0x2e, 0x69,
            0x73, 0x6f, 0x00, 0x6f, 0x63, 0x74, 0x65, 0x74,
            0x00, 0x74, 0x73, 0x69, 0x7a, 0x65, 0x00, 0x30,
            0x00, 0x62, 0x6c, 0x6b, 0x73, 0x69, 0x7a, 0x65,
            0x00, 0x31, 0x34, 0x30, 0x38, 0x00
        };
        datum rr{read_request, read_request + sizeof(read_request)};

        // expected JSON output: {"tftp":{"opcode":"read","filename":"mfsbsd-se-10.1-RELEASE-amd64.iso","mode":"octet","options":[{"option":"tsize","value":"0"},{"option":"blksize","value":"1408"}]}
        //
        uint8_t expected_json_output[] = {
            0x7b, 0x22, 0x74, 0x66, 0x74, 0x70, 0x22, 0x3a,
            0x7b, 0x22, 0x6f, 0x70, 0x63, 0x6f, 0x64, 0x65,
            0x22, 0x3a, 0x22, 0x72, 0x65, 0x61, 0x64, 0x22,
            0x2c, 0x22, 0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61,
            0x6d, 0x65, 0x22, 0x3a, 0x22, 0x6d, 0x66, 0x73,
            0x62, 0x73, 0x64, 0x2d, 0x73, 0x65, 0x2d, 0x31,
            0x30, 0x2e, 0x31, 0x2d, 0x52, 0x45, 0x4c, 0x45,
            0x41, 0x53, 0x45, 0x2d, 0x61, 0x6d, 0x64, 0x36,
            0x34, 0x2e, 0x69, 0x73, 0x6f, 0x22, 0x2c, 0x22,
            0x6d, 0x6f, 0x64, 0x65, 0x22, 0x3a, 0x22, 0x6f,
            0x63, 0x74, 0x65, 0x74, 0x22, 0x2c, 0x22, 0x6f,
            0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0x3a,
            0x5b, 0x7b, 0x22, 0x6f, 0x70, 0x74, 0x69, 0x6f,
            0x6e, 0x22, 0x3a, 0x22, 0x74, 0x73, 0x69, 0x7a,
            0x65, 0x22, 0x2c, 0x22, 0x76, 0x61, 0x6c, 0x75,
            0x65, 0x22, 0x3a, 0x22, 0x30, 0x22, 0x7d, 0x2c,
            0x7b, 0x22, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e,
            0x22, 0x3a, 0x22, 0x62, 0x6c, 0x6b, 0x73, 0x69,
            0x7a, 0x65, 0x22, 0x2c, 0x22, 0x76, 0x61, 0x6c,
            0x75, 0x65, 0x22, 0x3a, 0x22, 0x31, 0x34, 0x30,
            0x38, 0x22, 0x7d, 0x5d, 0x7d, 0x0a
        };

        tftp::packet tftp{rr};
        if (tftp.is_not_empty()) {
            output_buffer<1024> buf;
            json_object json_record{&buf};
            tftp.write_json(json_record);
            return buf.memcmp(expected_json_output, sizeof(expected_json_output)) == 0;
        }
        return false;
    }

    // registered port: 69


} // namespace tftp

namespace {

    [[maybe_unused]] inline int tftp_packet_fuzz_test(const uint8_t *data, size_t size) {
        return json_output_fuzzer<tftp::packet>(data, size);
    }

};

#endif // TFTP_HPP
