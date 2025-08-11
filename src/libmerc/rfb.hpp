// rfb.hpp

#ifndef RFB_HPP
#define RFB_HPP

#include "datum.h"
#include "protocol.h"
#include "json_object.h"
#include "match.h"
//#include "fingerprint.h"

namespace rfb {

    //  RFB 003.008\n (hex 52 46 42 20 30 30 33 2e 30 30 38 0a)
    //
    class protocol_version_handshake : public base_protocol {
        literal_byte<'R','F','B',' '> preamble; // ,'0','0','3','.'
        datum version;
        bool valid = false;

    public:

        protocol_version_handshake(datum &d) : preamble{d} {
            version.parse_up_to_delim(d, '\n');
            if (d.is_not_null()) {
                valid = true;
            }
        }

        bool is_not_empty() const { return valid; }

        void write_json(json_object &o, bool metadata=false) {
            (void)metadata;
            if (valid) {
                json_object rfb_json{o, "vnc"};                        // note: "vnc" not "rfb"
                rfb_json.print_key_json_string("version", version);
                rfb_json.close();
            }
        }

        static constexpr mask_and_value<8> matcher{
            { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
            { 'R', 'F', 'B', ' ', '0', '0', '3', '.' }
        };

    };

    /// performs unit tests for VNC/RFB and returns true if all pass,
    /// and false otherwise
    ///
    [[maybe_unused]] static bool unit_test() {

        uint8_t vnc_protocol_version[] = {
            0x52, 0x46, 0x42, 0x20, 0x30, 0x30, 0x33, 0x2e,
            0x30, 0x30, 0x38, 0x0a
        };

        if (protocol_version_handshake::matcher.matches(vnc_protocol_version) != true) {
            return false;  // something is wrong with the matcher
        }

        datum vnc_data{vnc_protocol_version, vnc_protocol_version + sizeof(vnc_protocol_version)};

        uint8_t expected_json_output[] = {
            0x7b, 0x22, 0x76, 0x6e, 0x63, 0x22, 0x3a, 0x7b, 0x22, 0x76, 0x65, 0x72,
            0x73, 0x69, 0x6f, 0x6e, 0x22, 0x3a, 0x22, 0x30, 0x30, 0x33, 0x2e, 0x30,
            0x30, 0x38, 0x22, 0x7d, 0x7d
        };

        protocol_version_handshake pvh{vnc_data};
        if (pvh.is_not_empty()) {
            output_buffer<1024> buf;
            json_object record{&buf};
            pvh.write_json(record);
            record.close();
            if (buf.memcmp(expected_json_output, sizeof(expected_json_output)) == 0) {
                return true;
            }
        }
        return false;
    }

};

namespace {

    [[maybe_unused]] inline int rfb_protocol_version_handshake_fuzz_test(const uint8_t *data, size_t size) {
        return json_output_fuzzer<rfb::protocol_version_handshake>(data, size);
    }

};

#endif // RFB_HPP
