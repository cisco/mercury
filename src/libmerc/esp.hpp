// esp.h
//

#ifndef ESP_H
#define ESP_H

#include "datum.h"
#include "protocol.h"
#include "json_object.h"

//  ESP format (following RFC 4303, Figure 1)
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
//   |               Security Parameters Index (SPI)                 | ^Int.
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
//   |                      Sequence Number                          | |ered
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | ----
//   |                    Payload Data* (variable)                   | |   ^
//   ~                                                               ~ |   |
//   |                                                               | |Conf.
//   +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
//   |               |     Padding (0-255 bytes)                     | |ered*
//   +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |   |
//   |                               |  Pad Length   | Next Header   | v   v
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ------
//   |         Integrity Check Value-ICV   (variable)                |
//   ~                                                               ~
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//   The ESN facility allows use of a 64-bit sequence number for an SA.
//   (See Appendix A, "Extended (64-bit) Sequence Numbers", for details.)
//   Only the low-order 32 bits of the sequence number are transmitted in
//   the plaintext ESP header of each packet.
//
//   The SPI value of zero (0) is reserved for local, implementation-
//   specific use and MUST NOT be sent on the wire.
//
//   The sequence number is a monotonically increasing unsigned 32-bit
//   integer in network byte order.  The first ESP packet sent for a
//   given SPI has a value of 1.

// class esp represents an ESP packet observed on the wire
//
// ESP can be carried in UDP (RFC 3948), in which case the
// non_esp_marker is used to distinguish ESP from IKE
//

// ESP can run over IP as protocol 50, or run over UDP, with the
// default port of 500, in which case it is usually multiplexed
// with IKE over the same port
//
#ifdef _WIN32
static const uint16_t esp_default_port = hton<uint16_t>(4500);
#else
static constexpr uint16_t esp_default_port = hton<uint16_t>(4500);
#endif

class esp : public base_protocol {
    datum spi;
    datum seq;
    datum payload;
    bool valid = false;

public:

    esp(datum &d) : spi{d, 4}, seq{d, 4}, payload{d} {
        std::array<uint8_t, 4> non_esp_marker = { 0x00, 0x00, 0x00, 0x00 };
        if (d.is_not_empty() and spi.equals(non_esp_marker) == false) {

            // to limit the volume of output, we only write out
            // JSON records for seq == 1, which should be the
            // first ESP packet for a security association
            //
            if (!seq.equals(std::array<uint8_t,4>{0x00, 0x00, 0x00, 0x01})) {
                return;
            }
            valid = true;
        }
    }

    bool is_not_empty() {
        return valid;
    }

    void write_json(json_object &o, bool metadata_output=false) const {
        if (valid) {
            json_object esp_json{o, "esp"};
            esp_json.print_key_hex("spi", spi);
            esp_json.print_key_hex("seq", seq);
            esp_json.print_key_uint("payload_length", payload.length());

            if (metadata_output) {
                //
                // print out initial bytes of payload
                //
                datum tmp = payload;
                tmp.trim_to_length(32);
                esp_json.print_key_hex("payload", tmp);
            }
            esp_json.close();
        }
    }

    void write_l7_metadata(cbor_object &o, bool) {
        cbor_array protocols{o, "protocols"};
        protocols.print_string("esp");
        protocols.close();
    }

};

[[maybe_unused]] inline int esp_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<esp>(data, size);
}

namespace esp_unit_test {
#ifndef NDEBUG
    inline bool unit_test() {
        char buffer[2048];

        uint8_t esp_first[] = {
            0x12, 0x34, 0x56, 0x78,
            0x00, 0x00, 0x00, 0x01,
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04
        };
        datum d1{esp_first, esp_first + sizeof(esp_first)};
        esp pkt1{d1};
        if (!pkt1.is_not_empty()) return false;
        {
            buffer_stream buf{buffer, sizeof(buffer)};
            json_object json{&buf};
            pkt1.write_json(json, true);
            json.close();
            buf.write_char('\0');
            if (!strstr(buffer, "12345678")) return false;
        }

        uint8_t esp_not_first[] = { 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x02, 0xde, 0xad, 0xbe, 0xef };
        datum d2{esp_not_first, esp_not_first + sizeof(esp_not_first)};
        esp pkt2{d2};
        if (pkt2.is_not_empty()) return false;

        uint8_t non_esp[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef };
        datum d3{non_esp, non_esp + sizeof(non_esp)};
        esp pkt3{d3};
        if (pkt3.is_not_empty()) return false;

        return true;
    }
#endif
} // namespace esp_unit_test

#endif // ESP_H
