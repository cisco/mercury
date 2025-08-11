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
};

[[maybe_unused]] inline int esp_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<esp>(data, size);
}

#endif // ESP_H
