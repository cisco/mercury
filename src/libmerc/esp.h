// esp.h
//

#ifndef ESP_H
#define ESP_H

#include "datum.h"
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

// class esp represents an ESP packet observed on the wire
//
class esp {
    datum spi;
    datum seq;

public:

    esp(datum &d) : spi{d, 4}, seq{d, 4} { }

    bool is_not_empty() {
        return true;
    }

    void write_json(json_object &o, bool metadata_output=false) const {
        (void)metadata_output;
        json_object esp_json{o, "esp"};
        esp_json.print_key_hex("spi", spi);
        esp_json.print_key_hex("seq", seq);
        esp_json.close();
    }
};


#endif // ESP_H
