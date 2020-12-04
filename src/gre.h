// gre.h


#ifndef GRE_H
#define GRE_H

#include "datum.h"

/*
 *     Generic Routing Encapsulation (GRE) as per RFC 2784
 *
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |C|       Reserved0       | Ver |         Protocol Type         |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |      Checksum (optional)      |       Reserved1 (Optional)    |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *     GRE as per RFC 1701
 *
 *         0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |C|R|K|S|s|Recur|  Flags  | Ver |         Protocol Type         |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |      Checksum (optional)      |       Offset (optional)       |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                         Key (optional)                        |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                    Sequence Number (optional)                 |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                         Routing (optional)
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

class gre_header {
 public:

 gre_header(struct datum &d) : protocol_type{0} {
        if (d.length() < (int)sizeof(uint32_t)) {
            d.set_null();
            return;
        }
        std::array<uint8_t, 2> flags_bytes;
        d.read_array(flags_bytes);
        d.read_uint16(&protocol_type);
        if (d.is_not_null() && (flags_bytes[0] & 0x80)) {
            d.skip(4);  // skip over Checksum and Offset fields
        }
    }

    uint16_t get_protocol_type() { return protocol_type; }

 private:
    uint16_t protocol_type;
};

#endif
