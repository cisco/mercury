/*
 * ppp.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef PPP_H
#define PPP_H

#include "datum.h"

#define PPP_FRAME_FLAG      0x7E
#define PPP_ADDRESS_FIELD   0xFF
#define PPP_CONTROL_FIELD   0x03

#define PPP_PROTOCOL_MASK   0x01

/*
 * ppp
 *
 */

// PPP frame (following RFC 1661)
//
//  +----------+----------+----------+----------+-------------+---------+------------+----------+
//  | Flag     | Address  | Control  | Protocol | Information | Padding | Checksum   | Flag     |
//  | 8 bits   | 8 bits   | 8 bits   | 8/16 bits|      *      |    *    | 16/32 bits |  8 bits  |
//  +----------+----------+----------+----------+-------------+---------+------------+----------+

class ppp {
    
    enum protocol : uint16_t {
        type_none = 0x0000, 
        ipv4      = 0x0021, // ipv4 encapsulation
        ipv6      = 0x0057  // ipv6 encapsulation
    };

    class variable_len_proto {
        ppp::protocol proto = ppp::type_none;

    public:

        void set_proto(datum &d) {
            uint16_t value = 0;
            uint8_t b;

            d.lookahead_uint8(&b);
            if (b & PPP_PROTOCOL_MASK) {
                if (!d.read_uint8(&b)) {
                    proto = ppp::type_none;
                    return;
                }
                proto = (ppp::protocol)b;
            }
            else {
                for (int i=0; i<2; i++) {
                    value *= 256;
                    d.read_uint8(&b);
                    value += b;
                }
                proto = (ppp::protocol)value;
            }
        }

        ppp::protocol get_proto_type() const { return proto; }    
    };

    variable_len_proto protocol_type;
    uint8_t flag = 0x00;
    uint8_t address = 0x00;
    uint8_t control = 0x00;

 public:

    static bool is_ip(datum &pkt) {
        ppp ppp_frame{pkt};
        ppp::protocol ppptype = ppp_frame.protocol_type.get_proto_type();
        switch(ppptype) {
        case ppp::ipv4:
        case ppp::ipv6:
            return true;
            break;
        default:
            ;
        }
        return false;  // not an IP packet
    }

    ppp(struct datum &p) {
        uint8_t curr_byte;

        p.lookahead_uint8(&curr_byte);
        if (curr_byte == PPP_FRAME_FLAG) {
            p.read_uint8(&flag);
            p.lookahead_uint8(&curr_byte);
            if (curr_byte == PPP_ADDRESS_FIELD) {
                p.read_uint8(&address);
                p.read_uint8(&control);
            }
        }
        else if (curr_byte == PPP_ADDRESS_FIELD) {
            p.read_uint8(&address);
            p.read_uint8(&control);    
        }

        protocol_type.set_proto(p);
        
        return;
    }

};


#endif  /* PPP_H */