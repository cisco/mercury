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
 * PPP protocol type definitions
*/
#define PPP_TYPE_NONE   0x0000

#define PPP_TYPE_IP     0x0021
#define PPP_TYPE_IPV6   0x0057

/*
 * ppp
 *
 */

class ppp {
    uint16_t ppptype = PPP_TYPE_NONE;
    uint8_t flag = 0x00;
    uint8_t address = 0x00;
    uint8_t control = 0x00;

 public:

    static bool get_ip(datum &pkt) {
        ppp ppp_frame{pkt};
        uint16_t ppptype = ppp_frame.get_ppptype();
        switch(ppptype) {
        case PPP_TYPE_IP:
        case PPP_TYPE_IPV6:
            return true;
            break;
        default:
            ;
        }
        return false;  // not an IP packet
    }

    uint16_t get_ppptype() const { return ppptype; }

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

        p.lookahead_uint8(&curr_byte);
        if (curr_byte & PPP_PROTOCOL_MASK) {
            if (!p.read_uint8(&ppptype)) {
                ppptype = PPP_TYPE_NONE;
                return;
            }
        }
        else {
            if (!p.read_uint16(&ppptype))
                ppptype = PPP_TYPE_NONE;
        }
        
        return;
    }

};


#endif  /* PPP_H */