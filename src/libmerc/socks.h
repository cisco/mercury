/*
 * socks.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

/*
 * \file socks.h
 *
 * \brief interface file for SOCKS4, SOCKS5, and sub-auth code
 */
#ifndef SOCKS_H
#define SOCKS_H

#include "json_object.h"
#include "match.h"


class socks4_req {
    encoded<uint8_t> version;
    encoded<uint8_t> cmd;
    encoded<uint16_t> port;
    encoded<uint32_t> ip;
    datum id;
    datum domain;
    bool socks4a;   // true if extended ver of SOCKS4_c, called SOCKS4_a, with domain name
    bool is_valid;

    void parse(datum &pkt) {
        id.parse_up_to_delim(pkt, 0x00);
        if (id.data_end == pkt.data_end) {
            // delim not found
            return;
        }
        if (id.data_end == (pkt.data_end-1)) {
            // no domain name
            is_valid = true;
            return;
        }
        pkt.skip(1);    // skip 0x00
        domain.parse_up_to_delim(pkt, 0x00);
        if (domain.data_end == pkt.data_end) {
            // delim not found
            return;
        }
        if (domain.data_end == (pkt.data_end-1)) {
            is_valid = true;
            socks4a = true;
            return;
        }
        // did not reach pkt end
        is_valid = false;
        return;
    }

public:
    socks4_req(datum &pkt) :
        version{pkt},
        cmd{pkt},
        port{pkt},
        ip{pkt},
        id{nullptr,nullptr},
        domain{nullptr,nullptr},
        socks4a{false},
        is_valid{false} { parse(pkt); }

    static constexpr mask_and_value<4> matcher{
        { 0xff, 0xfc, 0x00, 0x00 },
        { 0x04, 0x00, 0x00, 0x00 }
    };

    // For SOCKS4, skipping the ver, cmd, port, ip, user-id follows (printable ASCII) and null byte
    // followed by optional domain name and null byte
    // check first and last byte of id for ascii printable and null termination
    static ssize_t get_payload_length(datum pkt) {
        ssize_t len = pkt.length();
        pkt.skip(8);
        if (!pkt.is_not_empty()) {
            return 0;
        }
        if ((pkt.length() == 1 && *pkt.data == 0x00)
            || ((*pkt.data>=32 || *pkt.data==0x00) && *(pkt.data_end-2)>=32 && *(pkt.data_end-1)==0x00)) {
                return len; 
        }
        else {
            return 0;
        }
    }

    uint8_t get_code() const {return cmd;}

    const char* get_code_str() const {
        switch (cmd) {
            case 0x01 : return "CONNECT";
            case 0x02 : return "BIND";
            default : return nullptr;
        }
    }

    void write_json(struct json_object &record, bool output_metadata) {
        if (!is_valid) {
            return;
        }
        json_object socks4_pkt(record, "socks4");
        type_codes<socks4_req> code(*this);
        socks4_pkt.print_key_value("cmd", code);
        socks4_pkt.print_key_int("port",port);
        if (output_metadata) {
            uint32_t ip_val = htonl(ip.value());
            socks4_pkt.print_key_ipv4_addr("ip",(uint8_t*)&ip_val);
        }
        socks4_pkt.print_key_json_string("id",id);
        if (socks4a) {
            if (output_metadata) {
                socks4_pkt.print_key_bool("socks4a", true);
            }
            socks4_pkt.print_key_json_string("domain",domain);
        }
    }

    bool is_not_empty() const { return (is_valid); }
};









#endif  // SOCKS_H 