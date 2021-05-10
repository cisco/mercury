/*
 * dns.cc
 *
 * Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <string>

#include "dns.h"


// dns_get_json_string() is used by the cython library
//
std::string dns_get_json_string(const char *dns_pkt, ssize_t pkt_len) {
    char buffer[8192*8];
    struct buffer_stream buf(buffer, sizeof(buffer));
    struct json_object dns{&buf};
    struct datum tmp_dns_pkt{(uint8_t *)dns_pkt, (uint8_t *)dns_pkt + pkt_len};
    struct dns_packet d{tmp_dns_pkt};
    d.write_json(dns);
    dns.close();
    std::string tmp_str(buffer, buf.length());
    return tmp_str;
}

