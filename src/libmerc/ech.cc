/*
 * ech.cc
 *
 * Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <string>

#include "ech.hpp"


// ech_config_get_json_string() is used by the cython library
//
std::string ech_config_get_json_string(const char *ech_config, ssize_t ech_config_len) {
    char buffer[1024];
    struct buffer_stream buf(buffer, sizeof(buffer));
    struct json_object ech_config_json{&buf};
    struct datum tmp_ech_config{(uint8_t *)ech_config, (uint8_t *)ech_config + ech_config_len};
    struct ech_config d{tmp_ech_config};
    d.write_json(ech_config_json);
    ech_config_json.close();
    std::string tmp_str(buffer, buf.length());
    return tmp_str;
}
