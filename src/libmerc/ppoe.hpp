/*
 * ppoe.hpp
 *
 * Copyright (c) 2025 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef PPPOE_HPP
#define PPPOE_HPP

#include "datum.h"

// PPoE Header
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  VER  | TYPE  |      CODE     |          SESSION_ID           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |            LENGTH             |           payload             ~
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class ppoe {
    datum version_and_type;
    datum code;
    datum session_id;
    datum length;

public:
    ppoe(struct datum &d) :
        version_and_type(d, 1),
        code(d, 1),
        session_id(d, 2),
        length(d, 2) { }
};

namespace {

    [[maybe_unused]] inline int ppoe_fuzz_test(const uint8_t *data, size_t size) {
        struct datum pkt_data{data, data+size};
        ppoe ppoe_object{pkt_data};
        return 0;
    }

};

#endif
