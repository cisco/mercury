// util_obj.h
//
// utility objects
//
// Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
// License at https://github.com/cisco/mercury/blob/master/LICENSE


#ifndef UTIL_OBJ_H
#define UTIL_OBJ_H

#include "datum.h"
#include "buffer_stream.h"

struct ipv4_addr : public datum {
    static const unsigned int bytes_in_addr = 4;
    ipv4_addr() : datum{} { }

    void parse(struct datum &d) {
        datum::parse(d, bytes_in_addr);
    }

    void operator()(struct buffer_stream &b) const {
        b.write_char('\"');
        if (data) {
            b.write_ipv4_addr(data);
        }
        b.write_char('\"');
    }
};

struct ipv6_addr : public datum {
    static const unsigned int bytes_in_addr = 16;
    ipv6_addr() : datum{} { }

    void parse(struct datum &d) {
        datum::parse(d, bytes_in_addr);
    }

    void operator()(struct buffer_stream &b) const {
        b.write_char('\"');
        if (data) {
            b.write_ipv6_addr(data);
        }
        b.write_char('\"');
    }
};

#endif // UTIL_OBJ_H

