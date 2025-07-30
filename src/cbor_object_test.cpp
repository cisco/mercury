/*
 * cbor_object_test.cc
 *
 * test driver for json output code
 *
 * Copyright (c) 2021 Cisco Systems, Inc.  All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <stdio.h>

#include "libmerc/cbor_object.hpp"

int main() {

    // write an example mercury JSON output to a buffer
    //
    dynamic_buffer data_buf{4096};
    cbor_object r{data_buf};
    {
        cbor_object fingerprints{r, "fingerprints"};
        fingerprints.print_key_string("tcp", "(7210)(020405b4)(04)(08)(01)(030307)");
        fingerprints.close();
    }
    r.print_key_string("src_ip", "10.0.2.15");
    r.print_key_string("dst_ip", "172.217.7.228");
    r.print_key_uint("protocol", 6);
    r.print_key_uint("src_port", 3759);
    r.print_key_uint("dst_port", 443);
    // r.print_key_float("event_start", 1565099169.266276);
    r.close();
    data_buf.contents().fprint_hex(stdout); fputc('\n', stdout);

    // write some test output
    //
    data_buf.reset();
    struct cbor_object o{data_buf};
    o.print_key_string("key", "value");
    o.print_key_string("another_key", "another_value");
    {
        struct cbor_object n{o, "nested"};
        n.print_key_string("day", "Monday");
        n.print_key_string("month", "April");
        {
            struct cbor_object nn{n, "double_nested"};
            nn.print_key_uint("two_plus_two", 5);
            nn.print_key_string("note", "for very large values of two");
            nn.close();
        }
        n.close();
    }
    o.print_key_string("addendum", "this is just to test commas");
    {
        cbor_array a{o, "numerology"};
        {
            cbor_object oa{a};
            oa.print_key_string("note", "the key value pair is wrapped in an object");
            oa.close();
        }
        {
            cbor_object oa{a};
            oa.print_key_string("foo", "bar");
            oa.close();
        }
        {
            cbor_object oa{a};
            oa.print_key_string("author", "Thomas Pynchon");
            oa.close();
        }
        {
            cbor_object oa{a};
            oa.print_key_string("title", "Gravity's Rainbow");
            oa.close();
        }
        a.close();
    }

    o.print_key_bool("cbor_is_fun", true);
    o.print_key_null("latin word for none");

    o.close();
    data_buf.contents().fprint_hex(stdout); fputc('\n', stdout);

    // struct cbor_object o2{&buf2};
    // {
    //     struct cbor_array a{o2, "features"};
    //     {
    //         cbor_array b{a};
    //         b.print_string("abc");
    //         b.print_string("def");
    //         b.close();
    //         //a.print_string("xzy");
    //         cbor_array b2{a};
    //         b2.print_string("abc");
    //         b2.print_string("def");
    //         b2.close();
    //     }
    //     a.close();
    // }
    // o2.close();
    // buf2.write_line(stdout);

    data_buf.reset();
    static_dictionary<3> dict{
        {
            "metadata",
            "flow_key",
            "start_time"
        }
    };
    static_dictionary<5> flow_key_dict{
        {
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol"
        }
    };
    {
        cbor_object_compact compact{data_buf, dict};
        compact.print_key_string("metadata", "none");
        {
            cbor_object_compact nested_object{compact, "flow_key", flow_key_dict};
            nested_object.print_key_string("src_ip", "192.168.1.1");
            nested_object.print_key_uint("src_port", 443);
        }
        compact.print_key_uint("start_time", 1753877684);
    }
    data_buf.contents().fprint_hex(stdout); fputc('\n', stdout);

    return 0;
}
