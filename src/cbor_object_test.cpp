// cbor_object_test.cpp
//
// Test/example driver for the classes cbor_object, cbor_array,
// cbor_object_compact, and cbor_to_json_translator.
//
// License: https://github.com/cisco/mercury/blob/master/LICENSE

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

    decode_fprint_json(data_buf.contents(), stdout);

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
        {
            cbor_array nested_array{a};
            nested_array.print_string("this string is in a nested array");
            nested_array.close();
        }
        a.close();
    }

    o.print_key_bool("cbor_is_fun", true);
    o.print_key_null("latin word for none");

    o.close();
    data_buf.contents().fprint_hex(stdout); fputc('\n', stdout);

    decode_fprint_json(data_buf.contents(), stdout);

    data_buf.reset();
    {
        cbor_object nested_array_example{data_buf};
        {
            cbor_array outer_array{nested_array_example, "outer_array"};
            {
                cbor_array inner_array{outer_array};
                inner_array.print_string("foobar");
                inner_array.close();
            }
            outer_array.close();
        }
        nested_array_example.close();
    }
    data_buf.contents().fprint_hex(stdout); fputc('\n', stdout);
    decode_fprint_json(data_buf.contents(), stdout);

    // cbor_object_compact uses short integers as keys, instead of
    // text strings, to reduce the size of maps
    //
    constexpr static_dictionary<9> dict = {
        {
            "unknown",
            "metadata",
            "flow_key",
            "event_start",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol"
        }
    };
    data_buf.reset();
    {
        cbor_object_compact compact{data_buf, dict};
        compact.print_key_string("metadata", "none");
        {
            cbor_object_compact nested_object{compact, "flow_key", dict};
            nested_object.print_key_string("src_ip", "192.168.1.1");
            nested_object.print_key_uint("src_port", 443);
            nested_object.close();
        }
        compact.print_key_uint("event_start", 1753877684);
        //compact.print_key_uint("this_key_is_not_in_the_dictionary", 0);
        compact.close();
    }
    data_buf.contents().fprint_hex(stdout); fputc('\n', stdout);
    decode_fprint_json(data_buf.contents(), stdout);

    vocabulary v{dict};
    decode_fprint_json(data_buf.contents(), stdout, &v);

    // write static_dictionary into a CBOR record, to facilitate translation
    //
    data_buf.reset();
    {
        cbor_object encoded_dict{data_buf};
        {
            cbor_array words{encoded_dict, "words"};
            for (const auto & word : dict) {
                words.print_string(word);
            }
            words.close();
        }
        encoded_dict.close();
    }
    data_buf.contents().fprint_hex(stdout); fputc('\n', stdout);
    decode_fprint_json(data_buf.contents(), stdout);

    datum encoded_dict_data = data_buf.contents();
    vocabulary voc{encoded_dict_data};

    /// TODO:
    ///
    ///   - simpify and push functionality into base classes
    ///   - constexpr
    ///   - unit tests
    ///   - fuzz tests
    ///   - document
    ///   - use tag to indicate "process the following data as a fingerprint"???
    ///

    return 0;
}
