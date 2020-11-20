#include <stdio.h>

#include "json_object.h"

int main() {

#if 0
    // write an example mercury JSON output to stdout
    //
    struct json_file_object record{stdout};
    {
        struct json_file_object fingerprints{record, "fingerprints"};
        fingerprints.print_key_string("tcp", "(7210)(020405b4)(04)(08)(01)(030307)");
        fingerprints.close();
    }
    record.print_key_string("src_ip", "10.0.2.15");
    record.print_key_string("dst_ip", "172.217.7.228");
    record.print_key_uint("protocol", 6);
    record.print_key_uint("src_port", 3759);
    record.print_key_uint("dst_port", 443);
    record.print_key_float("event_start", 1565099169.266276);
    record.close();

    fprintf(stdout, "\n"); // one object per line
#endif // 0

    // write an example mercury JSON output to a buffer
    //
    char buffer[16384];
    struct buffer_stream buf(buffer, sizeof(buffer));
    {
        struct json_object r{&buf};
        {
            struct json_object fingerprints{r, "fingerprints"};
            fingerprints.print_key_string("tcp", "(7210)(020405b4)(04)(08)(01)(030307)");
            fingerprints.close();
        }
        r.print_key_string("src_ip", "10.0.2.15");
        r.print_key_string("dst_ip", "172.217.7.228");
        r.print_key_uint("protocol", 6);
        r.print_key_uint("src_port", 3759);
        r.print_key_uint("dst_port", 443);
        r.print_key_float("event_start", 1565099169.266276);
        r.close();
    }
    buf.write(stdout);

    //    return 0; // for now

    // write some test output
    //
    fprintf(stdout, "\n");
    struct buffer_stream buf2(buffer, sizeof(buffer));
    struct json_object o{&buf2};
    o.print_key_string("key", "value");
    o.print_key_string("another_key", "another_value");
    {
        struct json_object n{o, "nested"};
        n.print_key_string("day", "Monday");
        n.print_key_string("month", "April");
        {
            struct json_object nn{n, "double_nested"};
            nn.print_key_uint("two_plus_two", 5);
            nn.print_key_string("note", "for very large values of two");
            nn.close();
        }
        n.close();
    }
    o.print_key_string("addendum", "this is just to test commas");
    {
        struct json_array a{o, "numerology"};
        {
            struct json_object oa{a};
            oa.print_key_string("note", "the key value pair is wrapped in an object");
            oa.reinit(a);
            oa.print_key_string("foo", "bar");
            oa.reinit(a);
            oa.print_key_string("author", "Thomas Pynchon");
            oa.print_key_string("title", "Gravity's Rainbow");
            oa.close();
        }
        a.close();
    }

    // const unsigned char method[5] = "POST";
    // struct parser p{method, method + 4};
    // o.print_key_hex("hex", p);
    o.print_key_bool("json_is_fun", true);
    o.print_key_null("latin word for none");

    o.close();
    buf2.write_line(stdout);

    return 0;
}
