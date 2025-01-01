// parse.cpp

#include <cstdio>
#include <string>
#include <iostream>
#include <fstream>

#include "libmerc/base64.h"
#include "libmerc/ocsp.hpp"
#include "libmerc/oid.hpp"

// get_datum(std::string &s) returns a datum that corresponds to the
// std::string s.
//
static inline datum get_datum(const std::string &s) {
    uint8_t *data = (uint8_t *)s.c_str();
    return { data, data + s.length() };
}

template <typename T>
void parse_and_write_json(datum &d) {
    //
    // parse line, then write json
    //
    T msg{d};
    if (!msg.is_valid()) {
        return;
    }
    output_buffer<8192> buf;
    json_object_asn1 o{&buf};
    msg.write_json(o);
    o.close();
    buf.write_line(stdout);
}



int main(int argc, char *argv[]) {

    fprintf(stdout, "oid_unit_test: %s\n", oid_unit_test() ? "passed" : "failed");

    bool hex = false;
    bool base64 = false;
    if (argc == 2 and strcmp(argv[1], "--hex") == 0) {
        hex = true;
    }
    if (argc == 2 and strcmp(argv[1], "--base64") == 0) {
        base64 = true;
    }

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.length() == 0) {
            // break;  // assume no more input
            fprintf(stdout, "warning: ignoring empty line\n");
            continue; // ignore empty line
        }

        if (hex) {
            //
            // if line starts and ends with quotations, ignore them
            //
            if (line.length() >= 2 and line.front() == '\"' and line.back() == '\"') {
                line = line.substr(1,line.length()-2);
            }
            data_buffer<4096> buf;
            buf.copy_from_hex((uint8_t *)line.c_str(), line.length());
            datum d = buf.contents();
            if (d.is_null()) {
                fprintf(stderr, "error reading line\n");
                return 0;
            } else {
                fprintf(stderr, "----------------------------------------------------\n");
                d.fprint_hex(stderr); fputc('\n', stderr);
                parse_and_write_json<ocsp::response>(d);

                //            return 0; // EARLY RETURN
            }

        } else if (base64) {
            //
            // if line starts and ends with quotations, ignore them
            //
            if (line.length() >= 2 and line.front() == '\"' and line.back() == '\"') {
                line = line.substr(1,line.length()-2);
            }

            uint8_t buf[4096];
            int retval = base64::decode(buf, sizeof(buf), line.c_str(), line.length());
            if (retval < 0) {
                fprintf(stderr, "error converting line from base64 (%s)\n", line.c_str());
                return EXIT_FAILURE;
            }
            datum d = { buf, buf + retval };
            fprintf(stderr, "----------------------------------------------------\n");
            d.fprint_hex(stderr); fputc('\n', stderr);
            parse_and_write_json<ocsp::response>(d);



        } else {
            datum d = get_datum(line);
            fprintf(stdout, "----------------------------------------------------\n");
            d.fprint(stdout); fputc('\n', stdout);
        }

        // parse line, then write json
        //
        // ocsp::response msg{d};
        // output_buffer<4096> buf;
        // json_object_asn1 o{&buf};
        // msg.write_json(o);
        // o.close();
        // buf.write_line(stdout);

    }
    fprintf(stderr, "----------------------------------------------------\n");

    return 0;
}
