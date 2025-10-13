// snmp.cpp
//
// SNMP parsing
//
// compilation:
//    g++ -Wall -Wno-deprecated-declarations -Wno-narrowing snmp.cpp libmerc/asn1/oid.cc libmerc/utils.cc -o snmp

#include "libmerc/datum.h"
#include "libmerc/asn1.h"
#include "libmerc/utils.h"
#include "libmerc/snmp.hpp"
#include <string>
#include <iostream>

int main(int, char *[]) {

    std::array<uint8_t, 30> var_bind_data = {
        0x30, 0x0d, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02, 0x05, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x08, 0x05, 0x00
    };

    output_buffer<4096> buf;
    json_object o{&buf};
    datum var_bind_datum{var_bind_data};
    o.print_key_hex("var_bind", var_bind_datum);
    snmp::var_bind vb{var_bind_datum};
    if (vb.is_not_empty()) {
        vb.write_json(o);
    }
    o.close();
    buf.write_line(stdout);
    return 0;

    std::string line;
    while (std::getline(std::cin, line)) {

        // decode hex line to raw binary data
        //
        uint8_t rawbuf[4096];
        size_t num_bytes = hex_to_raw(rawbuf, sizeof(rawbuf), line.c_str());
        if (num_bytes == 0) {
            fprintf(stderr, "note: ignoring empty line\n");
            continue; // omit further processing, go to next line
        }
        datum d{rawbuf, rawbuf + num_bytes};

        // parse data as an SNMP packet, then write out the JSON
        // representation
        //

        snmp::packet snmp{d};
        if (snmp.is_not_empty()) {
            output_buffer<4096> buf;
            json_object o{&buf};
            snmp.write_json(o);
            o.close();
            buf.write_line(stdout);
        }

    }

    return 0;
}
