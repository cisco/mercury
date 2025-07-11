// asn1.cpp
//
// generic asn1 parsing
//
// compilation:
//    g++ -Wall -Wno-deprecated-declarations -Wno-narrowing asn1.cpp libmerc/asn1.cc libmerc/asn1/oid.cc libmerc/utils.cc -o asn1

#include "libmerc/datum.h"
#include "libmerc/asn1.h"
#include "libmerc/utils.h"
#include <string>
#include <iostream>

int main(int, char *[]) {

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

        // perform recursive ASN.1 parsing of data, writing json
        // representation
        //
        output_buffer<4096> buf;
        json_array a{&buf};
        tlv::recursive_parse(d, a);
        a.close();
        buf.write_line(stdout);

    }

    return 0;
}
