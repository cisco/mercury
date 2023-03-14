// reader.cpp
//
// example driver for ipv4/ipv6/hostname/subnet watchlist

#include <cstdio>
#include <string>
#include <iostream>
#include <fstream>

#include "libmerc/watchlist.hpp"

int main(int argc, char *argv[]) {

    std::ios::sync_with_stdio(false);  // for performance

    // run unit test functions
    //
    if (ipv6_address_string::unit_test() == false) {
        fprintf(stderr, "error: ipv6_address_string::unit_test() failed\n");
        return EXIT_FAILURE;
    }
    if (ipv4_address_string::unit_test() == false) {
        fprintf(stderr, "error: ipv4_address_string::unit_test() failed\n");
        return EXIT_FAILURE;
    }

    std::ifstream doh_file{"doh.txt"};
    watchlist doh{doh_file};
    //  watchlist doh{std::cin};
    // doh.print();

    // loop over input lines, parsing each line as an ipv4_addr or
    // dns_name and then testing them against the watchlist
    //
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.length() == 0) {
            // break;  // assume no more input
            // fprintf(stdout, "warning: empty line\n");
            continue; // ignore empty line
        }
        datum d = get_datum(line);

        //        fprintf(stdout, "----------------------------------------------------\n");
        d.fprint(stdout); // fputc('\n', stdout);

        host_identifier hid = host_identifier_constructor(d);

        if (std::holds_alternative<std::monostate>(hid)) {
            // fprintf(stdout, "\tnot a valid host identifier\n");
            continue;  // not a valid hid; don't process it further
        }

        if (doh.contains(hid)) {
            fprintf(stdout, "\tHIT\n");
        } else {
            fprintf(stdout, "\tMISS\n");
            //exit(EXIT_FAILURE);
        }

    }

    return 0;
}
