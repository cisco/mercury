// driver for os_identifier
//
// compile as:
//    g++ -I ../libmerc/ -Wall driver_os_identifier.cc -o driver_os_identifier ../libmerc/datum.cc -lz
//
// run as:
//    ./driver_os_identifier mercury.json

#include <iostream>
#include <fstream>

#include "os_identifier.h"

bool verbose = true;  // set to true for details about incomplete mercury_records

int main(int argc, char *argv[]) {
    if (argv[1] == NULL) {
        printf("error: please supply mercury output file\n");
        return -1;
    }
    fprintf(stderr, "processing: %s\n",argv[1]);

    /* initialize OS identification models */
    os_analysis_init("../../resources");

    std::ifstream ifs {argv[1]};
    if (!ifs.is_open()) {
        std::cerr << "Could not open file for reading!\n";
        return -1;
    }
    std::string line;
    while (getline(ifs,line)) {
        /* extract features and update host data */
        os_process_line(line, verbose);
    }

    /* classify all src_ip's */
    os_classify_all_samples();

    return 0;
}
