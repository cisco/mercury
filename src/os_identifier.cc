/* os_identifier.cc
 *
 * driver program for os_identifier.h
 *
 * compile as:
 *    g++ -I ../libmerc/ -Wall os_identifier.cc -o os_identifier ../libmerc/datum.cc -lz
 *
 * run as:
 *
 *    ./os_identifier <json-file>
 *
 * where <json-file> is a mercury JSON output file containing fingerprints
 */

#include <iostream>
#include <fstream>

#include "os-identification/os_identifier.h"

bool verbose = false;  // set to true for details about incomplete mercury_records

int main(int argc, char *argv[]) {
    if (argc != 2 || argv[1] == NULL) {
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
