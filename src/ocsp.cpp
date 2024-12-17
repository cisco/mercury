// ocsp.cpp
//
// online certificate status checking protocol test driver

#include <cstdio>
#include "libmerc/ocsp.hpp"

int main(int argc, char *argv[]) {

    FILE *output = nullptr;
    if (argc == 2 and strcmp(argv[1], "verbose") == 0) {
        output = stdout;   // verbose output
    } else if (argc > 2) {
        fprintf(stderr, "error: too many arguments\n\nusage: %s [verbose]\n", argv[0]);
    }

    bool passed = ocsp::request::unit_test(output);
    printf("ocsp::request::unit_test %s\n", passed ? "passed" : "failed");

    return 0;
}
