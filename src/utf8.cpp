// utf8.cpp
//
// test driver for utf8 class

#include <cstdio>

#include "libmerc/datum.h"
#include "libmerc/json_object.h"
#include "libmerc/utf8.hpp"

int main(int, char *[]) {

    FILE *output = stdout;
    printf("utf8_string::unit_test(): %s\n", utf8_string::unit_test(output) ? "passed" : "failed");

    return 0;
}
