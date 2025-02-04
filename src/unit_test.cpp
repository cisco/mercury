// unit_test.cpp
//
// run unit tests

#include <unistd.h>
#include <cstdio>
#include "libmerc/datum.h"
#include "libmerc/base64.h"
#include "libmerc/tofsee.hpp"
#include "libmerc/snmp.h"
#include "libmerc/ip_address.hpp"
#include "libmerc/watchlist.hpp"

// Macros to colorize output
//
#define RED_ON     "\033[31m"
#define GREEN_ON   "\033[32m"
#define COLOR_OFF  "\033[39m"

int main(int, char *[]) {

    assert(printf("DEBUG enabled\n") == 14);

    FILE *f = stdout;
    int tty = isatty(fileno(f));
    const char *passed = "passed";
    const char *failed = "failed";
    if (tty) {
        passed = GREEN_ON "passed" COLOR_OFF;
        failed = RED_ON   "failed" COLOR_OFF;
    }

    typedef bool (*unit_test_func)();
    struct test_case {
        const char *class_name;
        unit_test_func func;
    };
    test_case test_cases[] = {
        {
            "encoded<uint8_t>",
            &encoded<uint8_t>::unit_test
        },
        {
            "encoded<uint16_t>",
            &encoded<uint16_t>::unit_test
        },
        {
            "encoded<uint32_t>",
            &encoded<uint32_t>::unit_test
        },
        {
            "encoded<uint64_t>",
            &encoded<uint64_t>::unit_test
        },
        {
            "tofsee_initial_message",
            &tofsee_initial_message::unit_test
        },
        {
            "snmp",
            &snmp::unit_test
        },
        {
            "base64",
            &base64::unit_test
        },
        {
            "ipv6_address",
            &ipv6_address::unit_test
        },
    };
    size_t num_tests = 0;
    size_t num_passed = 0;
    for (const auto &tc : test_cases) {
        bool result = tc.func();
        fprintf(f, "%s::unit_test(): %s\n", tc.class_name, result ? passed : failed);
        num_tests++;
        if (result == true) { num_passed++; }
    }

    typedef bool (*unit_test_func_verbose)(FILE *);
    struct test_case_verbose {
        const char *class_name;
        unit_test_func_verbose func;
    };
    test_case_verbose test_cases_verbose[] = {
        {
            "ipv6_address_string",
            &ipv6_address_string::unit_test
        },
        {
            "ipv4_address",
            &ipv4_address::unit_test
        },
        {
            "ipv4_address_string",
            &ipv4_address_string::unit_test
        },
        {
            "server_identifier",
            &server_identifier::unit_test
        },
    };
    for (const auto &tc : test_cases_verbose) {
        bool result = tc.func(nullptr);
        fprintf(f, "%s::unit_test(): %s\n", tc.class_name, result ? passed : failed);
        num_tests++;
        if (result == true) {
            num_passed++;
        } else {
            fprintf(f, "re-running %s::unit_test() in verbose mode:\n", tc.class_name);
            tc.func(f);
        }
    }

    fprintf(f, "%zu out of %zu unit tests passed\n", num_passed, num_tests);

    // the following tests have external dependencies, and thus are
    // not built and run at present
    //
    // fprintf(f, "tls_extensions::unit_test(): %s\n", tls_extensions::unit_test() ? passed : failed);
    // fprintf(f, "bencoding::dictionary::unit_test(): %s\n", bencoding::dictionary::unit_test() ? passed : failed);

    if (num_passed == num_tests) {
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}
