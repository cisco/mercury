// cbor.cpp

#include <cstdio>
#include <vector>
#include <cctype>
#include <iostream>
#include <fstream>

#include "options.h"
#include "libmerc/cbor.hpp"
#include "libmerc/fdc.hpp"
#include "libmerc/file_datum.hpp"

using namespace mercury_option;

int main(int argc, char *argv[]) {

    // run unit tests (when NDEBUG is not defined)
    //
    assert(static_dictionary<0>::unit_test() == true);
    assert(cbor::unit_test() == true);
    assert(cbor_fingerprint::unit_test() == true);
    assert(fdc::unit_test() == true);

    const char *summary = "usage: %s [OPTIONS]\n";
    option_processor opt({
            { argument::none,     "--decode-cbor",        "decode input as generic CBOR" },
            { argument::none,     "--decode-fdc",         "decode input as FDC" },
            { argument::none,     "--encode-fingerprint", "encode fingerprint string as CBOR" },
            { argument::required, "--input-file",         "read data from file <filename>" },
            { argument::none,     "--verbose-tests",      "run unit tests in verbose mode" },
            { argument::none,     "--help",               "print out help message" },
        });

    if (!opt.process_argv(argc, argv)) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    auto [ input_file_is_set, input_file ] = opt.get_value("--input-file");
    bool decode_cbor    = opt.is_set("--decode-cbor");
    bool decode_fdc     = opt.is_set("--decode-fdc");
    bool encode_fp      = opt.is_set("--encode-fingerprint");
    bool verbose_tests  = opt.is_set("--verbose-tests");
    bool help_needed    = opt.is_set("--help");
    if (help_needed) {
        opt.usage(stdout, argv[0], summary);
        return 0;
    }

    if (verbose_tests) {
        bool sd_result = static_dictionary<0>::unit_test(stdout);
        bool cbor_result = cbor::unit_test(stdout);
        bool cbor_fingerprint_result = cbor_fingerprint::unit_test(stdout);
        bool fdc_result = fdc::unit_test(stdout);

        printf("static_dictionary::unit_test: %s\n", sd_result ? "passed" : "failed");
        printf("cbor::unit_test: %s\n", cbor_result ? "passed" : "failed");
        printf("cbor_fingerprint::unit_test: %s\n", cbor_fingerprint_result ? "passed" : "failed");
        printf("fdc::unit_test: %s\n", fdc_result ? "passed" : "failed");

        if (sd_result and cbor_result and cbor_fingerprint_result and fdc_result) {
            printf("all unit tests passed\n");
            return EXIT_SUCCESS;
        }
        fprintf(stderr, "error: one or more unit tests failed\n");
        return EXIT_FAILURE;
    }

    if (input_file_is_set) {

        if (encode_fp) {
            fprintf(stderr, "error: option --encode-fingerprint is incompatible with --input-file\n");
            return EXIT_FAILURE;
        }

        file_datum input{input_file.c_str()};
        if (decode_cbor) {
            bool decode_ok = cbor::decode_fprint(input, stdout);
            if (!decode_ok) {
                fprintf(stderr, "error: could not decode complete input file\n");
                return EXIT_FAILURE;
            }
        }
        if (decode_fdc) {
            static const size_t MAX_DST_ADDR_LEN   = 48;
            static const size_t MAX_SNI_LEN        = 257;
            static const size_t MAX_USER_AGENT_LEN = 512;
            static const size_t MAX_FP_STR_LEN     = 4096;
            char fp_str[MAX_FP_STR_LEN];
            char dst_ip_str[MAX_DST_ADDR_LEN];
            char sn_str[MAX_SNI_LEN];
            char ua_str[MAX_USER_AGENT_LEN];
            uint16_t dst_port;

            bool ok = fdc::decode(input,
                                  writeable{(uint8_t*)fp_str, MAX_FP_STR_LEN},
                                  writeable{(uint8_t*)sn_str, MAX_SNI_LEN},
                                  writeable{(uint8_t*)dst_ip_str, MAX_DST_ADDR_LEN},
                                  dst_port,
                                  writeable{(uint8_t*)ua_str, MAX_USER_AGENT_LEN});
            if (ok) {
                fprintf(stdout, "{\"fdc\":{");
                fprintf(stdout, "\"fingerprint\": \"%s\",", fp_str);
                fprintf(stdout, "\"sni\": \"%s\",", sn_str);
                fprintf(stdout, "\"dst_ip_str\": \"%s\",", dst_ip_str);
                fprintf(stdout, "\"dst_port\": %u,", dst_port);
                fprintf(stdout, "\"user-agent\": \"%s\"", ua_str);
                fprintf(stdout, "}}\n");
            } else {
                fprintf(stderr, "error: could not decode FDC\n");
            }
        }

    } else if (encode_fp) {

        std::ios::sync_with_stdio(false);  // for performance
        std::string line;
        while (std::getline(std::cin, line)) {
            if (line.length() == 0) {
                continue; // ignore empty line
            }

            // verify that we can represent this fingerprint in CBOR
            //
            if (!cbor_fingerprint::test_fingerprint(line.c_str())){
                fprintf(stderr, "error: could not encode/decode fingerprint %s\n", line.c_str());
                return EXIT_FAILURE;
            }

            // convert fingerprint to CBOR
            //
            datum fp_data{(uint8_t *)line.c_str(), (uint8_t *)line.c_str() + line.length()};
            dynamic_buffer data_buf{4096};
            cbor_fingerprint::encode_cbor_fingerprint(fp_data, data_buf);

            // print out hex representation
            //
            data_buf.contents().fprint_hex(stdout); fputc('\n', stdout);

            // print out human-readable CBOR
            //
            cbor::decode_fprint(data_buf.contents(), stdout);
        }
        return EXIT_SUCCESS;

    } else {
        fprintf(stderr, "error: no input file specified\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
