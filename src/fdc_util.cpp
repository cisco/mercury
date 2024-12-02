// fdc_util.cc
//
// a utility that can read newline separated list of fdc and decode it into raw features
// used for testing and debugging the FDC coding and decoding
//
// compile as:
//
//   g++ -Wall -Wno-narrowing libmerc_util.cc pcap_file_io.c -pthread -ldl -std=c++17 -o libmerc_util


#include "options.h"
#include "libmerc/datum.h"
#include "libmerc/json_object.h"
#include "libmerc/result.h"
#include "libmerc/fdc.hpp"

#include <iostream>
#include <fstream>
#include <string>

using namespace mercury_option;  //from options.h


int main(int argc, char *argv[]) {

    const char summary[] =
        "usage:\n"
        "   fdc_util --read <fdc file> --out <raw_features_output>\n"
        "\n";

    class option_processor opt({
        { argument::required,   "--read",      "read PCAP file <arg>" },
        { argument::required,   "--out",       "raw features output file <arg>" },
        { argument::none,       "--help",      "print out help message" }
    });
    if (!opt.process_argv(argc, argv)) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    auto [ fdc_is_set, fdc_file ] = opt.get_value("--read");
    auto [ output_is_set, output_file ] = opt.get_value("--out");
    auto [ resources_is_set, resources_file ] = opt.get_value("--resources");
    bool print_help = opt.is_set("--help");

    if (print_help) {
        opt.usage(stdout, argv[0], summary);
        return EXIT_SUCCESS;
    }

    if (!fdc_is_set) {
        fprintf(stderr, "error: --read missing from command line\n");
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }
    if (!output_is_set) {
        fprintf(stderr, "error: --out missing from command line\n");
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

   std::ifstream fdc_stream(fdc_file);
   std::ofstream raw_stream(output_file);

   std::string fdc_line;

   bool error = false;
   int line_count = 0;

    while ( getline (fdc_stream,fdc_line) ) {
        line_count++;
        std::cout << fdc_line;
        
        static const size_t MAX_FP_STR_LEN     = 4096;
        char fp_str[MAX_FP_STR_LEN];
        char dst_ip_str[MAX_DST_ADDR_LEN];
        char sn_str[MAX_SNI_LEN];
        char ua_str[MAX_USER_AGENT_LEN];
        uint16_t dst_port;

        datum encoded_fdc{fdc_line.c_str()};
        bool decoding_ok = fdc::decode(encoded_fdc,
                                       writeable{(uint8_t*)fp_str, MAX_FP_STR_LEN},
                                       writeable{(uint8_t*)sn_str, MAX_SNI_LEN},
                                       writeable{(uint8_t*)dst_ip_str, MAX_DST_ADDR_LEN},
                                       dst_port,
                                       writeable{(uint8_t*)ua_str, MAX_USER_AGENT_LEN});
        
        // if (!decoding_ok) {
        //     error = true;
        //     break;
        // }

        char buffer[64*8192];       // note: hardcoded length for now
        struct buffer_stream buf(buffer, sizeof(buffer));
        json_object raw_features{&buf};
        raw_features.print_key_hex("fingerprint",datum{fp_str});
        raw_features.print_key_string("server_name",sn_str);
        raw_features.print_key_string("user_agent", ua_str);
        raw_features.print_key_string("dest_ip",dst_ip_str);
        raw_features.print_key_int("dest_port",dst_port);
        raw_features.close();

        raw_stream << std::string{buf.dstr} << "\n";        

    }

    fdc_stream.close();
    raw_stream.close();

    if (error) {
        std::cout << "Decoding failed at line:" << line_count << "\n";
    }

    return 0;
}
