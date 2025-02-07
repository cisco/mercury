// classify.cpp
//
// run the mercury classifier on inputs provided on the command line
//
// example usage:
//
//   classify --resources "resources-mp.tgz" --fingerprint "http/(474554)(485454502f312e31)((43616368652d436f6e74726f6c)(436f6e6e656374696f6e3a204b6565702d416c697665)(4163636570743a202a2f2a)(557365722d4167656e74)(486f7374))" --dst-addr "2.18.121.140" --server-name "au.download.windowsupdate.com" --dst-port 80

#include <cstdio>
#include "libmerc/analysis.h"
#include "options.h"

using namespace mercury_option;

int main(int argc, char *argv[]) {

   const char *summary = "usage: %s [OPTIONS]\n";
   option_processor opt({
            { argument::required, "--resources",         "read classifier resources from file <arg>" },
            { argument::required, "--fingerprint",       "set NPF fingerprint" },
            { argument::required, "--server-name" ,      "set TLS/QUIC server name or HTTP host" },
            { argument::required, "--dst-addr" ,         "set destination IP address" },
            { argument::required, "--dst-port" ,         "set destination TCP/UDP port" },
            { argument::required, "--user-agent",        "set HTTP user-agent string" },
            { argument::none,     "--help",              "print out help message" },
        });

    if (!opt.process_argv(argc, argv)) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    auto [ resource_file_is_set, resource_file ] = opt.get_value("--resources");
    auto [ fingerprint_is_set,  fingerprint ] = opt.get_value("--fingerprint");
    auto [ server_name_is_set, server_name ] = opt.get_value("--server-name");
    auto [ dst_addr_is_set, dst_addr ] = opt.get_value("--dst-addr");
    auto [ dst_port_is_set, dst_port ] = opt.get_value("--dst-port");
    auto [ user_agent_is_set, user_agent ] = opt.get_value("--user-agent");
    bool help_needed    = opt.is_set("--help");
    if (help_needed) {
        opt.usage(stdout, argv[0], summary);
        return 0;
    }

    bool err = false;
    if (!resource_file_is_set) { fprintf(stderr, "error: --resource-file not set\n"); err = true; }
    if (!fingerprint_is_set)   { fprintf(stderr, "error: --fingerprint not set\n");   err = true; }
    if (!server_name_is_set)   { fprintf(stderr, "error: --server-name not set\n");   err = true; }
    if (!dst_addr_is_set)      { fprintf(stderr, "error: --dst-addr not set\n");      err = true; }
    if (!dst_port_is_set)      { fprintf(stderr, "error: --dst-port not set\n");      err = true; }
    // if (!user_agent_is_set)    { fprintf(stderr, "error: --user-agent not set\n"); err = true; }
    if (err) {
         opt.usage(stderr, argv[0], summary);
         exit(EXIT_FAILURE);
    }

    try {

        uint16_t dst_port_uint16 = std::stoul(dst_port);
        if (dst_port_uint16 >= std::numeric_limits<uint16_t>::max()) {
            fprintf(stderr, "error: destination port out of range\n");
            opt.usage(stderr, argv[0], summary);
            exit(EXIT_FAILURE);
        }

        classifier *c = analysis_init_from_archive(0, // verbosity
                                                   "../../../2025-02-6/resources-mp.tgz",
                                                   nullptr,
                                                   enc_key_type_none,
                                                   0,
                                                   0,
                                                   true);
        if (c == nullptr) {
            fprintf(stderr, "error: could not initialize classifier\n");
            exit(EXIT_FAILURE);
        }

        analysis_result result = c->perform_analysis(fingerprint.c_str(),
                                                     server_name.c_str(),
                                                     dst_addr.c_str(),
                                                     dst_port_uint16,
                                                     user_agent.c_str());

        // analysis_result result = c->perform_analysis("http/(474554)(485454502f312e31)((43616368652d436f6e74726f6c)(436f6e6e656374696f6e3a204b6565702d416c697665)(4163636570743a202a2f2a)(557365722d4167656e74)(486f7374))",
        //                                              "au.download.windowsupdate.com",
        //                                              "2.18.121.140",
        //                                              80,
        //                                              "Microsoft-Delivery-Optimization/10.0");

        output_buffer<4096> buf;
        json_object o{&buf};
        result.write_json(o, "analysis");
        o.close();
        buf.write_line(stdout);

    }
    catch (std::invalid_argument &e) {
        fprintf(stderr, "error: invalid argument for dst-port (must be between 0 and 65535)\n");
        exit(EXIT_FAILURE);
    }
    catch (std::exception &e) {
        fprintf(stderr, "error: %s\n", e.what());
        exit(EXIT_FAILURE);
    }
    catch (...) {
        fprintf(stderr, "%s: unknown error\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}
