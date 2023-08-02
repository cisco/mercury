// libmerc_util.cc
//
// a wrapper around libmerc.so that processes pcap files and can be
// used for testing and debugging that library
//
// compile as:
//
//   g++ -Wall -Wno-narrowing libmerc_util.cc pcap_file_io.c -pthread -ldl -std=c++17 -o libmerc_util


#include "options.h"
#include "libmerc_api.h"
#include "pcap.h"
#include "packet.h"
#include "libmerc/datum.h"
#include "libmerc/json_object.h"

using namespace mercury_option;  //from options.h

class length_and_data {
    const uint8_t *data;
    const uint8_t *data_end;

public:

    length_and_data(const uint8_t *buffer, const uint8_t *buffer_end) : data{nullptr}, data_end{nullptr} {
        if (buffer == nullptr) {
            return;  // error
        }
        int length = *buffer++;
        if (buffer + length > buffer_end) {
            length = buffer_end - buffer;  // truncate length
        }
        data = buffer;
        data_end = buffer + length;
    }

    size_t bytes_accepted() const {
        if (data) {
            return 1 + data_end - data;
        }
        return 0;
    }

    size_t length() const { return data_end - data; }

    const uint8_t *value() const { return data; }

    /*explicit*/ operator datum() const { return {data, data_end}; }

};

// libmerc_printer is derived from libmerc_api, and adds functions for
// printing out analysis results as json or text
//
struct libmerc_printer : public libmerc_api {

    libmerc_printer(const char *lib_path) : libmerc_api{lib_path} {}

    // The function fprint_analysis_context() prints out all of the
    // information available about an analysis context.  It is an example
    // of how the libmerc.h interface can be used.  It makes more calls
    // that are necessary, to illustrate how the library responds.  In
    // particular, if the analysis_context is NULL, then it is unnecessary
    // to call any other functions, and if fingerprint_type is
    // fingerprint_type_unknown, then it is unnecessary to call
    // analysis_context_get_fingerprint_string().
    //
    void fprint_analysis_context(FILE *f, const struct analysis_context *ctx) {

        const struct libmerc_api *merc = this;

        fprintf(f, "---------- start of %s ----------\n", __func__);
        if (ctx == NULL) {
            fprintf(f, "null analysis_context (no analysis present)\n");
        }
        enum fingerprint_type type = this->get_fingerprint_type(ctx);
        const char *fp_type_str = fingerprint_type_string(type);
        fprintf(f, "fingerprint_type: %s\n", fp_type_str);
        fprintf(f, "fingerprint_type_code: %u\n", type);

        const char *fp_string = this->get_fingerprint_string(ctx);
        if (fp_string) {
            fprintf(f, "fingerprint_string: %s\n", fp_string);
        } else {
            fprintf(f, "fingerprint_string: not present (null)\n");
        }
        enum fingerprint_status fp_status = this->get_fingerprint_status(ctx);
        if (fp_status == fingerprint_status_labeled) {
            fprintf(f, "fingerprint_status: labeled\n");
        } else if (fp_status == fingerprint_status_unlabled) {
            fprintf(f, "fingerprint_status: unlabeled\n");
        } else if (fp_status == fingerprint_status_randomized) {
            fprintf(f, "fingerprint_status: randomized\n");
        } else if (fp_status == fingerprint_status_unanalyzed) {
            fprintf(f, "fingerprint_status: unanalyzed\n");
        } else if (fp_status == fingerprint_status_no_info_available) {
            fprintf(f, "fingerprint_status: no info available\n");
        } else {
            fprintf(f, "fingerprint_status: unknown status code (%d)\n", fp_status);
        }

        const char *server_name = this->get_server_name(ctx);
        if (server_name) {
            fprintf(f, "server_name: %s\n", server_name);
        } else {
            fprintf(f, "server_name: not present (null)\n");
        }

        const char *user_agent = this->get_user_agent(ctx);
        if (user_agent) {
            fprintf(f, "user_agent: %s\n", user_agent);
        } else {
            fprintf(f, "user_agent: not present (null)\n");
        }

        const uint8_t *alpn_buffer;
        size_t alpn_buffer_length;
        fprintf(f, "application_layer_protocol_negotiation: ");
        if (this->get_alpns(ctx, &alpn_buffer, &alpn_buffer_length)) {
            const uint8_t *alpn = alpn_buffer;
            const uint8_t *alpn_end = alpn + alpn_buffer_length;
            while (alpn < alpn_end) {
                length_and_data name{alpn, alpn_end};
                fprintf(f, "%.*s ", (int)name.length(), name.value());
                alpn += name.bytes_accepted(); // advance through buffer
            }
            fprintf(f, "\n");
        }

        const char *probable_process = NULL;
        double probability_score = 0.0;
        if (merc->get_process_info(ctx,
                                   &probable_process,
                                   &probability_score)) {
            fprintf(f,
                    "probable_process: %s\tprobability_score: %f\n",
                    probable_process,
                    probability_score);
        }
        bool probable_process_is_malware = false;
        double probability_malware = 0.0;
        if (merc->get_malware_info(ctx,
                                   &probable_process_is_malware,
                                   &probability_malware)) {
            fprintf(f,
                    "probable_process_is_malware: %s\tprobability_malware: %f\n",
                    probable_process_is_malware ? "true" : "false",
                    probability_malware);
        }
        fprintf(f, "----------  end of %s  ----------\n", __func__);
    }

    void fprint_json_analysis_context(FILE *f, const struct analysis_context *ctx) {

        constexpr size_t buffer_len = 4096;
        char buffer[buffer_len];
        buffer_stream buf{buffer, buffer_len};
        json_object json{&buf};

        if (ctx != NULL) {
            enum fingerprint_type type = this->get_fingerprint_type(ctx);
            const char *fp_type_str = fingerprint_type_string(type);
            json.print_key_string("fingerprint_type", fp_type_str);
            json.print_key_uint("fingerprint_type_code", type);

            const char *fp_string = this->get_fingerprint_string(ctx);
            json.print_key_string("fingerprint_string", fp_string ? fp_string : "not present (null)");

            enum fingerprint_status fp_status = this->get_fingerprint_status(ctx);
            const char *fp_status_string = "unknown status code";
            if (fp_status == fingerprint_status_labeled) {
                fp_status_string = "labeled";
            } else if (fp_status == fingerprint_status_unlabled) {
                fp_status_string = "unlabeled";
            } else if (fp_status == fingerprint_status_randomized) {
               fp_status_string = "randomized";
            } else if (fp_status == fingerprint_status_unanalyzed) {
                fp_status_string = "unanalyzed";
            } else if (fp_status == fingerprint_status_no_info_available) {
                fp_status_string = "no info available";
            } else {
                fp_status_string = "unknown status code";
            }
            json.print_key_string("fingerprint_status", fp_status_string);
            json.print_key_uint("fingerprint_status_code", fp_status);

            const char *server_name = this->get_server_name(ctx);
            json.print_key_string("server_name", server_name ? server_name : "not present (null)");

            const char *user_agent = this->get_user_agent(ctx);
            json.print_key_string("user_agent", user_agent ? user_agent : "not present (null)");

            const uint8_t *alpn_buffer;
            size_t alpn_buffer_length;
            if (this->get_alpns(ctx, &alpn_buffer, &alpn_buffer_length)) {
                struct json_array a{json, "application_layer_protocol_negotiation"};
                const uint8_t *alpn = alpn_buffer;
                const uint8_t *alpn_end = alpn + alpn_buffer_length;
                while (alpn < alpn_end) {
                    length_and_data name{alpn, alpn_end};
                    datum tmp = name;
                    a.print_json_string(tmp);
                    alpn += name.bytes_accepted(); // advance through buffer
                }
                a.close();
            }

            const char *probable_process = NULL;
            double probability_score = 0.0;
            if (get_process_info(ctx,
                                 &probable_process,
                                 &probability_score)) {
                json.print_key_string("probable_process", probable_process ? probable_process : "not present (null)");
                json.print_key_float("probability_score", probability_score);
            }
            bool probable_process_is_malware = false;
            double probability_malware = 0.0;
            if (get_malware_info(ctx,
                                 &probable_process_is_malware,
                                 &probability_malware)) {
                json.print_key_bool("probable_process_is_malware", probable_process_is_malware);
                json.print_key_float("probability_malware", probability_malware);
            }

        }
        json.close();
        buf.write_line(f);
    }

    const char *fingerprint_type_string(fingerprint_type fp_type) {
        switch(fp_type) {
        case fingerprint_type_unknown:     return "unknown";
        case fingerprint_type_tls:         return "tls";
        case fingerprint_type_tls_server:  return "tls_server";
        case fingerprint_type_http:        return "http";
        case fingerprint_type_http_server: return "http_server";
        case fingerprint_type_ssh:         return "ssh";
        case fingerprint_type_ssh_kex:     return "ssh_kex";
        case fingerprint_type_tcp:         return "tcp";
        case fingerprint_type_dhcp:        return "dhcp";
        case fingerprint_type_smtp_server: return "smtp_server";
        case fingerprint_type_dtls:        return "dtls";
        case fingerprint_type_dtls_server: return "dtls_server";
        case fingerprint_type_quic:        return "quic";
        default:
            ;
        }
        return "unregistered fingerprint type";
    }
};

int main(int argc, char *argv[]) {

    const char summary[] =
        "usage:\n"
        "   libmerc_util --read <pcap file> --libmerc <shared object file> [OPTIONS]\n"
        "\n"
        "OPTIONS\n";

    class option_processor opt({
        { argument::required,   "--read",      "read PCAP file <arg>" },
        { argument::required,   "--libmerc",   "use libmerc.so file <arg>" },
        { argument::required,   "--resources", "use resource file <arg>" },
        { argument::none,       "--stats",     "generate stats.json.gz file" },
        { argument::none,       "--verbose",   "turn on verbose output" },
        { argument::none,       "--help",      "print out help message" }
    });
    if (!opt.process_argv(argc, argv)) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    auto [ pcap_is_set, pcap_file ] = opt.get_value("--read");
    auto [ libmerc_is_set, libmerc_file ] = opt.get_value("--libmerc");
    auto [ resources_is_set, resources_file ] = opt.get_value("--resources");
    bool verbose = opt.is_set("--verbose");
    bool do_stats = opt.is_set("--stats");
    bool print_help = opt.is_set("--help");

    if (print_help) {
        opt.usage(stdout, argv[0], summary);
        return EXIT_SUCCESS;
    }

    if (!pcap_is_set) {
        fprintf(stderr, "error: --read missing from command line\n");
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }
    if (!libmerc_is_set) {
        fprintf(stderr, "error: --libmerc missing from command line\n");
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    char *resources_path = (char *)"../resources/resources.tgz";
    if (resources_is_set) {
        resources_path = (char *)resources_file.c_str();
    }
    size_t i=0;
    try {

        // load libmerc.so from location provided through --libmerc option
        //
        libmerc_printer mercury(libmerc_file.c_str());

        // set libmerc configuration
        //
        libmerc_config config;
        config.resources = resources_path;
        config.do_analysis = true;
        config.do_stats = do_stats;

        // initalize mercury library
        //
        mercury_context mc = mercury.init(&config, verbose);
        if (mc == nullptr) {
            throw std::runtime_error("mercury_init() returned null");
        }

        // create mercury packet processor
        //
        mercury_packet_processor mpp = mercury.packet_processor_construct(mc);
        if (mpp == NULL) {
            fprintf(stderr, "error in mercury_packet_processor_construct()\n");
            return -1;
        }

	pcap::file_reader pcap{pcap_file.c_str()};
        packet<65536> pkt;
        while (true) {

            // get packet from pcap file
            //
            datum pkt_data = pkt.get_next(pcap);
            if (!pkt_data.is_not_empty()) {
                break;
            }

            // analyze packet, get analysis result and write it out
            //
            struct timespec ts; // TODO: set from pkt
            const struct analysis_context *ctx = mercury.get_analysis_context(mpp, (uint8_t *)pkt_data.data, pkt_data.length(), &ts);
            if (ctx) {
                mercury.fprint_json_analysis_context(stdout, ctx);
            }
            bool need_more_pkts = mercury.more_pkts_needed(mpp);
            fprintf(stdout, "{more_pkts_needed:%s}\n", need_more_pkts ? "true" : "false");

            i++;
        }

        // destroy packet processor
        //
        mercury.packet_processor_destruct(mpp);

        // write out stats data, if needed
        //
        if (do_stats) {
            mercury.write_stats_data(mc, "stats.json.gz");
        }

        // destroy mercury context
        //
        mercury.finalize(mc);
    }
    catch (std::exception &e) {
        fprintf(stderr, "error processing pcap_file %s\n", pcap_file.c_str());
        fprintf(stderr, "%s\n", e.what());
        exit(EXIT_FAILURE);
    }
    catch (...) {
        fprintf(stderr, "unknown error processing pcap_file %s\n", pcap_file.c_str());
        exit(EXIT_FAILURE);
    }

    // fprintf(stderr, "packet count: %zu\n", i);

    return 0;
}
