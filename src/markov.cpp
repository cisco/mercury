// markov.cpp
//

#include "markov.hpp"
#include "options.h"

#include <vector>
#include <iostream>
#include <unordered_map>
#include <algorithm>
#include <cstring>
#include <fstream>      // std::ifstream

using namespace mercury_option;

int main(int argc, char *argv[]) {

    // fprintf(stderr, "%zu\n", dns_char_set::char_to_index('.'));
    // fprintf(stderr, "%c\n", dns_char_set::index_to_char(dns_char_set::char_to_index('.')));
    // for (size_t i=0; i<dns_char_set::N; i++) {
    //     fprintf(stdout, "\t'%c'\t%zu\n", dns_char_set::index_to_char(i), dns_char_set::char_to_index(dns_char_set::index_to_char(i)));
    // }
    // return 0;

    option_processor opt({
        { argument::required,   "--data-input",   "read data lines from file (- == stdin)" },
        { argument::required,   "--build-model",  "read lines from file, build model (- == stdin)" },
        { argument::required,   "--write-model",  "write model to file"                            },
        { argument::required,   "--read-model",   "read model to file"                             },
        { argument::none,       "--dump",         "dump model to stdout"                           },
        { argument::none,       "--random-test",  "apply random test to input lines"               },
        { argument::none,       "--entropy",      "estimate entropy of input lines"                },
        { argument::required,   "--upper-bound",  "filter random-test or entropy based on bound"   },
        { argument::required,   "--lower-bound",  "filter random-test or entropy based on bound"   },
        { argument::none,       "--rate",         "report rate (entropy per character)"            },
        { argument::none,       "--stationary",   "report stationary distribution"                 },
    });
    const char summary[] =
        "usage:\n"
        "   markov [OPTIONS]\n"
        "\n"
        "OPTIONS\n"
        ;
    if (!opt.process_argv(argc, argv)) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    auto [ got_data_input, data_input_filename ]   = opt.get_value("--data-input");
    auto [ got_model_input, model_input_filename ] = opt.get_value("--build-model");
    auto [ write_model, write_model_filename ]     = opt.get_value("--write-model");
    auto [ read_model, read_model_filename ]       = opt.get_value("--read-model");
    bool dump                                      = opt.is_set("--dump");
    bool random_test                               = opt.is_set("--random-test");
    bool entropy                                   = opt.is_set("--entropy");
    auto [ got_upper_bound, upper_bound ]          = opt.get_value("--upper-bound");
    auto [ got_lower_bound, lower_bound ]          = opt.get_value("--lower-bound");
    bool rate                                      = opt.is_set("--rate");
    bool stationary                                = opt.is_set("--stationary");

    // sanity check options
    //
    if (data_input_filename == "-" and model_input_filename == "-") {
        fprintf(stderr, "error: both data input and model input are stdin\n");
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }
    if (dump + random_test + entropy + rate + stationary> 1) {
        fprintf(stderr, "error: only one of --dump, --entropy, --random-test, --rate, or --stationary can be used at a time\n");
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }
    // fprintf(stderr, "upper bound: %f\n", atof(upper_bound.c_str()));
    // fprintf(stderr, "lower bound: %f\n", atof(lower_bound.c_str()));

    using char_set = dns_char_set;

    markov_model<char_set> *mm = nullptr;
    if (read_model) {
        FILE *infile = fopen(read_model_filename.c_str(), "r");
        mm = new markov_model<char_set>(infile);
        fclose(infile);
    } else {
        mm = new markov_model<char_set>();
    }
    if (mm == nullptr) {
        fprintf(stderr, "error: could not allocate markov model\n");
        return 0;
    }

    std::istream *input = &std::cin;
    std::ifstream *ifs = nullptr;
    if (got_model_input && model_input_filename != "-") {
        ifs = new std::ifstream(model_input_filename);
        if (ifs == nullptr or !*ifs) {
            fprintf(stderr, "error: could not open file %s for reading\n", model_input_filename.c_str());
            return EXIT_FAILURE;
        }
        input = ifs;
    }
    std::string line;
    while (got_model_input and std::getline(*input, line)) {
        if (line.length() == 0 || line[0] == '/') {
            continue;
        }
        mm->add(line);
    }
    if (ifs) { delete ifs; }

    if (write_model) {
        //
        // write model mm into file
        //
        FILE *f = fopen(write_model_filename.c_str(), "w");
        mm->write_to_file(f);
        fclose(f);
    }

    // read data lines, if data input specified
    //
    std::istream *data_input = &std::cin;
    std::ifstream *data_ifs = nullptr;
    if (got_data_input && data_input_filename != "-") {
        data_ifs = new std::ifstream(data_input_filename);
        if (data_ifs == nullptr or !*data_ifs) {
            fprintf(stderr, "error: could not open file %s for reading\n", data_input_filename.c_str());
            return EXIT_FAILURE;
        }
        data_input = data_ifs;
    }

    // process each line of input
    //
    std::string word;
    while (got_data_input and std::getline(*data_input, word)) {
        if (word.length() == 0 || word[0] == '/') {
            continue;
        }
        double value = 0.0;
        if (entropy) {
            value = mm->shannon_entropy(word);
        } else if (random_test) {
            value = mm->test_random(word);
        }
        if ((got_upper_bound && value > atof(upper_bound.c_str())) || (got_lower_bound && value < atof(lower_bound.c_str()))) {
            continue;  // no output for this word
        }
        fprintf(stdout, "%s\t%.17f\n", word.c_str(), value);
    }
    if (data_ifs) { delete data_ifs; }

    if (dump) {
        mm->fprint_dump(stdout);
    }

    if (rate) {
        fprintf(stdout, "%f\n", mm->entropy_rate());
    }

    if (stationary) {
        auto u = mm->stationary_distribution();
        for (const auto &p : u) {
            fprintf(stdout, "%f\n", p);
        }
    }

    return 0;
}
