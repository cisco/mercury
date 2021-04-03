/*
 * string.cc
 *
 * run string algorithms (edit distance, longest common subsequence,
 * longest common substring, matching substrings)
 */

#include <stdio.h>
#include "stringalgs.h"
#include "options.h"

int main(int argc, char *argv[]) {

    const char summary[] =
        "usage:\n"
        "\tstring [OPTIONS]\n\n"
        "Reads one string per line from standard input (or <file>, if the --read <file>\n"
        "option is used), loops over pairs of strings, and analyzes them with the\n"
        "methods specified in the options.  At least one method MUST be specified.\n\n"
        "OPTIONS\n";

    class option_processor opt({
        { argument::required,   "--read",          "read strings from input file <arg>" },
        { argument::none,       "--edit-distance", "method: compute edit distance" },
        { argument::none,       "--subsequence",   "method: compute longest common subsequence" },
        { argument::none,       "--substring",     "method: compute longest common substring" },
        { argument::none,       "--matching",      "method: compute matching substrings" },
        { argument::none,       "--normalize",     "normalize distance to [0,1]" },
        { argument::none,       "--help",          "prints out help message" }
    });

    const char *progname = "string";

    if (!opt.process_argv(argc, argv)) {
        opt.usage(stderr, progname, summary);
        return EXIT_FAILURE;
    }

    auto [ input_file_is_set, filename ] = opt.get_value("--read");
    bool edit_dist   = opt.is_set("--edit-distance");
    bool lcsubseq    = opt.is_set("--subsequence");
    bool lcsubstr    = opt.is_set("--substring");
    bool match_str   = opt.is_set("--matching");
    bool normalize   = opt.is_set("--normalize");
    bool print_help  = opt.is_set("--help");

    if (!edit_dist && !lcsubseq && !lcsubstr && !match_str && !print_help) {
        fprintf(stderr, "error: no analysis method specified\n");
        opt.usage(stderr, progname, summary);
        return EXIT_FAILURE;
    }

    if (print_help) {
        opt.usage(stdout, progname, summary);
        return 0;
    }

    FILE *stream = stdin;
    if (input_file_is_set) {
        // read words from input file
        stream = fopen(filename.c_str(), "r");
        if (stream == NULL) {
            fprintf(stderr, "error: could not open file '%s' for reading (%s)\n",
                    filename.c_str(),
                    errno ? strerror(errno) : "unknown error");
            exit(EXIT_FAILURE);
        }
    }
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    std::vector<std::basic_string<uint8_t>> s;
    while ((nread = getline(&line, &len, stream)) != -1) {
        std::basic_string<uint8_t> tmp((uint8_t *)line, nread);
        if (nread > 0) {
            tmp.erase(tmp.length()-1);
        }
        s.push_back(tmp);
    }
    free(line);
    fclose(stream);

    size_t s_len = s.size();
    for (size_t i=0; i<s_len; i++) {
        for (size_t j=0; j<s_len; j++) {
            if (i == j) {
                break;
            }
            if (lcsubseq) {
                struct longest_common_subsequence<uint32_t> lcs(s[i].c_str(), s[i].size(), s[j].c_str(), s[j].size());
                if (normalize) {
                    // normalize by max string size
                    float normed_length = (float)lcs.length() / ((float)(s[i].size() > s[j].size() ? s[i].size() : s[j].size()));
                    fprintf(stdout, "%f\t'%s'\t'%s'\t'%s'\n", normed_length, lcs.value().c_str(), s[i].c_str(), s[j].c_str());
                } else {
                    fprintf(stdout, "%d\t'%s'\t'%s'\t'%s'\n", lcs.length(), lcs.value().c_str(), s[i].c_str(), s[j].c_str());
                }
            }
            if (lcsubstr) {
                struct longest_common_substring<uint8_t> lcstr(s[i].c_str(), s[i].size(), s[j].c_str(), s[j].size());
                if (normalize) {
                    // normalize by max string size
                    float normed_length = (float)lcstr.length() / ((float)s[i].size() > s[j].size() ? s[i].size() : s[j].size());
                    fprintf(stdout, "%f\t'%s'\t'%s'\t'%s'\n", normed_length, lcstr.lcstr().c_str(), s[i].c_str(), s[j].c_str());
                } else {
                    fprintf(stdout, "%d\t'%s'\t'%s'\t'%s'\n", lcstr.length(), lcstr.lcstr().c_str(), s[i].c_str(), s[j].c_str());
                }
            }
            if (match_str) {
                struct matching_substrings<uint8_t> m(s[i].c_str(), s[i].size(), s[j].c_str(), s[j].size());
                if (normalize) {
                    // normalize by max string size
                    float normed_length = (float)m.length() / ((float)s[i].size() > s[j].size() ? s[i].size() : s[j].size());
                    fprintf(stdout, "%f\t'%s'\t'%s'\t'%s'\n", normed_length, m.value().c_str(), s[i].c_str(), s[j].c_str());
                } else {
                    fprintf(stdout, "%d\t'%s'\t'%s'\t'%s'\n", m.length(), m.value().c_str(), s[i].c_str(), s[j].c_str());
                }
            }
            if (edit_dist) {
                struct edit_distance<uint32_t> ed(s[i].c_str(), s[i].size(), s[j].c_str(), s[j].size());
                if (normalize) {
                    // normalize by the sum of string sizes
                    float normed_dist = (float)ed.value() / ((float) s[i].size() + s[j].size());
                    fprintf(stdout, "%f\t'%s'\t'%s'\n", normed_dist, s[i].c_str(), s[j].c_str());
                } else {
                    fprintf(stdout, "%d\t'%s'\t'%s'\n", ed.value(), s[i].c_str(), s[j].c_str());
                }
            }
        }
    }

    return 0;
}
