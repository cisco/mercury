/*
 * string.cc
 *
 * run string algorithms (edit distance, longest common subsequence,
 * longest common substring, matching substrings)
 */

#include <stdio.h>
#include <algorithm>      // for std::sort()
#include <numeric>        // for std::iota()
#include <cassert>
#include "stringalgs.h"
#include "options.h"

// create_sorted_index(v) returns a vector of indices that sort the
// input vector v into ascending order
//
template <typename T>
std::vector<size_t> create_sorted_index(std::vector<T> const& v) {
    std::vector<size_t> idx(v.size());
    std::iota(begin(idx), end(idx), static_cast<size_t>(0));
    std::sort(begin(idx), end(idx), [&](size_t lhs, size_t rhs) { return v[lhs] < v[rhs]; } );
    return idx;
}

using namespace mercury_option;

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
        { argument::none,       "--hamming",       "method: compute hamming distance" },
        { argument::none,       "--find-mask",     "method: find common mask and value" },
        { argument::none,       "--average",       "report average distance to all other strings" },
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
    bool hamming     = opt.is_set("--hamming");
    bool find_mask   = opt.is_set("--find-mask");
    bool average     = opt.is_set("--average");
    bool normalize   = opt.is_set("--normalize");
    bool print_help  = opt.is_set("--help");

    if (!edit_dist && !lcsubseq && !lcsubstr && !match_str && !find_mask && !hamming && !print_help) {
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

    // read in strings from input stream
    //
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    size_t max_len = 0; // length of largest input string

    std::vector<std::basic_string<uint8_t>> s;
    while ((nread = getline(&line, &len, stream)) != -1) {
        std::basic_string<uint8_t> tmp((uint8_t *)line, nread);
        if (nread > 0) {
            tmp.erase(tmp.length()-1);
        }
        s.push_back(tmp);
        if (tmp.length() > max_len) {
            max_len = tmp.length();
        }
    }
    free(line);
    fclose(stream);

    // if we are computing average distances, create a vector to
    // hold the running sums and initialize it to zero
    //
    std::vector<size_t> sum(s.size(), 0);

    // loop over each pair of strings, and apply method
    //
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
                struct edit_distance<uint8_t, uint32_t> ed(s[i].c_str(), s[i].size(), s[j].c_str(), s[j].size());
                if (normalize) {
                    // normalize by the sum of string sizes
                    float normed_dist = (float)ed.value() / ((float) s[i].size() + s[j].size());
                    fprintf(stdout, "%f\t'%s'\t'%s'\n", normed_dist, s[i].c_str(), s[j].c_str());
                } else {
                    fprintf(stdout, "%d\t'%s'\t'%s'\n", ed.value(), s[i].c_str(), s[j].c_str());
                }
            }
            if (hamming) {
                std::basic_string<uint8_t> si = uint8_string_from_hex((const char *)s[i].c_str());
                std::basic_string<uint8_t> sj = uint8_string_from_hex((const char *)s[j].c_str());
                size_t d = hamming_distance(si, sj);
                if (average) {
                    // output average distance from each string to all others
                    sum[j] += d;
                    sum[i] += d;
                } else {
                    fprintf(stdout, "%zu\t'%s'\t'%s'\n", d, s[i].c_str(), s[j].c_str());
                }
            }
        }
    }

    // report average distances
    //
    if (average) {
        std::vector<size_t> idx = create_sorted_index(sum);
        assert(idx.size() == s_len);
        for (size_t i=0; i<s_len; i++) {
            size_t k = idx[i];
            fprintf(stdout, "%f\t%s\n", (double)sum[k]/s_len, s[k].c_str());
        }
    }

    // single-pass methods
    //
    if (find_mask) {
        class mask_and_value mv{max_len/2};
        for (auto & x : s) {
            std::basic_string<uint8_t> s = uint8_string_from_hex((const char *)x.c_str());
            mv.observe(s.c_str(), s.length());
        }
        auto m_and_v = mv.value();
        fprintf(stdout, "mask:   ");
        fprint_uint8_string(stdout, m_and_v.first);
        fputc('\n', stdout);
        fprintf(stdout, "value:  ");
        fprint_uint8_string(stdout, m_and_v.second);
        fputc('\n', stdout);
        fprintf(stdout, "weight: %zu\n", mv.weight());

        assert(mv.check(s));

    }

    return 0;
}
