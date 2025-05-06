// fingerprint.cc
//
// fingerprint conversion and analysis
//
// build:  g++ -Wall -DNDEBUG=1 -std=c++17 fingerprint.cc -o fingerprint -lcrypto
// run:    cat fingerprint_db.json | ./fingerprint


#include <stdio.h>
#include <string>
#include <vector>
#include <ostream>
#include <regex>
#include <openssl/md5.h>

#include "options.h"
#include "fingerprint.h"

using namespace mercury_option;

#include "libmerc/rapidjson/document.h"
class fp_pattern {
public:
    std::regex version;
    std::regex ciphersuite_vector;
    std::regex extensions;

    fp_pattern(fp tmp_fp) : version{tmp_fp.version},
                            ciphersuite_vector{tmp_fp.ciphersuite_vector},
                            extensions{}
    {
        if (tmp_fp.extensions.size() > 0) {
            extensions = tmp_fp.extensions[0];  // note: only using first element
        }
    }

    bool is_match(fp rhs) {
        if (!std::regex_match(rhs.version, version)) { return false; }
        if (!std::regex_match(rhs.ciphersuite_vector, ciphersuite_vector)) { return false; }
        if (!std::regex_match(rhs.extensions[0], extensions)) { return false; }
        //            fprintf(stderr, "matched %s\n", rhs.version.c_str());
        return true;
    }

    fp match(fp rhs) {
        std::cmatch matching_version;
        std::regex_search(rhs.version.c_str(), matching_version, version);
        std::cmatch matching_ciphersuite_vector;
        std::regex_search(rhs.ciphersuite_vector.c_str(), matching_ciphersuite_vector, ciphersuite_vector);
        std::vector<std::string> matching_extensions;
        for (const auto & e : rhs.extensions) {
            std::cmatch matching_xtn;
            std::regex_search(e.c_str(), matching_xtn, extensions);
            matching_extensions.push_back(matching_xtn.str());
        }
        return fp{matching_version.str(), matching_ciphersuite_vector.str(), matching_extensions};
    }
};


// unit_test(f) performs unit testing on the NPF to JA3 conversion.
// The argument f is either a FILE pointer (e.g. stderr, stdout) to
// which data will be written (to enable a 'verbose' mode), or nullptr
// (to enable a 'silent' mode).
//
bool unit_test(FILE *f) {

    struct test_case {
        const std::string r1;
        const std::string a1;
        const std::string h1;

        bool check(FILE *f) const {
            fp tls_fp1(a1);
            if (h1 != tls_fp1.get_ja3_hash() || tls_fp1.ja3() != r1) {
                if (f != nullptr) {
                    fprintf(f, "error: ja3 reference value mismatch\n");
                    fprintf(f, "input: %s\n", a1.c_str());
                    tls_fp1.fprint(f);
                    fprintf(f, "computed ja3 intermediate representation: %s\n", tls_fp1.ja3().c_str());
                    fprintf(f, "expected ja3 intermediate_representation: %s\n", r1.c_str());
                    fprintf(f, "computed ja3 hash: %s\n", tls_fp1.get_ja3_hash().c_str());
                    fprintf(f, "expected ja3 hash: %s\n", h1.c_str());
                }
                return false;
            }
            return true;
        }

    };

    std::string r1 = "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0";
    std::string a1 = "(0301)(002f00350005000ac009c00ac013c0140032003800130004)((0000)(000a0006001700180019)(000b00020000))";
    std::string h1 = "ada70206e40642a3e4461f35503241d5";
    test_case tc1{r1, a1, h1};
    if (!tc1.check(f)) { return false; }

    std::string r2 = "769,4-5-10-9-100-98-3-6-19-18-99,,,";
    std::string a2 = "(0301)(00040005000a00090064006200030006001300120063)()";
    std::string h2 = "de350869b8c85de67a350c8d186f11e6";
    test_case tc2{r2, a2, h2};
    if (!tc2.check(f)) { return false; }

    if (f) { fprintf(f, "unit test passed\n"); }
    return true;
}

std::string ja3_ir_to_bp(const std::string &s) {

    char outbuf[8096] = { '\0', };
    char *out = &outbuf[0];
    size_t outlen = 8096;

    printf("%s\n", s.c_str());

    const char *c = s.c_str();
    char *next = (char *)c;

    unsigned long int digits;
    digits = strtoul(c, &next, 10);
    printf("version: %lu\n", digits);
    int r = snprintf(out, outlen, "(%04lx)(", digits); out += r; outlen -= r;
    if (*next == ',') {
        c = next + 1;
    }
    while (true) {
        digits = strtoul(c, &next, 10);
        printf("ciphersuite: %lu\n", digits);
        r = snprintf(out, outlen, "%04lx", digits); out += r; outlen -= r;
        if (*next == '-') {
            c = next + 1;
        } else {
            break; // at end of ciphersuites
        }
    }
    r = snprintf(out, outlen, ")"); out += r; outlen -= r;
    if (*next == ',') {
        c = next + 1;
    } else {
        return "";   // error; invalid format
    }
    std::vector<std::string> extensions;
    char tmp[16];
    while (true) {
        digits = strtoul(c, &next, 10);
        printf("extension: %lu\n", digits);
        snprintf(tmp, sizeof(tmp), "%04lx", digits);
        extensions.push_back(tmp);
        // r = snprintf(out, outlen, "(%04lx)", digits); out += r; outlen -= r;
        if (*next == '-') {
            c = next + 1;
        } else {
            break; // at end of extensions
        }
    }
    if (*next == ',') {
        c = next + 1;
    } else {
        return "";   // error; invalid format
    }
    std::vector<std::string> supported_groups;
    while (true) {
        digits = strtoul(c, &next, 10);
        printf("supported group: %lu\n", digits);
        snprintf(tmp, sizeof(tmp), "%04lx", digits);
        supported_groups.push_back(tmp);
        if (*next == '-') {
            c = next + 1;
        } else {
            break; // at end of supported groups
        }
    }
    if (*next == ',') {
        c = next + 1;
    } else {
        return "";   // error; invalid format
    }
    std::vector<std::string> elliptic_curve_formats;
    while (true) {
        digits = strtoul(c, &next, 10);
        printf("elliptic curve format: %lu\n", digits);
        snprintf(tmp, sizeof(tmp), "%04lx", digits);
        elliptic_curve_formats.push_back(tmp);
        if (*next == '-') {
            c = next + 1;
        } else {
            break; // at end of elliptic curve formats
        }
    }

    std::string output{outbuf, (size_t)(out - outbuf)};

    // add extensions
    //
    output += '(';
    for (const auto & x : extensions) {
        output += '(';
        if (x == "000a") {
            output += x;
            uint16_t length = 2 * supported_groups.size();
            snprintf(tmp, sizeof(tmp), "%04x", length);
            output += tmp;
            for (const auto & y : supported_groups) {
                output += y;
            }
        } else if (x == "000b") {
            output += x;
            uint16_t length = 2 * elliptic_curve_formats.size();
            snprintf(tmp, sizeof(tmp), "%04x", length);
            output += tmp;
            for (const auto & y : elliptic_curve_formats) {
                output += y;
            }
        } else {
            output += x;
        }
        output += ')';
    }
    output += ')';

    return output;
}

int main(int argc, char *argv[]) {

    // compile with -DNDEBUG=1 to disable unit testing
    // pass stderr to unit_test() for debugging output
    //
    assert(unit_test(nullptr) == 1);

    const char summary[] =
        "usage:\n"
        "   fingerprint [OPTIONS]\n"
        "\n"
        "OPTIONS\n"
        ;
    class option_processor opt({
        { argument::none,       "--input-json",    "input is in JSON format" },
        { argument::none,       "--output-ja3-ir", "output JA3 intermediate representation" },
        { argument::required,   "--match",         "filter fingerprints matching <arg>" },
        { argument::none,       "--help",          "print out help message" }
    });
    if (argc > 1 && !opt.process_argv(argc, argv)) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    bool json       = opt.is_set("--input-json");
    bool ja3_ir     = opt.is_set("--output-ja3-ir");
    auto [ pattern_is_set, pattern ] = opt.get_value("--match");
    bool print_help = opt.is_set("--help");
    if (print_help) {
        opt.usage(stdout, argv[0], summary);
        return 0;
    }

    fp tmp_fp{pattern};
    //    tmp_fp.fprint(stderr);
    fp_pattern fp_matcher{tmp_fp};

    // process input (each line in JSON or plain format)
    //
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    while ((nread = getline(&line, &len, stdin)) > 0) {
        size_t line_length = nread-1;

        // extract fingerprint string from input line
        //
        std::string fp_string;
        if (json) {
            // parse line as JSON object {"str_repr":"..."}
            //
            rapidjson::Document fp_object;
            fp_object.Parse(line);

            if (fp_object.HasMember("str_repr") && fp_object["str_repr"].IsString()) {
                fp_string = fp_object["str_repr"].GetString();
            }

        } else {
            // parse line as fingerprint in balanced parenthesis notation
            //
            std::string tmp{line, line_length};    // truncate terminating '\n'
            fp_string = tmp;
        }

        // process fingerprint string
        //
        fp tmp_fp(fp_string);

        if (!tmp_fp) {
            continue; // tmp_fp is not valid, so continue on to the next one
        }

        // apply pattern (if there is one)
        //
        if (pattern_is_set) {
            // fprintf(stdout, "before: %s\n", fp_string.c_str());
            tmp_fp = fp_matcher.match(tmp_fp);
            // fprintf(stdout, "matched: %s\n", tmp_fp.get_str_repr().c_str());
        }

        // output (matched part of) fingerprint
        //
        if (ja3_ir) {
            fprintf(stdout, "%s\t%s\t%s\n", tmp_fp.ja3().c_str(), tmp_fp.get_ja3_hash().c_str(), fp_string.c_str());
        } else {
            fprintf(stdout, "%s\t%s\n", tmp_fp.get_ja3_hash().c_str(), fp_string.c_str());
        }

    }

    return 0;
}
