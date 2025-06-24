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

using namespace mercury_option;

#include "libmerc/rapidjson/document.h"

struct char_pair { char first; char second; };

inline struct char_pair raw_to_hex(unsigned char x) {
    char hex[]= "0123456789abcdef";
    struct char_pair result = { hex[x >> 4], hex[x & 0x0f] };
    return result;
}

class fp {
public:
    std::string version;
    std::string ciphersuite_vector;
    std::vector<std::string> extensions;
    bool valid = false;

    char open = '(';
    char close = ')';

    std::string parse_value_from_str(const char **cc) {
        const char *c = *cc;
        if (*c++ == open) {
            const char *start = c;
            while (*c != close) {
                c++;
            }
            std::string value(start, (int)(c - start));
            c++; // advance past 'open' delimiter
            *cc = c;
            return value;
        }
        return "";
    }

    explicit operator bool() const { return valid; }

    fp(const std::string &v, const std::string & cv, const std::vector<std::string> &e) : version{v}, ciphersuite_vector{cv}, extensions{e} { }

    fp(std::string s) : version{}, ciphersuite_vector{}, extensions{} {

        if (s == "") {
            fprintf(stderr, "warning: got empty string in %s\n", __func__);
            return;
        }
        if (s == "randomized") {
            fprintf(stderr, "warning: got randomized string in %s\n", __func__);
            return;
        }

        if (s[0] == '<') {
            // use bracket delimeters
            open = '<';
            close = '>';
        }

        // ignore "quic/" or "http/" prefix, if need be
        //
        for (const auto &prefix : { std::string{"http/"}, std::string{"quic/"} }) {
            if (!s.compare(0, prefix.length(), prefix)) {
                fprintf(stderr, "note: ignoring %s fingerprint\n", prefix.c_str());
                return;
            }
        }
        const char *c = s.c_str();

        // remove leading "tls/" prefix, if need be
        //
        std::string prefix = "tls/";
        if (!s.compare(0, prefix.length(), prefix)) {
            c += prefix.length();
        }

        // remove format version identifier, if need be
        //
        fprintf(stderr, "searching for / in %s\n", s.c_str());
        size_t first_slash = s.find_first_of('/');
        if (first_slash != std::string::npos) {
            size_t second_slash = s.find_first_of('/', first_slash+1);
            if (second_slash != std::string::npos) {
                s.erase(first_slash, second_slash - first_slash);
            }
        }

        version = parse_value_from_str(&c);
        ciphersuite_vector = parse_value_from_str(&c);

        if (*c++ == open) {
            while (true) {
                std::string tmp = parse_value_from_str(&c);
                if (tmp != "") {
                    extensions.push_back(tmp);
                } else {
                    break;
                }
            }
        }

        valid = true;
    }

    void fprint(FILE *f) {
        fprintf(f, "version: %s\n", version.c_str());
        fprintf(f, "ciphersuite_vector: %s\n", ciphersuite_vector.c_str());
        for (const auto &s : extensions) {
            fprintf(f, "extension: %s\n", s.c_str());
        }
    }

    std::string get_str_repr() const {
        std::string s = "(";
        s += version;
        s += ")(";
        s += ciphersuite_vector;
        s += ")(";
        for (const auto &e : extensions) {
            s += "(";
            s += e;
            s += ")";
        }
        s += ")";

        return s;
    }

    void ja3(FILE *f) {
        std::string s = ja3();
        fprintf(f, "%s\n", s.c_str());
    }

    std::string ja3() {
        try {

            char outbuf[8092] = { 0, };
            size_t buflen = 8092;
            char *buf = &outbuf[0];

            uint16_t v = std::stoul(version, nullptr, 16);
            int r = snprintf(buf, buflen, "%u,", v);
            buf += r; buflen -= r;

            bool first = true;
            char ciphersuite[5] = { 0x0, 0x0, 0x0, 0x0, 0x0 };
            for (auto c = ciphersuite_vector.begin(); c < ciphersuite_vector.end();  ) {
                ciphersuite[0] = *c++;
                ciphersuite[1] = *c++;
                ciphersuite[2] = *c++;
                ciphersuite[3] = *c++;
                unsigned long int cs = std::stoul(ciphersuite, nullptr, 16);
                if (cs != 0x0a0a) {  // skip GREASE ciphersuites
                    if (!first) {
                        r = snprintf(buf, buflen, "-");
                        buf += r; buflen -= r;
                    }
                    first = false;
                    r = snprintf(buf, buflen, "%lu", cs);
                    buf += r; buflen -= r;
                }
            }

            r = snprintf(buf, buflen, ",");
            buf += r; buflen -= r;
            std::string supported_groups, elliptic_curve_point_formats;
            first = true;
            if (extensions.size() > 0) {
                for (const auto & x : extensions) {
                    std::string typecode = x.substr(0, 4);
                    unsigned long int x_type = std::stoul(typecode, nullptr, 16);
                    if (x_type != 0x0a0a) {  // skip GREASE types
                        if (!first) {
                            r = snprintf(buf, buflen, "-");
                            buf += r; buflen -= r;
                        }
                        first = false;
                        r = snprintf(buf, buflen, "%lu", x_type);
                        buf += r; buflen -= r;
                    }
                    // copy some elements for further processing
                    if (x_type == 0x000a) {
                        supported_groups = x;
                    } else if (x_type == 0x000b) {
                        elliptic_curve_point_formats = x;
                    }
                }
            }

            r = snprintf(buf, buflen, ",");
            buf += r; buflen -= r;

            // each supported group is expressed with uint16_t (two
            // byte unsigned integer), and the sequence of values
            // starts at an offset of six bytes (skipping the type
            // code, extension length, and supported group list length
            // fields)
            //
            if (supported_groups.length() >= 12) {
                first = true;
                char tmp[5] = { 0x0, 0x0, 0x0, 0x0, 0x0 };
                for (auto c = supported_groups.begin() + 8; c < supported_groups.end();  ) {
                    tmp[0] = *c++;
                    tmp[1] = *c++;
                    tmp[2] = *c++;
                    tmp[3] = *c++;
                    unsigned long int cs = std::stoul(tmp, nullptr, 16);
                    if (cs != 0x0a0a) {  // skip GREASE
                        if (!first) {
                            r = snprintf(buf, buflen, "-");
                            buf += r; buflen -= r;
                        }
                        first = false;
                        r = snprintf(buf, buflen, "%lu", cs);
                        buf += r; buflen -= r;
                    }
                }
            }

            r = snprintf(buf, buflen, ",");
            buf += r; buflen -= r;
            if (elliptic_curve_point_formats.length() >= 8) {
                first = true;
                char tmp[5] = { 0x0, 0x0, 0x0, 0x0, 0x0 };

                // each format is expressed in a single byte on the
                // wire, and the sequence of formats starts after five
                // bytes (type code, length, and format length)
                //
                for (auto c = elliptic_curve_point_formats.begin() + 10; c < elliptic_curve_point_formats.end();  ) {
                    tmp[0] = *c++;
                    tmp[1] = *c++;
                    unsigned long int cs = std::stoul(tmp, nullptr, 16);
                    if (!first) {
                        r = snprintf(buf, buflen, "-");
                        buf += r; buflen -= r;
                    }
                    first = false;
                    r = snprintf(buf, buflen, "%lu", cs);
                    buf += r; buflen -= r;
                }
            }

            std::string tmp{outbuf, (size_t)(buf - outbuf)};
            return tmp;
        }
        catch (...) {
            fprintf(stderr, "error: could not convert fingerprint to ja3\n");
            // fprint(stderr);
        }

        return "";
    }

    std::string get_ja3_hash() {
        std::string tmp = ja3();

        unsigned char digest[16];
        MD5_CTX md5_ctx;
        MD5_Init(&md5_ctx);
        MD5_Update(&md5_ctx, tmp.data(), tmp.length());
        MD5_Final(digest, &md5_ctx);

        std::string output;
        for (auto & c : digest) {
            char_pair pair = raw_to_hex(c);
            output.push_back(pair.first);
            output.push_back(pair.second);
        }
        return output;
    }

};

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