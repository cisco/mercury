// fingerprint.cc
//
// fingerprint conversion and analysis
//
// build:  g++ -Wall fingerprint.cc -o fingerprint -lcrypto
// run:    cat fingerprint_db.json | ./fingerprint


#include <stdio.h>
#include <string>
#include <vector>
#include <ostream>
#include <regex>
#include <openssl/md5.h>

#include "options.h"

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

    fp(const std::string &v, const std::string & cv, const std::vector<std::string> &e) : version{v}, ciphersuite_vector{cv}, extensions{e} { }

    fp(std::string &s) : version{}, ciphersuite_vector{}, extensions{} {

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

        const char *c = s.c_str();
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
                for (auto c = supported_groups.begin() + 12; c < supported_groups.end();  ) {
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

void test() {

    std::string r1 = "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0";
    std::string a1 = "(0301)(002f00350005000ac009c00ac013c0140032003800130004)((0000)(000a0006001700180019)(000b00020000))";
    std::string h1 = "ada70206e40642a3e4461f35503241d5";

    fp tls_fp1(a1);
    tls_fp1.fprint(stderr);
    // tls_fp1.ja3(stdout);
    fprintf(stderr, "ref: %s\n", r1.c_str());
    fprintf(stderr, "tmp: %s\n", tls_fp1.ja3().c_str());
    fprintf(stderr, "out: %s\n", tls_fp1.get_ja3_hash().c_str());
    fprintf(stderr, "ref: %s\n", h1.c_str());

    std::string r2 = "769,4-5-10-9-100-98-3-6-19-18-99,,,";
    std::string a2 = "(0301)(00040005000a00090064006200030006001300120063)()";
    std::string h2 = "de350869b8c85de67a350c8d186f11e6";

    fp tls_fp2(a2);
    tls_fp2.fprint(stderr);
    // tls_fp2.ja3(stdout);
    fprintf(stderr, "ref: %s\n", r2.c_str());
    fprintf(stderr, "tmp: %s\n", tls_fp2.ja3().c_str());
    fprintf(stderr, "out: %s\n", tls_fp2.get_ja3_hash().c_str());
    fprintf(stderr, "ref: %s\n", h2.c_str());

    return;

    std::string tls_fp_str = "(0303)(c030c02cc028c02400a500a1009f006b00690068c032c02ec02ac026009d003dc02fc02bc027c02300a400a0009e0067003f003ec031c02dc029c025009c003c00ff)((000b000403000102)(000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a)(0023)(000d0020001e060106020603050105020503040104020403030103020303020102020203)(000f000101))";

    fp tls_fp(tls_fp_str);
    tls_fp.fprint(stderr);
    tls_fp.ja3(stdout);
    fprintf(stderr, "%s\n", tls_fp.ja3().c_str());
    fprintf(stderr, "%s\n", tls_fp.get_ja3_hash().c_str());

    //769,4-5-10-9-100-98-3-6-19-18-99,,, --> de350869b8c85de67a350c8d186f11e6

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

    const char summary[] =
        "usage:\n"
        "   fingerprint [OPTIONS]\n"
        "\n"
        "OPTIONS\n"
        ;
    class option_processor opt({
        { argument::none,       "--input-json",   "input is in JSON format" },
        { argument::none,       "--output-ja3-ir", "output JA3 intermediate representation" },
        { argument::required,   "--match",         "filter fingerprints matching <arg>" },
        { argument::none,       "--help",      "print out help message" }
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
        if (fp_string == "randomized") {
            fprintf(stderr, "note: ignoring randomized fingerprint\n");
        } else {
            fp tmp_fp(fp_string);

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

    }

    return 0;
}
