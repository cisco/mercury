

#include <stdio.h>
#include <string>
#include <vector>
#include <ostream>
#include <regex>
#include <openssl/md5.h>

#include "datum.h"
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
            for (const auto &prefix : { std::string{"http/"} }) {
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
                size_t first_slash = s.find_first_of('/');
                if (first_slash != std::string::npos) {
                    size_t second_slash = s.find_first_of('/', first_slash+1);
                    if (second_slash != std::string::npos) {
                        s.erase(first_slash, second_slash - first_slash);
                    }
                }
                version = parse_value_from_str(&c);
                ciphersuite_vector = parse_value_from_str(&c);
            }
    
            // remove leading "quic/" prefix, if need be
            //
            prefix = "quic/";
            if (!s.compare(0, prefix.length(), prefix)) {
                c += prefix.length();
                // remove format version identifier, if need be
                size_t first_slash = s.find_first_of('/');
                if (first_slash != std::string::npos) {
                    size_t second_slash = s.find_first_of('/', first_slash+1);
                    if (second_slash != std::string::npos) {
                        s.erase(first_slash, second_slash - first_slash);
                    }
                }
                version = parse_value_from_str(&c);
                std::string temp = parse_value_from_str(&c);
                ciphersuite_vector = parse_value_from_str(&c);
            }
    
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

fp* fp_init(const char * s){
    return new fp(s);
}

std::string fp_get_ciphersuite_vector(fp *f) {
    datum result(f->ciphersuite_vector);
    return result.get_string();
}