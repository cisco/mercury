// fpdb_reader.hpp
//
// JSON parser for reading FPDB files

#ifndef FPDB_READER_HPP
#define FPDB_READER_HPP

#include "libmerc/rapidjson/document.h"
#include "libmerc/libmerc.h"
#include "libmerc/fingerprint.h"
#include "libmerc/result.h"
#include "libmerc/watchlist.hpp"
#include "libmerc/rapidjson/document.h"


#include <vector>
#include <map>
#include <algorithm>

class process_info {
public:
    std::string name;
    bool malware;
    uint64_t count;
    attribute_result::bitset attributes;
    std::unordered_map<uint32_t, uint64_t>    ip_as;
    std::unordered_map<std::string, uint64_t> hostname_domains;
    std::unordered_map<uint16_t, uint64_t>    portname_applications;
    std::unordered_map<std::string, uint64_t> ip_ip;
    std::unordered_map<std::string, uint64_t> hostname_sni;
    std::unordered_map<std::string, uint64_t> user_agent;
    std::map<std::string, uint64_t> os_info;
    bool extended_fp_metadata = false;

    process_info(const std::string &proc_name,
                 bool is_malware,
                 uint64_t proc_count,
                 attribute_result::bitset &attr,
                 const std::unordered_map<uint32_t, uint64_t> &as,
                 const std::unordered_map<std::string, uint64_t> &domains,
                 const std::unordered_map<uint16_t, uint64_t> &ports,
                 const std::unordered_map<std::string, uint64_t> &ip,
                 const std::unordered_map<std::string, uint64_t> &sni,
                 const std::unordered_map<std::string, uint64_t> &ua,
                 const std::map<std::string, uint64_t> &oses) :
        name{proc_name},
        malware{is_malware},
        count{proc_count},
        attributes{attr},
        ip_as{as},
        hostname_domains{domains},
        portname_applications{ports},
        ip_ip{ip},
        hostname_sni{sni},
        user_agent{ua},
        os_info{oses} {
        if (!ip.empty() && !sni.empty()) {
            extended_fp_metadata = true;
        }
    }

    void print(FILE *f) const {
        fprintf(f, "{\"process\":\"%s\"", name.c_str());
        fprintf(f, ",\"count\":\"%" PRIu64 "\"", count);
        fprintf(f, ",\"classes_ip_as\":{");
        char comma = ' ';
        for (auto &x : ip_as) {
            fprintf(f, "%c\"%u\":%" PRIu64, comma, x.first, x.second);
            comma = ',';
        }
        fprintf(f, "}");
        fprintf(f, ",\"classes_hostname_domains\":{");
        comma = ' ';
        for (auto &x : hostname_domains) {
            fprintf(f, "%c\"%s\":%" PRIu64, comma, x.first.c_str(), x.second);
            comma = ',';
        }
        fprintf(f, "}");
        fprintf(f, ",\"classes_port_applications\":{");
        comma = ' ';
        for (auto &x : portname_applications) {
            fprintf(f, "%c\"%u\":%" PRIu64, comma, x.first, x.second);
            comma = ',';
        }
        fprintf(f, "}");

        if (!ip_ip.empty() && !hostname_sni.empty()) {
            fprintf(f, ",\"classes_ip_ip\":{");
            comma = ' ';
            for (auto &x : ip_ip) {
                fprintf(f, "%c\"%s\":%" PRIu64, comma, x.first.c_str(), x.second);
                comma = ',';
            }
            fprintf(f, "}");

            fprintf(f, ",\"classes_hostname_sni\":{");
            comma = ' ';
            for (auto &x : hostname_sni) {
                fprintf(f, "%c\"%s\":%" PRIu64, comma, x.first.c_str(), x.second);
                comma = ',';
            }
            fprintf(f, "}");
        }

        // TBD: print malware data

        fprintf(f, "}");
    }
};


// struct common_data holds data that is common to all fingerprints,
// within the classifier
//
struct common_data {
    //    std::vector<std::string> tag_names;
    attribute_names attr_name;
    watchlist doh_watchlist;
    ssize_t doh_idx = -1;
};

// data type used in floating point computations
//
using floating_point_type = long double;

// an instance of class update represents an update to a prior
// probability
//
class update {
public:
    update(unsigned int i, floating_point_type v) : index{i}, value{v} {}
    unsigned int index;  // index of probability to update
    floating_point_type value;   // value of update
};

class resources {

    std::unordered_map<std::string, std::vector<process_info>> fpdb;

    std::vector<fingerprint_type> fp_types;
    bool first_line = true;
    bool MALWARE_DB = false;
    bool EXTENDED_FP_METADATA = false;

    size_t tls_fingerprint_format = 0;

    const subnet_data *subnet_data_ptr = nullptr;

    common_data common;

public:

    enum verbosity { verbose=true, silent=false };

    resources(std::istream &input, verbosity verbosity_level=silent) {
        size_t line_number = 0;
        std::string line;
        while (std::getline(input, line)) {
            if (line.length() == 0 || line[0] == '/') {
                continue;
            }
            //fprintf(stdout, "%s\n", line.c_str());
            if (verbosity_level) { fprintf(stderr, "\rreading line %zu", line_number++); }
            process_fp_db_line(line);
        }
        if (verbosity_level) { fputc('\n', stderr); }
    }

    static fingerprint_type get_fingerprint_type(const std::string &s) {
        if (s == "tls") {
            return fingerprint_type_tls;
        } else if (s == "http") {
            return fingerprint_type_http;
        } else if (s == "quic") {
            return fingerprint_type_quic;
        }
        return fingerprint_type_unknown;
    }

    static std::pair<fingerprint_type, size_t> get_fingerprint_type_and_version(const std::string &s) {
        fingerprint_type type = fingerprint_type_unknown;
        unsigned int version = 0;
        auto idx = s.find('/');
        if (idx != std::string::npos) {

            try {
                if (s.compare(0, idx, "tls") == 0) {
                    type = fingerprint_type_tls;
                } else if (s.compare(0, idx, "http") == 0) {
                    type = fingerprint_type_http;
                } else if (s.compare(0, idx, "quic") == 0) {
                    type = fingerprint_type_quic;
                }
                std::string version_and_tail{s.substr(idx+1)};

                // check whether there is no explicit version number
                //
                std::string randomized{"randomized"};
                if (version_and_tail.at(0) == '(' || version_and_tail.compare(0, randomized.length(), randomized) == 0) {
                    version = 0;
                } else {
                    version = std::stoi(version_and_tail);  // parse version number
                }
            }
            catch (...) {
                printf_err(log_warning, "unknown protocol or version in fingerprint %s\n", s.c_str());
                return { fingerprint_type_unknown, 0 };
            }
        }
        return { type, version };
    }

    void process_fp_db_line(std::string &line_str) {

        rapidjson::Document fp;
        fp.Parse(line_str.c_str());

        std::string fp_string;
        if (fp.HasMember("str_repr") && fp["str_repr"].IsString()) {
            fp_string = fp["str_repr"].GetString();

            if (fp_string.length() == 0) {
                printf_err(log_warning, "ignoring zero-length fingerprint string in resource file\n");
                return;  // can't process this entry, so skip it
            }

            if (fp_string.length() >= fingerprint::max_length()) {
                printf_err(log_warning, "ignoring length %zu fingerprint string in resource file; too long\n", fp_string.length());
                return;  // can't process this entry, so skip it
            }

        }


        fingerprint_type fp_type_code = fingerprint_type_tls;
        std::string fp_type_string;
        if (fp.HasMember("fp_type") && fp["fp_type"].IsString()) {
            fp_type_string = fp["fp_type"].GetString();
            fp_type_code = get_fingerprint_type(fp_type_string.c_str());
        }
        if (fp_type_code != fingerprint_type_unknown) {
            if (std::find(fp_types.begin(), fp_types.end(), fp_type_code) == fp_types.end()) {
                fp_types.push_back(fp_type_code);
            }
        }

        // if a TLS fingerprint string does not contain a protocol
        // name, and is not 'randomized', add "tls/" in order to provide
        // backwards compatibility with resource files with the older
        // fingerprint format
        //
        if (fp_type_code == fingerprint_type_tls && (fp_string.at(0) == '(' || fp_string == "randomized")) {
            fp_string = "tls/" + fp_string;
        }

        std::pair<fingerprint_type, size_t> fingerprint_type_and_version = get_fingerprint_type_and_version(fp_string.c_str());

        if (fp_type_code != fingerprint_type_and_version.first) {
            printf_err(log_warning, "fingerprint type of str_repr '%s' does not match fp_type, ignorning JSON line\n", fp_string.c_str());
            return;
        }

        // ensure that all tls fingerprints in DB have the same version
        //
        if (fingerprint_type_and_version.first == fingerprint_type_tls) {
            if (first_line == true) {
                tls_fingerprint_format = fingerprint_type_and_version.second;
            } else {
                if (fingerprint_type_and_version.second != tls_fingerprint_format) {
                    printf_err(log_warning, "fingerprint version with inconsistent format, ignoring JSON line\n");
                    return;
                }
            }
            first_line = false;
        }

        uint64_t total_count = 0;
        if (fp.HasMember("total_count") && fp["total_count"].IsUint64()) {
            total_count = fp["total_count"].GetUint64();
        }
        (void)total_count; // prevent compiler complaining

        std::vector<class process_info> process_vector;

        if (fp.HasMember("process_info") && fp["process_info"].IsArray()) {
            //fprintf(stderr, "process_info[]\n");

            unsigned int process_number = 0;
            for (auto &x : fp["process_info"].GetArray()) {
                uint64_t count = 0;
                bool malware = false;

                if (x.HasMember("count") && x["count"].IsUint64()) {
                    count = x["count"].GetUint64();
                    //fprintf(stderr, "\tcount: %lu\n", x["count"].GetUint64());
                }
                if (x.HasMember("malware") && x["malware"].IsBool()) {
                    if (MALWARE_DB == false && process_number > 1) {
                        throw std::runtime_error("error: malware data expected, but not present");
                    }
                    MALWARE_DB = true;
                    malware = x["malware"].GetBool();
                }
                if (count == 0) {
                    throw std::runtime_error("error: process_fp_db_line() count 0");
                    continue;
                }

                process_number++;
                //fprintf(stderr, "%s\n", "process_info");

                attribute_result::bitset attributes;
                std::unordered_map<uint32_t, uint64_t>    ip_as;
                std::unordered_map<std::string, uint64_t> hostname_domains;
                std::unordered_map<uint16_t, uint64_t>    portname_applications;
                std::unordered_map<std::string, uint64_t> ip_ip;
                std::unordered_map<std::string, uint64_t> hostname_sni;
                std::unordered_map<std::string, uint64_t> user_agent;
                std::map<std::string, uint64_t> os_info;

                std::string name;
                if (x.HasMember("process") && x["process"].IsString()) {
                    name = x["process"].GetString();
                    //fprintf(stderr, "\tname: %s\n", x["process"].GetString());
                }
                if (x.HasMember("attributes") && x["attributes"].IsObject()) {
                    for (auto &v : x["attributes"].GetObject()) {
                        if (v.name.IsString()) {
                            ssize_t idx = common.attr_name.get_index(v.name.GetString());
                            if (idx < 0) {
                                printf_err(log_warning, "unknown attribute %s while parsing process information\n", v.name.GetString());
                                throw std::runtime_error("error while parsing resource archive file");
                            }
                            if (v.value.IsBool() and v.value.GetBool()) {
                                attributes[idx] = 1;
                            }
                        }
                    }
                    common.attr_name.stop_accepting_new_names();

                }
                if (x.HasMember("classes_hostname_domains") && x["classes_hostname_domains"].IsObject()) {
                    //fprintf(stderr, "\tclasses_hostname_domains\n");
                    for (auto &y : x["classes_hostname_domains"].GetObject()) {
                        if (y.value.IsUint64()) {
                            //fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());
                            hostname_domains[y.name.GetString()] = y.value.GetUint64();
                        }
                    }
                }
                if (x.HasMember("classes_ip_as") && x["classes_ip_as"].IsObject()) {
                    //fprintf(stderr, "\tclasses_ip_as\n");
                    for (auto &y : x["classes_ip_as"].GetObject()) {
                        if (y.value.IsUint64()) {
                            //fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());

                            if (strcmp(y.name.GetString(), "unknown") != 0) {

                                errno = 0;
                                unsigned long as_number = strtol(y.name.GetString(), NULL, 10);
                                if (errno) {
                                    as_number = 0; // "unknown"
                                    printf_err(log_notice, "found string \"%s\" in ip_as\n", y.name.GetString());
                                }
                                if (as_number > 0xffffffff) {
                                    throw std::runtime_error("error: as number too high");
                                }
                                ip_as[as_number] = y.value.GetUint64();

                            }
                        }
                    }
                }

                if (x.HasMember("classes_ip_ip") && x["classes_ip_ip"].IsObject()) {
                    if (EXTENDED_FP_METADATA == false && process_number > 1) {
                        throw std::runtime_error("error: extended fingerprint metadata expected, but not present");
                    }
                    EXTENDED_FP_METADATA = true;
                    //fprintf(stderr, "\tclasses_ip_ip\n");
                    for (auto &y : x["classes_ip_ip"].GetObject()) {
                        if (!y.value.IsUint64()) {
                            printf_err(log_warning, "classes_ip_ip object element %s is not a Uint64\n", y.name.GetString());
                            //fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());
                            ip_ip[y.name.GetString()] = y.value.GetUint64();
                        }
                    }
                }
                if (x.HasMember("classes_hostname_sni") && x["classes_hostname_sni"].IsObject()) {
                    if (EXTENDED_FP_METADATA == false && process_number > 1) {
                        throw std::runtime_error("error: extended fingerprint metadata expected, but not present");
                    }
                    EXTENDED_FP_METADATA = true;
                    //fprintf(stderr, "\tclasses_hostname_sni\n");
                    for (auto &y : x["classes_hostname_sni"].GetObject()) {
                        if (y.value.IsUint64()) {
                            //fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());
                            hostname_sni[y.name.GetString()] = y.value.GetUint64();
                        }
                    }
                }
                if (x.HasMember("classes_user_agent") && x["classes_user_agent"].IsObject()) {
                    if (EXTENDED_FP_METADATA == false && process_number > 1) {
                        throw std::runtime_error("error: extended fingerprint metadata expected, but not present");
                    }
                    EXTENDED_FP_METADATA = true;
                    for (auto &y : x["classes_user_agent"].GetObject()) {
                        if (y.value.IsUint64()) {
                            //fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());
                            user_agent[y.name.GetString()] = y.value.GetUint64();
                        }
                    }
                }
                if (x.HasMember("os_info") && x["os_info"].IsObject()) {
                    for (auto &y : x["os_info"].GetObject()) {
                        if (std::string(y.name.GetString()) != "") {
                            os_info[y.name.GetString()] = y.value.GetUint64();
                        }
                    }
                }

                class process_info process(name, malware, count, attributes, ip_as, hostname_domains, portname_applications,
                                           ip_ip, hostname_sni, user_agent, os_info);
                // process.print(stdout);
                process_vector.push_back(process);
            }
            // class fingerprint_data fp_data(total_count, process_vector, os_dictionary, &subnets, &common, MALWARE_DB);
            // fp_data.print(stderr);

            //            std::vector<process_info> fp_data{process_vector};
            if (fpdb.find(fp_string) != fpdb.end()) {
                printf_err(log_warning, "fingerprint database has duplicate entry for fingerprint %s\n", fp_string.c_str());
            }
            fpdb[fp_string] = process_vector;
        }
    }

    const std::unordered_map<std::string, std::vector<process_info>> & get_fpdb() const { return fpdb; }
};

#endif // FPDB_READER_HPP
