/*
 * analysis.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <stdio.h>
#include <math.h>
#include "packet.h"
#include "addr.h"
#include "json_object.h"

int analysis_init(int verbosity, const char *resource_dir);

int analysis_finalize();

class analysis_result {
    static const size_t max_proc_len = 256;
    bool valid = false;
    char max_proc[max_proc_len];
    long double max_score;
    bool max_mal;
    long double malware_prob;
    bool classify_malware;

public:
    analysis_result() : valid{false}, max_proc{0}, max_score{0.0}, max_mal{false}, malware_prob{-1.0}, classify_malware{false} { }

    analysis_result(const char *proc, long double score) : valid{true}, max_proc{0}, max_score{score}, max_mal{false}, malware_prob{-1.0}, classify_malware{false} {
        strncpy(max_proc, proc, max_proc_len-1);
    }
    analysis_result(const char *proc, long double score, bool mal, long double mal_prob) :
        valid{true}, max_proc{0}, max_score{score}, max_mal{mal}, malware_prob{mal_prob}, classify_malware{true} {
        strncpy(max_proc, proc, max_proc_len-1);
    }

    void write_json(struct json_object &o, const char *key) {
        struct json_object analysis{o, key};
        if (valid) {
            analysis.print_key_string("process", max_proc);
            analysis.print_key_float("score", max_score);
            if (classify_malware) {
                analysis.print_key_uint("malware", max_mal);
                analysis.print_key_float("p_malware", malware_prob);
            }
        } else {
            analysis.print_key_string("status", "unknown_fingerprint");
        }
        analysis.close();
    }

    bool is_valid() { return valid; }
};

class analysis_result analyze_client_hello_and_key(const struct tls_client_hello &hello,
                                                   const struct key &key);



// classifier

#include <string>
#include <vector>
#include <unordered_map>
#include <zlib.h>
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "tls.h"

// helper functions

#define MAX_DST_ADDR_LEN 48
#define MAX_FP_STR_LEN 4096
#define MAX_SNI_LEN     257

extern std::unordered_map<uint16_t, std::string> port_mapping;

std::string get_port_app(uint16_t dst_port);

std::string get_domain_name(char* server_name);

uint16_t flow_key_get_dst_port(const struct key &key);

void flow_key_sprintf_dst_addr(const struct key &key,
                               char *dst_addr_str);

int gzgetline(gzFile f, std::vector<char>& v);

class process_info {
public:
    std::string name;
    bool malware;
    uint64_t count;
    std::unordered_map<uint32_t, uint64_t> ip_as;
    std::unordered_map<std::string, uint64_t> hostname_domains;
    std::unordered_map<std::string, uint64_t> portname_applications;
    std::unordered_map<std::string, uint64_t> ip_ip;
    std::unordered_map<std::string, uint64_t> hostname_sni;
    bool extended_fp_metadata = false;

    process_info(std::string proc_name,
                 bool is_malware,
                 uint64_t proc_count,
                 std::unordered_map<uint32_t, uint64_t> as,
                 std::unordered_map<std::string, uint64_t> domains,
                 std::unordered_map<std::string, uint64_t> ports,
                 std::unordered_map<std::string, uint64_t> ip,
                 std::unordered_map<std::string, uint64_t> sni) :
        name{proc_name},
        malware{is_malware},
        count{proc_count},
        ip_as{as},
        hostname_domains{domains},
        portname_applications{ports},
        ip_ip{ip},
        hostname_sni{sni} {
            if (!ip.empty() && !sni.empty()) {
                extended_fp_metadata = true;
            }
        }

    void print(FILE *f) {
        fprintf(f, "{\"process\":\"%s\"", name.c_str());
        fprintf(f, ",\"count\":\"%lu\"", count);
        fprintf(f, ",\"classes_ip_as\":{");
        char comma = ' ';
        for (auto &x : ip_as) {
            fprintf(f, "%c\"%u\":%lu", comma, x.first, x.second);
            comma = ',';
        }
        fprintf(f, "}");
        fprintf(f, ",\"classes_hostname_domains\":{");
        comma = ' ';
        for (auto &x : hostname_domains) {
            fprintf(f, "%c\"%s\":%lu", comma, x.first.c_str(), x.second);
            comma = ',';
        }
        fprintf(f, "}");
        fprintf(f, ",\"classes_port_applications\":{");
        comma = ' ';
        for (auto &x : portname_applications) {
            fprintf(f, "%c\"%s\":%lu", comma, x.first.c_str(), x.second);
            comma = ',';
        }
        fprintf(f, "}");

        if (!ip_ip.empty() && !hostname_sni.empty()) {
            fprintf(f, ",\"classes_ip_ip\":{");
            comma = ' ';
            for (auto &x : ip_ip) {
                fprintf(f, "%c\"%s\":%lu", comma, x.first.c_str(), x.second);
                comma = ',';
            }
            fprintf(f, "}");

            fprintf(f, ",\"classes_hostname_sni\":{");
            comma = ' ';
            for (auto &x : hostname_sni) {
                fprintf(f, "%c\"%s\":%lu", comma, x.first.c_str(), x.second);
                comma = ',';
            }
            fprintf(f, "}");
        }

        // TBD: print malware data

        fprintf(f, "}");
    }
};

class fingerprint_data {
public:
    uint64_t total_count;
    std::vector<class process_info> process_data;

    fingerprint_data() : total_count{0}, process_data{}  { }

    fingerprint_data(uint64_t count, std::vector<class process_info> processes) :
        total_count{count},
        process_data{processes}  { }

    void print(FILE *f) {
        fprintf(f, ",\"total_count\":%lu", total_count);
        fprintf(f, ",\"process_info\":[");
        char comma = ' ';
        for (auto &p : process_data) {
            fputc(comma, f);
            p.print(f);
            comma = ',';
        }
        fprintf(f, "]");
    }
};

// static const char* kTypeNames[] = { "Null", "False", "True", "Object", "Array", "String", "Number" };
// fprintf(stderr, "Type of member %s is %s\n", "str_repr", kTypeNames[fp["str_repr"].GetType()]);

class classifier {
    bool MALWARE_DB = false;
    bool EXTENDED_FP_METADATA = false;

public:
    std::unordered_map<std::string, class fingerprint_data> fpdb;

    classifier(const char *resource_file) : fpdb{} {

        gzFile in_file = gzopen(resource_file, "r");
        if (in_file == NULL) {
            throw "error: could not open resource file";
        }
        std::vector<char> line;
        while (gzgetline(in_file, line)) {
            std::string line_str(line.begin(), line.end());
            rapidjson::Document fp;
            fp.Parse(line_str.c_str());

            std::string fp_string;
            if (fp.HasMember("str_repr") && fp["str_repr"].IsString()) {
                fp_string = fp["str_repr"].GetString();
                //fprintf(stderr, "%s\n", fp_string.c_str());
            }

            uint64_t total_count = 0;
            if (fp.HasMember("total_count") && fp["total_count"].IsUint64()) {
                total_count = fp["total_count"].GetUint64();
            }

            std::vector<class process_info> process_vector;

            if (fp.HasMember("process_info") && fp["process_info"].IsArray()) {
                //fprintf(stderr, "process_info[]\n");

                unsigned int process_number = 0;
                for (auto &x : fp["process_info"].GetArray()) {
                    process_number++;
                    //fprintf(stderr, "%s\n", "process_info");

                    bool malware = false;
                    std::unordered_map<uint32_t, uint64_t> ip_as;
                    std::unordered_map<std::string, uint64_t> hostname_domains;
                    std::unordered_map<std::string, uint64_t> portname_applications;
                    std::unordered_map<std::string, uint64_t> ip_ip;
                    std::unordered_map<std::string, uint64_t> hostname_sni;

                    uint64_t count = 0;
                    std::string name;
                    if (x.HasMember("process") && x["process"].IsString()) {
                        name = x["process"].GetString();
                        //fprintf(stderr, "\tname: %s\n", x["process"].GetString());
                    }
                    if (x.HasMember("count") && x["count"].IsUint64()) {
                        count = x["count"].GetUint64();
                        //fprintf(stderr, "\tcount: %lu\n", x["count"].GetUint64());
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

                                unsigned long as_number = strtol(y.name.GetString(), NULL, 10);
                                if (as_number > 0xffffffff) {
                                    throw "error: as number too high";
                                }
                                ip_as[as_number] = y.value.GetUint64();
                            }
                        }
                    }
                    if (x.HasMember("classes_port_applications") && x["classes_port_applications"].IsObject()) {
                        //fprintf(stderr, "\tclasses_port_applications\n");
                        for (auto &y : x["classes_port_applications"].GetObject()) {
                            if (y.value.IsUint64()) {
                                //fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());
                            }
                            portname_applications[y.name.GetString()] = y.value.GetUint64();
                        }
                    }
                    if (x.HasMember("classes_ip_ip") && x["classes_ip_ip"].IsObject()) {
                        if (EXTENDED_FP_METADATA == false && process_number > 1) {
                            throw "error: extended fingerprint metadata expected, but not present";
                        }
                        EXTENDED_FP_METADATA = true;
                        //fprintf(stderr, "\tclasses_ip_ip\n");
                        for (auto &y : x["classes_ip_ip"].GetObject()) {
                            if (!y.value.IsUint64()) {
                                fprintf(stderr, "warning: classes_ip_ip object element %s is not a Uint64\n", y.name.GetString());
                                //fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());
                            }
                            ip_ip[y.name.GetString()] = y.value.GetUint64();
                        }
                    }
                    if (x.HasMember("classes_hostname_sni") && x["classes_hostname_sni"].IsObject()) {
                        if (EXTENDED_FP_METADATA == false && process_number > 1) {
                            throw "error: extended fingerprint metadata expected, but not present";
                        }
                        EXTENDED_FP_METADATA = true;
                        //fprintf(stderr, "\tclasses_hostname_sni\n");
                        for (auto &y : x["classes_hostname_sni"].GetObject()) {
                            if (y.value.IsUint64()) {
                                //fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());
                            }
                            hostname_sni[y.name.GetString()] = y.value.GetUint64();
                        }
                    }
                    if (x.HasMember("malware") && x["malware"].IsBool()) {
                        if (MALWARE_DB == false && process_number > 1) {
                            throw "error: malware data expected, but not present";
                        }
                        MALWARE_DB = true;
                        malware = x["malware"].GetBool();
                    }

                    class process_info process(name, malware, count, ip_as, hostname_domains, portname_applications, ip_ip, hostname_sni);
                    process_vector.push_back(process);
                }
                class fingerprint_data fp_data(total_count, process_vector);
                // fp_data.print(stderr);

                if (fpdb.find(fp_string) != fpdb.end()) {
                    fprintf(stderr, "warning: file %s has duplicate entry for fingerprint %s\n", resource_file, fp_string.c_str());
                }
                fpdb[fp_string] = fp_data;
            }

        }
        gzclose(in_file);

    }

    void print(FILE *f) {
        for (auto &fpdb_entry : fpdb) {
            fprintf(f, "{\"str_repr\":\"%s\"", fpdb_entry.first.c_str());
            fpdb_entry.second.print(f);
            fprintf(f, "}\n");
        }
    }

    struct analysis_result perform_analysis(char *fp_str, char *server_name, char *dst_ip, uint16_t dst_port) {
        const auto fpdb_entry = fpdb.find(fp_str);
        if (fpdb_entry == fpdb.end()) {
            return analysis_result();
        }
        class fingerprint_data &fp = fpdb_entry->second;

        uint32_t asn_int = get_asn_info(dst_ip);
        std::string asn = std::to_string(asn_int);
        std::string port_app = get_port_app(dst_port);
        std::string domain = get_domain_name(server_name);
        std::string server_name_str(server_name);
        std::string dst_ip_str(dst_ip);

        uint64_t fp_tc, p_count, tmp_value;
        long double prob_process_given_fp, score;
        long double max_score = -1.0;
        long double sec_score = -1.0;
        long double score_sum = 0.0;
        long double malware_prob = 0.0;
        rapidjson::Value equiv_class;
        std::string max_proc;
        std::string sec_proc;
        bool max_mal = false;
        bool sec_mal = false;

        rapidjson::Value proc;
        fp_tc = fp.total_count;

        long double base_prior;
        long double proc_prior = log(.1);

        unsigned int hits = 0;
        unsigned int num_procs = 0;
        for (const auto &p : fp.process_data) {
            ++num_procs;
            p_count = p.count;
            prob_process_given_fp = (long double)p_count/fp_tc;

            base_prior = log(1.0/fp_tc);
            score = log(prob_process_given_fp);
            score = fmax(score, proc_prior);

            fprintf(stderr, "process %s starting with score %Lf\n", p.name.c_str(), score);

            const auto tmp = p.ip_as.find(asn_int);
            if (tmp != p.ip_as.end()) {
                tmp_value = tmp->second;
                fprintf(stderr, "found ip_as:                 %s\n", asn.c_str());
                ++hits;
                score += log((long double)tmp_value/fp_tc)*0.13924;
            } else {
                score += base_prior*0.13924;
            }
            fprintf(stderr, "score: %Lf\n", score);

            const auto a = p.hostname_domains.find(domain);
            if (a != p.hostname_domains.end()) {
                tmp_value = a->second;
                fprintf(stderr, "found hostname_domains:      %s\n", domain.c_str());
                ++hits;
                score += log((long double)tmp_value/fp_tc)*0.15590;
            } else {
                score += base_prior*0.15590;
            }
            fprintf(stderr, "score: %Lf\n", score);

            const auto b = p.portname_applications.find(port_app);
            if (b != p.portname_applications.end()) {
                tmp_value = b->second;
                fprintf(stderr, "found portname_applications: %s\n", port_app.c_str());
                ++hits;
                score += log((long double)tmp_value/fp_tc)*0.00528;
            } else {
                score += base_prior*0.00528;
            }
            fprintf(stderr, "score: %Lf\n", score);

            if (EXTENDED_FP_METADATA) {
                fprintf(stderr, "looking for ip_ip %s\n", dst_ip_str.c_str());
                const auto ip_ip = p.ip_ip.find(dst_ip_str);
                if (ip_ip != p.ip_ip.end()) {
                    tmp_value = ip_ip->second;
                    fprintf(stderr, "found ip_ip %s with tmp_value %lu\n", dst_ip_str.c_str(), tmp_value);
                    ++hits;
                    score += log((long double)tmp_value/fp_tc)*0.56735;
                } else {
                    score += base_prior*0.56735;
                }
                fprintf(stderr, "score: %Lf\n", score);

                const auto hostname_sni = p.hostname_sni.find(server_name_str);
                if (hostname_sni != p.hostname_sni.end()) {
                    tmp_value = hostname_sni->second;
                    fprintf(stderr, "found server_name_str %s with tmp_value %lu\n", hostname_sni->first.c_str(), tmp_value);
                    ++hits;
                    score += log((long double)tmp_value/fp_tc)*0.96941;
                } else {
                    score += base_prior*0.96941;
                }
                fprintf(stderr, "score: %Lf\n", score);

            }

            score = exp(score);
            score_sum += score;

            fprintf(stderr, "exp(score): %Le\n", score);

            if (MALWARE_DB) {
                if (p.malware && score > 0.0) {
                    malware_prob += score;
                }

                if (score > max_score) {
                    sec_score = max_score;
                    sec_proc = max_proc;
                    sec_mal = max_mal;
                    max_score = score;
                    max_proc = p.name;
                    max_mal = p.malware;
                    fprintf(stderr, "[2] setting max_proc to %s with exp(score) %Le\n", p.name.c_str(), score);
                } else if (score > sec_score) {
                    sec_score = score;
                    sec_proc = p.name;
                    sec_mal = p.malware;
                    fprintf(stderr, "[3] setting sec_proc to %s with exp(score) %Le\n", p.name.c_str(), score);
                } else {
                   fprintf(stderr, "[4] rejecting process %s with exp(score) %Le\n", p.name.c_str(), score);
                }
            } else {
                if (score > max_score) {
                    max_score = score;
                    max_proc = p.name;
                    fprintf(stderr, "[1] setting max_proc to %s with exp(score) %Le\n", p.name.c_str(), score);
                } else {
                    fprintf(stderr, "rejecting process %s with exp(score) %Le\n", p.name.c_str(), score);
                }
            }
        }

        if (MALWARE_DB && max_proc == "generic dmz process" && sec_mal == false) {
            fprintf(stderr, "setting max_proc to sec_proc (%s to %s)\n", max_proc.c_str(), sec_proc.c_str());
            max_proc = sec_proc;
            max_score = sec_score;
            max_mal = sec_mal;
        }

        fprintf(stderr, "pre-adjust score: %Le\n", max_score);
        fprintf(stderr, "score_sum:        %Le\n", score_sum);

        if (score_sum > 0.0) {
            max_score /= score_sum;
            if (MALWARE_DB) {
                malware_prob /= score_sum;
            }
        }
        fprintf(stderr, "hits:      %u\n", hits);
        fprintf(stderr, "num_procs: %u\n", num_procs);
        fprintf(stderr, "final proc is %s with score %Lf\n\n", max_proc.c_str(), max_score);

        if (MALWARE_DB) {
            return analysis_result(max_proc.c_str(), max_score, max_mal, malware_prob);
        }
        return analysis_result(max_proc.c_str(), max_score);
    }

    class analysis_result analyze_client_hello_and_key(const struct tls_client_hello &hello,
                                                       const struct key &key) {
        uint16_t dst_port = flow_key_get_dst_port(key);
        char dst_ip_str[MAX_DST_ADDR_LEN];
        flow_key_sprintf_dst_addr(key, dst_ip_str);

        // copy fingerprint string
        char fp_str[MAX_FP_STR_LEN] = { 0 };
        struct buffer_stream fp_buf{fp_str, MAX_FP_STR_LEN};
        hello.write_fingerprint(fp_buf);
        fp_buf.write_char('\0'); // null-terminate
        // fprintf(stderr, "fingerprint: '%s'\n", fp_str);

        char sn_str[MAX_SNI_LEN] = { 0 };
        struct datum sn{NULL, NULL};
        hello.extensions.set_server_name(sn);
        sn.strncpy(sn_str, MAX_SNI_LEN);
        // fprintf(stderr, "server_name: '%.*s'\tcopy: '%s'\n", (int)sn.length(), sn.data, sn_str);

        return this->perform_analysis(fp_str, sn_str, dst_ip_str, dst_port);
    }

};

#endif /* ANALYSIS_H */
