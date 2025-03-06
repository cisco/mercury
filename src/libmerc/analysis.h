/*
 * analysis.h
 *
 * Copyright (c) 2019-2024 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <stdio.h>
#include <math.h>
#include <algorithm>
#include <stdexcept>
#include <assert.h>
#include "addr.h"
#include "result.h"
#include "dict.h"

#include <mutex>
#include <shared_mutex>
#include <map>
#include <list>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <vector>
#include <list>
#include <zlib.h>
#include <memory>
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "archive.h"
#include "watchlist.hpp"
#include "static_dict.hpp"
#include "naive_bayes.hpp"


class classifier *analysis_init_from_archive(int verbosity,
                               const char *archive_name,
                               const uint8_t *enc_key,
                               enum enc_key_type key_type,
                               float fp_proc_threshold,
                               float proc_dst_threshold,
                               bool report_os);

int analysis_finalize(classifier *c);

/// comparison operator for os_information
///
[[maybe_unused]] static bool operator==(const os_information &lhs, const os_information &rhs) {
    return lhs.os_name == rhs.os_name
        && lhs.os_prevalence == rhs.os_prevalence;
}

// helper function to convert results from double to long
// double arrays, which are used to represent probabilities in some
// other software components
//
template <size_t N, typename F>
static std::array<long double, N> convert_to_long_double_array(const std::array<F, N> &input) {
    std::array<long double, N> output;
    for (size_t i=0; i<N; i++) {
        output[i] = (long double)input[i];
    }
    return output;
}

// struct common_data holds data that is common to all fingerprints,
// within the classifier
//
struct common_data {
    attribute_names attr_name;
    watchlist doh_watchlist;
    ssize_t doh_idx = -1;
    ssize_t enc_channel_idx = -1;
};

class fingerprint_data {

    std::vector<bool> malware;
    std::vector<attribute_result::bitset> attr;
    std::vector<std::string> process_name;
    std::vector<std::vector<struct os_information>> process_os_info_vector;

    naive_bayes_tls_quic_http classifier;

    bool malware_db = true;

    const subnet_data *subnet_data_ptr = nullptr;

    common_data *common = nullptr;

public:
    uint8_t refcnt = 0;
    uint64_t total_count;

    fingerprint_data(const rapidjson::Value &process_info,
                     ptr_dict &os_dictionary,
                     const subnet_data *subnets,
                     common_data *c,
                     bool &malware_database,
                     size_t total_cnt,
                     bool report_os
                     ) :
        classifier{process_info,total_cnt},
        malware_db{malware_database},
        subnet_data_ptr{subnets},
        common{c},
        total_count{total_cnt}
    {
        unsigned int num_procs = process_info.GetArray().Size();

        process_name.reserve(num_procs);
        malware.reserve(num_procs);
        attr.reserve(num_procs);
        process_os_info_vector.reserve(num_procs);

        for (auto &x : process_info.GetArray()) {

            if (x.HasMember("process") && x["process"].IsString()) {
                std::string name = x["process"].GetString();
                process_name.push_back(name);
            }

            if (x.HasMember("malware") && x["malware"].IsBool()) {   // NOTE: malware assumed to be in schema
                malware.push_back(x["malware"].GetBool());
            }

            attribute_result::bitset attributes;
            if (x.HasMember("attributes") && x["attributes"].IsObject()) {
                for (auto &v : x["attributes"].GetObject()) {
                    if (v.name.IsString()) {
                        ssize_t idx = common->attr_name.get_index(v.name.GetString());
                        if (idx < 0) {
                            printf_err(log_warning, "unknown attribute %s while parsing process information\n", v.name.GetString());
                            throw std::runtime_error("error while parsing resource archive file");
                        }
                        if (v.value.IsBool() and v.value.GetBool()) {
                            attributes[idx] = 1;
                        }
                    }
                }
                common->attr_name.stop_accepting_new_names();
            }
            attr.push_back(attributes);

            std::vector<struct os_information> os_info_vector;
            if (report_os && x.HasMember("os_info") && x["os_info"].IsObject()) {
                for (auto &y : x["os_info"].GetObject()) {
                    fprintf(stderr, "os_info_vector: adding %s\n", y.name.GetString());
                    if (std::string(y.name.GetString()) != "") {
                        const char *os = os_dictionary.get(y.name.GetString());
                        struct os_information tmp{(char *)os, y.value.GetUint64()};
                        os_info_vector.push_back(tmp);
                    }
                }
            }
            process_os_info_vector.push_back(os_info_vector);

        }

        // process_name, malware, and process_os_info_vector should
        // all have the same number of elements as the number of
        // processes
        //
        assert(process_name.size() == num_procs);
        assert(malware.size() == num_procs);
        assert(process_os_info_vector.size() == num_procs);
        assert(attr.size() == num_procs);

    }

    ~fingerprint_data() {  }

    struct analysis_result perform_analysis(const char *server_name, const char *dst_ip, uint16_t dst_port,
                                            const char *user_agent, enum fingerprint_status status) {

        uint32_t asn_int = subnet_data_ptr->get_asn_info(dst_ip);
        std::string dst_ip_str(dst_ip);

        std::vector<double> process_score = classifier.classify(asn_int, dst_port, server_name, dst_ip_str, user_agent);

        // compute max_score, sec_score, index_max, and index_sec
        //
        double max_score = std::numeric_limits<double>::lowest();
        double sec_score = std::numeric_limits<double>::lowest();
        uint64_t index_max = 0;
        uint64_t index_sec = 0;
        for (uint64_t i=0; i < process_score.size(); i++) {
            if (process_score[i] > max_score) {
                sec_score = max_score;
                index_sec = index_max;
                max_score = process_score[i];
                index_max = i;
            } else if (process_score[i] > sec_score) {
                sec_score = process_score[i];
                index_sec = i;
            }
        }

        // convert process_score from log-prob values to probability
        // values, and compute score_sum, score_sum_without_max,
        // malware_prob, and the attr_prob vector.
        //
        double score_sum = 0.0;
        double score_sum_without_max = 0.0;
        double malware_prob = 0.0;
        std::array<double, attribute_result::MAX_TAGS> attr_prob;
        attr_prob.fill(0.0);
        for (uint64_t i=0; i < process_score.size(); i++) {
            process_score[i] = expf((float)(process_score[i] - max_score));
            score_sum += process_score[i];
            if (i != index_max) {
                score_sum_without_max += process_score[i];
            }
            if (malware[i]) {
                malware_prob += process_score[i];
            }
            for (int j = 0; j < attribute_result::MAX_TAGS; j++) {
                if (attr[i][j]) {
                    attr_prob[j] += process_score[i];
                }
            }
        }

        max_score = process_score[index_max];  // set max_score to probability
        sec_score = process_score[index_sec];  // set sec_score to probability

        if (score_sum > 0.0) {
            if (malware_db) {
                malware_prob /= score_sum;
            }
        }

        // fprintf(stderr, "(score_sum-max_score) - score_sum_without_max: %.40Lg\n", (score_sum - max_score) - score_sum_without_max);

        if (malware_db && process_name[index_max] == "generic dmz process" && malware[index_sec] == false) {
            // the most probable process is unlabeled, so choose the
            // next most probable one if it isn't malware, and adjust
            // the normalization sum as appropriate

            index_max = index_sec;
            score_sum = score_sum_without_max;
            max_score = sec_score;
        }
        if (score_sum > 0.0) {
            max_score /= score_sum;
            for (int j = 0; j < attribute_result::MAX_TAGS; j++) {
                attr_prob[j] /= score_sum;
            }
        }

        // check encrypted dns watchlist
        //
        attribute_result::bitset attr_tags = attr[index_max];
        if (common->doh_watchlist.contains(server_name) || common->doh_watchlist.contains_addr(dst_ip)) {
            attr_tags[common->doh_idx] = true;
            attr_prob[common->doh_idx] = 1.0;
        }

        attribute_result attr_res{attr_tags, convert_to_long_double_array(attr_prob), &common->attr_name.value(), common->attr_name.get_names_char()};

        // set os_info (to NULL if unavailable)
        //
        os_information *os_info_data = NULL;
        uint16_t os_info_size = 0;
        if (process_os_info_vector.size() > 0) {
            os_info_data = process_os_info_vector[index_max].data();
            os_info_size = process_os_info_vector[index_max].size();
        }
        if (malware_db) {
            return analysis_result(status, process_name[index_max].c_str(), max_score, os_info_data, os_info_size,
                                   malware[index_max], malware_prob, attr_res);
        }
        return analysis_result(status, process_name[index_max].c_str(), max_score, os_info_data, os_info_size, attr_res);
    }

};

// static const char* kTypeNames[] = { "Null", "False", "True", "Object", "Array", "String", "Number" };
// fprintf(stderr, "Type of member %s is %s\n", "str_repr", kTypeNames[fp["str_repr"].GetType()]);


class fingerprint_prevalence {
public:
    fingerprint_prevalence(uint32_t max_cache_size) : mutex_{}, list_{}, set_{}, known_set_{}, max_cache_size_{max_cache_size} {}

    // first check if known fingerprints contains fingerprint, then check adaptive set
    bool contains(std::string fp_str) const {
        if (known_set_.find(fp_str) != known_set_.end()) {
            return true;
        }

        std::shared_lock lock(mutex_);
        if (set_.find(fp_str) != set_.end()) {
            return true;
        }
        return false;
    }

    // seed known set of fingerprints
    void initial_add(const std::string &fp_str) {
        known_set_.insert(fp_str);
    }

    // update fingerprint LRU cache if needed
    void update(const std::string &fp_str) {
        if (known_set_.find(fp_str) != known_set_.end()) {
            return ;
        }

        std::unique_lock lock(mutex_, std::try_to_lock);

        if (!lock.owns_lock()) {
            return;  // Some other thread wins the lock. So bailing out
        }

        if (set_.find(fp_str) == set_.end()) {
            if (list_.size() == max_cache_size_) {
                set_.erase(list_.back());
                list_.pop_back();
            }
        } else {
            list_.erase(set_[fp_str]);
        }

        list_.push_front(fp_str);
        set_[fp_str] = list_.begin();
    }

    void print(FILE *f) {
        for (auto &entry : known_set_) {
            fprintf(f, "%s\n", entry.c_str());
        }
    }

private:
    mutable std::shared_mutex mutex_;
    std::list<std::string> list_;
    std::unordered_map<std::string, std::list<std::string>::iterator> set_;
    std::unordered_set<std::string> known_set_;
    uint32_t max_cache_size_;
};


class classifier {
    bool MALWARE_DB = false;
    bool EXTENDED_FP_METADATA = false;

    ptr_dict os_dictionary;  // used to hold/compact OS CPE strings

    subnet_data subnets;     // holds ASN/subnet information

    std::unordered_map<std::string, fingerprint_data *> fpdb;
    fingerprint_prevalence fp_prevalence{100000};

    std::string resource_version;  // as reported by VERSION file in resource archive

    static constexpr size_t num_qualifiers = 1; // number of qualifier expected in VERSION for the classifier to correctly load


    std::vector<fingerprint_type> fp_types;

    // the common object holds data that is common across all
    // fingerprint-specific classifiers, and is used by those
    // classifiers
    //
    common_data common;

    std::unordered_map<std::string, std::pair<uint32_t, size_t>> fp_count_and_format;

    bool disabled = false;   // if the classfier has not been initialised or disabled

public:

    static fingerprint_type get_fingerprint_type(const std::string &s) {
        if (s == "tls") {
            return fingerprint_type_tls;
        } else if (s == "http") {
            return fingerprint_type_http;
        } else if (s == "quic") {
            return fingerprint_type_quic;
        } else if (s == "tofsee") {
            return fingerprint_type_tofsee;
        }
        return fingerprint_type_unknown;
    }

    void print_fp_counts() {
        for (auto &it : fp_count_and_format) {
            printf_err(log_debug, "total %s fingerprints: %u\n", it.first.c_str(), it.second.first);
        }
    }

    void set_fingerprint_type_count(const std::string &fp_type) {
        if (fp_count_and_format.find(fp_type) != fp_count_and_format.end()) {
            fp_count_and_format[fp_type].first++;
        } else {
            // The fingerprint of type fp_type is seen for first time.
            // So set the count(first element of pair) to 1 and
            // format (second element of pair) to default format 0
            fp_count_and_format[fp_type].first = 1;
            fp_count_and_format[fp_type].second = 0;
        }
    }

    size_t get_tls_fingerprint_format() {
        return get_fingerprint_format("tls");
    }

    size_t get_quic_fingerprint_format() {
        return get_fingerprint_format("quic");
    }

    size_t get_fingerprint_format(std::string fp_type) {
        auto it = fp_count_and_format.find(fp_type);
        if (it != fp_count_and_format.end()) {
            return it->second.second;
        } else {
            return 0;
        }
    }

    bool is_disabled() const { return disabled; }

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
                } else if (s.compare(0, idx, "tofsee") == 0) {
                    type = fingerprint_type_tofsee;
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

    void process_watchlist_line(std::string &line_str) {
        if (!line_str.empty() && line_str[line_str.length()-1] == '\n') {
            line_str.erase(line_str.length()-1);
        }
        fprintf(stderr, "loading watchlist line '%s'\n", line_str.c_str());
        //  fp_prevalence.initial_add(line_str);
    }

    void process_fp_prevalence_line(std::string &line_str) {
        if (!line_str.empty() && line_str[line_str.length()-1] == '\n') {
            line_str.erase(line_str.length()-1);
        }
        // if a fingerprint string does not contain a protocol name,
        // add 'tls' in order to provide backwards compatibility with
        // resource files with the older fingerprint format
        //
        if (line_str.at(0) == '(') {
            line_str = "tls/" + line_str;
        }
        //fprintf(stderr, "loading fp_prevalence_line '%s'\n", line_str.c_str());
        fp_prevalence.initial_add(line_str);
    }

    bool validate_fp(std::string &fp_string, fingerprint_type fp_type_code, std::string fp_type_string) {
        if (fp_string.length() == 0) {
            printf_err(log_warning, "ignoring zero-length fingerprint string in resource file\n");
            return(false);  // can't process this entry, so skip it
        }

        if (fp_string.length() >= fingerprint::max_length()) {
            printf_err(log_warning, "ignoring length %zu fingerprint string in resource file; too long\n", fp_string.length());
            return(false);  // can't process this entry, so skip it
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
            printf_err(log_warning,
                       "fingerprint type of str_repr '%s' does not match fp_type, ignorning JSON line\n",
                       fp_string.c_str());
            return(false);
        }

        // ensure that all fingerprints of same type have the same version
        //
        const auto it = fp_count_and_format.find(fp_type_string);
        if (it != fp_count_and_format.end()) {
            // first fingerprint of type fp_type_string is seen
            if (it->second.first == 1) {
                it->second.second = fingerprint_type_and_version.second;
            } else {
                if (fingerprint_type_and_version.second != it->second.second) {
                    printf_err(log_warning,
                               "%s fingerprint version with inconsistent format, ignoring JSON line\n",
                               fp_type_string.c_str());
                    return(false);
                }
            }
        }
        return(true);
    }

    void process_fp_db_line(std::string &line_str, bool report_os) {

        rapidjson::Document fp;
        fp.Parse(line_str.c_str());
        if(!fp.IsObject()) {
            printf_err(log_warning, "invalid JSON line in resource file\n");
            return;
        }

        fingerprint_type fp_type_code = fingerprint_type_tls;
        std::string fp_type_string;
        if (fp.HasMember("fp_type") && fp["fp_type"].IsString()) {
            fp_type_string = fp["fp_type"].GetString();
            fp_type_code = get_fingerprint_type(fp_type_string.c_str());
            set_fingerprint_type_count(fp_type_string);

        }
        if (fp_type_code != fingerprint_type_unknown) {
            if (std::find(fp_types.begin(), fp_types.end(), fp_type_code) == fp_types.end()) {
                fp_types.push_back(fp_type_code);
            }
        }

        uint64_t total_count = 0;
        if (fp.HasMember("total_count") && fp["total_count"].IsUint64()) {
            total_count = fp["total_count"].GetUint64();
        }

        // if there is a feature_weights object, we read it and then
        // pass it on to the naive bayes classifier
        //
        feature_weights weights;
        if (fp.HasMember("feature_weights")) {
            weights.read_from_object(fp["feature_weights"]);
        }

        if (fp.HasMember("process_info") && fp["process_info"].IsArray()) {
            //fprintf(stderr, "process_info[]\n");

            // determine if this FPDB contains malware data and
            // extended metadata
            //
            if (fp["process_info"].Size() > 0){
                if (fp["process_info"][0].HasMember("malware")) {
                    MALWARE_DB = true;
                }
                if (fp["process_info"][0].HasMember("classes_ip_ip")) {
                    EXTENDED_FP_METADATA = true;
                }
            }

            // EXPERIMENTAL: using json-reading constructor
            //
            fingerprint_data *fp_data = new fingerprint_data(fp["process_info"],
                                                             os_dictionary,
                                                             &subnets,
                                                             &common,
                                                             MALWARE_DB,
                                                             total_count,
                                                             report_os
                                                             );

            if (fp.HasMember("str_repr") && fp["str_repr"].IsString()) {
                std::string fp_string = fp["str_repr"].GetString();
                if (!validate_fp(fp_string, fp_type_code, fp_type_string)) {
                    return;
                }

                if (fpdb.find(fp_string) != fpdb.end()) {
                    printf_err(log_warning, "fingerprint database has duplicate entry for fingerprint %s\n", fp_string.c_str());
                    return;
                }
                fpdb[fp_string] = fp_data;
                fp_data->refcnt++;
            }

            if (fp.HasMember("str_repr_array") && fp["str_repr_array"].IsArray()) {

                for (auto &x : fp["str_repr_array"].GetArray()) {
                    if (x.IsString()) {
                        std::string fp_string = x.GetString();

                        if (!validate_fp(fp_string, fp_type_code, fp_type_string)) {
                            return;
                        }

                        if (fpdb.find(fp_string) != fpdb.end()) {
                            printf_err(log_warning, "fingerprint database has duplicate entry for fingerprint %s\n", fp_string.c_str());
                            continue;
                        }
                        fpdb[fp_string] = fp_data;
                        fp_data->refcnt++;
                    }
                }
            }
        }
    }

    bool is_dual_db (std::string version_str) const {
        return (version_str.find("dual") != std::string::npos);
    }

    bool is_lite_db (std::string version_str) const {
        return (version_str.find("lite") != std::string::npos);
    }

    bool is_full_db (std::string version_str) const {
        return (version_str.find("full") != std::string::npos);
    }

    size_t fetch_qualifier_count (std::string version_str) const {
        return std::count(version_str.begin(),version_str.end(),';');
    }

    classifier(class encrypted_compressed_archive &archive,
               float fp_proc_threshold,
               float proc_dst_threshold,
               bool report_os) : os_dictionary{}, subnets{}, fpdb{}, resource_version{} {

        // reserve attribute for encrypted_dns watchlist
        //
        common.doh_idx = common.attr_name.get_index("encrypted_dns");

        // reserve attribute for encrypted_channel
        //
        common.enc_channel_idx = common.attr_name.get_index("encrypted_channel");

        // by default, we expect that tls fingerprints will be present in the resource file
        //
        fp_types.push_back(fingerprint_type_tls);

        bool threshold_set = ( (fp_proc_threshold > 0.0) || (proc_dst_threshold > 0.0) );  // switch to fingerprint_db_lite.json if available
        bool got_fp_prevalence = false;
        bool got_fp_db = false;
        bool got_version = false;
        bool got_doh_watchlist = false;
        bool dual_db = false;   // archive has both fingerprint_db_normal and fingerprint_db_lite
        bool lite_db = false;   // archive has fingerprint_db_lite named as fingerprint_db.json
        bool full_db = false;   // archive has fingerprint_db_full.json named as fingerprint_db.json
        bool legacy_archive = false;

        //        class compressed_archive archive{resource_archive_file};
        const class archive_node *entry = archive.get_next_entry();
        if (entry == nullptr) {
            throw std::runtime_error("error: could not read any entries from resource archive file");
        }

        clock_t load_start_time = clock();
        while (entry != nullptr) {
            if (entry->is_regular_file()) {
                std::string line_str;

                std::string name = entry->get_name();
                if (name == "fp_prevalence_tls.txt") {
                    while (archive.getline(line_str)) {
                        process_fp_prevalence_line(line_str);
                    }
                    got_fp_prevalence = true;
                } else if (name == "fingerprint_db_lite.json") {
                    // dual db, process fingerprint_db_lite when thresholds set
                    if (threshold_set) {
                        printf_err(log_debug, "loading fingerprint_db_lite.json\n");
                        while (archive.getline(line_str)) {
                            process_fp_db_line(line_str, report_os);
                        }
                        got_fp_db = true;
                        print_fp_counts();
                    }
                } else if (name == "fingerprint_db.json") {
                    got_fp_db = true;
                    if (legacy_archive) {
                        disabled = true;
                    }
                    else if (!threshold_set || lite_db || full_db) {
                        printf_err(log_debug, "loading fingerprint_db.json\n");
                        while (archive.getline(line_str)) {
                            process_fp_db_line(line_str, report_os);
                        }
                        print_fp_counts();
                    }
                } else if (name == "VERSION") {
                    while (archive.getline(line_str)) {
                        resource_version += line_str;
                    }
                    got_version = true;
                    dual_db = is_dual_db(resource_version);
                    lite_db = is_lite_db(resource_version);
                    full_db = is_full_db(resource_version);
                    legacy_archive = (!dual_db && !lite_db && !full_db);

                } else if (name == "pyasn.db") {
                    while (archive.getline(line_str)) {
                        subnets.process_line(line_str);
                    }
                    got_version = true;

                } else if (name == "doh-watchlist.txt") {
                    while (archive.getline(line_str)) {
                        common.doh_watchlist.process_line(line_str);
                    }
                    got_doh_watchlist = true;
                }
            }
            if (got_fp_db && got_fp_prevalence && got_version && got_doh_watchlist) {   // TODO: Do we want to require a VERSION file?
                break; // got all data, we're done here
            }
            entry = archive.get_next_entry();
        }

        clock_t load_end_time = clock();
        double load_elapsed_seconds = double(load_end_time - load_start_time) / CLOCKS_PER_SEC;
        
        if (load_elapsed_seconds >= 20) {
            printf_err(log_debug, "time taken to load resource archive: %.2f seconds\n", load_elapsed_seconds);
        }

        subnets.process_final();

        // verify that we found each of the required input files in
        // the resourece archive, and throw an error otherwise
        //
        if (!got_fp_db | !got_fp_prevalence | !got_version | !got_doh_watchlist) {
            throw std::runtime_error("resource archive is missing one or more files");
        }

        if (fetch_qualifier_count(resource_version) != num_qualifiers) {
            disabled = true;
            printf_err(log_debug,"resource qualifier count does not match, disabling classifier\n");
        }

    }

#if 0
    void print(FILE *f) {
        for (auto &fpdb_entry : fpdb) {
            fprintf(f, "{\"str_repr\":\"%s\"", fpdb_entry.first.c_str());
            fpdb_entry.second.print(f);
            fprintf(f, "}\n");
        }
        fp_prevalence.print(f);
    }
#endif

    std::unordered_map<std::string, uint16_t> string_to_port =
        {
         { "unknown",      0 },
         { "https",      443 },
         { "database",   448 },
         { "email",      465 },
         { "nntp",       563 },
         { "shell",      614 },
         { "ldap",       636 },
         { "ftp",        989 },
         { "nas",        991 },
         { "telnet",     992 },
         { "irc",        994 },
         { "alt-https", 1443 },
         { "docker",    2376 },
         { "tor",       8001 },
        };
    std::string port_to_app(uint16_t dst_port) {
        std::unordered_map<uint16_t, std::string> port_app = {
             {443, "https"},  {448,"database"}, {465,"email"},
             {563,"nntp"},    {585,"email"},    {614,"shell"},
             {636,"ldap"},    {989,"ftp"},      {990,"ftp"},
             {991,"nas"},     {992,"telnet"},   {993,"email"},
             {994,"irc"},     {995,"email"},    {1443,"alt-https"},
             {2376,"docker"}, {8001,"tor"},     {8443,"alt-https"},
             {9000,"tor"},    {9001,"tor"},     {9002,"tor"},
             {9101,"tor"}
        };
        auto it = port_app.find(dst_port);
        if (it != port_app.end()) {
            return it->second;
        }
        return "unknown";

    }

    struct analysis_result perform_analysis(const char *fp_str, const char *server_name, const char *dst_ip,
                                            uint16_t dst_port, const char *user_agent) {

        // fp_stats.observe(fp_str, server_name, dst_ip, dst_port); // TBD - decide where this call should go

        const auto fpdb_entry = fpdb.find(fp_str);
        if (fpdb_entry == fpdb.end()) {
            if (fp_prevalence.contains(fp_str)) {
                fp_prevalence.update(fp_str);
                return analysis_result(fingerprint_status_unlabled);
            } else {
                fp_prevalence.update(fp_str);
                /*
                 * Resource file has info about randomized fingerprints in the format
                 * protocol/format/randomized
                 * Eg: tls/1/randomized
                 */
                std::string randomized_str;
                const char *c = &fp_str[0];
                while (*c != '\0' && *c != '(') {
                    randomized_str.append(c, 1);
                    c++;
                }
                randomized_str.append("randomized");

                const auto fpdb_entry_randomized = fpdb.find(randomized_str);
                if (fpdb_entry_randomized == fpdb.end()) {
                    return analysis_result(fingerprint_status_randomized);  // TODO: does this actually happen?
                }
                fingerprint_data *fp_data = fpdb_entry_randomized->second;
                return fp_data->perform_analysis(server_name, dst_ip, dst_port, user_agent, fingerprint_status_randomized);
            }
        }
        fingerprint_data *fp_data = fpdb_entry->second;

        return fp_data->perform_analysis(server_name, dst_ip, dst_port, user_agent, fingerprint_status_labeled);
    }

    bool analyze_fingerprint_and_destination_context(const fingerprint &fp,
                                                     const destination_context &dc,
                                                     analysis_result &result
                                                     ) {

        if (fp.is_null()) {
            return true;  // no fingerprint to analyze
        }
        if (std::find(fp_types.begin(), fp_types.end(), fp.get_type()) == fp_types.end()) {
            result = analysis_result(fingerprint_status_unanalyzed);
            return true;  // not configured to analyze fingerprints of this type
        }
        result = this->perform_analysis(fp.string(), dc.sn_str, dc.dst_ip_str, dc.dst_port, dc.ua_str);

        // check for encrypted_channel
        //
        if (result.max_mal && fp.get_type() == fingerprint_type_tls) {
            result.attr.set_attr(common.enc_channel_idx, result.malware_prob);
        }

        return true;
    }

    const char *get_resource_version() {
        return resource_version.c_str();
    }

    ~classifier() {
        for (auto &fp : fpdb) {
            fingerprint_data *fp_data = fp.second;
            fp_data->refcnt--;
            if (fp_data->refcnt == 0) {
                delete(fp_data);
            }
        }
    }
};


#endif /* ANALYSIS_H */
