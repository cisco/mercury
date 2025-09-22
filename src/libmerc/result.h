/*
 * result.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef RESULT_H
#define RESULT_H

#include <stdbool.h>
#include <algorithm>
#include "libmerc.h"
#include "json_object.h"
#include "addr.h"
#include "fingerprint.h"
#include "flow_key.h"


#define max_proc_len 256

struct malware_result {
    bool max_mal;
    long double malware_prob;
};

class attribute_result {
public:

    // MAX_TAGS denotes the maximum number of attribute tags supported
    //
    static constexpr ssize_t MAX_TAGS = 13;
    typedef std::bitset<MAX_TAGS> bitset;

private:

    attribute_result::bitset tags;
    std::array<long double, MAX_TAGS> prob_score;
    const std::vector<std::string> *tag_names;
    const char *const *tag_names_char;
    attribute_context attr_ctx;
    bool initialized = false;

public:

    attribute_result() : tags{}, prob_score{}, tag_names{nullptr}, tag_names_char{nullptr}, attr_ctx{}, initialized{false}{ }

    attribute_result(std::bitset<MAX_TAGS> _tags, std::array<long double, MAX_TAGS> _prob_score, const std::vector<std::string> *_tag_names,
                        const char *const *names_char) :
        tags{_tags},
        prob_score{_prob_score},
        tag_names{_tag_names},
        tag_names_char{names_char},
        attr_ctx{},
        initialized{true}
    { }

    void reinit() {
        tags = 0;
    }

    void write_json(struct json_object &o) {
        if (!tag_names) {
            return;
        }

        struct json_array attributes{o, "attributes"};
        for (uint8_t i = 0; i < MAX_TAGS && i < tag_names->size(); i++) {
            if (tags[i]) {
                struct json_object tags{attributes};
                tags.print_key_string("name", (*tag_names)[i].c_str());
                tags.print_key_float("probability_score", prob_score[i]);
                tags.close();
            }
        }
        attributes.close();
    }

    void write_json(void *buffer, size_t buffer_size) {
        if (!tag_names) {
            return;
        }

        struct buffer_stream buf{(char *)buffer, (int)buffer_size};
        struct json_object record{&buf};
        write_json(record);
        record.close();
    }

    bool is_valid() const {
        return tags.any();
    }

    bool is_initialized() { return initialized; }

    void initialize (const std::vector<std::string> *_tag_names, const char *const *names_char) {
        tag_names = _tag_names;
        tag_names_char = names_char;
    }

    const struct attribute_context *get_attributes() {
        for (ssize_t i = 0; (i < MAX_TAGS) && ((size_t)i < tag_names->size()); i++) {
            // if the attribute bit is not set, the probability score is 0
            if(!tags[i]) {
                prob_score[i] = 0;
            }
        }
        attr_ctx.tag_names = tag_names_char;
        attr_ctx.prob_scores = prob_score.data();
        attr_ctx.attributes_len = tag_names->size();
        return &attr_ctx;
    }

    void set_attr (ssize_t idx, long double prob) {
        if (tag_names == nullptr) {
            return;
        }
        if ((idx < 0) || (idx >= MAX_TAGS) || ((size_t)idx >= tag_names->size()) )
            return;
        tags[idx] = true;
        prob_score[idx] = prob;
    }

};

// class attribute_names holds the strings corresponding to an ordered
// list of attribute names
//
class attribute_names {
    std::vector<std::string> names;
    std::array<const char*, attribute_result::MAX_TAGS> names_char;
    bool accept_more_names = true;

public:

    ssize_t get_index(const std::string &s) {
        if (accept_more_names) {
            names.push_back(s);
            if (names.size() > attribute_result::MAX_TAGS) {
                throw std::runtime_error("too many attributes in attribute_names");
            }
            return names.size() - 1;
        } else {
            ssize_t idx = std::distance(names.begin(),
                                        std::find(names.begin(), names.end(), s));
            if (idx >= (ssize_t)names.size()) {
                printf_err(log_warning, "error: unknown attribute %s while parsing resource file\n", s.c_str());
                return -1;
            }
            return idx;
        }
    }

    void stop_accepting_new_names() {
        accept_more_names = false;
        for (size_t i = 0; i < names.size(); i++)
            names_char[i] = names[i].c_str();
    }

    bool is_accepting_new_names() {
        return accept_more_names;
    }

    const std::vector<std::string> &value() const { return names; }

    const char* const* get_names_char() const { return names_char.data();}

};

struct analysis_result {
    enum fingerprint_status status;
    char max_proc[max_proc_len];
    long double max_score;
    bool max_mal;
    long double malware_prob;
    bool classify_malware;
    struct os_information *os_info;
    uint16_t os_info_len;

    // extended analysis_result
    // does not require classification to succeed
    attribute_result attr;

public:
    analysis_result() : status{fingerprint_status_no_info_available}, max_proc{'\0'}, max_score{0.0}, max_mal{false}, malware_prob{-1.0}, classify_malware{false},
                        os_info{NULL}, os_info_len{0}, attr{} { }

    analysis_result(enum fingerprint_status s) : status{s}, max_proc{'\0'}, max_score{0.0}, max_mal{false},
                                    malware_prob{-1.0}, classify_malware{false}, os_info{NULL}, os_info_len{0}, attr{} { }

    analysis_result(enum fingerprint_status s, const char *proc, long double score, os_information *os, uint16_t os_len, attribute_result _attr) :
        status{s}, max_proc{'\0'}, max_score{score}, max_mal{false}, malware_prob{-1.0}, classify_malware{false},
        os_info{os}, os_info_len{os_len}, attr{_attr} {
        strncpy(max_proc, proc, max_proc_len-1);
    }
    analysis_result(fingerprint_status s, const char *proc, long double score, os_information *os, uint16_t os_len, bool mal, long double mal_prob,
                    attribute_result _attr) :
        status{s}, max_proc{'\0'}, max_score{score}, max_mal{mal}, malware_prob{mal_prob}, classify_malware{true},
        os_info{os}, os_info_len{os_len}, attr{_attr} {
        strncpy(max_proc, proc, max_proc_len-1);
    }

    void write_json(struct json_object &o, const char *key) {
        struct json_object analysis{o, key};
        if (status == fingerprint_status_labeled) {
            analysis.print_key_string("process", max_proc);
            analysis.print_key_float("score", max_score);
            if (classify_malware) {
                analysis.print_key_uint("malware", max_mal);
                analysis.print_key_float("p_malware", malware_prob);
            }
            if ((os_info != NULL) && (os_info_len > 0)) { /* print operating system info */
                struct json_object os_json{analysis, "os_info"};
                for (uint16_t i = 0; i < os_info_len; i++) {
                    os_json.print_key_uint(os_info[i].os_name, os_info[i].os_prevalence);
                }
                os_json.close();
            }

            attr.write_json(analysis);

        } else if (status == fingerprint_status_randomized) {
            if (max_proc[0] != '\0') {
                analysis.print_key_string("process", max_proc);
                analysis.print_key_float("score", max_score);
                if (classify_malware) {
                    analysis.print_key_uint("malware", max_mal);
                    analysis.print_key_float("p_malware", malware_prob);
                }
                if ((os_info != NULL) && (os_info_len > 0)) { /* print operating system info */
                    struct json_object os_json{analysis, "os_info"};
                    for (uint16_t i = 0; i < os_info_len; i++) {
                        os_json.print_key_uint(os_info[i].os_name, os_info[i].os_prevalence);
                    }
                    os_json.close();
                }
            }
            analysis.print_key_string("status", "randomized_fingerprint");
            attr.write_json(analysis);
        } else if (status == fingerprint_status_unlabled) {
            analysis.print_key_string("status", "unlabeled_fingerprint");
            attr.write_json(analysis);
        } else {
            analysis.print_key_string("status", "unknown");
            attr.write_json(analysis);
        }
        analysis.close();
    }

    bool is_valid() const {
        return ((status != fingerprint_status_no_info_available) || (attr.is_valid()));
    }

    void reinit() {
        status = fingerprint_status_no_info_available;
        max_proc[0] = '\0';
        os_info = NULL;
        classify_malware = false;
        attr.reinit();
    }

    bool get_process_info(const char **probable_process,     // output
                          double *probability_score          // output
                          ) const {

        if (is_valid() && max_proc[0] != '\0' ) {
            *probable_process = max_proc;
            *probability_score = max_score;
            return true;
        }
        return false;
    }

    bool get_malware_info(bool *probable_process_is_malware, // output
                          double *probability_malware        // output
                          ) const {

        if (is_valid() && classify_malware) {
            *probable_process_is_malware = max_mal;
            *probability_malware = malware_prob;
            return true;
        }
        return false;
    }

    bool get_os_info(const struct os_information **os_info_,   // output
                     size_t *os_info_len_                      // output
                     ) const {

        if (is_valid() && os_info != NULL) {
            *os_info_ = os_info;
            *os_info_len_ = os_info_len;
            return true;
        }
        return false;
    }
};

struct detailed_analysis_result : public analysis_result {

    std::vector<std::string> process_names;
    std::vector<double> normalized_process_scores;

    detailed_analysis_result(): analysis_result() {}

    detailed_analysis_result(fingerprint_status s): analysis_result(s) {}

    detailed_analysis_result(fingerprint_status s, long double mal_prob,
                             std::vector<std::string>& _process_names,
                             std::vector<double>& _normalized_process_scores): analysis_result(s) {
        malware_prob = mal_prob;
        process_names = _process_names;
        normalized_process_scores = _normalized_process_scores;
    }

    void reinit() {
        analysis_result::reinit();
        process_names.clear();
        normalized_process_scores.clear();
    }
};


// helper functions and constants

#define MAX_SNI_LEN     257
#define MAX_USER_AGENT_LEN 512
#define MAX_ALPN_LEN 32
#define MAX_ALPN 16
#define MAX_ALPN_STR_LEN 128

struct destination_context {
    char dst_ip_str[MAX_ADDR_STR_LEN];
    char sn_str[MAX_SNI_LEN];
    char ua_str[MAX_USER_AGENT_LEN];
    uint8_t alpn_array[MAX_ALPN_STR_LEN];
    size_t alpn_length;
    uint16_t dst_port;

    destination_context() : dst_port{0} {}

    void init(struct datum domain, struct datum user_agent, datum alpn, const struct key &key) {
        user_agent.strncpy(ua_str, MAX_USER_AGENT_LEN);
        domain.strncpy(sn_str, MAX_SNI_LEN);
        key.sprintf_dst_addr(dst_ip_str);
        dst_port = key.get_dst_port();

        alpn.write_to_buffer(alpn_array, sizeof(alpn_array));
        alpn_length = alpn.length();

    }

    // tofsee specific overload, the user_agent prints an ip address as a string
    void init_tofsee(struct datum domain, struct datum ip, datum alpn, const struct key &key) {
        std::string ua;
        ua = ua + std::to_string((int)ip.data[0]) + "." + std::to_string((int)ip.data[1]) + "." + std::to_string((int)ip.data[2]) + "." + std::to_string((int)ip.data[3]); 
        datum user_agent_built {(uint8_t*)ua.c_str(), (uint8_t*)ua.c_str() + ua.length()};
        user_agent_built.strncpy(ua_str, MAX_USER_AGENT_LEN);
        domain.strncpy(sn_str, MAX_SNI_LEN);
        key.sprintf_dst_addr(dst_ip_str);
        dst_port = key.get_dst_port();

        alpn.write_to_buffer(alpn_array, sizeof(alpn_array));
        alpn_length = alpn.length();
    }

    void reset() {
        dst_ip_str[0] = '\0';
        sn_str[0] = '\0';
        ua_str[0] = '\0';
        alpn_array[0] = 0;
        alpn_length = 0;
        dst_port = 0;
    }

};

struct analysis_context {
    fingerprint fp;
    struct destination_context destination;
    struct analysis_result result;
    bool flow_state_pkts_needed;

    analysis_context() : fp{}, destination{}, result{}, flow_state_pkts_needed{false} {}
    // could add structs needed for 'scratchwork'

    const char *get_server_name() const {
        if (destination.sn_str[0] != '\0') {
            return destination.sn_str;
        }
        return NULL;
    }

    const char *get_user_agent() const {
        if (destination.ua_str[0] != '\0') {
            return destination.ua_str;
        }
        return NULL;
    }

    bool get_alpns(const uint8_t **alpns, size_t *len) const {
        if (destination.alpn_array[0] != '\0') {
            *alpns = destination.alpn_array;
            *len = destination.alpn_length;
            return true;
        }
        return false;
    }

    void reset_user_agent() {
        destination.ua_str[0] = '\0';
    }

    bool more_pkts_needed() {
        return flow_state_pkts_needed;
    }
};


#endif // RESULT_H

