/*
 * result.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef RESULT_H
#define RESULT_H

#include <stdbool.h>
#include <bits/stdc++.h>
#include "libmerc.h"
#include "json_object.h"
#include "addr.h"
#include "fingerprint.h"

uint16_t flow_key_get_dst_port(const struct key &key);

void flow_key_sprintf_dst_addr(const struct key &key,
                               char *dst_addr_str);


#define max_proc_len 256

struct malware_result {
    bool max_mal;
    long double malware_prob;
};

class attribute_result {
public:

    // MAX_TAGS denotes the maximum number of attribute tags supported
    //
    static constexpr ssize_t MAX_TAGS = 8;
    typedef std::bitset<MAX_TAGS> bitset;

private:

    attribute_result::bitset tags;
    std::array<long double, MAX_TAGS> prob_score;
    const std::vector<std::string> *tag_names;

public:

    attribute_result() : tags{}, prob_score{}, tag_names{nullptr} { }

    attribute_result(std::bitset<MAX_TAGS> _tags, std::array<long double, MAX_TAGS> _prob_score, const std::vector<std::string> *_tag_names) :
        tags{_tags},
        prob_score{_prob_score},
        tag_names{_tag_names}
    { }

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

        struct buffer_stream buf{(char *)buffer, buffer_size};
        struct json_object record{&buf};
        write_json(record);
        record.close();
    }

};

// class attribute_names holds the strings corresponding to an ordered
// list of attribute names
//
class attribute_names {
    std::vector<std::string> names;
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
    }

    const std::vector<std::string> &value() const { return names; }
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
        } else if (status == fingerprint_status_unlabled) {
            analysis.print_key_string("status", "unlabeled_fingerprint");
        } else {
            analysis.print_key_string("status", "unknown");
        }
        analysis.close();
    }

    bool is_valid() const {
        return status != fingerprint_status_no_info_available;
    }

    void reinit() {
        status = fingerprint_status_no_info_available;
        max_proc[0] = '\0';
        os_info = NULL;
        classify_malware = false;
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


// helper functions and constants

#define MAX_DST_ADDR_LEN 48
#define MAX_SNI_LEN     257
#define MAX_USER_AGENT_LEN 512
#define MAX_ALPN_LEN 32
#define MAX_ALPN 16
#define MAX_ALPN_STR_LEN 128

struct destination_context {
    char dst_ip_str[MAX_DST_ADDR_LEN];
    char sn_str[MAX_SNI_LEN];
    char ua_str[MAX_USER_AGENT_LEN];
    uint8_t alpn_array[MAX_ALPN_STR_LEN];
    size_t alpn_length;
    uint16_t dst_port;

    destination_context() : dst_port{0} {}

    void init(struct datum domain, struct datum user_agent, datum alpn, const struct key &key) {
        user_agent.strncpy(ua_str, MAX_USER_AGENT_LEN);
        domain.strncpy(sn_str, MAX_SNI_LEN);
        flow_key_sprintf_dst_addr(key, dst_ip_str);
        dst_port = flow_key_get_dst_port(key);

        alpn.write_to_buffer(alpn_array, sizeof(alpn_array));
        alpn_length = alpn.length();

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

