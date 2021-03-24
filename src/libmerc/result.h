/*
 * result.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef RESULT_H
#define RESULT_H

#ifndef __cplusplus
#include <stdbool.h>
#else
#include "json_object.h"
#include "tls.h"
#include "addr.h"
#include "fingerprint.h"

uint16_t flow_key_get_dst_port(const struct key &key);

void flow_key_sprintf_dst_addr(const struct key &key,
                               char *dst_addr_str);

#endif


#define max_proc_len 256

struct malware_result {
    bool max_mal;
    long double malware_prob;
};

struct analysis_result {
    bool valid;  // = false;
    bool randomized; // = false;
    char max_proc[max_proc_len];
    long double max_score;
    bool max_mal;
    long double malware_prob;
    bool classify_malware;
    struct os_information *os_info;
    uint16_t os_info_len;

#ifdef __cplusplus
public:
    analysis_result() : valid{false}, randomized{false}, max_proc{0}, max_score{0.0}, max_mal{false}, malware_prob{-1.0}, classify_malware{false}, os_info{NULL}, os_info_len{0} { }

    analysis_result(const bool is_randomized) : valid{false}, randomized{is_randomized}, max_proc{0}, max_score{0.0}, max_mal{false}, malware_prob{-1.0}, classify_malware{false}, os_info{NULL}, os_info_len{0} { }

    analysis_result(const char *proc, long double score, os_information *os, uint16_t os_len) :
        valid{true}, randomized{false}, max_proc{0}, max_score{score}, max_mal{false}, malware_prob{-1.0}, classify_malware{false},
        os_info{os}, os_info_len{os_len} {
        strncpy(max_proc, proc, max_proc_len-1);
    }
    analysis_result(const char *proc, long double score, os_information *os, uint16_t os_len, bool mal, long double mal_prob) :
        valid{true}, randomized{false}, max_proc{0}, max_score{score}, max_mal{mal}, malware_prob{mal_prob}, classify_malware{true},
        os_info{os}, os_info_len{os_len} {
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
            if ((os_info != NULL) && (os_info_len > 0)) { /* print operating system info */
                struct json_object os_json{analysis, "os_info"};
                for (uint16_t i = 0; i < os_info_len; i++) {
                    os_json.print_key_uint(os_info[i].os_name, os_info[i].os_prevalence);
                }
                os_json.close();
            }
        } else if (randomized) {
            analysis.print_key_string("status", "randomized_fingerprint");
        } else {
            analysis.print_key_string("status", "unlabeled_fingerprint");
        }
        analysis.close();
    }

    bool is_valid() const { return valid; }
#endif
};


// helper functions and constants

#define MAX_DST_ADDR_LEN 48
#define MAX_SNI_LEN     257

struct destination_context {
    char dst_ip_str[MAX_DST_ADDR_LEN];
    char sn_str[MAX_SNI_LEN];
    uint16_t dst_port;

#ifdef __cplusplus
    destination_context() : dst_port{0} {}

    destination_context(const struct tls_client_hello &hello,
                        const struct key &key) {
        init(hello, key);
    }

    void init(const struct tls_client_hello &hello,
              const struct key &key) {

        struct datum sn{NULL, NULL};
        hello.extensions.set_server_name(sn);
        sn.strncpy(sn_str, MAX_SNI_LEN);
        flow_key_sprintf_dst_addr(key, dst_ip_str);
        dst_port = flow_key_get_dst_port(key);
    }

#endif

};

struct analysis_context {
    struct fingerprint fp;
    struct destination_context destination;
    struct analysis_result result;

#ifdef __cplusplus
    analysis_context() : fp{}, destination{}, result{} {}
    // could add structs needed for 'scratchwork'
#endif
};


#endif // RESULT_H

