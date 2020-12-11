/*
 * analysis.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <stdio.h>
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


#endif /* ANALYSIS_H */
