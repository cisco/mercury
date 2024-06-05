/*
 * analysis.cc
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <pthread.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <math.h>
#include <unordered_map>
#include <zlib.h>
#include <vector>
#include <algorithm>

#include "datum.h"
#include "analysis.h"
#include "utils.h"
#include "libmerc.h"

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"


classifier *analysis_init_from_archive(int, //verbosity
                                       const char *archive_name,
                                       const uint8_t *enc_key,
                                       enum enc_key_type key_type,
                                       const float fp_proc_threshold,
                                       const float proc_dst_threshold,
                                       const bool report_os,
                                       const bool minimize_ram) {

    if (enc_key != NULL || key_type != enc_key_type_none) {
        //fprintf(stderr, "note: decryption key provided in configuration\n");
    }

    // if (archive_name == nullptr) {
    //     archive_name = DEFAULT_RESOURCE_FILE;
    // }

    encrypted_compressed_archive archive{archive_name, enc_key}; // TODO: key type
    return new classifier(archive, fp_proc_threshold, proc_dst_threshold, report_os, minimize_ram);
}


int analysis_finalize(classifier *c) {

    if (c) {
        classifier *tmp = c;
        c = nullptr;   // swap pointer to null, to prevent future use
        delete tmp;    // free up classifier
    }

    return 1;
}

std::string get_domain_name(char* server_name) {
    std::string r_server_name(server_name);
    std::reverse(r_server_name.begin(), r_server_name.end());

    size_t pos = 0;
    uint8_t n = 2;
    std::string token;
    std::string out_domain;
    std::stringstream domain;
    while (((pos = r_server_name.find(".")) != std::string::npos) && (n > 0)) {
        token = r_server_name.substr(0, pos);
        domain << token;
        if (n > 1) {
            domain << ".";
        }
        r_server_name.erase(0, pos + 1);
        n -= 1;
    }

    out_domain = domain.str();
    std::reverse(out_domain.begin(), out_domain.end());

    return out_domain;
}
