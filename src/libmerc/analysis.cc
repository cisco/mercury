/*
 * analysis.cc
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */


#include <arpa/inet.h>
#include <pthread.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <math.h>
#include <unordered_map>
#include <zlib.h>
#include <vector>
#include <algorithm>

#include "analysis.h"
#include "utils.h"
#include "tls.h"
#include "libmerc.h"

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"


//pthread_mutex_t lock_fp_cache;
//std::unordered_map<std::string,char*> fp_cache;

// uint16_t get_port_mapping(std::string s) {
//     auto x = port_mapping.find(s);
//     if (x == port_mapping.end()) {
//         return 0;  // error
//     }
//     return x.second;
// }

bool MALWARE_DB = true;
bool EXTENDED_FP_METADATA = true;

int gzgetline(gzFile f, std::string &s) {
    std::vector<char> v(256);
    unsigned pos = 0;
    for (;;) {
        if (gzgets(f, &v[pos], v.size()-pos) == 0) {
            // EOF
            return 0;
        }
        unsigned read = strlen(&v[pos]);
        if (v[pos+read-1] == '\n') {
            pos = pos + read - 1;
            break;
        }
        pos = v.size() - 1;
        v.resize(v.size() * 2);
    }
    v.resize(pos);
    std::string tmp_str(v.begin(), v.end());
    s = tmp_str;
    return 1;
}


#ifndef DEFAULT_RESOURCE_FILE
#define DEFAULT_RESOURCE_FILE "/usr/local/share/mercury/resources.tgz"
#endif

classifier *c = NULL;

int analysis_init_from_archive(int verbosity,
                               const char *archive_name,
                               const uint8_t *enc_key,
                               enum enc_key_type key_type,
                               const float fp_proc_threshold,
                               const float proc_dst_threshold,
                               const bool report_os) {

    if (enc_key != NULL || key_type != enc_key_type_none) {
        //fprintf(stderr, "note: decryption key provided in configuration\n");
    }

    if (archive_name == nullptr) {
        archive_name = DEFAULT_RESOURCE_FILE;
    }

    encrypted_compressed_archive archive{archive_name, enc_key}; // TODO: key type
    c = new classifier(archive, fp_proc_threshold, proc_dst_threshold, report_os);
    return 0;

    // TBD: move warnings to appropriate place(s)

    if (verbosity > 0) {
        fprintf(stderr, "warning: could not open resource archive '%s'\n", archive_name);
    }
    fprintf(stderr, "warning: could not initialize analysis module\n");
    return -1;
}


int analysis_finalize() {

    if (c) {
        classifier *tmp = c;
        c = nullptr;   // swap pointer to null, to prevent future use
        delete tmp;    // free up classifier
    }

    return 1;
}

#define SNI_HEADER_LEN 9

//#define MAX_DST_ADDR_LEN 40
void flow_key_sprintf_dst_addr(const struct flow_key *key,
                               char *dst_addr_str) {

    if (key->type == ipv4) {
        uint8_t *d = (uint8_t *)&key->value.v4.dst_addr;
        snprintf(dst_addr_str,
                 MAX_DST_ADDR_LEN,
                 "%u.%u.%u.%u",
                 d[0], d[1], d[2], d[3]);
    } else if (key->type == ipv6) {
        uint8_t *d = (uint8_t *)&key->value.v6.dst_addr;
        snprintf(dst_addr_str,
                 MAX_DST_ADDR_LEN,
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
    } else {
        dst_addr_str[0] = '\0'; // make sure that string is null-terminated
    }
}

void flow_key_sprintf_src_addr(const struct flow_key *key,
                               char *src_addr_str) {

    if (key->type == ipv4) {
        uint8_t *s = (uint8_t *)&key->value.v4.src_addr;
        snprintf(src_addr_str,
                 MAX_DST_ADDR_LEN,
                 "%u.%u.%u.%u",
                 s[0], s[1], s[2], s[3]);
    } else if (key->type == ipv6) {
        uint8_t *s = (uint8_t *)&key->value.v6.src_addr;
        snprintf(src_addr_str,
                 MAX_DST_ADDR_LEN,
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15]);
    } else {
        src_addr_str[0] = '\0'; // make sure that string is null-terminated
    }
}

uint16_t flow_key_get_dst_port(const struct flow_key *key) {
    if (key->type == ipv4) {
        return ntohs(key->value.v4.dst_port);
    } else if (key->type == ipv6) {
        return ntohs(key->value.v6.dst_port);
    }

    return 0;
}


void flow_key_sprintf_dst_addr(const struct key &key,
                               char *dst_addr_str) {

    if (key.ip_vers == 4) {
        uint8_t *d = (uint8_t *)&key.addr.ipv4.dst;
        snprintf(dst_addr_str,
                 MAX_DST_ADDR_LEN,
                 "%u.%u.%u.%u",
                 d[0], d[1], d[2], d[3]);
    } else if (key.ip_vers == 6) {
        uint8_t *d = (uint8_t *)&key.addr.ipv6.dst;
        snprintf(dst_addr_str,
                 MAX_DST_ADDR_LEN,
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
    } else {
        dst_addr_str[0] = '\0'; // make sure that string is null-terminated
    }
}

uint16_t flow_key_get_dst_port(const struct key &key) {
    return ntohs(key.dst_port);
}


std::string get_port_app(uint16_t dst_port) {
    std::unordered_map<uint16_t, std::string> port_mapping = {{443, "https"},  {448,"database"}, {465,"email"},
                                                              {563,"nntp"},    {585,"email"},    {614,"shell"},
                                                              {636,"ldap"},    {989,"ftp"},      {990,"ftp"},
                                                              {991,"nas"},     {992,"telnet"},   {993,"email"},
                                                              {994,"irc"},     {995,"email"},    {1443,"alt-https"},
                                                              {2376,"docker"}, {8001,"tor"},     {8443,"alt-https"},
                                                              {9000,"tor"},    {9001,"tor"},     {9002,"tor"},
                                                              {9101,"tor"}};

    auto it = port_mapping.find(dst_port);
    if (it != port_mapping.end()) {
        return it->second;
    }

    return "unknown";
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

bool fingerprint_data::malware_db = false;
