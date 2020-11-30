/*
 * analysis.c
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

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"

rapidjson::Document fp_db;

#define MAX_FP_STR_LEN 4096
#define MAX_SNI_LEN     257

//pthread_mutex_t lock_fp_cache;
//std::unordered_map<std::string,char*> fp_cache;

std::unordered_map<uint16_t, std::string> port_mapping = {{443, "https"},  {448,"database"}, {465,"email"},
                                                          {563,"nntp"},    {585,"email"},    {614,"shell"},
                                                          {636,"ldap"},    {989,"ftp"},      {990,"ftp"},
                                                          {991,"nas"},     {992,"telnet"},   {993,"email"},
                                                          {994,"irc"},     {995,"email"},    {1443,"alt-https"},
                                                          {2376,"docker"}, {8001,"tor"},     {8443,"alt-https"},
                                                          {9000,"tor"},    {9001,"tor"},     {9002,"tor"},
                                                          {9101,"tor"}};

bool MALWARE_DB = true;
bool EXTENDED_FP_METADATA = true;


int gzgetline(gzFile f, std::vector<char>& v) {
    v = std::vector<char>(256);
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
    return 1;
}


int database_init(const char *resource_file) {
    fp_db.SetObject();
    rapidjson::Document::AllocatorType& allocator = fp_db.GetAllocator();

    gzFile in_file = gzopen(resource_file, "r");
    if (in_file == NULL) {
        return -1;
    }
    std::vector<char> line;
    while (gzgetline(in_file, line)) {
        std::string line_str(line.begin(), line.end());
        rapidjson::Document fp(&allocator);
        fp.Parse(line_str.c_str());

        rapidjson::Value::ConstMemberIterator itr = fp["process_info"][0].FindMember("malware");
        if (itr == fp["process_info"][0].MemberEnd()) {
            MALWARE_DB = false;
        }

        itr = fp["process_info"][0].FindMember("classes_hostname_sni");
        if (itr == fp["process_info"][0].MemberEnd()) {
            EXTENDED_FP_METADATA = false;
        }

        fp_db.AddMember(fp["str_repr"], fp, allocator);
    }
    gzclose(in_file);

    return 0;  /* success */
}

void database_finalize() {
    fp_db.SetObject();
}


#ifndef DEFAULT_RESOURCE_DIR
#define DEFAULT_RESOURCE_DIR "/usr/local/share/mercury"
#endif

int analysis_init(int verbosity, const char *resource_dir) {

//    if (pthread_mutex_init(&lock_fp_cache, NULL) != 0) {
//       printf("\n mutex init has failed\n");
//        return -1;
//    }
//    fp_cache = {};

    const char *resource_dir_list[] =
      {
       DEFAULT_RESOURCE_DIR,
       "resources",
       "../resources",
       NULL
      };
    if (resource_dir) {
        resource_dir_list[0] = resource_dir;  // use directory from configuration
        resource_dir_list[1] = NULL;          // fail otherwise
    }

    char resource_file_name[PATH_MAX];

    unsigned int index = 0;
    while (resource_dir_list[index] != NULL) {
        strncpy(resource_file_name, resource_dir_list[index], PATH_MAX-1);
        strncat(resource_file_name, "/pyasn.db", PATH_MAX-1);
        int retcode = addr_init(resource_file_name);

        if (retcode == 0) {
            strncpy(resource_file_name, resource_dir_list[index], PATH_MAX-1);
            strncat(resource_file_name, "/fingerprint_db.json.gz", PATH_MAX-1);
            retcode = database_init(resource_file_name);
            if (retcode == 0) {
                if (verbosity > 0) {
                    fprintf(stderr, "initialized analysis module with resource directory %s\n", resource_dir_list[index]);
                }
                return 0;
            }
        }
        if (verbosity > 0) {
            fprintf(stderr, "warning: could not open file '%s'\n", resource_file_name);
            fprintf(stderr, "warning: could not initialize analysis module with resource directory '%s', trying next in list\n", resource_dir_list[index]);
        }

        index++;  /* try next directory in the list */
    }
    fprintf(stderr, "warning: could not initialize analysis module\n");
    return -1;
}


int analysis_finalize() {

    addr_finalize();
    database_finalize();
//    cache_finalize();

    return 1;
}

#define SNI_HEADER_LEN 9

#define MAX_DST_ADDR_LEN 40
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

// #include <iostream> // for debugging
// #include "rapidjson/writer.h"
// print out fp_db for debugging
// rapidjson::StringBuffer buffer;
// rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
// fp_db.Accept(writer);
// std::cerr << buffer.GetString() << std::endl;

struct analysis_result perform_analysis(char *fp_str, char *server_name, char *dst_ip, uint16_t dst_port) {
    rapidjson::Value::ConstMemberIterator matcher = fp_db.FindMember(fp_str);
    if (matcher == fp_db.MemberEnd()) {
        return analysis_result();
    }
    rapidjson::Value& fp = fp_db[fp_str];

    uint32_t asn_int = get_asn_info(dst_ip);
    std::string asn = std::to_string(asn_int);
    std::string port_app = get_port_app(dst_port);
    std::string domain = get_domain_name(server_name);
    std::string server_name_str(server_name);
    std::string dst_ip_str(dst_ip);

    uint32_t fp_tc, p_count, tmp_value;
    long double prob_process_given_fp, score;
    long double max_score = -1.0;
    long double sec_score = -1.0;
    long double score_sum = 0.0;
    long double malware_prob = 0.0;
    rapidjson::Value equiv_class;
    std::string max_proc, sec_proc;
    bool max_mal = false;
    bool sec_mal = false;

    rapidjson::Value proc;
    fp_tc = fp["total_count"].GetInt();

    long double base_prior;
    long double proc_prior = log(.1);
    rapidjson::Value::ConstMemberIterator itr;

    const rapidjson::Value& procs = fp["process_info"];
    for (rapidjson::SizeType i = 0; i < procs.Size(); i++) {
        p_count = procs[i]["count"].GetInt();
        prob_process_given_fp = (long double)p_count/fp_tc;

        base_prior = log(1.0/fp_tc);
        itr = procs[i].FindMember("domain_mean");
        if ((itr != procs[i].MemberEnd()) && (procs[i]["domain_mean"].GetFloat() < 0.5)) {
            base_prior = log(.1/fp_tc);
        }

        score = log(prob_process_given_fp);
        score = fmax(score, proc_prior);

        itr = procs[i]["classes_ip_as"].FindMember(asn.c_str());
        if (itr != procs[i]["classes_ip_as"].MemberEnd()) {
            tmp_value = procs[i]["classes_ip_as"][asn.c_str()].GetInt();
            score += log((long double)tmp_value/fp_tc)*0.13924;
        } else {
            score += base_prior*0.13924;
        }

        itr = procs[i]["classes_hostname_domains"].FindMember(domain.c_str());
        if (itr != procs[i]["classes_hostname_domains"].MemberEnd()) {
            tmp_value = procs[i]["classes_hostname_domains"][domain.c_str()].GetInt();
            score += log((long double)tmp_value/fp_tc)*0.15590;
        } else {
            score += base_prior*0.15590;
        }

        itr = procs[i]["classes_port_applications"].FindMember(port_app.c_str());
        if (itr != procs[i]["classes_port_applications"].MemberEnd()) {
            tmp_value = procs[i]["classes_port_applications"][port_app.c_str()].GetInt();
            score += log((long double)tmp_value/fp_tc)*0.00528;
        } else {
            score += base_prior*0.00528;
        }

        if (EXTENDED_FP_METADATA) {
            itr = procs[i]["classes_ip_ip"].FindMember(dst_ip_str.c_str());
            if (itr != procs[i]["classes_ip_ip"].MemberEnd()) {
                tmp_value = procs[i]["classes_ip_ip"][dst_ip_str.c_str()].GetInt();
                score += log((long double)tmp_value/fp_tc)*0.56735;
            } else {
                score += base_prior*0.56735;
            }

            itr = procs[i]["classes_hostname_sni"].FindMember(server_name_str.c_str());
            if (itr != procs[i]["classes_hostname_sni"].MemberEnd()) {
                tmp_value = procs[i]["classes_hostname_sni"][server_name_str.c_str()].GetInt();
                score += log((long double)tmp_value/fp_tc)*0.96941;
            } else {
                score += base_prior*0.96941;
            }
        }

        score = exp(score);
        score_sum += score;

        if (MALWARE_DB) {
            if (procs[i]["malware"].GetBool() == true && score > 0.0) {
                malware_prob += score;
            }

            if (score > max_score) {
                sec_score = max_score;
                sec_proc = max_proc;
                sec_mal = max_mal;
                max_score = score;
                max_proc = procs[i]["process"].GetString();
                max_mal = procs[i]["malware"].GetBool();
            } else if (score > sec_score) {
                sec_score = score;
                sec_proc = procs[i]["process"].GetString();
                sec_mal = procs[i]["malware"].GetBool();
            }
        } else {
            if (score > max_score) {
                max_score = score;
                max_proc = procs[i]["process"].GetString();
            }
        }

    }

    if (MALWARE_DB && max_proc == "generic dmz process" && sec_mal == false) {
        max_proc = sec_proc;
        max_score = sec_score;
        max_mal = sec_mal;
    }

    if (score_sum > 0.0) {
        max_score /= score_sum;
        if (MALWARE_DB) {
            malware_prob /= score_sum;
        }
    }

    if (MALWARE_DB) {
        return analysis_result(max_proc.c_str(), max_score, max_mal, malware_prob);
    }
    return analysis_result(max_proc.c_str(), max_score);
}

void write_analysis_from_extractor_and_flow_key(struct json_object &o,
                                                const struct tls_client_hello &hello,
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

    class analysis_result res = perform_analysis(fp_str, sn_str, dst_ip_str, dst_port);
    if (res.is_valid() == false) {
        return;
    }
    res.write_json(o, "analysis");
}

