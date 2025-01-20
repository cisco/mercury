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


class classifier *analysis_init_from_archive(int verbosity,
                               const char *archive_name,
                               const uint8_t *enc_key,
                               enum enc_key_type key_type,
                               float fp_proc_threshold,
                               float proc_dst_threshold,
                               bool report_os);

int analysis_finalize(classifier *c);


// process and malware classifier classes
//

class process_info {
public:
    std::string name;
    bool malware;
    uint64_t count;
    attribute_result::bitset attributes;
    std::unordered_map<uint32_t, uint64_t>    ip_as;
    std::unordered_map<std::string, uint64_t> hostname_domains;
    std::unordered_map<uint16_t, uint64_t>    dst_port;
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
        dst_port{ports},
        ip_ip{ip},
        hostname_sni{sni},
        user_agent{ua},
        os_info{oses} {
            if (!ip.empty() && !sni.empty()) {
                extended_fp_metadata = true;
            }
    }

    void print(FILE *f) {
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
        for (auto &x : dst_port) {
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
    ssize_t enc_channel_idx = -1;
};

// data type used in floating point computations
//
using floating_point_type = long double;

template <typename T>
class feature {
    std::unordered_map<T, std::vector<class update>> updates;

public:

    // construct a naive bayes feature of type T
    //
    feature(const std::unordered_map<T,uint64_t> &info, size_t total_count, floating_point_type weight=1.0) {
        floating_point_type base_prior = log(0.1 / total_count);
        for (const auto &[feat, count] : info) {
            const auto x = updates.find(feat);
            class update u{ index, (log((floating_point_type)count / total_count) - base_prior ) * weight };
            if (x != updates.end()) {
                x->second.push_back(u);
            } else {
                updates[feat] = { u };
            }
        }
    }

    // apply a naive bayes feature update to prob_vector
    //
    void update(std::vector<floating_point_type> &prob_vector, const T &asn_int) const {
        auto u = updates.find(asn_int);
        if (u != updates.end()) {
            for (const auto &x : u->second) {
                assert(x.index < prob_vector.size());
                prob_vector[x.index] += x.value;
            }
        }
    }

};

// an instance of class update represents an update to a prior
// probability
//
class update {
public:
    update(unsigned int i, floating_point_type v) : index{i}, value{v} {}
    unsigned int index;  // index of probability to update
    floating_point_type value;   // value of update

    bool operator==(const update &rhs) const {
        return index == rhs.index
            && value == rhs.value;
    }

    void combine(size_t rhs_count, size_t total_count, floating_point_type base_prior, floating_point_type domain_weight) {

        floating_point_type old_count = expl((value / domain_weight) + base_prior) * total_count;
        // fprintf(stderr, "old_count: %.20Le\t%.20Lf\n", old_count, roundl(old_count));
        size_t old_count_integral = (size_t)roundl(old_count);
        value = (log((floating_point_type)(rhs_count + old_count_integral) / total_count) - base_prior) * domain_weight;
    }

};

/// represents a model that assigns a probability update to a domain
/// name (or a TLS or QUIC server name, or an HTTP host name)
///
class domain_name_model {

public:

    bool operator==(const domain_name_model &rhs) const {

        if (hostname_domain_updates != rhs.hostname_domain_updates) {
            fprintf(stderr, "hostname_domain_updates mismatch\n");
            for (const auto &[key, value] : hostname_domain_updates) {
                const auto result = rhs.hostname_domain_updates.find(key);
                if (result == rhs.hostname_domain_updates.end()) {
                    fprintf(stderr, "\tkey %s in lhs but not rhs\n", key.c_str());
                } else {
                    std::vector<floating_point_type> vec;
                    fprintf(stderr, "\tkey %s: lhs:\t", key.c_str());
                    for (const auto & u : value) { fprintf(stderr, "{%u,%.20Le}", u.index, u.value); vec.push_back(u.value); };
                    fputc('\n', stderr);
                    fprintf(stderr, "\tkey %s: rhs:\t", key.c_str());
                    for (const auto & u : result->second) { fprintf(stderr, "{%u,%.20Le}", u.index, u.value); };
                    fputc('\n', stderr);
                    fprintf(stderr, "\tkey %s: dif:\t", key.c_str());
                    size_t i=0;
                    for (const auto & u : result->second) { fprintf(stderr, "{%u,%.20Le}", u.index, u.value - vec[i++]);  };
                    fputc('\n', stderr);

                    for (size_t j=0; j<value.size(); j++) {
                        if (value[j].value != result->second[j].value) {
                            fprintf(stderr, "\tMISMATCH: key:%s\tlhs:{%u,%.20Le}\trhs:{%u,%.20Le}\n",
                                    key.c_str(),
                                    value[j].index, value[j].value,
                                    result->second[j].index, result->second[j].value);
                        }
                    }
                }
            }
        }
        if (hostname_sni_updates != rhs.hostname_sni_updates) {
            fprintf(stderr, "hostname_sni_updates mismatch\n");
            for (const auto &[key, value] : hostname_sni_updates) {
                const auto result = rhs.hostname_sni_updates.find(key);
                if (result == rhs.hostname_sni_updates.end()) {
                    fprintf(stderr, "\tkey %s in lhs but not rhs\n", key.c_str());
                } else {
                    fprintf(stderr, "\tkey %s: lhs:\t", key.c_str());
                    for (const auto & u : value) { fprintf(stderr, "{%u,%Le}", u.index, u.value);  };
                    fputc('\n', stderr);
                    fprintf(stderr, "\tkey %s: rhs:\t", key.c_str());
                    for (const auto & u : result->second) { fprintf(stderr, "{%u,%Le}", u.index, u.value);  };
                    fputc('\n', stderr);
                }
            }
        }

        return hostname_domain_updates == rhs.hostname_domain_updates
            && hostname_sni_updates == rhs.hostname_sni_updates;
    }

    std::unordered_map<std::string, std::vector<class update>> hostname_domain_updates;
    std::unordered_map<std::string, std::vector<class update>> hostname_sni_updates;

    domain_name_model() {
        fprintf(stderr, "\n---constructing domain_name_model---\n");
    }

    domain_name_model(const std::vector<class process_info> &processes,
                      size_t total_count,
                      floating_point_type domain_weight,
                      floating_point_type sni_weight) {

        floating_point_type base_prior = log(0.1 / total_count);
        size_t index = 0;
        for (const auto &p : processes) {
            for (const auto &domains_and_count : p.hostname_domains) {
                const auto x = hostname_domain_updates.find(domains_and_count.first);
                class update u{ index, (log((floating_point_type)domains_and_count.second / total_count) - base_prior) * domain_weight };
                if (x != hostname_domain_updates.end()) {
                    x->second.push_back(u);
                    assert(x->second.size() <= processes.size());
                } else {
                    hostname_domain_updates[domains_and_count.first] = { u };
                }
            }
            for (const auto &sni_and_count : p.hostname_sni) {
                const auto x = hostname_sni_updates.find(sni_and_count.first);
                class update u{ index, (log((floating_point_type)sni_and_count.second / total_count) - base_prior) * sni_weight };
                if (x != hostname_sni_updates.end()) {
                    x->second.push_back(u);
                    assert(x->second.size() <= processes.size());
                } else {
                    hostname_sni_updates[sni_and_count.first] = { u };
                }
            }

            index++;
        }
    }

    // EXPERIMENTAL
    //
    void observe_domain(size_t index, const std::string &hostname_domains, size_t count, size_t total_count, floating_point_type domain_weight) {

        // fprintf(stderr, "hostname_domains: %s\tcount: %zu\n", hostname_domains.c_str(), count);

        floating_point_type base_prior = log(0.1 / total_count);
        std::pair<std::string,size_t> domains_and_count{ hostname_domains, count };

        const auto x = hostname_domain_updates.find(domains_and_count.first);
        class update u{ index, (log((floating_point_type)domains_and_count.second / total_count) - base_prior) * domain_weight };
        if (x != hostname_domain_updates.end()) {

            // check for previous occurence of this index
            //
            class update *prev_update = nullptr;
            for (auto & upd : x->second) {
                if (upd.index == index) {
                    prev_update = &upd;
                }
            }
            if (prev_update) {
                //fprintf(stderr, "update: %Le += %Le ", prev_update->value, u.value);
                // prev_update->value += u.value;  // note: possible loss of precision
                prev_update->combine(count, total_count, base_prior, domain_weight);  
                //fprintf(stderr, "(%Le)\n", prev_update->value);
            } else {
                x->second.push_back(u);
            }
            // assert(x->second.size() <= processes.size());

        } else {
            hostname_domain_updates[domains_and_count.first] = { u };
        }

    }

    // EXPERIMENTAL
    //
    void observe_sni(size_t index, const std::string &hostname_sni, size_t count, size_t total_count, floating_point_type sni_weight) {

        // fprintf(stderr, "hostname_sni: %s\n", hostname_sni.c_str());

        floating_point_type base_prior = log(0.1 / total_count);
        std::pair<std::string,size_t> sni_and_count{ hostname_sni, count };

        const auto x = hostname_sni_updates.find(sni_and_count.first);
        class update u{ index, (log((floating_point_type)sni_and_count.second / total_count) - base_prior) * sni_weight };
        if (x != hostname_sni_updates.end()) {

            // check for previous occurence of this index
            //
            class update *prev_update = nullptr;
            for (auto & upd : x->second) {
                if (upd.index == index) {
                    prev_update = &upd;
                }
            }
            if (prev_update) {
                // fprintf(stderr, "update: %Le += %Le ", prev_update->value, u.value);
                prev_update->combine(count, total_count, base_prior, sni_weight);
                // prev_update->value += u.value;  // note: possible loss of precision
                //fprintf(stderr, "(%Le)\n", prev_update->value);
            } else {
                x->second.push_back(u);
            }
            // assert(x->second.size() <= processes.size());

        } else {
            hostname_sni_updates[sni_and_count.first] = { u };
        }

    }

    void update(std::vector<floating_point_type> &process_score,
                //const std::string &domain,
                const std::string &server_name_str) const {

        std::string domain = get_tld_domain_name(server_name_str.c_str());

        auto hostname_domain_update = hostname_domain_updates.find(domain);
        if (hostname_domain_update != hostname_domain_updates.end()) {
            for (const auto &x : hostname_domain_update->second) {
                assert(x.index < process_score.size());
                process_score[x.index] += x.value;
            }
        }

        auto hostname_sni_update = hostname_sni_updates.find(server_name_str);
        if (hostname_sni_update != hostname_sni_updates.end()) {
            for (const auto &x : hostname_sni_update->second) {
                assert(x.index < process_score.size());
                process_score[x.index] += x.value;
            }
        }
    }

    // get_tld_domain_name() returns the string containing the top two
    // domains of the input string; that is, given "s3.amazonaws.com",
    // it returns "amazonaws.com".  If there is only one name, it is
    // returned.
    //
    static std::string get_tld_domain_name(const char* server_name) {

        const char *separator = NULL;
        const char *previous_separator = NULL;
        const char *c = server_name;
        while (*c) {
            if (*c == '.') {
                if (separator) {
                    previous_separator = separator;
                }
                separator = c;
            }
            c++;
        }
        if (previous_separator) {
            previous_separator++;  // increment past '.'
            return previous_separator;
        }
        return server_name;
    }

};

class naive_bayes {

    uint64_t total_count = 0;
    ptr_dict &os_dict;
    floating_point_type base_prior = 0;   // TODO: does this need to be a class member?

    std::vector<floating_point_type> process_prob;
    // std::vector<bool>        malware;
    //    std::vector<attribute_result::bitset> attr;
    std::unordered_map<uint32_t, std::vector<class update>> as_number_updates;
    std::unordered_map<uint16_t, std::vector<class update>> port_updates;
    std::unordered_map<std::string, std::vector<class update>> ip_ip_updates;
    std::unordered_map<std::string, std::vector<class update>> user_agent_updates;

    floating_point_type as_weight     = 0.13924;
    floating_point_type domain_weight = 0.15590;
    floating_point_type port_weight   = 0.00528;
    floating_point_type ip_weight     = 0.56735;
    floating_point_type sni_weight    = 0.96941;
    floating_point_type ua_weight     = 1.0;

    domain_name_model domain_name;
    //  feature<uint32_t> asn;

public:

    bool operator==(const naive_bayes &rhs) const {
        if (as_number_updates != rhs.as_number_updates) {
            fprintf(stderr, "as_number_updates mismatch\n");
            for (const auto &[key, value] : as_number_updates) {
                const auto result = rhs.as_number_updates.find(key);
                if (result == rhs.as_number_updates.end()) {
                    fprintf(stderr, "\tkey %u in lhs but not rhs\n", key);
                } else {
                    fprintf(stderr, "\tkey %u: lhs:\t", key); for (const auto & u : value) { fprintf(stderr, "{%u,%Le}", u.index, u.value);  }; fputc('\n', stderr);
                    fprintf(stderr, "\tkey %u: rhs:\t", key); for (const auto & u : result->second) { fprintf(stderr, "{%u,%Le}", u.index, u.value);  };  fputc('\n', stderr);
                }
            }
        }
        if (port_updates != rhs.port_updates) {
            fprintf(stderr, "port_updates mismatch\n");
            for (const auto &[key, value] : port_updates) {
                const auto result = rhs.port_updates.find(key);
                if (result == rhs.port_updates.end()) {
                    fprintf(stderr, "\tkey %u in lhs but not rhs\n", key);
                } else {
                    fprintf(stderr, "\tkey %u: lhs:\t", key); for (const auto & u : value) { fprintf(stderr, "{%u,%Le}", u.index, u.value);  }; fputc('\n', stderr);
                    fprintf(stderr, "\tkey %u: rhs:\t", key); for (const auto & u : result->second) { fprintf(stderr, "{%u,%Le}", u.index, u.value);  };  fputc('\n', stderr);
                }
            }
        }

        fprintf(stderr, "process_prob match:  %u\n", process_prob == rhs.process_prob);
        // fprintf(stderr, "malware match:  %u\n", malware == rhs.malware);
        // fprintf(stderr, "attr match:  %u\n", attr == rhs.attr);
        fprintf(stderr, "as_number_updates match:  %u\n", as_number_updates == rhs.as_number_updates);
        fprintf(stderr, "port_updates match:       %u\n", port_updates == rhs.port_updates);
        fprintf(stderr, "ip_ip_updates match:      %u\n", ip_ip_updates == rhs.ip_ip_updates);
        fprintf(stderr, "user_agent_updates match: %u\n", user_agent_updates == rhs.user_agent_updates);
        fprintf(stderr, "domain_name match:        %u\n", domain_name == rhs.domain_name);

        return process_prob == rhs.process_prob
            // && malware == rhs.malware
            // && attr == rhs.attr
            && as_number_updates == rhs.as_number_updates
            && port_updates == rhs.port_updates
            && ip_ip_updates == rhs.ip_ip_updates
            && user_agent_updates == rhs.user_agent_updates
            && domain_name == rhs.domain_name;
    }

    static constexpr uint8_t num_features = 6;
    static constexpr static_dictionary<naive_bayes::num_features> features {
        {
            "as",
            "domain",
            "port",
            "ip",
            "sni",
            "ua"
        }
    };

    using feature_weights = std::array<floating_point_type, naive_bayes::num_features>;

    static constexpr feature_weights default_feature_weights = {
        0.13924,  // as_weight
        0.15590,  // domain_weight
        0.00528,  // port_weight
        0.56735,  // ip_weight
        0.96941,  // sni_weight
        1.0       // ua_weight
    };

    //    naive_bayes() { }

    naive_bayes(const std::vector<class process_info> &processes,
                uint64_t count,
                ptr_dict &os_dictionary,
                const naive_bayes::feature_weights &weights)
        : total_count{count},
          os_dict{os_dictionary},
          as_weight{weights[features.index("as")]},
          domain_weight{weights[features.index("domain")]},
          port_weight{weights[features.index("port")]},
          ip_weight{weights[features.index("ip")]},
          sni_weight{weights[features.index("sni")]},
          ua_weight{weights[features.index("ua")]},
          domain_name{
              processes,
              total_count,
              domain_weight,
              sni_weight
          }
    {

        //fprintf(stderr, "compiling fingerprint_data for %lu processes\n", processes.size());

        // initialize data structures
        //
        process_prob.reserve(processes.size());

        base_prior = log(0.1 / total_count);
        size_t index = 0;
        for (const auto &p : processes) {

            //fprintf(stderr, "compiling process \"%s\"\n", p.name.c_str());

            floating_point_type proc_prior = log(.1);
            floating_point_type prob_process_given_fp = (floating_point_type)p.count / total_count;
            floating_point_type score = log(prob_process_given_fp);
            process_prob.push_back(fmax(score, proc_prior) + base_prior * (as_weight + domain_weight + port_weight + ip_weight + sni_weight + ua_weight));

            for (const auto &as_and_count : p.ip_as) {
                const auto x = as_number_updates.find(as_and_count.first);
                class update u{ index, (log((floating_point_type)as_and_count.second / total_count) - base_prior ) * as_weight };
                if (x != as_number_updates.end()) {
                    x->second.push_back(u);
                } else {
                    as_number_updates[as_and_count.first] = { u };
                }
            }
            for (const auto &port_and_count : p.dst_port) {
                const auto x = port_updates.find(port_and_count.first);
                class update u{ index, (log((floating_point_type)port_and_count.second / total_count) - base_prior) * port_weight };
                if (x != port_updates.end()) {
                    x->second.push_back(u);
                } else {
                    port_updates[port_and_count.first] = { u };
                }
            }
            for (const auto &ip_and_count : p.ip_ip) {
                const auto x = ip_ip_updates.find(ip_and_count.first);
                class update u{ index, (log((floating_point_type)ip_and_count.second / total_count) - base_prior) * ip_weight };
                if (x != ip_ip_updates.end()) {
                    x->second.push_back(u);
                } else {
                    ip_ip_updates[ip_and_count.first] = { u };
                }
            }
            for (const auto &ua_and_count : p.user_agent) {
                const auto x = user_agent_updates.find(ua_and_count.first);
                class update u{ index, (log((floating_point_type)ua_and_count.second / total_count) - base_prior) * ua_weight };
                if (x != user_agent_updates.end()) {
                    x->second.push_back(u);
                } else {
                    user_agent_updates[ua_and_count.first] = { u };
                }
            }

            ++index;
        }

        // process_prob should have the same number of elements as the
        // input vector processes
        //
        assert(process_prob.size() == processes.size());

    }

    // EXPERIMENTAL constructor that reads directly from JSON
    //
    naive_bayes(const rapidjson::Value &process_info,
                size_t total_count,
                bool report_os,
                ptr_dict &os_dictionary,
                // bool &MALWARE_DB,
                bool &EXTENDED_FP_METADATA,
                float &fp_proc_threshold,
                float &proc_dst_threshold
                // common_data &common
                ) :
        os_dict{os_dictionary}
    {

        // fprintf(stderr, "num processes: %u\n", process_info.GetArray().Size());

        size_t index = 0;   // zero-based index of process in probability vector

        if (total_count == 0) {
            fprintf(stderr, "warning: total_count==0\n");
        }
        base_prior = log(0.1 / total_count);

        unsigned int process_number = 0;
        for (auto &x : process_info.GetArray()) {
            uint64_t count = 0;
            bool malware = false;

            if (x.HasMember("count") && x["count"].IsUint64()) {
                count = x["count"].GetUint64();
                //fprintf(stderr, "\tcount: %lu\n", x["count"].GetUint64());
            }
            // if (x.HasMember("malware") && x["malware"].IsBool()) {
            //     if (MALWARE_DB == false && process_number > 1) {
            //         throw std::runtime_error("error: malware data expected, but not present");
            //     }
            //     MALWARE_DB = true;
            //     malware = x["malware"].GetBool();
            // }
            if (count == 0) {
                throw std::runtime_error("error: process_fp_db_line() count 0");
                continue;
            }
            /* do not load process into memory if prevalence is below threshold */
            if ((process_number > 1) && ((float)count/total_count < fp_proc_threshold) && (malware != true)) {
                continue;
            }

            process_number++;
            //fprintf(stderr, "%s\n", "process_info");

            floating_point_type proc_prior = log(.1);
            floating_point_type prob_process_given_fp = (floating_point_type)count / total_count;
            floating_point_type score = log(prob_process_given_fp);
            process_prob.push_back(fmax(score, proc_prior) + base_prior * (as_weight + domain_weight + port_weight + ip_weight + sni_weight + ua_weight));

            // attribute_result::bitset attributes;
            // std::unordered_map<uint32_t, uint64_t>    ip_as;
            // std::unordered_map<std::string, uint64_t> hostname_domains;
            // std::unordered_map<uint16_t, uint64_t>    dst_port;
            // std::unordered_map<std::string, uint64_t> ip_ip;
            // std::unordered_map<std::string, uint64_t> hostname_sni;
            // std::unordered_map<std::string, uint64_t> user_agent;
            std::map<std::string, uint64_t> os_info;

            std::string name;
            if (x.HasMember("process") && x["process"].IsString()) {
                name = x["process"].GetString();
                //fprintf(stderr, "\tname: %s\n", x["process"].GetString());
            }

            // if (x.HasMember("attributes") && x["attributes"].IsObject()) {
            //     for (auto &v : x["attributes"].GetObject()) {
            //         if (v.name.IsString()) {
            //             ssize_t idx = common.attr_name.get_index(v.name.GetString());
            //             if (idx < 0) {
            //                 printf_err(log_warning, "unknown attribute %s while parsing process information\n", v.name.GetString());
            //                 throw std::runtime_error("error while parsing resource archive file");
            //             }
            //             if (v.value.IsBool() and v.value.GetBool()) {
            //                 if (idx > attr.size()) {
            //                     std::string err{"bad index for attribute vector for "};
            //                     err += v.name.GetString();
            //                     throw std::runtime_error{err};
            //                 }
            //                 attr[idx] = 1;
            //             }
            //         }
            //     }
            //     common.attr_name.stop_accepting_new_names();
            //
            // }

            if (x.HasMember("classes_hostname_domains") && x["classes_hostname_domains"].IsObject()) {
                //fprintf(stderr, "\tclasses_hostname_domains\n");
                for (auto &y : x["classes_hostname_domains"].GetObject()) {
                    if (y.value.IsUint64() && ((float)y.value.GetUint64()/count > proc_dst_threshold)) {
                        //fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());

                        // Once data pipeline is updated to normalize the domain names, the following code will be used:
                        // hostname_domains[server_identifier{y.name.GetString()}] = y.value.GetUint64();
                        //
                        // and this code will be removed:
                        std::string normalized = server_identifier{y.name.GetString()}.get_normalized_domain_name(server_identifier::detail::on);
                        // if (hostname_domains.find(normalized) != hostname_domains.end()) {
                        //     // If two different domain names are normalized to the same domain name, then the counts are added.
                        //     hostname_domains[normalized] += y.value.GetUint64();
                        // } else {
                        //     hostname_domains[normalized] = y.value.GetUint64();
                        // }

                        // EXPERIMENTAL
                        //
                        domain_name.observe_domain(index, normalized, y.value.GetUint64(), total_count, domain_weight);

                    }
                }
            }
            if (x.HasMember("classes_ip_as") && x["classes_ip_as"].IsObject()) {
                //fprintf(stderr, "\tclasses_ip_as\n");
                for (auto &y : x["classes_ip_as"].GetObject()) {
                    if (y.value.IsUint64() && ((float)y.value.GetUint64()/count > proc_dst_threshold)) {
                        //fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());

                        if (strcmp(y.name.GetString(), "unknown") != 0) {

                            errno = 0;
                            unsigned long as_number = strtol(y.name.GetString(), NULL, 10);
                            if (errno) {
                                as_number = 0; // "unknown"
                                printf_err(log_warning, "unexpected string \"%s\" in ip_as\n", y.name.GetString());
                            }
                            if (as_number > 0xffffffff) {
                                throw std::runtime_error("error: as number too high");
                            }
                            // ip_as[as_number] = y.value.GetUint64();

                            // EXPERIMENTAL
                            //
                            std::pair<uint32_t,size_t> as_and_count = { as_number, y.value.GetUint64() };
                            const auto x = as_number_updates.find(as_and_count.first);
                            class update u{ index, (log((floating_point_type)as_and_count.second / total_count) - base_prior ) * as_weight };
                            if (x != as_number_updates.end()) {
                                x->second.push_back(u);
                            } else {
                                as_number_updates[as_and_count.first] = { u };
                            }

                        }
                    }
                }
            }
            if (x.HasMember("classes_port_port") && x["classes_port_port"].IsObject()) {
                //fprintf(stderr, "\tclasses_port_port\n");
                for (auto &y : x["classes_port_port"].GetObject()) {
                    if (y.value.IsUint64() && ((float)y.value.GetUint64()/count > proc_dst_threshold)) {
                        uint64_t tmp_port = 0;
                        try {
                            tmp_port = std::stoul(y.name.GetString());
                        }
                        catch (...) {
                            printf_err(log_warning, "unexpected string \"%s\" in classes_port_port\n", y.name.GetString());
                        }
                        if (tmp_port > std::numeric_limits<uint16_t>::max()) {
                            printf_err(log_warning, "number %" PRIu64 " too high in classes_port_port\n", tmp_port);
                            tmp_port = 0;    // error: port numbers should 16-bit unsigned integers
                        }
                        // dst_port[tmp_port] = y.value.GetUint64();

                        // EXPERIMENTAL
                        //
                        std::pair<uint16_t,size_t> port_and_count = { tmp_port, y.value.GetUint64() };
                        const auto x = port_updates.find(port_and_count.first);
                        class update u{ index, (log((floating_point_type)port_and_count.second / total_count) - base_prior) * port_weight };
                        if (x != port_updates.end()) {
                            x->second.push_back(u);
                        } else {
                            port_updates[port_and_count.first] = { u };
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
                    if (!y.value.IsUint64() && ((float)y.value.GetUint64()/count > proc_dst_threshold)) {
                        printf_err(log_warning, "classes_ip_ip object element %s is not a Uint64\n", y.name.GetString());
                        //fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());
                        // ip_ip[y.name.GetString()] = y.value.GetUint64();

                        // EXPERIMENTAL
                        //
                        // empty for now, to preserve compatibility
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
                    if (y.value.IsUint64() && ((float)y.value.GetUint64()/count > proc_dst_threshold)) {
                        //fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());

                        // Once data pipeline is updated to normalize the domain names, the following code will be used:
                        // hostname_sni[server_identifier{y.name.GetString()}] = y.value.GetUint64();
                        //
                        // and this code will be removed:
                        std::string normalized = server_identifier{y.name.GetString()}.get_normalized_domain_name(server_identifier::detail::on);
                        // if (hostname_sni.find(normalized) != hostname_sni.end()) {
                        //     // If two different domain names are normalized to the same domain name, then the counts are added.
                        //     hostname_sni[normalized] += y.value.GetUint64();
                        // } else {
                        //     hostname_sni[normalized] = y.value.GetUint64();
                        // }

                        // EXPERIMENTAL
                        //
                        domain_name.observe_sni(index, normalized, y.value.GetUint64(), total_count, sni_weight);

                    }
                }
            }
            if (x.HasMember("classes_user_agent") && x["classes_user_agent"].IsObject()) {
                if (EXTENDED_FP_METADATA == false && process_number > 1) {
                    throw std::runtime_error("error: extended fingerprint metadata expected, but not present");
                }
                EXTENDED_FP_METADATA = true;
                for (auto &y : x["classes_user_agent"].GetObject()) {
                    if (y.value.IsUint64() && ((float)y.value.GetUint64()/count > proc_dst_threshold)) {
                        //fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());
                        // user_agent[y.name.GetString()] = y.value.GetUint64();


                        // EXPERIMENTAL
                        //
                        std::pair<std::string,size_t> ua_and_count = { y.name.GetString(), y.value.GetUint64() };
                        const auto x = user_agent_updates.find(ua_and_count.first);
                        class update u{ index, (log((floating_point_type)ua_and_count.second / total_count) - base_prior) * ua_weight };
                        if (x != user_agent_updates.end()) {
                            x->second.push_back(u);
                        } else {
                            user_agent_updates[ua_and_count.first] = { u };
                        }

                    }
                }
            }
            if (report_os && x.HasMember("os_info") && x["os_info"].IsObject()) {
                for (auto &y : x["os_info"].GetObject()) {
                    if (std::string(y.name.GetString()) != "") {
                        os_info[y.name.GetString()] = y.value.GetUint64();
                    }
                }
            }

            // class process_info process(name, malware, count, attributes, ip_as, hostname_domains, dst_port,
            //                            ip_ip, hostname_sni, user_agent, os_info);
            // process_vector.push_back(process);

            index++;
        }

        // fingerprint_data  *fp_data = new fingerprint_data(total_count, process_vector,
        //                                                   os_dictionary, &subnets, &common, MALWARE_DB, weights);

    }

    std::vector<floating_point_type> classify(uint32_t asn_int,
                                              uint16_t dst_port,
                                              const std::string &server_name_str,
                                              const std::string &dst_ip_str,
                                              const char *user_agent) const {

        std::vector<floating_point_type> process_score = process_prob;  // working copy of probability vector

        auto asn_update = as_number_updates.find(asn_int);
        if (asn_update != as_number_updates.end()) {
            for (const auto &x : asn_update->second) {
                process_score[x.index] += x.value;
            }
        }
        auto port_update = port_updates.find(dst_port);
        if (port_update != port_updates.end()) {
            for (const auto &x : port_update->second) {
                process_score[x.index] += x.value;
            }
        }
        auto ip_ip_update = ip_ip_updates.find(dst_ip_str);
        if (ip_ip_update != ip_ip_updates.end()) {
            for (const auto &x : ip_ip_update->second) {
                process_score[x.index] += x.value;
            }
        }
        if (user_agent != nullptr) {
            std::string user_agent_str(user_agent);
            auto user_agent_update = user_agent_updates.find(user_agent_str);
            if (user_agent_update != user_agent_updates.end()) {
                for (const auto &x : user_agent_update->second) {
                    process_score[x.index] += x.value;
                }
            }
        }

        domain_name.update(process_score, server_name_str);

        return process_score;
    }

    bool is_recomputation_required(floating_point_type new_as_weight, floating_point_type new_domain_weight,
                                 floating_point_type new_port_weight, floating_point_type new_ip_weight,
                                 floating_point_type new_sni_weight, floating_point_type new_ua_weight) {
        if (new_as_weight != as_weight or new_domain_weight != domain_weight or
            new_port_weight != port_weight or new_ip_weight != ip_weight or
            new_sni_weight != sni_weight or new_ua_weight != ua_weight) {
            return true;
        }

        return false;
    }

    void recompute_probabilities(floating_point_type new_as_weight, floating_point_type new_domain_weight,
                                 floating_point_type new_port_weight, floating_point_type new_ip_weight,
                                 floating_point_type new_sni_weight, floating_point_type new_ua_weight) {

        if (!is_recomputation_required(new_as_weight, new_domain_weight, new_port_weight,
                                       new_ip_weight, new_sni_weight, new_ua_weight)) {
            return;
        }

        floating_point_type old_weights = base_prior * (as_weight + domain_weight + port_weight + ip_weight + sni_weight + ua_weight);
        floating_point_type new_weights = base_prior * (new_as_weight + new_domain_weight + new_port_weight + new_ip_weight + new_sni_weight + new_ua_weight);

        /*
         * Process probability is originally calculated as,
         * process_prob = fmax(score, proc_prior) + base_prior * (as_weight + domain_weight + port_weight + ip_weight + sni_weight + ua_weight)
         * when weights are changed, then process_prob can be recalculated as,
         *
         * process_prob = process_prob - base_prior * (as_weight + domain_weight + port_weight + ip_weight + sni_weight + ua_weight)
                            + base_prior * (new_as_weight + new_domain_weight + new_port_weight + new_ip_weight + new_sni_weight + new_ua_weight)
         */
        for (auto &p : process_prob) {
            p = p - old_weights + new_weights;
        }

        /*
         * Update value is originally calculated as
         * update.value  = log((floating_point_type)as_and_count.second / total_count) - base_prior ) * as_weight
         */
        for (auto &v : as_number_updates) {
            for (auto &update : v.second) {
                update.value = update.value * new_as_weight/as_weight;
            }
        }

        // TODO: replace this functionality
        //
        // for (auto &v: hostname_domain_updates) {
        //     for (auto &update : v.second) {
        //         update.value = update.value * new_domain_weight/domain_weight;
        //     }
        // }

        for (auto &v: port_updates) {
            for (auto &update : v.second) {
                update.value = update.value * new_port_weight/port_weight;
            }
        }

        for (auto &v: ip_ip_updates) {
            for (auto &update : v.second) {
                update.value = update.value * new_ip_weight/ip_weight;
            }
        }

        // TODO: replace this functionality
        //
        // for (auto &v: hostname_sni_updates) {
        //     for (auto &update : v.second) {
        //         update.value = update.value * new_sni_weight/sni_weight;
        //     }
        // }

        for (auto &v: user_agent_updates) {
            for (auto &update : v.second) {
                update.value = update.value * new_ua_weight/ua_weight;
            }
        }

        as_weight = new_as_weight;
        domain_weight = new_domain_weight;
        port_weight = new_port_weight;
        ip_weight = new_ip_weight;
        sni_weight = new_sni_weight;
        ua_weight = new_ua_weight;
    }
};

static bool operator==(const os_information &lhs, const os_information &rhs) {
    if (true) { //lhs.os_name != rhs.os_name || lhs.os_prevalence != rhs.os_prevalence) {
        fprintf(stderr, "lhs: %s, %zu\n", lhs.os_name, lhs.os_prevalence);
        fprintf(stderr, "rhs: %s, %zu\n", rhs.os_name, rhs.os_prevalence);
    }
    return lhs.os_name == rhs.os_name
        && lhs.os_prevalence == rhs.os_prevalence;
}

class fingerprint_data {

    std::vector<bool> malware;
    std::vector<attribute_result::bitset> attr;
    std::vector<std::string> process_name;
    std::vector<std::vector<struct os_information>> process_os_info_vector;

public:
    naive_bayes classifier;
private:
    bool malware_db = false;

    const subnet_data *subnet_data_ptr = nullptr;

    common_data *common = nullptr;

public:
    uint8_t refcnt = 0;
    uint64_t total_count;

    bool operator==(const fingerprint_data &rhs) const {

        fprintf(stderr, "classifier equal:      %u\n", classifier == rhs.classifier);
        fprintf(stderr, "malware equal:         %u\n", malware == rhs.malware);
        fprintf(stderr, "attr equal:            %u\n", attr == rhs.attr);
        fprintf(stderr, "process_name equal:    %u\n", process_name == rhs.process_name);
        fprintf(stderr, "process_os_info equal: %u\n", process_os_info_vector == rhs.process_os_info_vector);
        fprintf(stderr, "poi.size equal:        %u (%zu, %zu)\n", process_os_info_vector.size() == rhs.process_os_info_vector.size(), process_os_info_vector.size(), rhs.process_os_info_vector.size());

        if (process_os_info_vector.size() != rhs.process_os_info_vector.size()) {
            fprintf(stderr, "process_os_info_vector.size() != rhs.process_os_info_vector.size()\n");
        } else {
            // fprintf(stderr, "comparing process_os_info_vector and process_os_info_vector\n");
            for (size_t i=0; i<process_os_info_vector.size(); i++) {
                const std::vector<os_information> &lo = process_os_info_vector[i];
                const std::vector<os_information> &ro = rhs.process_os_info_vector[i];
                if (lo.size() != ro.size()) {
                    fprintf(stderr, "lo.size (%zu) != ro.size (%zu)\n", lo.size(), ro.size());
                } else {
                    for (size_t j=0; j<lo.size(); j++) {
                        const os_information &l = lo[j];
                        const os_information &r = ro[j];
                        fprintf(stderr, "lhs: {%s, %zu}\n", l.os_name, l.os_prevalence);
                        fprintf(stderr, "rhs: {%s, %zu}\n", r.os_name, r.os_prevalence);
                    }
                }
            }

            size_t pn = 0;
            for (const auto & osiv : process_os_info_vector) {
                fprintf(stderr, "process_os_info_vector[%zu]:     ", pn++);
                for (const auto & osi : osiv) {
                    fprintf(stderr, "{%s, %zu}", osi.os_name, osi.os_prevalence);
                }
                fputc('\n', stderr);
            }
            pn = 0;
            for (const auto & osiv : rhs.process_os_info_vector) {
                fprintf(stderr, "rhs.process_os_info_vector[%zu]: ", pn++);
                for (const auto & osi : osiv) {
                    fprintf(stderr, "{%s, %zu}", osi.os_name, osi.os_prevalence);
                }
                fputc('\n', stderr);
            }
        }

        return classifier == rhs.classifier
            && malware == rhs.malware
            && attr == rhs.attr
            && process_name == rhs.process_name
            && process_os_info_vector == rhs.process_os_info_vector;
    }

    // EXPERIMENTAL json-reading constructor
    //
    fingerprint_data(const rapidjson::Value &process_info,
                     ptr_dict &os_dictionary,
                     const subnet_data *subnets,
                     common_data *c,
                     bool malware_database,
                     size_t total_cnt,
                     bool report_os,
                     bool &EXTENDED_FP_METADATA,
                     float fp_proc_threshold,
                     float proc_dst_threshold
                     ) :
        classifier{
            process_info,
            total_cnt,
            report_os,
            os_dictionary,
            EXTENDED_FP_METADATA,
            fp_proc_threshold,
            proc_dst_threshold
        },
        malware_db{malware_database},
        subnet_data_ptr{subnets},
        common{c},
        total_count{total_cnt}
    {
        unsigned int num_procs = process_info.GetArray().Size();

        fprintf(stderr, "num processes: %u\n", num_procs);

        process_name.reserve(num_procs);
        malware.reserve(num_procs);
        attr.reserve(num_procs);
        process_os_info_vector.reserve(num_procs);

        for (auto &x : process_info.GetArray()) {

            if (x.HasMember("process") && x["process"].IsString()) {
                std::string name = x["process"].GetString();
                //fprintf(stderr, "\tname: %s\n", x["process"].GetString());
                process_name.push_back(name);
            }

            if (x.HasMember("malware") && x["malware"].IsBool()) {   // NOTE: malware assumed to be in schema
                malware.push_back(x["malware"].GetBool());
            }

            if (x.HasMember("attributes") && x["attributes"].IsObject()) {
                attribute_result::bitset attributes;
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

                attr.push_back(attributes);
            }

            //            report_os = true;
            fprintf(stderr, "report_os: %u\n", report_os);
            std::vector<struct os_information> os_info_vector;
            if (report_os && x.HasMember("os_info") && x["os_info"].IsObject()) {
                for (auto &y : x["os_info"].GetObject()) {
                    fprintf(stderr, "os_info_vector: adding %s\n", y.name.GetString());
                    if (std::string(y.name.GetString()) != "") {
                        // os_info[y.name.GetString()] = y.value.GetUint64();
                        const char *os = os_dictionary.get(y.name.GetString());
                        struct os_information tmp{(char *)os, y.value.GetUint64()};
                        os_info_vector.push_back(tmp);
                    }
                    // fprintf(stderr, "os_info_vector.size(): %zu\n", os_info_vector.size());
                }
            }
            process_os_info_vector.push_back(os_info_vector);
            // fprintf(stderr, "process_os_info_vector.size(): %zu\n", process_os_info_vector.size());

            // if (p.os_info.size() > 0) {
            //
            //     // create a vector of os_information structs, whose char * makes
            //     // use of the os_dictionary
            //     //
            //     std::vector<struct os_information> &os_info_vector = process_os_info_vector.back();
            //     for (const auto &os_and_count : p.os_info) {
            //         const char *os = os_dictionary.get(os_and_count.first);
            //         struct os_information tmp{(char *)os, os_and_count.second};
            //         os_info_vector.push_back(tmp);
            //     }
            // }


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

    fingerprint_data(uint64_t count,
                     const std::vector<class process_info> &processes,
                     ptr_dict &os_dictionary,
                     const subnet_data *subnets,
                     common_data *c,
                     bool malware_database,
                     const naive_bayes::feature_weights &feature_weights) :
        classifier{processes, count, os_dictionary, feature_weights},
        malware_db{malware_database},
        subnet_data_ptr{subnets},
        common{c},
        total_count{count}
    {

        //fprintf(stderr, "compiling fingerprint_data for %lu processes\n", processes.size());

        // initialize data structures
        //
        process_name.reserve(processes.size());
        malware.reserve(processes.size());
        attr.reserve(processes.size());
        process_os_info_vector.reserve(processes.size());

        for (const auto &p : processes) {
            process_name.push_back(p.name);
            malware.push_back(p.malware);
            attr.push_back(p.attributes);
            process_os_info_vector.push_back(std::vector<struct os_information>{});
            if (p.os_info.size() > 0) {

                // create a vector of os_information structs, whose char * makes
                // use of the os_dictionary
                //
                std::vector<struct os_information> &os_info_vector = process_os_info_vector.back();
                for (const auto &os_and_count : p.os_info) {
                    const char *os = os_dictionary.get(os_and_count.first);
                    struct os_information tmp{(char *)os, os_and_count.second};
                    os_info_vector.push_back(tmp);
                }
            }
        }

        // process_name, malware, and process_os_info_vector should
        // all have the same number of elements as the input vector
        // processes
        //
        assert(process_name.size() == processes.size());
        assert(malware.size() == processes.size());
        assert(process_os_info_vector.size() == processes.size());

    }

    ~fingerprint_data() {
    }

#if 0
    void print(FILE *f) {
        fprintf(f, ",\"total_count\":%" PRIu64, total_count);
        fprintf(f, ",\"process_info\":[");

        // TBD: fingerprint_data::print() output should be a JSON representation of object

        for (size_t i=0; i < process_name.size(); i++) {
            fprintf(f, "process: %s\tprob: %Le\n", process_name[i].c_str(), process_prob[i]);
        }
        fprintf(f, "as_number_updates:\n");
        for (const auto &asn_and_updates : as_number_updates) {
            fprintf(f, "\t%u:\n", asn_and_updates.first);
            for (const auto &update : asn_and_updates.second) {
                fprintf(f, "\t\t{ %u, %Le }\n", update.index, update.value);
            }
        }
        //std::unordered_map<std::string, std::vector<class update>> hostname_domain_updates;
        fprintf(f, "hostname_domain_updates:\n");
        for (const auto &domain_and_updates : hostname_domain_updates) {
            fprintf(f, "\t%s:\n", domain_and_updates.first.c_str());
            for (const auto &update : domain_and_updates.second) {
                fprintf(f, "\t\t{ %u, %Le }\n", update.index, update.value);
            }
        }
        fprintf(f, "port_updates:\n");
        for (const auto &port_and_updates : port_updates) {
            fprintf(f, "\t%u:\n", port_and_updates.first);
            for (const auto &update : port_and_updates.second) {
                fprintf(f, "\t\t{ %u, %Le }\n", update.index, update.value);
            }
        }
        fprintf(f, "]");
    }
#endif

    struct analysis_result perform_analysis(const char *server_name, const char *dst_ip, uint16_t dst_port,
                                            const char *user_agent, enum fingerprint_status status) {

        server_identifier server_id{server_name};
        std::string server_name_str = server_id.get_normalized_domain_name(server_identifier::detail::on);
        uint32_t asn_int = subnet_data_ptr->get_asn_info(dst_ip);
        std::string dst_ip_str(dst_ip);

        std::vector<floating_point_type> process_score = classifier.classify(asn_int, dst_port, server_name_str, dst_ip_str, user_agent);

        floating_point_type max_score = std::numeric_limits<floating_point_type>::lowest();
        floating_point_type sec_score = std::numeric_limits<floating_point_type>::lowest();
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

        floating_point_type score_sum = 0.0;
        floating_point_type malware_prob = 0.0;

        std::array<floating_point_type, attribute_result::MAX_TAGS> attr_prob;
        attr_prob.fill(0.0);
        for (uint64_t i=0; i < process_score.size(); i++) {
            process_score[i] = expf((float)(process_score[i] - max_score));
            score_sum += process_score[i];
            if (malware[i]) {
                malware_prob += process_score[i];
            }
            for (int j = 0; j < attribute_result::MAX_TAGS; j++) {
                if (attr[i][j]) {
                    attr_prob[j] += process_score[i];
                }
            }
        }

        max_score = process_score[index_max];
        sec_score = process_score[index_sec];

        if (score_sum > 0.0) {
            if (malware_db) {
                malware_prob /= score_sum;
            }
        }
        if (malware_db && process_name[index_max] == "generic dmz process" && malware[index_sec] == false) {
            // the most probable process is unlabeled, so choose the
            // next most probable one if it isn't malware, and adjust
            // the normalization sum as appropriate

            index_max = index_sec;
            score_sum -= max_score;
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

        attribute_result attr_res{attr_tags, attr_prob, &common->attr_name.value(), common->attr_name.get_names_char()};

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

    void recompute_probabilities(floating_point_type new_as_weight, floating_point_type new_domain_weight,
                                 floating_point_type new_port_weight, floating_point_type new_ip_weight,
                                 floating_point_type new_sni_weight, floating_point_type new_ua_weight) {
        classifier.recompute_probabilities(new_as_weight, new_domain_weight, new_port_weight, new_ip_weight, new_sni_weight, new_ua_weight);
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

    void process_fp_db_line(std::string &line_str, float fp_proc_threshold, float proc_dst_threshold, bool report_os) {

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

        /*
         * The json object "feature_weights" consists of the feature weights
         * to be used in weighted naive bayes classifier and it is an
         * optional parameter. When feature weights are present, the weights
         * will be read from resource file and the same will be used in
         * the naive bayes classifier.
         *
         * If no weights are present, then default weights will be used.
         * When feature_weights json object is present, it has to contain
         * weights for all expected features. Missing feature weights or
         * unknown feature weights will be considered as error and the
         * fingerprint entry will not be processed.
         */
        naive_bayes::feature_weights weights{naive_bayes::default_feature_weights};
        if (fp.HasMember("feature_weights") && fp["feature_weights"].IsObject()) {
            if (fp["feature_weights"].MemberCount() != naive_bayes::num_features) {
                printf_err(log_err,
                           "Expecting %d feature weights but observed %d\n",
                            naive_bayes::num_features, fp["feature_weights"].MemberCount());
                return;
            }
            for (auto &v : fp["feature_weights"].GetObject()) {
                if (!v.value.IsFloat()) {
                    printf_err(log_err, "Unexpected value for feature weight \"%s\" \n", v.name.GetString());
                    return;
                }
                if (strcmp(v.name.GetString(), "as") == 0) {
                    weights[naive_bayes::features.index("as")] = v.value.GetFloat();
                } else if (strcmp(v.name.GetString(), "domain") == 0) {
                    weights[naive_bayes::features.index("domain")] = v.value.GetFloat();
                } else if (strcmp(v.name.GetString(), "port") == 0) {
                    weights[naive_bayes::features.index("port")] = v.value.GetFloat();
                } else if (strcmp(v.name.GetString(), "ip") == 0) {
                    weights[naive_bayes::features.index("ip")] = v.value.GetFloat();
                } else if (strcmp(v.name.GetString(), "sni") == 0) {
                    weights[naive_bayes::features.index("sni")] = v.value.GetFloat();
                } else if (strcmp(v.name.GetString(), "ua") == 0) {
                    weights[naive_bayes::features.index("ua")] = v.value.GetFloat();
                } else {
                    printf_err(log_err, "Unexpected feature weight \"%s\" \n", v.name.GetString());
                    return;
                }
            }
        }

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
                /* do not load process into memory if prevalence is below threshold */
                if ((process_number > 1) && ((float)count/total_count < fp_proc_threshold) && (malware != true)) {
                    continue;
                }

                process_number++;
                //fprintf(stderr, "%s\n", "process_info");

                attribute_result::bitset attributes;
                std::unordered_map<uint32_t, uint64_t>    ip_as;
                std::unordered_map<std::string, uint64_t> hostname_domains;
                std::unordered_map<uint16_t, uint64_t>    dst_port;
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
                        if (y.value.IsUint64() && ((float)y.value.GetUint64()/count > proc_dst_threshold)) {
                            //fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());

                            // Once data pipeline is updated to normalize the domain names, the following code will be used:
                            // hostname_domains[server_identifier{y.name.GetString()}] = y.value.GetUint64();
                            //
                            // and this code will be removed:
                            std::string normalized = server_identifier{y.name.GetString()}.get_normalized_domain_name(server_identifier::detail::on);
                            if (hostname_domains.find(normalized) != hostname_domains.end()) {
                                // If two different domain names are normalized to the same domain name, then the counts are added.
                                hostname_domains[normalized] += y.value.GetUint64();
                            } else {
                                hostname_domains[normalized] = y.value.GetUint64();
                            }
                        }
                    }
                }
                if (x.HasMember("classes_ip_as") && x["classes_ip_as"].IsObject()) {
                    //fprintf(stderr, "\tclasses_ip_as\n");
                    for (auto &y : x["classes_ip_as"].GetObject()) {
                        if (y.value.IsUint64() && ((float)y.value.GetUint64()/count > proc_dst_threshold)) {
                            //fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());

                            if (strcmp(y.name.GetString(), "unknown") != 0) {

                                errno = 0;
                                unsigned long as_number = strtol(y.name.GetString(), NULL, 10);
                                if (errno) {
                                    as_number = 0; // "unknown"
                                    printf_err(log_warning, "unexpected string \"%s\" in ip_as\n", y.name.GetString());
                                }
                                if (as_number > 0xffffffff) {
                                    throw std::runtime_error("error: as number too high");
                                }
                                ip_as[as_number] = y.value.GetUint64();

                            }
                        }
                    }
                }
                if (x.HasMember("classes_port_port") && x["classes_port_port"].IsObject()) {
                    //fprintf(stderr, "\tclasses_port_port\n");
                    for (auto &y : x["classes_port_port"].GetObject()) {
                        if (y.value.IsUint64() && ((float)y.value.GetUint64()/count > proc_dst_threshold)) {
                            uint64_t tmp_port = 0;
                            try {
                                tmp_port = std::stoul(y.name.GetString());
                            }
                            catch (...) {
                                printf_err(log_warning, "unexpected string \"%s\" in classes_port_port\n", y.name.GetString());
                            }
                            if (tmp_port > std::numeric_limits<uint16_t>::max()) {
                                printf_err(log_warning, "number %" PRIu64 " too high in classes_port_port\n", tmp_port);
                                tmp_port = 0;    // error: port numbers should 16-bit unsigned integers
                            }
                            dst_port[tmp_port] = y.value.GetUint64();
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
                        if (!y.value.IsUint64() && ((float)y.value.GetUint64()/count > proc_dst_threshold)) {
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
                        if (y.value.IsUint64() && ((float)y.value.GetUint64()/count > proc_dst_threshold)) {
                            //fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());

                            // Once data pipeline is updated to normalize the domain names, the following code will be used:
                            // hostname_sni[server_identifier{y.name.GetString()}] = y.value.GetUint64();
                            //
                            // and this code will be removed:
                            std::string normalized = server_identifier{y.name.GetString()}.get_normalized_domain_name(server_identifier::detail::on);
                            if (hostname_sni.find(normalized) != hostname_sni.end()) {
                                // If two different domain names are normalized to the same domain name, then the counts are added.
                                hostname_sni[normalized] += y.value.GetUint64();
                            } else {
                                hostname_sni[normalized] = y.value.GetUint64();
                            }
                        }
                    }
                }
                if (x.HasMember("classes_user_agent") && x["classes_user_agent"].IsObject()) {
                    if (EXTENDED_FP_METADATA == false && process_number > 1) {
                        throw std::runtime_error("error: extended fingerprint metadata expected, but not present");
                    }
                    EXTENDED_FP_METADATA = true;
                    for (auto &y : x["classes_user_agent"].GetObject()) {
                        if (y.value.IsUint64() && ((float)y.value.GetUint64()/count > proc_dst_threshold)) {
                            //fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());
                            user_agent[y.name.GetString()] = y.value.GetUint64();
                        }
                    }
                }
                if (report_os && x.HasMember("os_info") && x["os_info"].IsObject()) {
                    for (auto &y : x["os_info"].GetObject()) {
                        if (std::string(y.name.GetString()) != "") {
                            os_info[y.name.GetString()] = y.value.GetUint64();
                        }
                    }
                }

                class process_info process(name, malware, count, attributes, ip_as, hostname_domains, dst_port,
                                           ip_ip, hostname_sni, user_agent, os_info);
                process_vector.push_back(process);
            }

            //  EXPERIMENT: construct naive_bayes classifier directly from JSON
            //
            naive_bayes naive_bayes_expt(fp["process_info"],
                                         total_count,
                                         report_os,
                                         os_dictionary,
                                         // MALWARE_DB,
                                         EXTENDED_FP_METADATA,
                                         fp_proc_threshold,
                                         proc_dst_threshold
                                         // common
                                         );

            // EXPERIMENT: construct fingerprint_data from JSON
            //
            // fingerprint_data fp_data_expt(fp["process_info"],
            //                               os_dictionary,
            //                               &subnets,
            //                               &common,
            //                               MALWARE_DB,
            //                               total_count,
            //                               report_os,
            //                               EXTENDED_FP_METADATA,
            //                               fp_proc_threshold,
            //                               proc_dst_threshold
            //                               );
            //
            // fingerprint_data  *fp_data = new fingerprint_data(total_count, process_vector,
            //                                                     os_dictionary, &subnets, &common, MALWARE_DB, weights);


            // EXPERIMENTAL: using json-reading constructor
            //
            fingerprint_data *fp_data = new fingerprint_data(fp["process_info"],
                                                             os_dictionary,
                                                             &subnets,
                                                             &common,
                                                             MALWARE_DB,
                                                             total_count,
                                                             report_os,
                                                             EXTENDED_FP_METADATA,
                                                             fp_proc_threshold,
                                                             proc_dst_threshold
                                                             );

            // fprintf(stderr, "classifier equal:          %u\n", fp_data->classifier == naive_bayes_expt);         // TODO: remove
            // fprintf(stderr, "fp_data->classifier equal: %u\n", fp_data->classifier == fp_data_expt.classifier);  // TODO: remove
            // fprintf(stderr, "fp_data == fp_data_expt:   %u\n", *fp_data == fp_data_expt);                        // TODO: remove

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
                            process_fp_db_line(line_str, 0.0, 0.0, report_os);
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
                            process_fp_db_line(line_str, 0.0, 0.0, report_os);
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

    /*
     * This function perform_analysis_with_weights accepts
     * weights of features of weighed naive bayes classifier as input
     * and performs analysis based on the updated weights.
     * This function is mainly required for tuning the weights and is
     * intended to be used during the training phase where the
     * functionality is exposed using cython api and is not
     * intended to be used in packet processing path. 
     */
    struct analysis_result perform_analysis_with_weights(const char *fp_str, const char *server_name, const char *dst_ip,
                                            uint16_t dst_port, const char *user_agent, floating_point_type new_as_weight, floating_point_type new_domain_weight,
                                 floating_point_type new_port_weight, floating_point_type new_ip_weight,
                                 floating_point_type new_sni_weight, floating_point_type new_ua_weight) {

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
                fp_data->recompute_probabilities(new_as_weight, new_domain_weight, new_port_weight, new_ip_weight, new_sni_weight, new_ua_weight);
                return fp_data->perform_analysis(server_name, dst_ip, dst_port, user_agent, fingerprint_status_randomized);
            }
        }
        fingerprint_data *fp_data = fpdb_entry->second;

        fp_data->recompute_probabilities(new_as_weight, new_domain_weight, new_port_weight, new_ip_weight, new_sni_weight, new_ua_weight);
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
