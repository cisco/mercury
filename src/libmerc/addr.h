/*
 * addr.h
 *
 * interface into address processing functions, including longest
 * prefix matching
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef ADDR_H
#define ADDR_H

#include <unordered_map>
#include <unordered_set>
#include <string>
#include <stdexcept>
#include "archive.h"

#include "lctrie/lctrie.h"

// BGP_MAX_ENTRIES is the max number of subnets
//
#define BGP_MAX_ENTRIES  4000000

class subnet_data {

    // the ipv4_subnet_trie and ipv4_subnet_array variables hold the
    // level compressed path trie data and subnet information for IPv4
    // BGP Autonomous System Numbers, respectively.
    //
    lct<ipv4_addr_t> ipv4_subnet_trie;
    lct_subnet_t *ipv4_subnet_array;

    // ip domain tries used for domain-faking detection
    lct<ipv4_addr_t> ipv4_domain_trie;
    lct_subnet_t *ipv4_domain_array;

    // data used during construction
    lct_subnet<ipv4_addr_t> *prefix;
    int num = 0;

    // ip domain mapping arrays used during construction of lctrie for domain-faking detection
    lct_subnet<ipv4_addr_t> *domains_prefix;
    int domains_prefix_num = 0;

    // list of domains, for which domain-faking checking has to be done
    std::unordered_map<std::string, uint32_t> domains_watchlist;

    // stores proxies and sinkhole subnets, to be exempted from domain-faking check
    std::unordered_set<uint32_t> domain_faking_exceptions;

public:

    subnet_data() {
        ipv4_subnet_trie.root = nullptr;
        ipv4_subnet_trie.bases = nullptr;
        ipv4_subnet_trie.ncount = 0;
        ipv4_subnet_trie.bcount = 0;
        ipv4_subnet_trie.shortest = 0;
        ipv4_subnet_trie.nets = 0;
        ipv4_subnet_array = nullptr;
        prefix = (lct_subnet_t *)calloc(sizeof(lct_subnet_t), BGP_MAX_ENTRIES);
        if (prefix == nullptr) {
            throw std::runtime_error("error: could not initialize subnet_data");
        }
        // start with the RFC 1918 and 3927 private and link local
        // subnets as a basis for any table set
        num += init_private_subnets(&prefix[num], BGP_MAX_ENTRIES);

        // fill up the rest of the array with reserved IP subnets
        num += init_special_subnets(&prefix[num], BGP_MAX_ENTRIES);

        // initialize ip domain trie
        ipv4_domain_trie.root = nullptr;
        ipv4_domain_trie.bases = nullptr;
        ipv4_domain_trie.ncount = 0;
        ipv4_domain_trie.bcount = 0;
        ipv4_domain_trie.shortest = 0;
        ipv4_domain_trie.nets = 0;
        ipv4_domain_array = nullptr;

        domains_prefix = (lct_subnet_t *)calloc(sizeof(lct_subnet_t), BGP_MAX_ENTRIES);
        if (domains_prefix == nullptr) {
            throw std::runtime_error("error: could not initialize domains_prefix");
        }

    }

    void process_final();
    void process_domain_mappings_final();

    subnet_data(encrypted_compressed_archive &archive);

    ~subnet_data();

    uint32_t get_asn_info(const char* dst_ip) const;

    int process_line(std::string &line);

    int process_domain_mappings_line(std::string &line, std::unordered_map<uint32_t, ssize_t> &subnet_map);
    int lct_add_domain_mapping(uint32_t &addr, uint8_t &mask_length, std::string &domain, std::unordered_map<uint32_t, ssize_t> &subnet_map);

    bool is_domain_faking(const char *server_name, const char *dst_ip) const;
};

#endif // ADDR_H
