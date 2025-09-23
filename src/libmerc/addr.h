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

struct Ipv6AddrHash {
    std::size_t operator()(const ipv6_addr_lct& addr) const {
        std::size_t hash1 = std::hash<uint64_t>()(addr.a[0]);
        std::size_t hash2 = std::hash<uint64_t>()(addr.a[1]);
        return hash1 ^ (hash2 << 1);
    }
};

class subnet_data {

    // the ipv4_subnet_trie and ipv4_subnet_array variables hold the
    // level compressed path trie data and subnet information for IPv4
    // BGP Autonomous System Numbers, respectively.
    //
    lct<ipv4_addr_t> ipv4_subnet_trie;
    lct_subnet_t *ipv4_subnet_array;

    lct<ipv6_addr_lct> ipv6_subnet_trie;
    lct_subnet_v6_t *ipv6_subnet_array;

    // ipv4 domain tries used for domain-faking detection
    lct<ipv4_addr_t> ipv4_domain_trie;
    lct_subnet_t *ipv4_domain_array;

    // ipv6 domain tries used for domain-faking detection
    lct<ipv6_addr_lct> ipv6_domain_trie;
    lct_subnet_v6_t *ipv6_domain_array;

    // data used during construction
    lct_subnet<ipv4_addr_t> *prefix = nullptr;
    int num = 0;

    lct_subnet<ipv6_addr_lct> *prefix_v6 = nullptr;
    int num_v6 = 0;

    // ip domain mapping arrays used during construction of lctrie for domain-faking detection
    lct_subnet<ipv4_addr_t> *domains_prefix = nullptr;
    int domains_prefix_num = 0;

    lct_subnet<ipv6_addr_lct> *domains_prefix_v6 = nullptr;
    int domains_prefix_v6_num = 0;

    // list of domains, for which domain-faking checking has to be done
    std::unordered_map<std::string, uint32_t> domains_watchlist;

public:

    subnet_data() {

        // initialize ipv4 asn subnet trie
        ipv4_subnet_trie.root = nullptr;
        ipv4_subnet_trie.bases = nullptr;
        ipv4_subnet_trie.ncount = 0;
        ipv4_subnet_trie.bcount = 0;
        ipv4_subnet_trie.shortest = 0;
        ipv4_subnet_trie.nets = 0;
        ipv4_subnet_array = nullptr;

        // initialize ipv6 asn subnet trie
        ipv6_subnet_trie.root = nullptr;
        ipv6_subnet_trie.bases = nullptr;
        ipv6_subnet_trie.ncount = 0;
        ipv6_subnet_trie.bcount = 0;
        ipv6_subnet_trie.shortest = 0;
        ipv6_subnet_trie.nets = 0;
        ipv6_subnet_array = nullptr;

        // initialize ip domain trie
        ipv4_domain_trie.root = nullptr;
        ipv4_domain_trie.bases = nullptr;
        ipv4_domain_trie.ncount = 0;
        ipv4_domain_trie.bcount = 0;
        ipv4_domain_trie.shortest = 0;
        ipv4_domain_trie.nets = 0;
        ipv4_domain_array = nullptr;

        // initialize ipv6 domain trie
        ipv6_domain_trie.root = nullptr;
        ipv6_domain_trie.bases = nullptr;
        ipv6_domain_trie.ncount = 0;
        ipv6_domain_trie.bcount = 0;
        ipv6_domain_trie.shortest = 0;
        ipv6_domain_trie.nets = 0;
        ipv6_domain_array = nullptr;
    }

    void process_final();
    void process_final_v6();
    void process_domain_mappings_final();
    void process_domain_mappings_final_v6();

    subnet_data(encrypted_compressed_archive &archive);

    ~subnet_data();

    uint32_t get_asn_info(const char* dst_ip) const;

    int process_asn_subnets(const std::vector<std::string> &subnets);
    int process_asn_subnets_v6(const std::vector<std::string> &subnets);

    int process_domain_mapping_line(std::string &line_str, std::vector<std::pair<std::string, std::string>> &subnets,
        std::vector<std::pair<std::string, std::string>> &subnets_v6, bool &minimize_ram);
    int process_domain_mapping_subnets(const std::vector<std::pair<std::string, std::string>> &subnets);
    int process_domain_mapping_subnets_v6(const std::vector<std::pair<std::string, std::string>> &subnets);
    int lct_add_domain_mapping(uint32_t &addr, uint8_t &mask_length, std::string &domain,
        std::unordered_map<uint32_t, ssize_t> &subnet_map);
    int lct_add_domain_exception(uint32_t &addr, uint8_t &mask_length);
    int lct_add_domain_mapping_v6(ipv6_addr_lct &addr, uint8_t &mask_length, std::string &domain_name, std::unordered_map<ipv6_addr_lct, ssize_t, Ipv6AddrHash> &subnet_map);
    int lct_add_domain_exception_v6(ipv6_addr_lct &addr, uint8_t &mask_length);

    bool is_domain_faking(const char *server_name, const char *dst_ip) const;
};

#endif // ADDR_H
