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

#include <string>
#include "archive.h"

#include "lctrie/lctrie.h"
#include "lctrie/lctrie_bgp.h"

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

    // data used during construction
    lct_subnet<ipv4_addr_t> *prefix;
    int num = 0;

public:

    subnet_data() {
        ipv4_subnet_trie.root = nullptr;
        ipv4_subnet_trie.bases = nullptr;
        ipv4_subnet_array = nullptr;
        prefix = (lct_subnet_t *)calloc(sizeof(lct_subnet_t), BGP_MAX_ENTRIES);
        if (prefix == nullptr) {
            throw "error: could not initialize subnet_data";
        }
        // start with the RFC 1918 and 3927 private and link local
        // subnets as a basis for any table set
        num += init_private_subnets(&prefix[num], BGP_MAX_ENTRIES);

        // fill up the rest of the array with reserved IP subnets
        num += init_special_subnets(&prefix[num], BGP_MAX_ENTRIES);

    }

    void process_final();

    subnet_data(encrypted_compressed_archive &archive);

    ~subnet_data();

    uint32_t get_asn_info(const char* dst_ip) const;

    int process_line(std::string &line);
};

#endif // ADDR_H
