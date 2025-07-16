/*
 * addr.cc
 *
 * address processing functions, including longest prefix match
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <string.h>
#include <locale.h>
#include <string>
#include <unordered_map>
#include "addr.h"
#include "archive.h"
#include "datum.h"  // for ntoh()
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "ip_address.hpp"

#include "lctrie/lctrie.h"
#include "lctrie/lctrie_bgp.h"


// apply netmasks to IPv6 entries, should be done prior to sorting the subnet array
//
void subnet_mask_v6(lct_subnet<ipv6_addr_t> *subnets, size_t size) {
    char pstr[LCTRIE_INET6_ADDRSTRLEN], pstr2[LCTRIE_INET6_ADDRSTRLEN];
    ipv6_addr_t prefix, prefix2;

    constexpr unsigned int bits_in_T = sizeof(ipv6_addr_t) * 8;
    for (size_t i = 0; i < size; ++i) {
        lct_subnet<ipv6_addr_t> *p = &subnets[i];

        ipv6_addr_t netmask;
        netmask.a[0] = netmask.a[1] = -1;
        
        if (p->len < bits_in_T) {
            for (unsigned int j = 0; j < p->len; ++j) {
                ipv6_addr_t shift;
                shift.a[0] = 0;
                shift.a[1] = 1;
                shift = shift << j;
                shift = ~shift;
                netmask = netmask & shift;
            }
        }

      ipv6_addr_t newaddr;
      newaddr = p->addr & netmask;

      if (newaddr != p->addr) {
          fprint_addr(stderr, "address", &p->addr);
          fprint_addr(stderr, "netmask", &netmask);
          fprint_addr(stderr, "newaddr", &newaddr);

          prefix = p->addr;
          prefix2 = newaddr;
          if (!inet_ntop(address_family<ipv6_addr_t>::typecode, &(prefix.a), pstr, sizeof(pstr))) {
              fprintf(stderr, "ERROR: %s\n", strerror(errno));
          }
          if (!inet_ntop(address_family<ipv6_addr_t>::typecode, &(prefix2.a), pstr2, sizeof(pstr2))) {
              fprintf(stderr, "ERROR: %s\n", strerror(errno));
          }

          fprintf(stderr, "Subnet %s/%d has not been properly masked, should be %s/%d\n",
                  pstr, p->len, pstr2, p->len);

          p->addr = newaddr;
    }
  }
}


// apply netmasks to IPv4 entries, should be done prior to sorting the subnet array
//
void subnet_mask_v4(lct_subnet<ipv4_addr_t> *subnets, size_t size) {
    char pstr[LCTRIE_INET6_ADDRSTRLEN], pstr2[LCTRIE_INET6_ADDRSTRLEN];
    ipv4_addr_t prefix, prefix2;

    constexpr unsigned int bits_in_T = sizeof(ipv4_addr_t) * 8;
    for (size_t i = 0; i < size; ++i) {
        lct_subnet<ipv4_addr_t> *p = &subnets[i];

        uint32_t netmask = -1;
        if (p->len < bits_in_T) {
            for (unsigned int j = 0; j < (bits_in_T - p->len); ++j) {
                netmask &= ~((ipv4_addr_t)1 << j);
            }
        }

      ipv4_addr_t newaddr = p->addr & netmask;

      if (newaddr != p->addr) {
          fprint_addr(stderr, "address", &p->addr);
          fprint_addr(stderr, "netmask", &netmask);
          fprint_addr(stderr, "newaddr", &newaddr);

          prefix = hton(p->addr);
          prefix2 = hton(newaddr);
          if (!ntop(address_family<ipv4_addr_t>::typecode, &(prefix), pstr, sizeof(pstr))) {
              fprintf(stderr, "ERROR: %s\n", strerror(errno));
          }
          if (!ntop(address_family<ipv4_addr_t>::typecode, &(prefix2), pstr2, sizeof(pstr2))) {
              fprintf(stderr, "ERROR: %s\n", strerror(errno));
          }

          fprintf(stderr, "Subnet %s/%d has not been properly masked, should be %s/%d\n",
                  pstr, p->len, pstr2, p->len);

          p->addr = newaddr;
    }
  }
}

// char_string_to_ipv4_addr(s, addr) parses a dotted quad IPv4 address
// out of the null-terminated character string s, sets addr to the
// host-byte-order representation of that address, and returns true on
// success.  If s does not contain a dotted quad, then the function
// returns false and addr should be ignored.
//
bool char_string_to_ipv4_addr(const char *s, uint32_t &addr) {
    uint8_t d[4];
    int num_items_parsed = sscanf(s,
                                  "%hhu.%hhu.%hhu.%hhu",
                                  d, d+1, d+2, d+3);
    if (num_items_parsed == 4) {
        addr = (uint32_t)d[3] | (uint32_t)d[2] << 8 | (uint32_t)d[1] << 16 | (uint32_t)d[0] << 24;
        addr = ntoh(addr);
        return true;
    }
    return false;
}

subnet_data::~subnet_data() {

    if (ipv6_subnet_trie.root) {
        free(ipv6_subnet_trie.root);
    }
    lct_free(&ipv6_subnet_trie);
    if (ipv6_subnet_array) {
        free(ipv6_subnet_array);
    }
    if (prefix_v6) {
        free(prefix_v6);
    }
    if (ipv4_subnet_trie.root) {
        //
        // TBD: this free ought to be in lct_tree()
        //
        free(ipv4_subnet_trie.root);
    }
    lct_free(&ipv4_subnet_trie);
    if (ipv4_subnet_array) {
        free(ipv4_subnet_array);
    }
    if (prefix) {
        free(prefix);
    }

    if (ipv4_domain_trie.root) {
        free(ipv4_domain_trie.root);
    }
    lct_free(&ipv4_domain_trie);
    // free all the memory allocations in ipv4_domain_array
    //
    if (ipv4_domain_array) {
        lct_subnet_t* subnet_itr = ipv4_domain_array;
        for (int i = 0; i < domains_prefix_num; i++) {
            free(subnet_itr->info.domain.domain_idx_arr);
            subnet_itr->info.domain.domain_idx_arr = nullptr;
            subnet_itr->info.domain.domain_idx_arr_len = 0;
            ++subnet_itr;
        }
        free(ipv4_domain_array);
    }
    if (domains_prefix) {
        free(domains_prefix);
    }

    if (ipv6_domain_trie.root) {
        free(ipv6_domain_trie.root);
    }
    lct_free(&ipv6_domain_trie);
    // free all the memory allocations in ipv6_domain_array
    if (ipv6_domain_array) {
        lct_subnet_v6_t* subnet_itr = ipv6_domain_array;
        for (int i = 0; i < domains_prefix_v6_num; i++) {
            free(subnet_itr->info.domain.domain_idx_arr);
            subnet_itr->info.domain.domain_idx_arr = nullptr;
            subnet_itr->info.domain.domain_idx_arr_len = 0;
            ++subnet_itr;
        }
        free(ipv6_domain_array);
    }
    if (domains_prefix_v6) {
        free(domains_prefix_v6);
    }
}

uint32_t subnet_data::get_asn_info(const char* dst_ip) const {

    uint32_t ipv4_addr;
    if (char_string_to_ipv4_addr(dst_ip, ipv4_addr)) {
        lct_subnet_t *subnet = lct_find(&ipv4_subnet_trie, ntoh(ipv4_addr));
        if (subnet == NULL) {
            return 0;
        }
        if (subnet->info.type == IP_SUBNET_BGP) {
            return subnet->info.bgp.asn;
        }
    }

    ipv6_addr_t ipv6_addr;
    if (ipv6_subnet_array&& inet_pton(AF_INET6, dst_ip, &ipv6_addr.a)) {
        lct_subnet_v6_t *subnet = lct_find(&ipv6_subnet_trie, ipv6_addr);
        if (subnet == NULL) {
            return 0;
        }
        if (subnet->info.type == IP_SUBNET_BGP) {
            return subnet->info.bgp.asn;
        }
    }

    return 0;
}

int subnet_data::process_asn_subnets(const std::vector<std::string> &subnets) {

    prefix = (lct_subnet_t *)calloc(sizeof(lct_subnet_t), subnets.size());
    if (prefix == nullptr) {
        throw std::runtime_error("error: could not initialize subnet_data");
    }

    // Add Special and Private subnets to ASN subnets
    //
    // parse the subnets and ASN strings    // start with the RFC 1918 and 3927 private and link local
    // subnets as a basis for any table set
    //
    // num += init_private_subnets(&prefix[num], BGP_MAX_ENTRIES);
    //
    // fill up the rest of the array with reserved IP subnets
    //
    // num += init_special_subnets(&prefix[num], BGP_MAX_ENTRIES);

    for (const std::string &line_str : subnets) {
        // set the prefix[num] to the subnet and ASN found in line
        if (lct_subnet_set_from_string(&prefix[num], line_str.c_str()) != 0) {
            printf_err(log_err, "could not parse subnet string '%s'\n", line_str.c_str());
            continue;  // failure
        }
        num++;
    }
    return 0;       // success
}

int subnet_data::process_asn_subnets_v6(const std::vector<std::string> &subnets) {

    prefix_v6 = (lct_subnet_v6_t *)calloc(sizeof(lct_subnet_v6_t), subnets.size());
    if (prefix_v6 == nullptr) {
        throw std::runtime_error("error: could not initialize v6 subnet_data");
    }

    for (const std::string &line_str : subnets) {
        if (lct_subnet_set_from_string(&prefix_v6[num_v6], line_str.c_str()) != 0) {
            printf_err(log_err, "could not parse v6 subnet string '%s'\n", line_str.c_str());
            continue;   // failure
        }
        num_v6++;
    }
    return 0;       // success
}

int subnet_data::lct_add_domain_mapping(uint32_t &addr, uint8_t &mask_length, std::string &domain_name, std::unordered_map<uint32_t, ssize_t> &subnet_map) {
    uint32_t domain_idx;
    if (domains_watchlist.find(domain_name) == domains_watchlist.end()) {    // new domain; assign a domain id and save in the domain watchlist
        domain_idx = domains_watchlist.size();
        domains_watchlist[domain_name] = domain_idx;
    } else {
        domain_idx = domains_watchlist[domain_name];    // domain already seen; retrieve domain id
    }

    lct_subnet<uint32_t> *subnet_itr;
    if (subnet_map.find(addr) != subnet_map.end()) {    // subnet present in map, domain_idx needs to be appended
        subnet_itr = &domains_prefix[subnet_map[addr]];
        if (subnet_itr->info.type == IP_SUBNET_DOMAIN && subnet_itr->addr == addr && subnet_itr->len == mask_length) {
            uint8_t *old_arr = subnet_itr->info.domain.domain_idx_arr;

            ++subnet_itr->info.domain.domain_idx_arr_len;
            uint8_t *new_domain_idx_arr = (uint8_t *)realloc(subnet_itr->info.domain.domain_idx_arr, subnet_itr->info.domain.domain_idx_arr_len * sizeof(uint8_t));

            if (new_domain_idx_arr == NULL) {
                free(old_arr);
                old_arr = nullptr;
                return -1;    // failed to add this entry because of realloc failure
            }
            else {
                subnet_itr->info.domain.domain_idx_arr = new_domain_idx_arr;
                subnet_itr->info.domain.domain_idx_arr[subnet_itr->info.domain.domain_idx_arr_len-1] = domain_idx;
            }
        }
    }
    else {    // create a new entry in the map
        subnet_itr = &domains_prefix[domains_prefix_num];

        subnet_itr->addr = addr;
        subnet_itr->len = mask_length;
        subnet_itr->info.type = IP_SUBNET_DOMAIN;
        subnet_itr->info.domain.domain_idx_arr_len = 1;
        subnet_itr->info.domain.domain_idx_arr = (uint8_t *)malloc(sizeof(uint8_t));
        subnet_itr->info.domain.domain_idx_arr[0] = domain_idx;

        subnet_map[addr] = domains_prefix_num;
        domains_prefix_num++;
    }

    return 0;       // success
}

int subnet_data::lct_add_domain_exception(uint32_t &addr, uint8_t &mask_length) {

    lct_subnet_t *subnet_itr;
    subnet_itr = &domains_prefix[domains_prefix_num];
    subnet_itr->addr = addr;
    subnet_itr->len = mask_length;
    subnet_itr->info.type = IP_SUBNET_DOMAIN_EXCEPTION;
    domains_prefix_num++;

    return 0;       // success
}

int subnet_data::process_domain_mapping_subnets(const std::vector<std::pair<std::string, std::string>> &subnets) {

    std::unordered_map<uint32_t, ssize_t> subnet_map;
    domains_prefix = (lct_subnet_t *)calloc(sizeof(lct_subnet_t), subnets.size());
    if (domains_prefix == nullptr) {
        throw std::runtime_error("error: could not initialize domains_prefix");
    }

    for (const std::pair<std::string, std::string> &subnet_entry : subnets) {
        std::string subnet_str = subnet_entry.first;
        std::string subnet_tag = subnet_entry.second;

        uint32_t addr;
        unsigned char *dq = (unsigned char *)&addr;
        uint8_t mask_length;
        constexpr unsigned int bits_in_T = sizeof(uint32_t) * 8;

        int num_items_parsed = sscanf(subnet_str.c_str(),"%hhu.%hhu.%hhu.%hhu/%hhu",
                dq + 3, dq + 2, dq + 1, dq, &mask_length);
        if (num_items_parsed == 5) {
            if ((mask_length == 0) || (mask_length > bits_in_T)) {
                    fprintf(stderr, "ERROR: %u is not a valid prefix length\n", mask_length);
                    continue;      // failure
                }

            if (subnet_tag == "proxy" || subnet_tag == "sinkhole") {
                if (lct_add_domain_exception(addr, mask_length) != 0) {
                    continue;      // failure
                }
            }
            else if(lct_add_domain_mapping(addr, mask_length, subnet_tag, subnet_map) != 0) {
                    continue;      // failure
            }
        }
    }

    return 0;
}

int subnet_data::lct_add_domain_mapping_v6(ipv6_addr_t &addr, uint8_t &mask_length, std::string &domain_name, std::unordered_map<ipv6_addr_t, ssize_t, Ipv6AddrHash> &subnet_map) {

    uint32_t domain_idx;
    if (domains_watchlist.find(domain_name) == domains_watchlist.end()) {    // new domain; assign a domain id and save in the domain watchlist
        domain_idx = domains_watchlist.size();
        domains_watchlist[domain_name] = domain_idx;
    } else {
        domain_idx = domains_watchlist[domain_name];    // domain already seen; retrieve domain id
    }

    lct_subnet<ipv6_addr_t> *subnet_itr;
    if (subnet_map.find(addr) != subnet_map.end()) {    // subnet present in map, domain_idx needs to be appended
        subnet_itr = &domains_prefix_v6[subnet_map[addr]];
        if (subnet_itr->info.type == IP_SUBNET_DOMAIN && subnet_itr->addr == addr && subnet_itr->len == mask_length) {
            uint8_t *old_arr = subnet_itr->info.domain.domain_idx_arr;

            ++subnet_itr->info.domain.domain_idx_arr_len;
            uint8_t *new_domain_idx_arr = (uint8_t *)realloc(subnet_itr->info.domain.domain_idx_arr, subnet_itr->info.domain.domain_idx_arr_len * sizeof(uint8_t));

            if (new_domain_idx_arr == NULL) {
                free(old_arr);
                old_arr = nullptr;
                return -1;    // failed to add this entry because of realloc failure
            }
            else {
                subnet_itr->info.domain.domain_idx_arr = new_domain_idx_arr;
                subnet_itr->info.domain.domain_idx_arr[subnet_itr->info.domain.domain_idx_arr_len-1] = domain_idx;
            }
        }
    }
    else {
        subnet_itr = &domains_prefix_v6[domains_prefix_v6_num];
        subnet_itr->addr = addr;
        subnet_itr->len = mask_length;
        subnet_itr->info.type = IP_SUBNET_DOMAIN;
        subnet_itr->info.domain.domain_idx_arr_len = 1;
        subnet_itr->info.domain.domain_idx_arr = (uint8_t *)malloc(sizeof(uint8_t));
        subnet_itr->info.domain.domain_idx_arr[0] = domain_idx;

        subnet_map[addr] = domains_prefix_v6_num;
        domains_prefix_v6_num++;
    }

    return 0;
}

int subnet_data::lct_add_domain_exception_v6(ipv6_addr_t &addr, uint8_t &mask_length) {

    lct_subnet_v6_t *subnet_itr;
    subnet_itr = &domains_prefix_v6[domains_prefix_v6_num];
    subnet_itr->addr = addr;
    subnet_itr->len = mask_length;
    subnet_itr->info.type = IP_SUBNET_DOMAIN_EXCEPTION;
    domains_prefix_v6_num++;

    return 0;       // success
}

int subnet_data::process_domain_mapping_subnets_v6(const std::vector<std::pair<std::string, std::string>> &subnets) {

    std::unordered_map<ipv6_addr_t, ssize_t, Ipv6AddrHash> subnet_map;
    domains_prefix_v6 = (lct_subnet_v6_t *)calloc(sizeof(lct_subnet_v6_t), subnets.size());
    if (domains_prefix_v6 == nullptr) {
        throw std::runtime_error("error: could not initialize domains_prefix");
    }

    for (size_t i = 0; i < subnets.size(); ++i) {
        const std::pair<std::string, std::string> &subnet_entry = subnets[i];
        std::string subnet_str = subnet_entry.first;
        std::string subnet_tag = subnet_entry.second;

        ipv6_addr_t addr;
        uint8_t mask_length;
        char addr_str[LCTRIE_INET6_ADDRSTRLEN];
        constexpr unsigned int bits_in_T = sizeof(ipv6_addr_t) * 8;

        int num_items_parsed = sscanf(subnet_str.c_str(),"%45[^/]/%hhu", addr_str, &mask_length);

        if (num_items_parsed == 2) {
            if ((mask_length == 0) || (mask_length > bits_in_T)) {
                fprintf(stderr, "ERROR: %u is not a valid prefix length\n", mask_length);
                return -1;
            }

            char parsed_subnet_string[LCTRIE_INET6_ADDRSTRLEN];
            strncpy(parsed_subnet_string, addr_str, LCTRIE_INET6_ADDRSTRLEN);
            inet_pton(AF_INET6, parsed_subnet_string, &addr.a);

            if (subnet_tag == "proxy_v6" || subnet_tag == "sinkhole_v6") {
                if (lct_add_domain_exception_v6(addr, mask_length) != 0) {
                    continue;  // failure
                }
            }
            else if(lct_add_domain_mapping_v6(addr, mask_length, subnet_tag, subnet_map) != 0) {
                continue;  // failure
            }
        }
    }

    return 0;
}


int subnet_data::process_domain_mapping_line(std::string &line_str, std::vector<std::pair<std::string, std::string>> &subnets,
    std::vector<std::pair<std::string, std::string>> &subnets_v6) {

    rapidjson::Document domain_obj;
    domain_obj.Parse(line_str.c_str());
    if(!domain_obj.IsObject()) {
        printf_err(log_warning, "invalid JSON line in resource file\n");
        return -1;  // failure
    }

    std::string subnet_type;
    std::string subnet_str;
    std::string subnet_tag;

    if (domain_obj.HasMember("subnet") && domain_obj["subnet"].IsString()) {
        subnet_str = domain_obj["subnet"].GetString();
    }
    else {
        return -1;  // failure
    }
    if (domain_obj.HasMember("type") && domain_obj["type"].IsString()) {
        subnet_type = domain_obj["type"].GetString();
    }
    else {
        return -1;  // failure
    }
    if (domain_obj.HasMember("tag") && domain_obj["tag"].IsString()) {
        subnet_tag = domain_obj["tag"].GetString();
    }
    else {
        return -1;  // failure
    }

    if (subnet_type == "domain_mapping") {
        subnets.push_back(std::make_pair(subnet_str, subnet_tag));
    }
    else if (subnet_type == "proxy" || subnet_type == "sinkhole") {
        subnets.push_back(std::make_pair(subnet_str, subnet_type));
    }
    else if (subnet_type == "domain_mapping_v6") {
        subnets_v6.push_back(std::make_pair(subnet_str, subnet_tag));
    }
    else if (subnet_type == "proxy_v6" || subnet_type == "sinkhole_v6") {
        subnets_v6.push_back(std::make_pair(subnet_str, subnet_type));
    }
    else {
        printf_err(log_warning, "unknown subnet type '%s' in resource archive\n", subnet_type.c_str());
        return -1;  // failure
    }

    return 0;   // success
}

void subnet_data::process_final() {

    // free the memory reserved for asn subnet prefixes, if pyasn.db not processed
    //
    if (num == 0) {
        if (prefix) {
            free(prefix);
            prefix = nullptr;
        }
        return;
    }

    // validate subnet prefixes against their netmasks
    // and sort the resulting array
    subnet_mask_v4(prefix, num);
    qsort(prefix, num, sizeof(lct_subnet<ipv4_addr_t>), subnet_cmp<ipv4_addr_t>);

    // de-duplicate subnets and shrink the buffer down to its
    // actual size and split into prefixes and bases
    num -= subnet_dedup(prefix, num);
    lct_subnet_t *tmp = (lct_subnet_t *)realloc(prefix, num * sizeof(lct_subnet_t));
    if (tmp != NULL) {
        prefix = tmp;
    } else {
        return;  // TODO: leak check
    }

    // allocate a buffer for the IP stats
    lct_ip_stats_t *stats = (lct_ip_stats_t *) calloc(num, sizeof(lct_ip_stats_t));
    if (!stats) {
        return;  // TODO: leak check
    }

    // count which subnets are prefixes of other subnets
    subnet_prefix(prefix, stats, num);
    free(stats);

    // we're storing twice as many subnets as necessary for easy
    // iteration over the entire sorted subnet list.
    for (int i = 0; i < num; i++) {
        // quick error check on the optimized prefix indexes
        uint32_t prfx;
        prfx = prefix[i].prefix;
        if (prfx != IP_PREFIX_NIL && prefix[prfx].type == IP_PREFIX_FULL) {
            /* error: optimized subnet index points to a full prefix */
            return;  // TODO: leak check
        }
    }

    // actually build the trie and get the trie node count for statistics printing
    memset(&ipv4_subnet_trie, 0, sizeof(lct<ipv4_addr_t>));
    lct_build(&ipv4_subnet_trie, prefix, num);

    // set subnet array to actual value; after this, the subnet_data
    // object is ready for use
    //
    ipv4_subnet_array = prefix;
    prefix = nullptr;           // to avoid free(prefix)
}

void subnet_data::process_final_v6() {

    // free the memory reserved for asn subnet prefixes, if pyasn.db not processed
    //
    if (num_v6 == 0) {
        if (prefix_v6) {
            free(prefix_v6);
            prefix_v6 = nullptr;
        }
        return;
    }

    // validate subnet prefixes against their netmasks
    // and sort the resulting array
    subnet_mask_v6(prefix_v6, num_v6);
    qsort(prefix_v6, num_v6, sizeof(lct_subnet<ipv6_addr_t>), subnet_cmp<ipv6_addr_t>);

    // de-duplicate subnets and shrink the buffer down to its
    // actual size and split into prefixes and bases
    num_v6 -= subnet_dedup(prefix_v6, num_v6);
    lct_subnet_v6_t *tmp = (lct_subnet_v6_t *)realloc(prefix_v6, num_v6 * sizeof(lct_subnet_v6_t));
    if (tmp != NULL) {
        prefix_v6 = tmp;
    } else {
        return;
    }

    // allocate a buffer for the IP stats
    lct_ip_stats_t *stats = (lct_ip_stats_t *) calloc(num_v6, sizeof(lct_ip_stats_t));
    if (!stats) {
        return;  // TODO: leak check
    }

    // count which subnets are prefixes of other subnets
    subnet_prefix(prefix_v6, stats, num_v6);
    free(stats);

    // we're storing twice as many subnets as necessary for easy
    // iteration over the entire sorted subnet list.
    for (int i = 0; i < num_v6; i++) {
        // quick error check on the optimized prefix indexes
        uint32_t prfx;
        prfx = prefix_v6[i].prefix;
        if (prfx != IP_PREFIX_NIL && prefix_v6[prfx].type == IP_PREFIX_FULL) {
            /* error: optimized subnet index points to a full prefix */
            return;  // TODO: leak check
        }
    }

    // actually build the trie and get the trie node count for statistics printing
    memset(&ipv6_subnet_trie, 0, sizeof(lct<ipv6_addr_t>));
    lct_build(&ipv6_subnet_trie, prefix_v6, num_v6);

    // set subnet array to actual value; after this, the subnet_data
    // object is ready for use
    //
    ipv6_subnet_array = prefix_v6;
    prefix_v6 = nullptr;           // to avoid free(prefix)
}

void subnet_data::process_domain_mappings_final() {

    // free the memory reserved for domain mapping prefixes, if domain-mappings.db not processed
    //
    if (domains_prefix_num == 0) {
        if (domains_prefix) {
            free(domains_prefix);
            domains_prefix = nullptr;
        }
        return;
    }

    // validate subnet prefixes against their netmasks
    // and sort the resulting array
    subnet_mask_v4(domains_prefix, domains_prefix_num);
    qsort(domains_prefix, domains_prefix_num, sizeof(lct_subnet<ipv4_addr_t>), subnet_cmp<ipv4_addr_t>);

    // de-duplicate subnets and shrink the buffer down to its
    // actual size and split into prefixes and bases
    domains_prefix_num -= subnet_dedup(domains_prefix, domains_prefix_num);
    lct_subnet_t *tmp = (lct_subnet_t *)realloc(domains_prefix, domains_prefix_num * sizeof(lct_subnet_t));
    if (tmp != NULL) {
        domains_prefix = tmp;
    } else {
        return;  // TODO: leak check
    }

    // allocate a buffer for the IP stats
    lct_ip_stats_t *stats = (lct_ip_stats_t *) calloc(domains_prefix_num, sizeof(lct_ip_stats_t));
    if (!stats) {
        return;  // TODO: leak check
    }

    // count which subnets are prefixes of other subnets
    subnet_prefix(domains_prefix, stats, domains_prefix_num);
    free(stats);

    // we're storing twice as many subnets as necessary for easy
    // iteration over the entire sorted subnet list.
    for (int i = 0; i < domains_prefix_num; i++) {
        // quick error check on the optimized prefix indexes
        uint32_t prfx;
        prfx = domains_prefix[i].prefix;
        if (prfx != IP_PREFIX_NIL && domains_prefix[prfx].type == IP_PREFIX_FULL) {
            /* error: optimized subnet index points to a full prefix */
            return;  // TODO: leak check
        }
    }

    // actually build the trie and get the trie node count for statistics printing
    memset(&ipv4_domain_trie, 0, sizeof(lct<ipv4_addr_t>));
    lct_build(&ipv4_domain_trie, domains_prefix, domains_prefix_num);

    // set subnet array to actual value; after this, the subnet_data
    // object is ready for use
    //
    ipv4_domain_array = domains_prefix;
    domains_prefix = nullptr;   //  to avoid free(prefix)
}

void subnet_data::process_domain_mappings_final_v6() {
    // free the memory reserved for asn subnet prefixes, if domain_mappings.db not processed
    //
    if (domains_prefix_v6_num == 0) {
        if (domains_prefix_v6) {
            free(domains_prefix_v6);
            domains_prefix_v6 = nullptr;
        }
        return;
    }

    // validate subnet prefixes against their netmasks
    // and sort the resulting array
    subnet_mask_v6(domains_prefix_v6, domains_prefix_v6_num);
    qsort(domains_prefix_v6, domains_prefix_v6_num, sizeof(lct_subnet<ipv6_addr_t>), subnet_cmp<ipv6_addr_t>);

    // de-duplicate subnets and shrink the buffer down to its
    // actual size and split into prefixes and bases
    domains_prefix_v6_num -= subnet_dedup(domains_prefix_v6, domains_prefix_v6_num);
    lct_subnet_v6_t *tmp = (lct_subnet_v6_t *)realloc(domains_prefix_v6, domains_prefix_v6_num * sizeof(lct_subnet_v6_t));
    if (tmp != NULL) {
        domains_prefix_v6 = tmp;
    } else {
        return;
    }

    // allocate a buffer for the IP stats
    lct_ip_stats_t *stats = (lct_ip_stats_t *) calloc(domains_prefix_v6_num, sizeof(lct_ip_stats_t));
    if (!stats) {
        return;  // TODO: leak check
    }

    // count which subnets are prefixes of other subnets
    subnet_prefix(domains_prefix_v6, stats, domains_prefix_v6_num);
    free(stats);

    // we're storing twice as many subnets as necessary for easy
    // iteration over the entire sorted subnet list.
    for (int i = 0; i < domains_prefix_v6_num; i++) {
        // quick error check on the optimized prefix indexes
        uint32_t prfx;
        prfx = domains_prefix_v6[i].prefix;
        if (prfx != IP_PREFIX_NIL && domains_prefix_v6[prfx].type == IP_PREFIX_FULL) {
            /* error: optimized subnet index points to a full prefix */
            return;  // TODO: leak check
        }
    }

    // actually build the trie and get the trie node count for statistics printing
    memset(&ipv6_domain_trie, 0, sizeof(lct<ipv6_addr_t>));
    lct_build(&ipv6_domain_trie, domains_prefix_v6, domains_prefix_v6_num);

    // set subnet array to actual value; after this, the subnet_data
    // object is ready for use
    //
    ipv6_domain_array = domains_prefix_v6;
    domains_prefix_v6 = nullptr;           // to avoid free(prefix)
}

bool subnet_data::is_domain_faking(const char *domain_name_, const char* dst_ip) const {

    std::string domain_name;
    const char *subdomain = "www.";

    // check for domain-faking with www. subdomain as well
    //
    if (strncmp(domain_name_, subdomain, 4) == 0) {
        domain_name = domain_name_ + 4;
    }
    else {
        domain_name = domain_name_;
    }

    uint32_t domain_idx = -1;
    auto it = domains_watchlist.find(domain_name);
    if (it != domains_watchlist.end()) {
        domain_idx = it->second;
    } else {
        return false;  // not domain-faking - as the domain is not in domain-mappings db
    }

    uint32_t ipv4_addr;
    if (!char_string_to_ipv4_addr(dst_ip, ipv4_addr)) {
        return false; // IPv6 or invalid address
    }

    ipv4_address ip4(ipv4_addr);
    if (ip4.get_addr_type() == ipv4_address::addr_type::private_use) {
        return false; // not domain-faking - as the IP is a private address
    }

    lct_subnet_t *subnet = lct_find(&ipv4_domain_trie, ntoh(ipv4_addr));
    if (subnet == NULL) {
        return true; // IP not found in trie - domain-faking
    }

    if (subnet->info.type == IP_SUBNET_DOMAIN) {
        for (uint8_t domain_idx_itr = 0; domain_idx_itr < subnet->info.domain.domain_idx_arr_len; domain_idx_itr++) {
            if (subnet->info.domain.domain_idx_arr[domain_idx_itr] == domain_idx) {
                return false; // match - domain is mapped to the subnet - not domain-faking
            }
        }
    }
    else if (subnet->info.type == IP_SUBNET_DOMAIN_EXCEPTION) {
        return false; // subnet is an exception - not domain-faking
    }

    return true; // no match - domain-faking
}
