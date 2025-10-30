#include <stdlib.h>
#include <stdio.h>
#include <libgen.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <locale.h>
#include <unordered_map>
#include <vector>
#include <random>

#include <sys/time.h>


#include "../addr.cc"
#include "lctrie_ip.hpp"
#include "lctrie_bgp.hpp"
#include "lctrie.hpp"
#include "../ipv6_lctrie.h"

#define BGP_MAX_ENTRIES             4000000


bool test_ipv4(const char *input_file, FILE *f) {
    int num = 0;
    lct_subnet<uint32_t> *p, *subnet = NULL;
    lct<uint32_t> t;

    setlocale(LC_NUMERIC, "");

    if (!(p = (lct_subnet<uint32_t> *)calloc(sizeof(lct_subnet<uint32_t>), BGP_MAX_ENTRIES))) {
        fprintf(stderr, "Could not allocate subnet input buffer\n");
        exit(EXIT_FAILURE);
    }

    int rc;
    if (f) fprintf(f, "Reading prefixes from %s...\n\n", input_file);
    if (0 > (rc = read_prefix_table<uint32_t>(input_file, &p[num], BGP_MAX_ENTRIES - num))) {
        fprintf(stderr, "could not read prefix file \"%s\"\n", input_file);
        return rc;
    }
    num += rc;

    subnet_mask_v4(p, num);
    qsort(p, num, sizeof(lct_subnet<uint32_t>), subnet_cmp<uint32_t>);

    num -= subnet_dedup(p, num);
    p = (lct_subnet<uint32_t> *)realloc(p, num * sizeof(lct_subnet<uint32_t>));

    lct_ip_stats_t *stats = (lct_ip_stats_t *) calloc(num, sizeof(lct_ip_stats_t));
    if (!stats) {
        fprintf(stderr, "Failed to allocate prefix statistics buffer\n");
        return 0;
    }

    subnet_prefix(p, stats, num);

    for (int i = 0; i < num; i++) {
        uint32_t prefix = p[i].prefix;
        if (prefix != IP_PREFIX_NIL && p[prefix].type == IP_PREFIX_FULL) {
            if (f) fprintf(f, "ERROR: optimized subnet index points to a full prefix\n");
        }
    }

    memset(&t, 0, sizeof(lct<uint32_t>));
    lct_build<uint32_t>(&t, p, num);

    const std::vector<std::pair<std::string, std::string>> test_cases {
        {"1.1.1.1", "1.1.1.0/24"},
        {"8.8.8.8", "8.8.8.0/24"},
        {"61.46.67.1", "61.46.0.0/16"},
        {"74.125.224.72", "74.125.128.0/17"},
        {"172.217.0.0", "172.217.0.0/19"},
        {"205.251.192.0", "205.251.192.0/19"},
    };

    bool all_matched = true;
    if (f) fprintf(f, "Testing trie matches for some well known subnets...\n");
    for (const auto& [addr_str, trie_prefix] : test_cases) {

        uint32_t key;
        if (!char_string_to_ipv4_addr(addr_str.c_str(), key)) {
            if (f) fprintf(f, "ERROR: could not parse test address %s\n", addr_str.c_str());
            all_matched = false;
            break;
        }

        subnet = lct_find(&t, ntoh(key));

        if (subnet) {
            ipv4_address addr = ipv4_address(ntoh(subnet->addr));
            std::string addr_s = addr.get_string();
            addr_s += "/" + std::to_string(subnet->len);
            if (addr_s.compare(trie_prefix) != 0) {
                if (f) fprintf(f, "ERROR: expected prefix %s but found %s\n", trie_prefix.c_str(), addr_s.c_str());
                all_matched = false;
                break;
            } else {
                if (f) fprintf(f, "%s address matched expected prefix %s\n", addr_str.c_str(), trie_prefix.c_str());
            }
        } else {
            if (f) fprintf(f, "ERROR: expected prefix %s but found no match\n", trie_prefix.c_str());
            all_matched = false;
            break;
        }
    }

    lct_free<uint32_t>(&t);
    free(stats);
    free(p);

    return all_matched;
}


bool test_ipv6(const char *input_file, FILE *f) {
    int num = 0;
    lct_subnet<ipv6_addr_lct> *p, *subnet = NULL;
    lct<ipv6_addr_lct> t;

    // we need this to get thousands separators ?
    setlocale(LC_NUMERIC, "");

    if (!(p = (lct_subnet<ipv6_addr_lct> *)calloc(sizeof(lct_subnet<ipv6_addr_lct>), BGP_MAX_ENTRIES))) {
        fprintf(stderr, "Could not allocate subnet input buffer\n");
        exit(EXIT_FAILURE);
    }

    int rc;
    if (f) fprintf(f, "Reading prefixes from %s...\n\n", input_file);
    if (0 > (rc = read_prefix_table<ipv6_addr_lct>(input_file, &p[num], BGP_MAX_ENTRIES - num))) {
        if (f) fprintf(f, "could not read prefix file \"%s\"\n", input_file);
        return rc;
    }
    num += rc;

    subnet_mask_v6(p, num);
    qsort(p, num, sizeof(lct_subnet<ipv6_addr_lct>), subnet_cmp<ipv6_addr_lct>);

    num -= subnet_dedup<ipv6_addr_lct>(p, num);
    p = (lct_subnet<ipv6_addr_lct> *)realloc(p, num * sizeof(lct_subnet<ipv6_addr_lct>));

    lct_ip_stats_t *stats = (lct_ip_stats_t *) calloc(num, sizeof(lct_ip_stats_t));
    if (!stats) {
        fprintf(stderr, "Failed to allocate prefix statistics buffer\n");
        return 0;
    }

    subnet_prefix(p, stats, num);

    for (int i = 0; i < num; i++) {
        uint32_t prefix_idx = p[i].prefix;
        if (prefix_idx != IP_PREFIX_NIL && p[prefix_idx].type == IP_PREFIX_FULL) {
            if (f) fprintf(f, "ERROR: optimized subnet index points to a full prefix\n");
        }
    }

    memset(&t, 0, sizeof(lct<ipv6_addr_lct>));
    lct_build<ipv6_addr_lct>(&t, p, num);

    std::vector<std::pair<std::string, std::string>> test_cases {
            {"2001:200::1", "2001:200::/37"},
            {"2003:1::", "2003::/25"},
            {"2a01:1000:1::", "2a01:1000::/24"},
            {"2400:4000:1::", "2400:4000::/26"},
            {"2a02:b000:1::", "2a02:b000::/23"},
            {"2001:1c00:1::", "2001:1c00::/36"},
            {"2c0f:fff0:1::", "2c0f:fff0::/32"},
            {"2001:1208:1::", "2001:1208::/32"},
            {"2c0f:fce8:4000:1::", "2c0f:fce8::/33"},
            {"2001:1288:2000:1::", "2001:1288::/32"},
            {"2c0f:fe78:5000:1::", "2c0f:fe78::/32"},
            {"2001:12e0:800:1::", "2001:12e0:800::/37"},
            {"2c0f:fb08:ff00:1::", "2c0f:fb08:ff00::/40"},
            {"2001:16a6:c100:1::", "2001:16a6:c100::/40"},
            {"2c0f:f7e8:1::", "2c0f:f7e8::/47"},
            {"2a09:bd00:1fe:1::", "2a09:bd00:1fe::/47"},
            {"2001:1670:8:4000:1::", "2001:1670::/32"},
            {"2401:7400:6801:1::", "2401:7400:4000::/34"},
            {"2001:418:141f:100:1::", "2001:418:1418::/45"},
            {"2a01:5a8:3:1::", "2a01:5a8::/46"},
            {"2001:8b0:0:40:1::", "2001:8b0::/43"},
            {"2a0b:7280:0:4:1::", "2a0b:7280::/29"},
            {"2001:1490:0:1000:1::", "2001:1490::/32"},
            {"2a00:4120:8000:70::", "2a00:4120:8000::/46"},
            {"2403:2c00:cfff:0:0:0:0:1", "2403:2c00:c000::/35"},
            {"2a00:1760:6007::f8", "2a00:1760::/30"},
            {"2403:2c00:7:1::1", "2403:2c00::/33"},
            {"2a03:d000:299f:e000::15", "2a03:d000:2000::/36"},
    };

    bool all_matched = true;
    for (const auto& [addr_str, trie_prefix] : test_cases) {

        ipv6_addr_lct key;
        datum addr_datum = get_datum(addr_str.c_str());
        ipv6_address_string addr_parser{addr_datum};
        if (!addr_parser.is_valid()) {
            if (f) fprintf(f, "ERROR: could not parse test address %s\n", addr_str.c_str());
            all_matched = false;
            break;
        }
        std::tuple<uint64_t, uint64_t> addr_tuple = addr_parser.get_2tuple();
        key.a[0] = std::get<0>(addr_tuple);
        key.a[1] = std::get<1>(addr_tuple);

        subnet = lct_find(&t, key);

        if (subnet) {

            ipv6_address addr;
            addr.a[0] = hton((uint32_t)(subnet->addr.a[0] >> 32));
            addr.a[1] = hton((uint32_t)(subnet->addr.a[0] & 0xFFFFFFFF));
            addr.a[2] = hton((uint32_t)(subnet->addr.a[1] >> 32));
            addr.a[3] = hton((uint32_t)(subnet->addr.a[1] & 0xFFFFFFFF));

            std::string addr_s = addr.get_string()+ "/" + std::to_string(subnet->len);
            if (addr_s.compare(trie_prefix) != 0) {
                if (f) fprintf(f, "ERROR: expected prefix %s but found %s\n", trie_prefix.c_str(), addr_s.c_str());
                all_matched = false;
                break;
            } else {
                if (f) fprintf(f, "%s address matched expected prefix %s\n", addr_str.c_str(), trie_prefix.c_str());
            }
        } else {
            if (f) fprintf(f, "ERROR: expected prefix %s but found no match\n", trie_prefix.c_str());
            all_matched = false;
            break;
        }
    }

    lct_free<ipv6_addr_lct>(&t);
    free(stats);
    free(p);

    return all_matched;
}

static inline bool lctrie_v4_unit_test(FILE *f = nullptr) {
    return test_ipv4("libmerc/lctrie/test_files/ipv4_lct", f);
}

static inline bool lctrie_v6_unit_test(FILE *f = nullptr) {
    return test_ipv6("libmerc/lctrie/test_files/ipv6_lct", f);
}
