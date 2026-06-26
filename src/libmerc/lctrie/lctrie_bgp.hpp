#ifndef __LC_TRIE_BGP_HPP__
#define __LC_TRIE_BGP_HPP__
// begin #ifndef guard

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <typeinfo>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include "lctrie_ip.hpp"
#include "lctrie.hpp"
#include <type_traits>
#include "../ip_address.hpp"

typedef struct lct_bgp_asn {
  uint32_t num;
  char *desc;
} lct_bgp_asn_t;

inline int
lct_subnet_set_from_string(lct_subnet<uint32_t> *subnet, const char *subnet_string) {
  uint32_t addr;
  uint32_t asn;
  uint8_t mask_length;
  unsigned char *dq = (unsigned char *)&addr;

  constexpr unsigned int bits_in_T = sizeof(uint32_t) * 8;

  int num_items_parsed = sscanf(subnet_string,"%hhu.%hhu.%hhu.%hhu/%hhu\t%u",
                                dq + 3, dq + 2, dq + 1, dq, &mask_length, &asn);

  // printf("parsed subnet and ASN string %u.%u.%u.%u/%u\t%u (%u)\n",
  //	 ((addr >> 24) & 0xff), ((addr >> 16) & 0xff), ((addr >> 8) & 0xff), (addr & 0xff), mask_length, asn, num_items_parsed);

  if (num_items_parsed == 6) {

      if ((mask_length == 0) || (mask_length > bits_in_T)) {
          fprintf(stderr, "ERROR: %u is not a valid prefix length\n", mask_length);
          return -1;
      }

      subnet->addr = addr;
      subnet->len = mask_length;
      subnet->info.type = IP_SUBNET_BGP;
      subnet->info.bgp.asn = asn;
      return 0;
  }
  return -1;  /* error parsing subnet_string */
}

inline int
lct_subnet_set_from_string(lct_subnet<ipv6_addr_lct> *subnet, const char *subnet_string) {
  ipv6_addr_lct addr;
  uint32_t asn;
  uint8_t mask_length;
  char addr_str[LCTRIE_INET6_ADDRSTRLEN];

  constexpr unsigned int bits_in_T = sizeof(ipv6_addr_lct) * 8;

  int num_items_parsed = sscanf(subnet_string,"%45[^/]/%hhu\t%u", addr_str, &mask_length, &asn);

  if (num_items_parsed == 3) {
    if ((mask_length == 0) || (mask_length > bits_in_T)) {
        fprintf(stderr, "ERROR: %u is not a valid prefix length\n", mask_length);
        return -1;
    }

    uint32_t addr_len = strlen(addr_str);
    if (addr_len >= LCTRIE_INET6_ADDRSTRLEN) {
        fprintf(stderr, "ERROR: IPv6 address string too long: %s\n", addr_str);
        return -1;
    }

    datum addr_datum = get_datum(addr_str);
    ipv6_address_string addr_parser{addr_datum};
    
    if (!addr_parser.is_valid()) {
        fprintf(stderr, "ERROR: Invalid IPv6 address format: %s\n", addr_str);
        return -1;
    }

    std::tuple<uint64_t, uint64_t> addr_tuple = addr_parser.get_2tuple();
    addr.a[0] = std::get<0>(addr_tuple);
    addr.a[1] = std::get<1>(addr_tuple);

    subnet->addr = addr;
    subnet->len = mask_length;
    subnet->info.type = IP_SUBNET_BGP;
    subnet->info.bgp.asn = asn;

    return 0;
  }

  return -1;  /* error parsing subnet_string */
}

// read the subnet to ASN file
// return number of entries read
// return negative on failure
// template <typename T>
// extern int
// read_prefix_table(char *filename,
//                   lct_subnet_t prefix[],
//                   size_t prefix_size);

template <typename T>
int
read_prefix_table(const char *filename,
                  lct_subnet<T> prefix[],
                  size_t prefix_size) {
    int num = 0;
    std::ifstream infile;

    infile.open(filename);
    if (!infile.is_open()) {
        perror("ifstream::open");
        return -1;
    }

    std::string line;
    while (std::getline(infile, line)) {

        // strip CRLF from Windows line endings
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if ((size_t)num >= prefix_size) {
            fprintf(stderr, "error: prefix buffer full at %d entries\n", num);
            return -1;
        }

        if (lct_subnet_set_from_string(&prefix[num], line.c_str()) != 0) {
            fprintf(stderr, "error: could not parse subnet string '%s'\n", line.c_str());
            return -1;
        }

        num++;
    }

    infile.close();

    return num;
}

// read the ASN to description file return number of entries read;
// return negative on failure
//
int read_asn_table(char *filename,
                   lct_bgp_asn_t prefix[],
                   size_t prefix_size);

template <typename T>
int read_prefix_table_from_string(const char *data,
                                  lct_subnet<T> prefix[],
                                  size_t prefix_size) {
    int num = 0;
    std::istringstream ss(data);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if ((size_t)num >= prefix_size) {
            fprintf(stderr, "error: prefix buffer full at %d entries\n", num);
            return -1;
        }
        if (lct_subnet_set_from_string(&prefix[num], line.c_str()) != 0) {
            fprintf(stderr, "error: could not parse subnet string '%s'\n", line.c_str());
            return -1;
        }
        num++;
    }
    return num;
}

#define LCTRIE_BGP_MAX_ENTRIES 4000000

static inline bool lctrie_v4_unit_test(FILE *f = nullptr) {
    static const char ipv4_data[] =
        "1.0.0.0/24\t13335\n"
        "1.1.1.0/24\t13335\n"
        "8.0.0.0/15\t3356\n"
        "8.8.0.0/16\t3356\n"
        "8.8.8.0/24\t3356\n"
        "61.0.0.0/14\t9829\n"
        "61.46.0.0/16\t9617\n"
        "74.0.0.0/15\t3257\n"
        "74.125.0.0/18\t15169\n"
        "74.125.64.0/23\t396982\n"
        "74.125.66.0/24\t396982\n"
        "74.125.67.0/24\t15169\n"
        "74.125.68.0/22\t15169\n"
        "74.125.72.0/21\t15169\n"
        "74.125.80.0/20\t15169\n"
        "74.125.96.0/19\t15169\n"
        "74.125.128.0/17\t15169\n"
        "172.0.0.0/17\t7018\n"
        "172.2.0.0/17\t7018\n"
        "172.217.0.0/19\t15169\n"
        "205.0.0.0/11\t749\n"
        "205.200.0.0/18\t7122\n"
        "205.251.0.0/20\t29838\n"
        "205.251.16.0/23\t29838\n"
        "205.251.19.0/24\t29838\n"
        "205.251.192.0/19\t16509\n";

    int num = 0;
    lct_subnet<uint32_t> *p = (lct_subnet<uint32_t> *)calloc(LCTRIE_BGP_MAX_ENTRIES, sizeof(lct_subnet<uint32_t>));
    if (!p) { fprintf(stderr, "Could not allocate subnet input buffer\n"); return false; }

    int rc = read_prefix_table_from_string<uint32_t>(ipv4_data, &p[num], LCTRIE_BGP_MAX_ENTRIES - num);
    if (rc < 0) { free(p); return false; }
    num += rc;

    subnet_mask_v4(p, num);
    qsort(p, num, sizeof(lct_subnet<uint32_t>), subnet_cmp<uint32_t>);
    num -= subnet_dedup(p, num);
    p = (lct_subnet<uint32_t> *)realloc(p, num * sizeof(lct_subnet<uint32_t>));

    lct_ip_stats_t *stats = (lct_ip_stats_t *)calloc(num, sizeof(lct_ip_stats_t));
    if (!stats) { free(p); return false; }
    subnet_prefix(p, stats, num);

    lct<uint32_t> t;
    memset(&t, 0, sizeof(lct<uint32_t>));
    lct_build<uint32_t>(&t, p, num);

    const std::vector<std::pair<std::string, std::string>> test_cases {
        {"1.1.1.1",       "1.1.1.0/24"},
        {"8.8.8.8",       "8.8.8.0/24"},
        {"61.46.67.1",    "61.46.0.0/16"},
        {"74.125.224.72", "74.125.128.0/17"},
        {"172.217.0.0",   "172.217.0.0/19"},
        {"205.251.192.0", "205.251.192.0/19"},
    };

    bool all_matched = true;
    for (const auto& [addr_str, trie_prefix] : test_cases) {
        uint32_t key;
        uint8_t d[4];
        if (sscanf(addr_str.c_str(), "%hhu.%hhu.%hhu.%hhu", d, d+1, d+2, d+3) != 4) {
            if (f) fprintf(f, "ERROR: could not parse test address %s\n", addr_str.c_str());
            all_matched = false; break;
        }
        key = ntoh((uint32_t)d[3] | (uint32_t)d[2] << 8 | (uint32_t)d[1] << 16 | (uint32_t)d[0] << 24);

        lct_subnet<uint32_t> *subnet = lct_find(&t, ntoh(key));
        if (subnet) {
            ipv4_address addr = ipv4_address(ntoh(subnet->addr));
            std::string addr_s = addr.get_string() + "/" + std::to_string(subnet->len);
            if (addr_s != trie_prefix) {
                if (f) fprintf(f, "ERROR: expected prefix %s but found %s\n", trie_prefix.c_str(), addr_s.c_str());
                all_matched = false; break;
            } else {
                if (f) fprintf(f, "%s address matched expected prefix %s\n", addr_str.c_str(), trie_prefix.c_str());
            }
        } else {
            if (f) fprintf(f, "ERROR: expected prefix %s but found no match\n", trie_prefix.c_str());
            all_matched = false; break;
        }
    }

    lct_free<uint32_t>(&t);
    free(stats);
    free(p);
    return all_matched;
}

static inline bool lctrie_v6_unit_test(FILE *f = nullptr) {
    static const char ipv6_data[] =
        "2a03::/32\t204094\n"
        "2a03:d000::/39\t31213\n"
        "2a03:d000:2000::/36\t31133\n"
        "2a00:1760::/30\t42772\n"
        "2403::/38\t4755\n"
        "2403:2c00::/33\t4058\n"
        "2403:2c00:c000::/35\t4058\n"
        "2a00:4120:8000::/46\t20804\n"
        "2a00:4120::/33\t20804\n"
        "2a00::/27\t3209\n"
        "2a01:5a8::/46\t8866\n"
        "2a0b:7280::/29\t48635\n"
        "2a0b::/29\t41453\n"
        "2401:7400:4000::/34\t4773\n"
        "2401:7400::/39\t4773\n"
        "2401:740::/32\t136515\n"
        "2a09::/48\t24013\n"
        "2a09:bd00::/48\t42385\n"
        "2a09:bd00:10::/44\t62261\n"
        "2a09:bd00:20::/44\t62261\n"
        "2a09:bd00:1fe::/47\t42385\n"
        "2c0f:f7e8::/47\t62217\n"
        "2c0f::/32\t328001\n"
        "2c0f:fb08::/33\t16637\n"
        "2c0f:fb08:ff00::/40\t12091\n"
        "2001:12e0:200::/40\t10429\n"
        "2001:12e0:800::/37\t10429\n"
        "2001:12e0:2000::/36\t10429\n"
        "2c0f:fe30::/32\t3700\n"
        "2c0f:fe38::/32\t33771\n"
        "2c0f:fe40::/32\t30844\n"
        "2c0f:fe60::/32\t37619\n"
        "2c0f:fe68::/32\t36868\n"
        "2c0f:fe78::/32\t37239\n"
        "2c0f:fe88::/32\t15808\n"
        "2c0f:fe90::/32\t36943\n"
        "2001:1284::/32\t14868\n"
        "2001:1288::/32\t28640\n"
        "2001:128c::/32\t25933\n"
        "2c0f:fce0::/32\t37027\n"
        "2c0f:fce8::/33\t37153\n"
        "2c0f:fcf0::/32\t36908\n"
        "2001:1208::/32\t8151\n"
        "2c0f:fff0::/32\t37125\n"
        "2001:1c00::/36\t33915\n"
        "2001:1c00:1000::/38\t33915\n"
        "2001:1c00:1500::/43\t33915\n"
        "2001:1c00:1520::/44\t33915\n"
        "2a02:af40::/29\t60187\n"
        "2a02:b000::/23\t1267\n"
        "2400:4000::/26\t4713\n"
        "2400:4040::/28\t4713\n"
        "2400:4050::/32\t4713\n"
        "2400:4051::/34\t4713\n"
        "2001:200::/37\t2500\n"
        "2003::/25\t2531\n"
        "2a01:1000::/24\t2531\n"
        "2001:8b0::/43\t25123\n"
        "2001:1c00:1400::/40\t33915\n"
        "2001:16a6::/33\t39386\n"
        "2001:16a6:8000::/34\t39386\n"
        "2001:16a6:c000::/40\t39386\n"
        "2001:16a6:c100::/40\t25019\n"
        "2001:16a6:c200::/39\t39386\n"
        "2001:16a6:c400::/38\t39386\n"
        "2001:16a6:c800::/37\t39386\n"
        "2001:16a6:d000::/36\t39386\n"
        "2001:16a6:e000::/35\t39386\n"
        "2001:1670::/32\t28885\n"
        "2001:418::/48\t2914\n"
        "2001:418:1::/48\t3130\n"
        "2001:418:2::/47\t2914\n"
        "2001:418:4::/46\t2914\n"
        "2001:418:8::/45\t2914\n"
        "2001:418:10::/44\t2914\n"
        "2001:418:20::/43\t2914\n"
        "2001:418:40::/42\t2914\n"
        "2001:418:80::/41\t2914\n"
        "2001:418:100::/40\t2914\n"
        "2001:418:200::/39\t2914\n"
        "2001:418:400::/38\t2914\n"
        "2001:418:800::/38\t2914\n"
        "2001:418:c00::/46\t2914\n"
        "2001:418:c04::/47\t2914\n"
        "2001:418:c06::/48\t262\n"
        "2001:418:c07::/48\t2914\n"
        "2001:418:c08::/45\t2914\n"
        "2001:418:c10::/44\t2914\n"
        "2001:418:c20::/43\t2914\n"
        "2001:418:c40::/42\t2914\n"
        "2001:418:c80::/41\t2914\n"
        "2001:418:d00::/40\t2914\n"
        "2001:418:e00::/39\t2914\n"
        "2001:418:1000::/38\t2914\n"
        "2001:418:1400::/48\t2914\n"
        "2001:418:1401::/62\t2914\n"
        "2001:418:1401:4::/64\t20940\n"
        "2001:418:1401:5::/64\t2914\n"
        "2001:418:1401:6::/64\t2914\n"
        "2001:418:1401:7::/64\t20940\n"
        "2001:418:1401:8::/61\t2914\n"
        "2001:418:1401:10::/61\t2914\n"
        "2001:418:1401:18::/64\t20940\n"
        "2001:418:1401:19::/64\t2914\n"
        "2001:418:1401:1a::/63\t2914\n"
        "2001:418:1401:1c::/64\t20940\n"
        "2001:418:1401:1d::/64\t2914\n"
        "2001:418:1401:1e::/63\t2914\n"
        "2001:418:1401:20::/64\t2914\n"
        "2001:418:1401:21::/64\t20940\n"
        "2001:418:1401:22::/63\t2914\n"
        "2001:418:1401:24::/64\t2914\n"
        "2001:418:1401:25::/64\t20940\n"
        "2001:418:1401:26::/63\t2914\n"
        "2001:418:1401:28::/62\t2914\n"
        "2001:418:1401:2c::/64\t20940\n"
        "2001:418:1401:2d::/64\t2914\n"
        "2001:418:1401:2e::/63\t2914\n"
        "2001:418:1401:30::/60\t2914\n"
        "2001:418:1401:40::/59\t2914\n"
        "2001:418:1401:60::/61\t2914\n"
        "2001:418:1401:68::/63\t2914\n"
        "2001:418:1401:6a::/64\t20940\n"
        "2001:418:1401:6b::/64\t2914\n"
        "2001:418:1401:6c::/62\t2914\n"
        "2001:418:1401:70::/63\t20940\n"
        "2001:418:1401:72::/63\t2914\n"
        "2001:418:1401:74::/62\t2914\n"
        "2001:418:1401:78::/62\t2914\n"
        "2001:418:1401:7c::/64\t2914\n"
        "2001:418:1401:7d::/64\t20940\n"
        "2001:418:1401:7e::/63\t2914\n"
        "2001:418:1401:80::/57\t2914\n"
        "2001:418:1401:100::/56\t2914\n"
        "2001:418:1401:200::/56\t2914\n"
        "2001:418:1401:300::/56\t20940\n"
        "2001:418:1401:400::/55\t20940\n"
        "2001:418:1401:600::/55\t2914\n"
        "2001:418:1401:800::/53\t2914\n"
        "2001:418:1401:1000::/52\t2914\n"
        "2001:418:1401:2000::/51\t2914\n"
        "2001:418:1401:4000::/50\t2914\n"
        "2001:418:1401:8000::/49\t2914\n"
        "2001:418:1402::/47\t2914\n"
        "2001:418:1404::/47\t2914\n"
        "2001:418:1406::/48\t2914\n"
        "2001:418:1407::/48\t3939\n"
        "2001:418:1408::/45\t2914\n"
        "2001:418:1410::/48\t2000\n"
        "2001:418:1411::/48\t213802\n"
        "2001:418:1412::/47\t2914\n"
        "2001:418:1414::/47\t2914\n"
        "2001:418:1416::/48\t396350\n"
        "2001:418:1417::/48\t2914\n"
        "2001:418:1418::/45\t2914\n"
        "2001:418:1420::/44\t2914\n"
        "2001:418:1430::/45\t2914\n"
        "2001:418:1438::/48\t2914\n"
        "2001:418:1439::/48\t1225\n"
        "2001:418:143a::/47\t2914\n"
        "2001:418:143c::/46\t2914\n"
        "2001:418:1440::/45\t2914\n"
        "2001:418:1448::/46\t2914\n"
        "2001:418:144c::/48\t2914\n"
        "2001:418:144d::/48\t275\n"
        "2001:418:144e::/47\t15562\n"
        "2001:418:1450::/48\t3938\n"
        "2001:418:1451::/48\t2914\n"
        "2001:418:1452::/47\t2914\n"
        "2001:418:1454::/47\t2914\n"
        "2001:418:1456::/53\t2914\n"
        "2001:418:1456:800::/55\t2914\n"
        "2001:418:1456:a00::/56\t2914\n"
        "2001:418:1456:b00::/59\t2914\n"
        "2001:418:1456:b20::/63\t397601\n"
        "2001:418:1456:b22::/64\t397601\n"
        "2001:418:1456:b23::/64\t2914\n"
        "2001:418:1456:b24::/62\t2914\n"
        "2001:418:1456:b28::/61\t2914\n"
        "2001:418:1456:b30::/60\t2914\n"
        "2001:418:1456:b40::/58\t2914\n"
        "2001:418:1456:b80::/57\t2914\n"
        "2001:418:1456:c00::/54\t2914\n"
        "2001:418:1456:1000::/52\t2914\n"
        "2001:418:1456:2000::/51\t2914\n"
        "2001:418:1456:4000::/50\t2914\n"
        "2001:418:1456:8000::/49\t2914\n"
        "2001:418:1457::/48\t2914\n"
        "2001:418:1458::/45\t2914\n"
        "2001:418:1460::/43\t2914\n"
        "2001:418:1480::/44\t2914\n"
        "2001:418:1490::/45\t2914\n"
        "2001:418:1498::/46\t2914\n"
        "2001:418:149c::/48\t152644\n"
        "2001:418:149d::/48\t2914\n"
        "2001:418:149e::/47\t2914\n"
        "2001:418:14a0::/43\t2914\n"
        "2001:418:14c0::/42\t2914\n"
        "2001:418:1500::/40\t2914\n"
        "2001:418:1600::/39\t2914\n"
        "2001:418:1800::/38\t2914\n"
        "2001:418:1c00::/48\t2914\n"
        "2001:418:1c01::/64\t2914\n"
        "2001:418:1c01:1::/64\t20940\n"
        "2001:418:1c01:2::/63\t2914\n"
        "2001:418:1c01:4::/62\t2914\n"
        "2001:418:1c01:8::/61\t2914\n"
        "2001:418:1c01:10::/60\t2914\n"
        "2001:418:1c01:20::/59\t2914\n"
        "2001:418:1c01:40::/58\t2914\n"
        "2001:418:1c01:80::/57\t2914\n"
        "2001:418:1c01:100::/56\t2914\n"
        "2001:418:1c01:200::/55\t2914\n"
        "2001:418:1c01:400::/54\t2914\n"
        "2001:418:1c01:800::/53\t2914\n"
        "2001:418:1c01:1000::/52\t2914\n"
        "2001:418:1c01:2000::/51\t2914\n"
        "2001:418:1c01:4000::/50\t2914\n"
        "2001:418:1c01:8000::/49\t2914\n"
        "2001:418:1c02::/47\t2914\n"
        "2001:418:1c04::/46\t2914\n"
        "2001:418:1c08::/45\t2914\n"
        "2001:418:1c10::/44\t2914\n"
        "2001:418:1c20::/43\t2914\n"
        "2001:418:1c40::/42\t2914\n"
        "2001:418:1c80::/41\t2914\n"
        "2001:418:1d00::/40\t2914\n"
        "2001:418:1e00::/39\t2914\n"
        "2001:418:2000::/36\t2914\n"
        "2001:418:3000::/37\t2914\n"
        "2001:418:3800::/46\t2914\n"
        "2001:418:3804::/47\t2914\n"
        "2001:418:3806::/48\t2914\n"
        "2001:418:3807::/48\t4128\n"
        "2001:418:3808::/45\t2914\n"
        "2001:418:3810::/44\t2914\n"
        "2001:418:3820::/43\t2914\n"
        "2001:418:3840::/42\t2914\n"
        "2001:418:3880::/41\t2914\n"
        "2001:418:3900::/40\t2914\n"
        "2001:418:3a00::/39\t2914\n"
        "2001:418:3c00::/38\t2914\n"
        "2001:418:4000::/48\t2914\n"
        "2001:418:4001::/63\t2914\n"
        "2001:418:4001:2::/64\t20940\n"
        "2001:418:4001:3::/64\t2914\n"
        "2001:418:4001:4::/64\t20940\n"
        "2001:418:4001:5::/64\t2914\n"
        "2001:418:4001:6::/63\t2914\n"
        "2001:418:4001:8::/61\t2914\n"
        "2001:418:4001:10::/60\t2914\n"
        "2001:418:4001:20::/59\t2914\n"
        "2001:418:4001:40::/58\t2914\n"
        "2001:418:4001:80::/57\t2914\n"
        "2001:418:4001:100::/56\t2914\n"
        "2001:418:4001:200::/55\t2914\n"
        "2001:418:4001:400::/54\t2914\n"
        "2001:418:4001:800::/53\t2914\n"
        "2001:418:4001:1000::/52\t2914\n"
        "2001:418:4001:2000::/51\t2914\n"
        "2001:418:4001:4000::/50\t2914\n"
        "2001:418:4001:8000::/49\t2914\n"
        "2001:418:4002::/47\t2914\n"
        "2001:418:4004::/48\t2914\n"
        "2001:418:4005::/48\t1412\n"
        "2001:418:4006::/47\t2914\n"
        "2001:418:4008::/45\t2914\n"
        "2001:418:4010::/44\t2914\n"
        "2001:418:4020::/43\t2914\n"
        "2001:418:4040::/42\t2914\n"
        "2001:418:4080::/41\t2914\n"
        "2001:418:4100::/40\t2914\n"
        "2001:418:4200::/39\t2914\n"
        "2001:418:4400::/38\t2914\n"
        "2001:418:4800::/37\t2914\n"
        "2001:418:5000::/36\t2914\n"
        "2001:418:6000::/35\t2914\n"
        "2001:418:8000::/46\t2914\n"
        "2001:418:8004::/47\t7019\n"
        "2001:418:8006::/48\t3927\n"
        "2001:418:8007::/48\t2914\n"
        "2001:418:8008::/45\t2914\n"
        "2001:418:8010::/44\t2914\n"
        "2001:418:8020::/43\t2914\n"
        "2001:418:8040::/42\t2914\n"
        "2001:418:8080::/41\t2914\n"
        "2001:418:8100::/40\t2914\n"
        "2001:418:8200::/39\t2914\n"
        "2001:418:8400::/46\t2914\n"
        "2001:418:8404::/63\t20940\n"
        "2001:418:8404:2::/63\t2914\n"
        "2001:418:8404:4::/62\t2914\n"
        "2001:418:8404:8::/61\t2914\n"
        "2001:418:8404:10::/60\t2914\n"
        "2001:418:8404:20::/59\t2914\n"
        "2001:418:8404:40::/58\t2914\n"
        "2001:418:8404:80::/57\t2914\n"
        "2001:418:8404:100::/56\t2914\n"
        "2001:418:8404:200::/55\t2914\n"
        "2001:418:8404:400::/54\t2914\n"
        "2001:418:8404:800::/53\t2914\n"
        "2001:418:8404:1000::/52\t2914\n"
        "2001:418:8404:2000::/51\t2914\n"
        "2001:418:8404:4000::/50\t2914\n"
        "2001:418:8404:8000::/49\t2914\n"
        "2001:418:8405::/48\t2914\n"
        "2001:418:8406::/47\t2914\n"
        "2001:418:8408::/45\t2914\n"
        "2001:418:8410::/44\t2914\n"
        "2001:418:8420::/43\t2914\n"
        "2001:418:8440::/42\t2914\n"
        "2001:418:8480::/41\t2914\n"
        "2001:418:8500::/40\t2914\n"
        "2001:418:8600::/39\t2914\n"
        "2001:418:8800::/37\t2914\n"
        "2001:418:9000::/37\t2914\n"
        "2001:418:9800::/45\t2914\n"
        "2001:418:9808::/48\t21778\n"
        "2001:418:9809::/48\t2914\n"
        "2001:418:980a::/47\t2914\n"
        "2001:418:980c::/46\t2914\n"
        "2001:418:9810::/44\t2914\n"
        "2001:418:9820::/43\t2914\n"
        "2001:418:9840::/42\t2914\n"
        "2001:418:9880::/41\t2914\n"
        "2001:418:9900::/40\t2914\n"
        "2001:418:9a00::/39\t2914\n"
        "2001:418:9c00::/38\t2914\n"
        "2001:418:a000::/35\t2914\n"
        "2001:418:c000::/34\t2914\n"
        "2001:1490::/32\t8895\n";

    int num = 0;
    lct_subnet<ipv6_addr_lct> *p = (lct_subnet<ipv6_addr_lct> *)calloc(LCTRIE_BGP_MAX_ENTRIES, sizeof(lct_subnet<ipv6_addr_lct>));
    if (!p) { fprintf(stderr, "Could not allocate subnet input buffer\n"); return false; }

    int rc = read_prefix_table_from_string<ipv6_addr_lct>(ipv6_data, &p[num], LCTRIE_BGP_MAX_ENTRIES - num);
    if (rc < 0) { free(p); return false; }
    num += rc;

    subnet_mask_v6(p, num);
    qsort(p, num, sizeof(lct_subnet<ipv6_addr_lct>), subnet_cmp<ipv6_addr_lct>);
    num -= subnet_dedup<ipv6_addr_lct>(p, num);
    p = (lct_subnet<ipv6_addr_lct> *)realloc(p, num * sizeof(lct_subnet<ipv6_addr_lct>));

    lct_ip_stats_t *stats = (lct_ip_stats_t *)calloc(num, sizeof(lct_ip_stats_t));
    if (!stats) { free(p); return false; }
    subnet_prefix(p, stats, num);

    lct<ipv6_addr_lct> t;
    memset(&t, 0, sizeof(lct<ipv6_addr_lct>));
    lct_build<ipv6_addr_lct>(&t, p, num);

    const std::vector<std::pair<std::string, std::string>> test_cases {
        {"2001:200::1",               "2001:200::/37"},
        {"2003:1::",                  "2003::/25"},
        {"2a01:1000:1::",             "2a01:1000::/24"},
        {"2400:4000:1::",             "2400:4000::/26"},
        {"2a02:b000:1::",             "2a02:b000::/23"},
        {"2001:1c00:1::",             "2001:1c00::/36"},
        {"2001:1c00:1001:1::",        "2001:1c00:1000::/38"},
        {"2c0f:fff0:1::",             "2c0f:fff0::/32"},
        {"2001:1208:1::",             "2001:1208::/32"},
        {"2c0f:fce8:4000:1::",        "2c0f:fce8::/33"},
        {"2001:1288:2000:1::",        "2001:1288::/32"},
        {"2c0f:fe78:5000:1::",        "2c0f:fe78::/32"},
        {"2001:12e0:800:1::",         "2001:12e0:800::/37"},
        {"2c0f:fb08:ff00:1::",        "2c0f:fb08:ff00::/40"},
        {"2001:16a6:c100:1::",        "2001:16a6:c100::/40"},
        {"2c0f:f7e8:1::",             "2c0f:f7e8::/47"},
        {"2a09:bd00:1fe:1::",         "2a09:bd00:1fe::/47"},
        {"2001:1670:8:4000:1::",      "2001:1670::/32"},
        {"2401:7400:6801:1::",        "2401:7400:4000::/34"},
        {"2001:418:141f:100:1::",     "2001:418:1418::/45"},
        {"2a01:5a8:3:1::",            "2a01:5a8::/46"},
        {"2001:8b0:0:40:1::",         "2001:8b0::/43"},
        {"2a0b:7280:0:4:1::",         "2a0b:7280::/29"},
        {"2001:1490:0:1000:1::",      "2001:1490::/32"},
        {"2a00:4120:8000:70::",       "2a00:4120:8000::/46"},
        {"2403:2c00:cfff:0:0:0:0:1",  "2403:2c00:c000::/35"},
        {"2a00:1760:6007::f8",        "2a00:1760::/30"},
        {"2403:2c00:7:1::1",          "2403:2c00::/33"},
        {"2a03:d000:299f:e000::15",   "2a03:d000:2000::/36"},
    };

    bool all_matched = true;
    for (const auto& [addr_str, trie_prefix] : test_cases) {
        ipv6_addr_lct key;
        datum addr_datum = get_datum(addr_str.c_str());
        ipv6_address_string addr_parser{addr_datum};
        if (!addr_parser.is_valid()) {
            if (f) fprintf(f, "ERROR: could not parse test address %s\n", addr_str.c_str());
            all_matched = false; break;
        }
        std::tuple<uint64_t, uint64_t> addr_tuple = addr_parser.get_2tuple();
        key.a[0] = std::get<0>(addr_tuple);
        key.a[1] = std::get<1>(addr_tuple);

        lct_subnet<ipv6_addr_lct> *subnet = lct_find(&t, key);
        if (subnet) {
            ipv6_address addr;
            addr.a[0] = hton((uint32_t)(subnet->addr.a[0] >> 32));
            addr.a[1] = hton((uint32_t)(subnet->addr.a[0] & 0xFFFFFFFF));
            addr.a[2] = hton((uint32_t)(subnet->addr.a[1] >> 32));
            addr.a[3] = hton((uint32_t)(subnet->addr.a[1] & 0xFFFFFFFF));
            std::string addr_s = addr.get_string() + "/" + std::to_string(subnet->len);
            if (addr_s != trie_prefix) {
                if (f) fprintf(f, "ERROR: expected prefix %s but found %s\n", trie_prefix.c_str(), addr_s.c_str());
                all_matched = false; break;
            } else {
                if (f) fprintf(f, "%s address matched expected prefix %s\n", addr_str.c_str(), trie_prefix.c_str());
            }
        } else {
            if (f) fprintf(f, "ERROR: expected prefix %s but found no match\n", trie_prefix.c_str());
            all_matched = false; break;
        }
    }

    lct_free<ipv6_addr_lct>(&t);
    free(stats);
    free(p);
    return all_matched;
}

// end #ifndef guard
#endif
