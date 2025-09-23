#ifndef __LC_TRIE_BGP_H__
#define __LC_TRIE_BGP_H__
// begin #ifndef guard

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <typeinfo>
#include <fstream>

#include "lctrie_ip.h"
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

// disable IPV6 on Windows
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
    (void)prefix_size;
    int num = 0;
    std::ifstream infile;

    // open the file for reading
    //
    infile.open(filename);
    if (!infile.is_open()) {
        perror("ifstream::open");
        return -1;
    }

    // validate and parse each line of input
    //
    std::string line;
    while (std::getline(infile, line)) {

        // clip off the trailing newline character
        //
        if (!line.empty() && line[line.length()-1] == '\n') {
            line.erase(line.length()-1);
        }

        // set the prefix[num] to the subnet and ASN found in line
        //
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

// end #ifndef guard
#endif
