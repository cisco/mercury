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

#include "lctrie_ip.h"

template <typename T>
void ipv6_print(FILE *f, const __uint128_t *addr) {
    uint16_t *a = (uint16_t *)addr;
    uint16_t *sentinel = a + (sizeof(__uint128_t)/sizeof(uint16_t)) - 1;

    while (a < sentinel) {
        fprintf(f, "%x", *a);
        putc(':', f);
        a++;
    }
    fprintf(f, "%x", *a);
}

template <typename T>
void ipv6_print_rev(FILE *f, const __uint128_t *addr) {
    uint16_t *a = (uint16_t *)addr;
    uint16_t *iterator = a + (sizeof(__uint128_t)/sizeof(uint16_t)) - 1;

    while (iterator > a) {
        fprintf(f, "%x", *iterator);
        putc(':', f);
        --iterator;
    }
    fprintf(f, "%x", *iterator);
}


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
lct_subnet_set_from_string(lct_subnet<__uint128_t> *subnet, const char *subnet_string) {
  uint32_t asn;
  uint8_t mask_length;

  // parse subnet_string as an IPv6 subnet line, such as the following:
  //
  // 2001::  32      6939_1101
  // 2001:250:208::  48      24349

  int advance = 0;

  // parse string as IPv6 address
  __uint128_t addr = 0;
  uint16_t *a = (uint16_t *)&addr;
  uint16_t *sentinel = a + (sizeof(__uint128_t)/sizeof(uint16_t));
  uint16_t *trailer = NULL;
  const char *start = subnet_string;
  int num_items_parsed = 1;
  size_t trailing_uint16s = 0;
  while (true) {

      if (a >= sentinel) {
          return -1;  // parse error; too many digits in address
      }

      // advance over (one or two) colons
      if (start[0] == ':') {
          start++;
          a++;
          if (start[0] == ':') {
              if (trailer) {
                  return -1; // parse error; multiple occurences of "::"
              }
              start++;
              a++;
              if (start[0] == ':') {
                  return -1; // parse error; ":::" is invalid
              }
              trailer = a;
          }
      }
      // check for end of address/subnet
      if (!isxdigit(start[0])) {
          break;
      }
      int bytes_consumed = -1;
      num_items_parsed = sscanf(start, "%hx%n", a, &bytes_consumed);
      if (num_items_parsed == 1) {
          *a = ntohs(*a);
          start += bytes_consumed;
          if (trailer) {
              trailing_uint16s++;
          }
      }  else {
          break;
      }
  }
  if (trailing_uint16s) {
      int shift = 8 - (trailer - (uint16_t *)&addr) - trailing_uint16s;
      //fprintf(stderr, "shift: %d\n", shift);
      //ipv6_print<__uint128_t>(stderr, &addr);
      //fprintf(stderr, "\tgot %zu trailing uint16s in %s\n", trailing_uint16s, subnet_string);

      // shift elements
      uint16_t *x = (uint16_t *)&addr;
      for (size_t i=0; i < trailing_uint16s; i++) {
          x[7-i] = x[7-i-shift];
          x[7-i-shift] = 0;
      }
      //ipv6_print<__uint128_t>(stderr, &addr);
      //fprintf(stderr, "\tgot %zu trailing uint16s in %s\n", trailing_uint16s, subnet_string);
      //fprintf(stderr, "-----------------------------\n");
  }
  addr = ntoh(addr);
  num_items_parsed = sscanf(start, "\t%hhu%n", &mask_length, &advance);
  if (num_items_parsed != 1) {
      return -1;
  }
  start += advance;
  num_items_parsed = sscanf(start, "\t%u", &asn);
  if (num_items_parsed != 1) {
      return -1;
  }

  // fprintf(stderr, "string: %s\n", subnet_string);
  // char pstr[INET6_ADDRSTRLEN];
  // inet_ntop(AF_INET6, &addr, pstr, INET6_ADDRSTRLEN);
  // fprintf(stderr, "before: %s\n", pstr);

  // debugging output
  // fprintf(stderr, "-------------------------------------------\n");
  // fprintf(stderr, "input:  %s\n", subnet_string);
  // fprintf(stderr, "output: ");
  // ipv6_print<__uint128_t>(stderr, &addr);
  // fprintf(stderr, "\t%u\t%u\n", mask_length, asn);

  // inet_ntop(AF_INET6, &addr, pstr, INET6_ADDRSTRLEN);
  // fprintf(stderr, "after:  %s\n", pstr);

  subnet->addr = addr;
  subnet->len = mask_length;
  subnet->info.type = IP_SUBNET_BGP;
  subnet->info.bgp.asn = asn;
  return 0;
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
  FILE *infile;
  char *line = NULL;
  size_t line_len = 0;

  // open the file for reading
  if (!(infile = fopen(filename, "r"))) {
    fprintf(stderr, "%s: %s\n", filename, strerror(errno));
    return -1;
  }

  // validate and parse each line of input
  while (-1 != getline(&line, &line_len, infile)) {
    // clip off the trailing newline character
    line[strcspn(line, "\n")] = 0;

    // set the prefix[num] to the subnet and ASN found in line
    if (lct_subnet_set_from_string(&prefix[num], line) != 0) {
      fprintf(stderr, "error: could not parse subnet string '%s'\n", line);
      return -1;
    }

    num++;
  }

  free(line);
  fclose(infile);

  return num;
}

// read the ASN to description file
// return number of entries read
// return negative on failure
extern int
read_asn_table(char *filename,
               lct_bgp_asn_t prefix[],
               size_t prefix_size);

// end #ifndef guard
#endif
