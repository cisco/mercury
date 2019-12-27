#ifndef __LC_TRIE_BGP_H__
#define __LC_TRIE_BGP_H__
// begin #ifndef guard

#include <stdlib.h>
#include <stdint.h>

#include "lctrie_ip.h"

typedef struct lct_bgp_asn {
  uint32_t num;
  char *desc;
} lct_bgp_asn_t;

// read the subnet to ASN file
// return number of entries read
// return negative on failure
extern int
read_prefix_table(char *filename,
                  lct_subnet_t prefix[],
                  size_t prefix_size);

// read the ASN to description file
// return number of entries read
// return negative on failure
extern int
read_asn_table(char *filename,
               lct_bgp_asn_t prefix[],
               size_t prefix_size);

// end #ifndef guard
#endif
