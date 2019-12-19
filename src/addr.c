/*
 * addr.c
 *
 * address processing functions, including longest prefix match
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "addr.h"

#if defined(__cplusplus)
    extern "C" {
#endif
#include "lctrie/lctrie.h"
#include "lctrie/lctrie_bgp.h"
#if defined(__cplusplus)
    }
#endif


#include <iostream>

lct_t ipv4_subnets;
uint32_t get_asn_info(char* dst_ip) {
    uint32_t ipv4_addr;

    if (inet_pton(AF_INET, dst_ip, &ipv4_addr) != 1) {
        return 0;
    }

    lct_subnet_t *subnet = lct_find(&ipv4_subnets, ntohl(ipv4_addr));
    if (subnet == NULL) {
        return 0;
    }
    if (subnet->info.type == IP_SUBNET_BGP) {
        return subnet->info.bgp.asn;
    }

    return 0;
}

#define BGP_MAX_ENTRIES             4000000
#define BGP_READ_FILE               1

// should we initialize the special prefix ranges?
#define LCT_INIT_PRIVATE            1
#define LCT_INIT_SPECIAL            1

#define LCT_VERIFY_PREFIXES         1
#define LCT_IP_DISPLAY_PREFIXES     0

int lct_init_from_file(char *filename) {
  int num = 0;
  uint32_t prefix;
  lct_subnet_t *p;
  lct_t *t = &ipv4_subnets;

  // we need this to get thousands separators
  setlocale(LC_NUMERIC, "");

  if (!(p = (lct_subnet_t *)calloc(sizeof(lct_subnet_t), BGP_MAX_ENTRIES))) {
    fprintf(stderr, "Could not allocate subnet input buffer\n");
    exit(EXIT_FAILURE);
  }

#if LCT_INIT_PRIVATE
  // start with the RFC 1918 and 3927 private and link local
  // subnets as a basis for any table set
  num += init_private_subnets(&p[num], BGP_MAX_ENTRIES);
#endif

#if LCT_INIT_SPECIAL
  // fill up the rest of the array with reserved IP subnets
  num += init_special_subnets(&p[num], BGP_MAX_ENTRIES);
#endif

#if BGP_READ_FILE
  // read in the ASN prefixes
  int rc;
  if (0 > (rc = read_prefix_table(filename, &p[num], BGP_MAX_ENTRIES - num))) {
    fprintf(stderr, "could not read prefix file \"%s\"\n", filename);
    return rc;
  }
  num += rc;
#endif

#if LCT_VERIFY_PREFIXES
  // Add a couple of custom prefixes.  Just use the void *data as a char *desc

  // 192.168.1.0/24 home subnet (common for SOHO wireless routers)
  p[num].info.type = IP_SUBNET_USER;
  p[num].info.usr.data = (void *)"Class A/24 home network";
  inet_pton(AF_INET, "192.168.1.0", &(p[num].addr));
  p[num].addr = ntohl(p[num].addr);
  p[num].len = 24;
  ++num;

  // 192.168.1.0/28 home sub-subnet.  used for testing address ranges
  p[num].info.type = IP_SUBNET_USER;
  p[num].info.usr.data = (void *)"Class A/24 guest network";
  inet_pton(AF_INET, "192.168.2.0", &(p[num].addr));
  p[num].addr = ntohl(p[num].addr);
  p[num].len = 24;
  ++num;

  // 192.168.1.0/28 home sub-subnet.  used for testing address ranges
  p[num].info.type = IP_SUBNET_USER;
  p[num].info.usr.data = (void *)"Class A/24 NAS network";
  inet_pton(AF_INET, "192.168.22.0", &(p[num].addr));
  p[num].addr = ntohl(p[num].addr);
  p[num].len = 24;
  ++num;
#endif

  // in a real world example, this data pointer would point to a more fleshed
  // out structure that would represent the host group

  // validate subnet prefixes against their netmasks
  // and sort the resulting array
  subnet_mask(p, num);
  qsort(p, num, sizeof(lct_subnet_t), subnet_cmp);

  // de-duplicate subnets and shrink the buffer down to its
  // actual size and split into prefixes and bases
  num -= subnet_dedup(p, num);
  p = (lct_subnet_t *)realloc(p, num * sizeof(lct_subnet_t));

  // allocate a buffer for the IP stats
  lct_ip_stats_t *stats = (lct_ip_stats_t *) calloc(num, sizeof(lct_ip_stats_t));
  if (!stats) {
    fprintf(stderr, "Failed to allocate prefix statistics buffer\n");
    return 0;
  }

  // count which subnets are prefixes of other subnets
  subnet_prefix(p, stats, num);

  // we're storing twice as many subnets as necessary for easy
  // iteration over the entire sorted subnet list.
  for (int i = 0; i < num; i++) {
    // quick error check on the optimized prefix indexes
    prefix = p[i].prefix;
    if (prefix != IP_PREFIX_NIL && p[prefix].type == IP_PREFIX_FULL) {
      printf("ERROR: optimized subnet index points to a full prefix\n");
    }
  }

  // actually build the trie and get the trie node count for statistics printing
  memset(t, 0, sizeof(lct_t));
  lct_build(t, p, num);

  return 0;
}

int addr_init(const char *resources_dir) {
    return lct_init_from_file((char *)resources_dir);
}
