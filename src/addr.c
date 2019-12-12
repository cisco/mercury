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

lct_t ipv4_subnets;

std::string get_asn_info(char* dst_ip) {
    uint32_t ipv4_addr;

    if (inet_pton(AF_INET, dst_ip, &ipv4_addr) != 1) {
        return NULL;
    }

    lct_subnet_t *subnet = lct_find(&ipv4_subnets, ntohl(ipv4_addr));
    if (subnet->type == IP_SUBNET_BGP) {
        return std::to_string(subnet->info.bgp.asn);
    }
    return NULL;
    // return "14618:Amazon.com";
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
  int nprefixes = 0, nbases = 0, nfull = 0;
  uint32_t prefix; //, localprefix;
  lct_subnet_t *p; //, *subnet = NULL;
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
  printf("Reading prefixes from %s...\n\n", filename);
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
  nprefixes = subnet_prefix(p, stats, num);
  nbases = num - nprefixes;

  // we're storing twice as many subnets as necessary for easy
  // iteration over the entire sorted subnet list.
#if LCT_IP_DISPLAY_PREFIXES
  printf("Enumerating database, get ready! 3..2..1..GO!!!\n\n");
#endif
  for (int i = 0; i < num; i++) {
#if LCT_IP_DISPLAY_PREFIXES
    print_subnet_stats(&p[i], &stats[i]);
#endif

    // count up the full prefixes to calculate the savings on trie nodes
    if (p[i].type == IP_PREFIX_FULL)
      ++nfull;

    // quick error check on the optimized prefix indexes
    prefix = p[i].prefix;
    if (prefix != IP_PREFIX_NIL && p[prefix].type == IP_PREFIX_FULL) {
      printf("ERROR: optimized subnet index points to a full prefix\n");
    }
  }

  uint32_t subnet_bytes = num * sizeof(lct_subnet_t);
  uint32_t stats_bytes = num * sizeof(lct_ip_stats_t);
  printf("\nStats:\n");
  printf("Read %'d unique subnets using %u %s memory for subnet descriptors and %u %s for ephemeral IP stats.\n",
         num,
         subnet_bytes / ((subnet_bytes > 1024) ? (subnet_bytes > 1024 * 1024) ? 1024 * 1024 : 1024 : 1),
         (subnet_bytes > 1024) ? (subnet_bytes > 1024 * 1024) ? "mB" : "kB" : "B",
         stats_bytes / ((stats_bytes > 1024) ? (stats_bytes > 1024 * 1024) ? 1024 * 1024 : 1024 : 1),
         (stats_bytes > 1024) ? (stats_bytes > 1024 * 1024) ? "mB" : "kB" : "B");
  printf("%'d subnets are fully allocated to subprefixes culling %1.2f%% subnets from the match count.\n",
         nfull, (100.0f * nfull) / num);
  printf("%'d optimized prefixes of %d base subnets will make a trie with %1.2f%% base leaf nodes.\n",
         nprefixes - nfull, nbases, (100.0f * nbases) / (num - nfull));
  printf("The trie will consist of %1.2f%% base subnets and %1.2f%% total subnets from the full subnet list.\n",
         (100.0f * nbases) / (num), (100.0f * (num - nfull)) / num);

  // actually build the trie and get the trie node count for statistics printing
  memset(t, 0, sizeof(lct_t));
  lct_build(t, p, num);
  uint32_t node_bytes = t->ncount * sizeof(lct_node_t) + t->bcount * sizeof(uint32_t);
  printf("The resulting trie has %'u nodes using %u %s memory.\n", t->ncount,
         node_bytes / ((node_bytes > 1024) ? (node_bytes > 1024 * 1024) ? 1024 * 1024 : 1024 : 1),
         (node_bytes > 1024) ? (node_bytes > 1024 * 1024) ? "mB" : "kB" : "B");
  printf("The trie's shortest base subnet to match is %hhu bits long\n", t->shortest);

  return 0;
}

int addr_init() {
    return lct_init_from_file((char *)"lctrie/bgp/data-raw-table");

}
