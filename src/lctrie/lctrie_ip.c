#include "lctrie_ip.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>


int subnet_cmp(const void *di, const void *dj) {
  const lct_subnet_t *i = (const lct_subnet_t *) di;
  const lct_subnet_t *j = (const lct_subnet_t *) dj;

  if (i->addr < j->addr)
    return -1;
  else if (i->addr > j->addr)
    return 1;
  else if (i->len < j->len)
    return -1;
  else if (i->len > j->len)
    return 1;
  else
    return 0;
}

int subnet_isprefix(lct_subnet_t *s, lct_subnet_t *t) {
  return s && t &&
         (s->len == 0 || // EXTRACT() can't handle 0 bits
          (s->len <= t->len &&
           EXTRACT(0, s->len, s->addr) ==
           EXTRACT(0, s->len, t->addr)));
}

void subnet_mask(lct_subnet_t *subnets, size_t size) {
  char pstr[INET_ADDRSTRLEN], pstr2[INET_ADDRSTRLEN];
  uint32_t prefix, prefix2;

  for (int i = 0; i < size; ++i) {
    lct_subnet_t *p = &subnets[i];

    uint32_t netmask = 0xffffffff;
    if (p->len < 32)
      for (int j = 0; j < (32 - p->len); ++j)
        netmask &= ~(1 << j);

    uint32_t newaddr = p->addr & netmask;
    if (newaddr != p->addr) {
      prefix = htonl(p->addr);
      prefix2 = htonl(newaddr);
      if (!inet_ntop(AF_INET, &(prefix), pstr, sizeof(pstr)))
        fprintf(stderr, "ERROR: %s\n", strerror(errno));
      if (!inet_ntop(AF_INET, &(prefix2), pstr2, sizeof(pstr2)))
        fprintf(stderr, "ERROR: %s\n", strerror(errno));

      fprintf(stderr, "Subnet %s/%d has not been properly masked, should be %s/%d\n",
              pstr, p->len, pstr2, p->len);

      p->addr = newaddr;
    }
  }
}

size_t subnet_dedup(lct_subnet_t *subnets, size_t size) {
  // remove duplicates
  char pstr[INET_ADDRSTRLEN];
  uint32_t prefix;
  size_t ndup = 0;

  for (int i = 0, j = 1; j < size; ++i, ++j) {
    // we have a duplicate!
    if (!subnet_cmp(&subnets[i], &subnets[j])) {
      prefix = htonl(subnets[i].addr);
      if (!inet_ntop(AF_INET, &(prefix), pstr, sizeof(pstr)))
        fprintf(stderr, "ERROR: %s\n", strerror(errno));

      printf("Subnet %s/%d type %d duplicates another of type %d\n",
             pstr, subnets[i].len, subnets[i].info.type, subnets[j].info.type);

      // assume that the prior defined subnet is the desired one,
      // dis-allowing redefinition of that subnet elsewhere,
      // ex. bogon file, BGP ASN list, user specified subnets
      //
      // slide the rest of the array over the second value.  if we're at the
      // end of the array, just let it drop off.
      if ((j + 1) < size)
        memmove(&subnets[j], &subnets[j + 1], (size - (j + 1)) * sizeof(lct_subnet_t));
      --size;
      ++ndup;
    }
  }

  if (ndup)
    printf("%lu duplicates removed\n\n", ndup);

  return ndup;
}

size_t subnet_prefix(lct_subnet_t *p, lct_ip_stats_t *stats, size_t size) {
  size_t npre = 0;

  uint32_t prefix;
#if LCT_IP_DEBUG_PREFIXES
  uint32_t prefix2;
  char pstr[INET_ADDRSTRLEN];
  char pstr2[INET_ADDRSTRLEN];
#endif

  // if the array in p is shrunk in any way, it invalidates
  // the prefix indexes in the table and forces us to recaculate
  // over again.
  //
  // we could remove this restriction if we stored a node's prefix
  // as a pointer, but that would force us to store node statistics
  // with the node instead of temporarily and throw them away later.

  // wow, this function is heavy.  real heavy, man.  no wonder
  // the internet was invented by deadhead geniuses in california, man.
  //
  // 5 full passes through the array to ensure operation
  // atomicity for the next step is necessary for the algorithm.

  // first, mark every node's prefix as invalid.
  // we can't do this consecutively with the following
  // step because an iteration can theoretically descend
  // deeper in the array to set a node's prefix index to
  // a value, and we wouldn't be able to compare that field
  // to a default canary value without first having initialized
  // everything on an initial walk through the array.
  for (int i = 0; i < size; ++i) {
    p[i].prefix = IP_PREFIX_NIL;
  }

  // go through and determine which subnets are prefixes of other subnets
  for (int i = 0; i < size; ++i) {
    int j = i + 1;  // fake out a psuedo second iterator
    if ((j < size) && subnet_isprefix(&p[i], &p[j])) {
#if LCT_IP_DEBUG_PREFIXES
      prefix = htonl(p[i].addr);
      prefix2 = htonl(p[j].addr);
      if (!inet_ntop(AF_INET, &(prefix), pstr, sizeof(pstr)))
        fprintf(stderr, "ERROR: %s\n", strerror(errno));
      if (!inet_ntop(AF_INET, &(prefix2), pstr2, sizeof(pstr2)))
        fprintf(stderr, "ERROR: %s\n", strerror(errno));

      printf("Subnet %s/%d is a prefix of subnet %s/%d\n",
             pstr, p[i].len, pstr2, p[j].len);
#endif

      // mark the prefix of the second node
      p[j].prefix = i;
      p[j].fullprefix = i;

      for (int k = j + 1; k < size && subnet_isprefix(&p[i], &p[k]); ++k) {
#if LCT_IP_DEBUG_PREFIXES
        prefix2 = htonl(p[k].addr);
        if (!inet_ntop(AF_INET, &(prefix2), pstr2, sizeof(pstr2)))
          fprintf(stderr, "ERROR: %s\n", strerror(errno));

        printf("Subnet %s/%d is also a prefix of subnet %s/%d\n",
               pstr, p[i].len, pstr2, p[k].len);
#endif
        // mark the prefix of the following node
        // if there's another more specific prefix, it will be overwritten
        // on additional passes further into the array
        p[k].prefix = i;
        p[k].fullprefix = i;
      }

      p[i].type = IP_PREFIX;
      ++npre;
    }
    else {
      p[i].type = IP_BASE;
    }
    stats[i].size = 1 << (32 - p[i].len);
    stats[i].used = 0;
  }

  // walk through the sorted array forwards to add the bases to their prefixes
  for (int i = 0; i < size; ++i) {
    // we'll walk the tree up from the bases up through their prefixes
    // the depends on prefixes with no prefix having their pre pointer
    // assigned to NUL
    if (IP_PREFIX_NIL != p[i].prefix) {
      // add the base's size to it's prefix's count
      stats[p[i].prefix].used += stats[i].size;
    }
  }

  // go through the array yet again to find full prefixes
  for (int i = 0; i < size; ++i ) {
    // if the prefix is fully used, mark it full
    if (stats[i].used == stats[i].size)
      p[i].type = IP_PREFIX_FULL;
  }

  // go through the array yet again to find full prefixes
  // and update the prefix pointer to the next non-full prefix or
  // IP_PREFIX_NIL.
  //
  // We can't do this in a consective pass since the subnet nodes don't
  // have indexes back to their base subnets.
  for (int i = 0; i < size; ++i ) {
    // if the prefix is fully used, mark it full
    prefix = p[i].prefix;
    if (prefix != IP_PREFIX_NIL && p[prefix].type == IP_PREFIX_FULL)
      p[i].prefix = p[prefix].prefix;
  }

  return npre;
}

int init_private_subnets(lct_subnet_t *subnets, size_t size) {
  if (size < 4) {
    fprintf(stderr, "Need a prefix buffer of size 15 for reserved ranges\n");
    return -1;
  }

  // 10.0.0.0/8          Private-Use Networks       RFC 1918
  // 172.16.0.0/12       Private-Use Networks       RFC 1918
  // 192.168.0.0/16      Private-Use Networks       RFC 1918
  // 169.254.0.0/16      Link Local                 RFC 3927

  // build the prefixes by hand
  int num = 0;

  // RFC 1918 Class A Private Addresses
  //
  subnets[num].info.type = IP_SUBNET_PRIVATE;
  subnets[num].info.priv.net_class = 'a';
  inet_pton(AF_INET, "10.0.0.0", &(subnets[num].addr));
  subnets[num].addr = ntohl(subnets[num].addr);
  subnets[num].len = 8;
  ++num;

  // RFC 1918 Class B Private Addresses
  //
  subnets[num].info.type = IP_SUBNET_PRIVATE;
  subnets[num].info.priv.net_class = 'b';
  inet_pton(AF_INET, "172.16.0.0", &(subnets[num].addr));
  subnets[num].addr = ntohl(subnets[num].addr);
  subnets[num].len = 12;
  ++num;

  // RFC 1918 Class C Private Addresses
  //
  subnets[num].info.type = IP_SUBNET_PRIVATE;
  subnets[num].info.priv.net_class = 'c';
  inet_pton(AF_INET, "192.168.0.0", &(subnets[num].addr));
  subnets[num].addr = ntohl(subnets[num].addr);
  subnets[num].len = 16;
  ++num;

  // RFC 3927 Link Local Addresses
  //
  subnets[num].info.type = IP_SUBNET_LINKLOCAL;
  inet_pton(AF_INET, "169.254.0.0", &(subnets[num].addr));
  subnets[num].addr = ntohl(subnets[num].addr);
  subnets[num].len = 16;
  ++num;

  return num;
}

int init_special_subnets(lct_subnet_t *subnets, size_t size) {
  if (size < 12) {
    fprintf(stderr, "Need a prefix buffer of size 12 for special ranges\n");
    return -1;
  }

  // 12 reserved address ranges according to RFC 5735 minus the RFC 1918
  // private use subnets.
  //
  // Most of these would be considered martians on a typical internet router
  // but private, multicast, broadcast, 6to4 relay anycast, and link local
  // may be typical and benign traffic seen behind an edge router, in a core
  // router, on local subnet switches.
  //
  // This list may be duplicated by other bogon filter lists, so checking
  // for duplicates between the reserved blocks and any 3rd party bogon
  // list would need to be de-duplicated before adding the ASN subnet
  // prefixes to a list
  //
  // 0.0.0.0/8           "This" Network             RFC 1122, Section 3.2.1.3
  // 127.0.0.0/8         Loopback                   RFC 1122, Section 3.2.1.3
  // 192.0.0.0/24        IETF Protocol Assignments  RFC 5736
  // 192.0.2.0/24        TEST-NET-1                 RFC 5737
  // 192.88.99.0/24      6to4 Relay Anycast         RFC 3068
  // 198.18.0.0/15       Network Interconnect
  //                     Device Benchmark Testing   RFC 2544
  // 198.51.100.0/24     TEST-NET-2                 RFC 5737
  // 203.0.113.0/24      TEST-NET-3                 RFC 5737
  // 224.0.0.0/4         Multicast                  RFC 3171
  // 240.0.0.0/4         Reserved for Future Use    RFC 1112, Section 4
  // 255.255.255.255/32  Limited Broadcast          RFC 919, Section 7
  //                                                RFC 922, Section 7

  // TODO define an x-macro so we can define this data in table form?
  // Would either need a switch case statement or a define for each type

  // just build the reservations by hand in order
  int num = 0;

  // RFC 1122, Sect. 3.2.1.3 "This" Networks
  //
  subnets[num].info.type = IP_SUBNET_RESERVED;
  subnets[num].info.rsv.desc = "RFC 1122, Sect. 3.2.1.3 \"This\" Networks";
  inet_pton(AF_INET, "0.0.0.0", &(subnets[num].addr));
  subnets[num].addr = ntohl(subnets[num].addr);
  subnets[num].len = 8;
  ++num;

  // RFC 1122, Sect. 3.2.1.3 Loopback
  //
  subnets[num].info.type = IP_SUBNET_LOOPBACK;
  inet_pton(AF_INET, "127.0.0.0", &(subnets[num].addr));
  subnets[num].addr = ntohl(subnets[num].addr);
  subnets[num].len = 8;
  ++num;

  // RFC 5736 IETF Protocol Assignments
  //
  subnets[num].info.type = IP_SUBNET_RESERVED;
  subnets[num].info.rsv.desc = "RFC 5736 IETF Protocol Assignments";
  inet_pton(AF_INET, "192.0.0.0", &(subnets[num].addr));
  subnets[num].addr = ntohl(subnets[num].addr);
  subnets[num].len = 24;
  ++num;

  // RFC 5737 TEST-NET-1
  //
  subnets[num].info.type = IP_SUBNET_RESERVED;
  subnets[num].info.rsv.desc = "RFC 5737 TEST-NET-1";
  inet_pton(AF_INET, "192.0.2.0", &(subnets[num].addr));
  subnets[num].addr = ntohl(subnets[num].addr);
  subnets[num].len = 24;
  ++num;

  // RFC 3068 6to4 Relay Anycast
  //
  subnets[num].info.type = IP_SUBNET_RESERVED;
  subnets[num].info.rsv.desc = "RFC 3068 6to4 Relay Anycast";
  inet_pton(AF_INET, "192.88.99.0", &(subnets[num].addr));
  subnets[num].addr = ntohl(subnets[num].addr);
  subnets[num].len = 24;
  ++num;

  // RFC 2544 Network Interconnect Device Benchmark Testing
  //
  subnets[num].info.type = IP_SUBNET_RESERVED;
  subnets[num].info.rsv.desc = "RFC 2544 Network Interconnect Device Benchmark Testing";
  inet_pton(AF_INET, "198.18.0.0", &(subnets[num].addr));
  subnets[num].addr = ntohl(subnets[num].addr);
  subnets[num].len = 15;
  ++num;

  // RFC 5737 TEST-NET-2
  //
  subnets[num].info.type = IP_SUBNET_RESERVED;
  subnets[num].info.rsv.desc = "RFC 5737 TEST-NET-2";
  inet_pton(AF_INET, "198.51.100.0", &(subnets[num].addr));
  subnets[num].addr = ntohl(subnets[num].addr);
  subnets[num].len = 24;
  ++num;

  // RFC 5737 TEST-NET-3
  //
  subnets[num].info.type = IP_SUBNET_RESERVED;
  subnets[num].info.rsv.desc = "RFC 5737 TEST-NET-3";
  inet_pton(AF_INET, "203.0.113.0", &(subnets[num].addr));
  subnets[num].addr = ntohl(subnets[num].addr);
  subnets[num].len = 24;
  ++num;

  // RFC 3171 Multicast Addresses
  //
  subnets[num].info.type = IP_SUBNET_MULTICAST;
  inet_pton(AF_INET, "224.0.0.0", &(subnets[num].addr));
  subnets[num].addr = ntohl(subnets[num].addr);
  subnets[num].len = 4;
  ++num;

  // RFC 1112, Section 4 Reserved for Future Use
  //
  subnets[num].info.type = IP_SUBNET_RESERVED;
  subnets[num].info.rsv.desc = "RFC 1112, Section 4 Reserved for Future Use";
  inet_pton(AF_INET, "240.0.0.0", &(subnets[num].addr));
  subnets[num].addr = ntohl(subnets[num].addr);
  subnets[num].len = 4;
  ++num;

  // RFC 919/922, Section 7 Limited Broadcast Address
  //
  subnets[num].info.type = IP_SUBNET_BROADCAST;
  inet_pton(AF_INET, "255.255.255.255", &(subnets[num].addr));
  subnets[num].addr = ntohl(subnets[num].addr);
  subnets[num].len = 32;
  ++num;

  return num;
}
