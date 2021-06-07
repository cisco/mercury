#ifndef __LC_TRIE_IP_H__
#define __LC_TRIE_IP_H__
// begin #ifndef guard

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <limits>

#include "common.h"

using ipv4_addr_t = uint32_t;
using ipv6_addr_t = __uint128_t;

#define IP_SUBNET_UNUSED      0
#define IP_SUBNET_BGP         1
#define IP_SUBNET_PRIVATE     2
#define IP_SUBNET_LINKLOCAL   3
#define IP_SUBNET_MULTICAST   4
#define IP_SUBNET_BROADCAST   5
#define IP_SUBNET_LOOPBACK    6
#define IP_SUBNET_RESERVED    7
#define IP_SUBNET_BOGON       8
#define IP_SUBNET_USER        9

#define LCT_IP_DEBUG_PREFIXES 0


// link local, multicast, loopback, and reserved have no additional
// information and thereforce only have a type

// subnet bgp has a 32-bit AS number
typedef struct lct_subnet_bgp_t {
  uint32_t type;
  uint32_t asn;
} lct_subnet_bgp_t;

// RFC1918 private IP subnets have a
typedef struct lct_subnet_private_t {
  uint32_t type;
  char net_class;
} lct_subnet_private_t;

// RFC5735 reserved IP subnets
typedef struct lct_subnet_reserved_t {
  uint32_t type;
  const char *desc;
} lct_subnet_reserved_t;

// User customized IP subnets (host groupings)
typedef struct lct_subnet_usr_t {
  uint32_t type;
  const void *data;
} lct_subnet_usr_t;

// union representing all possible subnet info types
typedef union lct_subnet_info {
  uint32_t type;
  lct_subnet_bgp_t bgp;
  lct_subnet_private_t priv;
  lct_subnet_reserved_t rsv;
  lct_subnet_usr_t usr;
} lct_subnet_info_t;

// subnet types
#define IP_BASE         0
#define IP_PREFIX       1
#define IP_PREFIX_FULL  2 // prefix full exhausted by its subprefixes

// nil prefix index canary
#define IP_PREFIX_NIL   UINT32_MAX

// the actual IP subnet structure
template <typename T>
//typedef
struct lct_subnet {
  T addr;        // subnet address
  uint8_t type;         // prefix type
  uint8_t len;          // CIDR address prefix length

  // index to our next highest prefix, .  this limits us to about 4 billion
  // entries, and we're not going to get close because the number of subnets
  // is always going to be less than the number of theoretical IP addresses.
  uint32_t prefix;
  uint32_t fullprefix;
  // Full prefix indexes don't cost us any extra memory on amd64, and allows
  // us to have a logical pointer to the next shortest prefix match while
  // also having an optimized pointer to the next prefix group we could
  // possibly match on.  It will reduce the number of short branch factor
  // interior trie nodes.

  lct_subnet_info_t info;
};
// Leave this structure unpacked so the compiler will memory align it
// in a mannder that favors fast access over memory unit size.

// ipv4 subnet
//
using lct_subnet_t = lct_subnet<uint32_t>;

// ipv6 subnet
//
using lct_subnet_v6_t = lct_subnet<__uint128_t>;


typedef struct lct_ip_stats {
  uint32_t size;  // size of the subnet
  uint32_t used;  // size of the subprefixed address space
} lct_ip_stats_t;

template <typename T> struct address_family;

template <> struct address_family<uint32_t> {
    constexpr static const int typecode = AF_INET;
};

template <> struct address_family<__uint128_t> {
    constexpr static const int typecode = AF_INET6;
};


#if 0
template <typename T>
int get_address_family() {
    int address_family = 0;
    if (typeid(T) == typeid(uint32_t)) {
        address_family = AF_INET;
    } else if (typeid(T) == typeid(__uint128_t)) {
        address_family = AF_INET6;
    } else {
        throw "unsupported address family";
    }
    return address_family;
}
#endif

// fill in user array with reserved IP subnets according to RFC 1918
// private use IP networks and RFC 3927 link local networks
//
template <typename T>
int init_private_subnets(lct_subnet<T> *subnets, size_t size) {
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
  subnets[num].addr = ntoh(subnets[num].addr);
  subnets[num].len = 8;
  ++num;

  // RFC 1918 Class B Private Addresses
  //
  subnets[num].info.type = IP_SUBNET_PRIVATE;
  subnets[num].info.priv.net_class = 'b';
  inet_pton(AF_INET, "172.16.0.0", &(subnets[num].addr));
  subnets[num].addr = ntoh(subnets[num].addr);
  subnets[num].len = 12;
  ++num;

  // RFC 1918 Class C Private Addresses
  //
  subnets[num].info.type = IP_SUBNET_PRIVATE;
  subnets[num].info.priv.net_class = 'c';
  inet_pton(AF_INET, "192.168.0.0", &(subnets[num].addr));
  subnets[num].addr = ntoh(subnets[num].addr);
  subnets[num].len = 16;
  ++num;

  // RFC 3927 Link Local Addresses
  //
  subnets[num].info.type = IP_SUBNET_LINKLOCAL;
  inet_pton(AF_INET, "169.254.0.0", &(subnets[num].addr));
  subnets[num].addr = ntoh(subnets[num].addr);
  subnets[num].len = 16;
  ++num;

  return num;
}

// fill in user array with reserved IP subnets according to RFC 5735
// minus the private IP subets from RFC 1918
//
template <typename T>
int init_special_subnets(lct_subnet<T> *subnets, size_t size) {
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
  subnets[num].addr = ntoh(subnets[num].addr);
  subnets[num].len = 8;
  ++num;

  // RFC 1122, Sect. 3.2.1.3 Loopback
  //
  subnets[num].info.type = IP_SUBNET_LOOPBACK;
  inet_pton(AF_INET, "127.0.0.0", &(subnets[num].addr));
  subnets[num].addr = ntoh(subnets[num].addr);
  subnets[num].len = 8;
  ++num;

  // RFC 5736 IETF Protocol Assignments
  //
  subnets[num].info.type = IP_SUBNET_RESERVED;
  subnets[num].info.rsv.desc = "RFC 5736 IETF Protocol Assignments";
  inet_pton(AF_INET, "192.0.0.0", &(subnets[num].addr));
  subnets[num].addr = ntoh(subnets[num].addr);
  subnets[num].len = 24;
  ++num;

  // RFC 5737 TEST-NET-1
  //
  subnets[num].info.type = IP_SUBNET_RESERVED;
  subnets[num].info.rsv.desc = "RFC 5737 TEST-NET-1";
  inet_pton(AF_INET, "192.0.2.0", &(subnets[num].addr));
  subnets[num].addr = ntoh(subnets[num].addr);
  subnets[num].len = 24;
  ++num;

  // RFC 3068 6to4 Relay Anycast
  //
  subnets[num].info.type = IP_SUBNET_RESERVED;
  subnets[num].info.rsv.desc = "RFC 3068 6to4 Relay Anycast";
  inet_pton(AF_INET, "192.88.99.0", &(subnets[num].addr));
  subnets[num].addr = ntoh(subnets[num].addr);
  subnets[num].len = 24;
  ++num;

  // RFC 2544 Network Interconnect Device Benchmark Testing
  //
  subnets[num].info.type = IP_SUBNET_RESERVED;
  subnets[num].info.rsv.desc = "RFC 2544 Network Interconnect Device Benchmark Testing";
  inet_pton(AF_INET, "198.18.0.0", &(subnets[num].addr));
  subnets[num].addr = ntoh(subnets[num].addr);
  subnets[num].len = 15;
  ++num;

  // RFC 5737 TEST-NET-2
  //
  subnets[num].info.type = IP_SUBNET_RESERVED;
  subnets[num].info.rsv.desc = "RFC 5737 TEST-NET-2";
  inet_pton(AF_INET, "198.51.100.0", &(subnets[num].addr));
  subnets[num].addr = ntoh(subnets[num].addr);
  subnets[num].len = 24;
  ++num;

  // RFC 5737 TEST-NET-3
  //
  subnets[num].info.type = IP_SUBNET_RESERVED;
  subnets[num].info.rsv.desc = "RFC 5737 TEST-NET-3";
  inet_pton(AF_INET, "203.0.113.0", &(subnets[num].addr));
  subnets[num].addr = ntoh(subnets[num].addr);
  subnets[num].len = 24;
  ++num;

  // RFC 3171 Multicast Addresses
  //
  subnets[num].info.type = IP_SUBNET_MULTICAST;
  inet_pton(AF_INET, "224.0.0.0", &(subnets[num].addr));
  subnets[num].addr = ntoh(subnets[num].addr);
  subnets[num].len = 4;
  ++num;

  // RFC 1112, Section 4 Reserved for Future Use
  //
  subnets[num].info.type = IP_SUBNET_RESERVED;
  subnets[num].info.rsv.desc = "RFC 1112, Section 4 Reserved for Future Use";
  inet_pton(AF_INET, "240.0.0.0", &(subnets[num].addr));
  subnets[num].addr = ntoh(subnets[num].addr);
  subnets[num].len = 4;
  ++num;

  // RFC 919/922, Section 7 Limited Broadcast Address
  //
  subnets[num].info.type = IP_SUBNET_BROADCAST;
  inet_pton(AF_INET, "255.255.255.255", &(subnets[num].addr));
  subnets[num].addr = ntoh(subnets[num].addr);
  subnets[num].len = 32;
  ++num;

  return num;
}

inline void fprint_addr(FILE *f, const char *key, const uint32_t *addr) {
    const uint8_t *n = (const uint8_t *)addr;
    fprintf(f, "%s: %u.%u.%u.%u\n", key, n[0], n[1], n[2], n[3]);
}

inline void fprint_addr(FILE *f, const char *key, const __uint128_t *addr) {
    const uint8_t *n = (const uint8_t *)addr;
    fprintf(f, "%s: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", key,
            n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7], n[8], n[9], n[10], n[11], n[12], n[13], n[14], n[15]);
}

// three-way subnet comparison for qsort
//extern int subnet_cmp(const void *di, const void *dj);

template <typename T>
int subnet_cmp(const void *di, const void *dj) {
    const lct_subnet<T> *i = (const lct_subnet<T> *) di;
    const lct_subnet<T> *j = (const lct_subnet<T> *) dj;

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



// apply netmasks to entries, should be done prior to sorting
// the array
//
template <typename T>
void subnet_mask(lct_subnet<T> *subnets, size_t size) {
    char pstr[INET6_ADDRSTRLEN], pstr2[INET6_ADDRSTRLEN];
    T prefix, prefix2;

    constexpr unsigned int bits_in_T = sizeof(T) * 8;
    for (size_t i = 0; i < size; ++i) {
        lct_subnet<T> *p = &subnets[i];

        //uint32_t netmask = 0xffffffff;
        T netmask = std::numeric_limits<T>::max();
        netmask = -1;
        if (p->len < bits_in_T) {
            for (unsigned int j = 0; j < (bits_in_T - p->len); ++j) {
                netmask &= ~((T)1 << j);
            }
        }

      T newaddr = p->addr & netmask;
      // const uint8_t *n = (const uint8_t *)&netmask;
      // fprintf(stderr, "netmask: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
      //         n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7], n[8], n[9], n[10], n[11], n[12], n[13], n[14], n[15]);
      // const uint8_t *b = (const uint8_t *)&p->addr;
      // fprintf(stderr, "addr:    %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
      //         b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
      // const uint8_t *a = (const uint8_t *)&newaddr;
      // fprintf(stderr, "newaddr: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
      //         a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);

      if (newaddr != p->addr) {
          fprint_addr(stderr, "address", &p->addr);
          fprint_addr(stderr, "netmask", &netmask);
          fprint_addr(stderr, "newaddr", &newaddr);

          prefix = hton(p->addr);
          prefix2 = hton(newaddr);
          if (!inet_ntop(address_family<T>::typecode, &(prefix), pstr, sizeof(pstr))) {
              fprintf(stderr, "ERROR: %s\n", strerror(errno));
          }
          if (!inet_ntop(address_family<T>::typecode, &(prefix2), pstr2, sizeof(pstr2))) {
              fprintf(stderr, "ERROR: %s\n", strerror(errno));
          }

          fprintf(stderr, "Subnet %s/%d has not been properly masked, should be %s/%d\n",
                  pstr, p->len, pstr2, p->len);

          p->addr = newaddr;
    }
  }
}

// de-duplicates subnets, should be run after applying netmasks
// and sorting the array.
// returns the number of duplicates removed
//
template <typename T>
size_t subnet_dedup(lct_subnet<T> *subnets, size_t size) {
  // remove duplicates
  char pstr[INET6_ADDRSTRLEN];
  T prefix;
  size_t ndup = 0;

  for (size_t i = 0, j = 1; j < size; ++i, ++j) {
    // we have a duplicate!
      if (!subnet_cmp<T>(&subnets[i], &subnets[j])) {
          prefix = hton(subnets[i].addr);
          if (!inet_ntop(address_family<T>::typecode, &(prefix), pstr, sizeof(pstr))) {
              fprintf(stderr, "ERROR: %s\n", strerror(errno));
          }

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
    printf("%zu duplicates removed\n\n", ndup);

  return ndup;
}


// is subnet s a prefix of the subnet t?
// requires the two elements to be sorted and in order according
// to subnet_cmp
template <typename T>
int subnet_isprefix(lct_subnet<T> *s, lct_subnet<T> *t) {
  return s && t &&
         (s->len == 0 || // EXTRACT() can't handle 0 bits
          (s->len <= t->len &&
           EXTRACT(0, s->len, s->addr) ==
           EXTRACT(0, s->len, t->addr)));
}


// calculates subnets that are prefixes of other subnets
// and returns the number found
//
template <typename T>
size_t subnet_prefix(lct_subnet<T> *p, lct_ip_stats_t *stats, size_t size) {
  size_t npre = 0;

  //int address_family = get_address_family<T>();

  T prefix;
#if LCT_IP_DEBUG_PREFIXES
  T prefix2;
  char pstr[INET6_ADDRSTRLEN];
  char pstr2[INET6_ADDRSTRLEN];
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
  for (size_t i = 0; i < size; ++i) {
    p[i].prefix = IP_PREFIX_NIL;
  }

  // go through and determine which subnets are prefixes of other subnets
  for (size_t i = 0; i < size; ++i) {
    size_t j = i + 1;  // fake out a psuedo second iterator
    if ((j < size) && subnet_isprefix(&p[i], &p[j])) {
#if LCT_IP_DEBUG_PREFIXES
      prefix = hton(p[i].addr);
      prefix2 = hton(p[j].addr);
      if (!inet_ntop(address_family, &(prefix), pstr, sizeof(pstr))) {
          fprintf(stderr, "ERROR: %s\n", strerror(errno));
      }
      if (!inet_ntop(address_family, &(prefix2), pstr2, sizeof(pstr2))) {
          fprintf(stderr, "ERROR: %s\n", strerror(errno));
      }

      printf("Subnet %s/%d is a prefix of subnet %s/%d\n",
             pstr, p[i].len, pstr2, p[j].len);
#endif

      // mark the prefix of the second node
      p[j].prefix = i;
      p[j].fullprefix = i;

      for (size_t k = j + 1; k < size && subnet_isprefix(&p[i], &p[k]); ++k) {
#if LCT_IP_DEBUG_PREFIXES
        prefix2 = hton(p[k].addr);
        if (!inet_ntop(address_family, &(prefix2), pstr2, sizeof(pstr2)))
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
  for (size_t i = 0; i < size; ++i) {
    // we'll walk the tree up from the bases up through their prefixes
    // the depends on prefixes with no prefix having their pre pointer
    // assigned to NUL
    if (IP_PREFIX_NIL != p[i].prefix) {
      // add the base's size to it's prefix's count
      stats[p[i].prefix].used += stats[i].size;
    }
  }

  // go through the array yet again to find full prefixes
  for (size_t i = 0; i < size; ++i ) {
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
  for (size_t i = 0; i < size; ++i ) {
    // if the prefix is fully used, mark it full
    prefix = p[i].prefix;
    if (prefix != IP_PREFIX_NIL && p[prefix].type == IP_PREFIX_FULL)
      p[i].prefix = p[prefix].prefix;
  }

  return npre;
}




// end #ifndef guard
#endif
