#include <stdlib.h>
#include <stdio.h>
#include <libgen.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <locale.h>

#include <arpa/inet.h>
#include <sys/time.h>

#include <random>

#include "lctrie_ip.h"
#include "lctrie_bgp.h"
#include "lctrie.h"


#define BGP_MAX_ENTRIES             4000000
#define BGP_READ_FILE               1

// should we initialize the special prefix ranges?
#define LCT_INIT_PRIVATE            1
#define LCT_INIT_SPECIAL            1

#define LCT_VERIFY_PREFIXES         1
#define LCT_IP_DISPLAY_PREFIXES     0

// random_ipv4_addr() and random_ipv6_addr() are helper functions for
// generating random addresses, for use in testing
//
std::random_device rd;
std::minstd_rand random_source(rd());

uint32_t random_ipv4_addr(void) {
    return random_source();
}

ipv6_addr random_ipv6_addr(void) {
    ipv6_addr tmp = 0;
    uint32_t *t = (uint32_t *)&tmp;
    t[0] = random_source();
    t[1] = random_source();
    t[2] = random_source();
    t[3] = random_source();
    return tmp;
}


template <typename T>
void print_subnet(lct_subnet<T> *subnet) {
    char pstr[INET6_ADDRSTRLEN];
    T prefix;

    if (!subnet) {
        printf("NULL, subnet not found\n");
        return;
    }

    prefix = hton(subnet->addr);
    if (typeid(T) == typeid(uint32_t)) {
        if (!inet_ntop(AF_INET, &(prefix), pstr, sizeof(pstr))) {
            fprintf(stderr, "ERROR: %s\n", strerror(errno));
            return;
        }
    } else if (typeid(T) == typeid(ipv6_addr)) {
        if (!inet_ntop(AF_INET6, &(prefix), pstr, sizeof(pstr))) {
            fprintf(stderr, "ERROR: %s\n", strerror(errno));
            return;
        }
    }

    switch (subnet->info.type) {
    case IP_SUBNET_BGP:
        printf("BGP%s prefix %s/%d for ASN %d\n", subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len,  subnet->info.bgp.asn);
        break;

    case IP_SUBNET_PRIVATE:
        printf("Private class %c%s subnet for %s/%d\n", subnet->info.priv.net_class, subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len);
        break;

    case IP_SUBNET_LINKLOCAL:
        printf("Link local%s subnet for %s/%d\n", subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len);
        break;

    case IP_SUBNET_MULTICAST:
        printf("Multicast%s subnet for %s/%d\n", subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len);
        break;

    case IP_SUBNET_BROADCAST:
        printf("Broadcast%s subnet for %s/%d\n", subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len);
        break;

    case IP_SUBNET_LOOPBACK:
        printf("Loopback%s subnet for %s/%d\n", subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len);
        break;

    case IP_SUBNET_RESERVED:
        printf("Reserved%s subnet for %s/%d, %s\n", subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len, subnet->info.rsv.desc);
        break;

    case IP_SUBNET_BOGON:
        printf("Bogon%s subnet for %s/%d\n", subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len);
        break;

    case IP_SUBNET_USER:
        printf("User%s subnet for %s/%d, %s\n", subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len, (char *) subnet->info.usr.data);
        break;

    default:
        printf("Invalid prefix type for %s/%d\n", pstr, subnet->len);
        break;
    }
}

void print_subnet_stats(lct_subnet_t *subnet, lct_ip_stats_t *stats) {
    char pstr[INET_ADDRSTRLEN];
    uint32_t prefix;

    if (!subnet || !stats) {
        printf("NULL, subnet not found\n");
        return;
    }

    prefix = hton(subnet->addr);
    if (!inet_ntop(AF_INET, &(prefix), pstr, sizeof(pstr))) {
        fprintf(stderr, "ERROR: %s\n", strerror(errno));
        return;
    }

    switch (subnet->info.type) {
    case IP_SUBNET_BGP:
        printf("BGP%s Prefix %s/%d (%d/%d) for ASN %d\n", subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len, stats->used, stats->size,  subnet->info.bgp.asn);
        break;

    case IP_SUBNET_PRIVATE:
        printf("Private Class %c%s Subnet %s/%d\n", subnet->info.priv.net_class, subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len);
        break;

    case IP_SUBNET_LINKLOCAL:
        printf("Link Local%s Subnet %s/%d\n", subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len);
        break;

    case IP_SUBNET_MULTICAST:
        printf("Multicast%s Subnet %s/%d\n", subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len);
        break;

    case IP_SUBNET_BROADCAST:
        printf("Broadcast%s Subnet %s/%d\n", subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len);
        break;

    case IP_SUBNET_LOOPBACK:
        printf("Loopback%s Subnet %s/%d\n", subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len);
        break;

    case IP_SUBNET_RESERVED:
        printf("Reserved%s Subnet %s/%d, %s\n", subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len, subnet->info.rsv.desc);
        break;

    case IP_SUBNET_BOGON:
        printf("Bogon%s Subnet %s/%d\n", subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len);
        break;

    case IP_SUBNET_USER:
        printf("User%s Subnet %s/%d, %s\n", subnet->type == IP_PREFIX_FULL ? " FULL" : "", pstr, subnet->len, (char *) subnet->info.usr.data);
        break;

    default:
        printf("Invalid subnet type for %s/%d\n", pstr, subnet->len);
        break;
    }
}

template <typename T>
int test_ipv4(char *input_file) {
    int num = 0;
    int nprefixes = 0, nbases = 0, nfull = 0;
    T prefix, localprefix;
    lct_subnet<T> *p, *subnet = NULL;
    lct<T> t;

    // we need this to get thousands separators
    setlocale(LC_NUMERIC, "");

    if (!(p = (lct_subnet<T> *)calloc(sizeof(lct_subnet<T>), BGP_MAX_ENTRIES))) {
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
    printf("Reading prefixes from %s...\n\n", input_file);
    if (0 > (rc = read_prefix_table<T>(input_file, &p[num], BGP_MAX_ENTRIES - num))) {
        fprintf(stderr, "could not read prefix file \"%s\"\n", input_file);
        return rc;
    }
    num += rc;
#endif

#if LCT_VERIFY_PREFIXES
    // Add a couple of custom prefixes.  Just use the void *data as a char *desc

    // 192.168.1.0/24 home subnet (common for SOHO wireless routers)
    p[num].info.type = IP_SUBNET_USER;
    p[num].info.usr.data = "Class A/24 home network";
    inet_pton(AF_INET, "192.168.1.0", &(p[num].addr));
    p[num].addr = ntoh(p[num].addr);
    p[num].len = 24;
    ++num;

    // 192.168.1.0/28 home sub-subnet.  used for testing address ranges
    p[num].info.type = IP_SUBNET_USER;
    p[num].info.usr.data = "Class A/24 guest network";
    inet_pton(AF_INET, "192.168.2.0", &(p[num].addr));
    p[num].addr = ntoh(p[num].addr);
    p[num].len = 24;
    ++num;

    // 192.168.1.0/28 home sub-subnet.  used for testing address ranges
    p[num].info.type = IP_SUBNET_USER;
    p[num].info.usr.data = "Class A/24 NAS network";
    inet_pton(AF_INET, "192.168.22.0", &(p[num].addr));
    p[num].addr = ntoh(p[num].addr);
    p[num].len = 24;
    ++num;
#endif

    // in a real world example, this data pointer would point to a more fleshed
    // out structure that would represent the host group

    // validate subnet prefixes against their netmasks
    // and sort the resulting array
    subnet_mask(p, num);
    qsort(p, num, sizeof(lct_subnet<T>), subnet_cmp<T>);

    // de-duplicate subnets and shrink the buffer down to its
    // actual size and split into prefixes and bases
    num -= subnet_dedup(p, num);
    p = (lct_subnet<T> *)realloc(p, num * sizeof(lct_subnet<T>));

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
    memset(&t, 0, sizeof(lct<T>));
    lct_build<T>(&t, p, num);
    uint32_t node_bytes = t.ncount * sizeof(lct_node_t) + t.bcount * sizeof(T);
    printf("The resulting trie has %'u nodes using %u %s memory.\n", t.ncount,
           node_bytes / ((node_bytes > 1024) ? (node_bytes > 1024 * 1024) ? 1024 * 1024 : 1024 : 1),
           (node_bytes > 1024) ? (node_bytes > 1024 * 1024) ? "mB" : "kB" : "B");
    printf("The trie's shortest base subnet to match is %hhu bits long\n", t.shortest);

    printf("\nBeginning test suite...\n\n");
    // TODO run some basic tests with known data sets to test that we're matching base subnets, prefix subnets
    //
    // TODO run some performance tests by looping for an interval and counting how many lookups we can make in
    //      that period.  Tally up the address types matched and print those statistics.

    const char *test_addr[] = {
                               "8.8.8.8",
                               "10.1.2.3",
                               "192.168.1.7",
                               "172.16.22.42",
                               "169.254.42.69",
                               "224.123.45.67",
                               "240.123.45.67",
                               "255.255.255.255",
#if LCT_VERIFY_PREFIXES
                               "192.168.0.0",
                               "192.168.0.255",
                               "192.168.1.0",
                               "192.168.1.1",
                               "192.168.1.2",
                               "192.168.1.3",
                               "192.168.1.4",
                               "192.168.1.7",
                               "192.168.1.8",
                               "192.168.1.15",
                               "192.168.1.16",
                               "192.168.1.31",
                               "192.168.1.32",
                               "192.168.1.63",
                               "192.168.1.64",
                               "192.168.1.127",
                               "192.168.1.128",
                               "192.168.1.255",
                               "192.168.2.128",
                               "192.168.3.128",
                               "192.168.22.128",
#endif
                               NULL
    };
    printf("Testing trie matches for some well known subnets...\n");
    for (int i = 0; test_addr[i] != NULL; ++i) {
        printf("%s is in ", test_addr[i]);

        if (!inet_pton(AF_INET, test_addr[i], (void *) &prefix)) {
            fprintf(stderr, "ERROR: %s\n", strerror(errno));
            continue;
        }

        subnet = lct_find<T>(&t, ntoh(prefix));
        print_subnet(subnet);
    }
    printf("Finished printed trie subnet matches.\n\n");

    printf("Performance testing, might take a while...\n");

    // init zero stats and seed the RNG
    unsigned int nlookup = 0, nhit = 0, nmiss = 0;
    srand(time(NULL));  // not crypto secure, but we don't need that

    // setup the start of our local range for the test
    inet_pton(AF_INET, "192.168.0.0", (void *) &localprefix);
    localprefix = ntoh(localprefix);

    // create array of random addresses to be looked up
    constexpr size_t num_addrs = 50000000;
    std::vector<ipv4_addr> address_vector;
    address_vector.reserve(num_addrs);
    for (size_t i = 0; i < num_addrs; i++) {
        address_vector.push_back(random_ipv4_addr());
    }

    // start the stop clock
    struct timeval start, now;
    gettimeofday(&start, NULL);
    for (auto a : address_vector) {
        // record the lookup, hit, and miss stats
        ++nlookup;
        subnet = lct_find(&t, a);
        if (subnet) {
            ++nhit;
        }
        else {
            ++nmiss;
        }

    }
    // get the current time
    gettimeofday(&now, NULL);
    unsigned long took_ms = 1000 * (now.tv_sec - start.tv_sec) + (now.tv_usec - start.tv_usec) / 1000;
    // timer has millisecond accuracy

    printf("Complete.\n");
    printf("%'u lookups with %'u hits and %'u misses in %ldms.\n", nlookup, nhit, nmiss,
           took_ms);
    printf("%'lu lookups/sec.\n\n", nlookup / took_ms * 1000);

    printf("Pausing to allow for system analysis.\n");
    printf("Hit enter key to continue...\n");
#ifdef PAUSE
    getc(stdin);
#endif

    // we're done with the subnets, stats, and trie;  dump them.
    lct_free<T>(&t);
    free(stats);
    free(p);

    return 0;
}

int test_ipv6(const char *input_file) {
    int num = 0;
    int nprefixes = 0, nbases = 0, nfull = 0;
    ipv6_addr prefix;
    lct_subnet<ipv6_addr> *p, *subnet = NULL;
    lct<ipv6_addr> t;

    // we need this to get thousands separators
    setlocale(LC_NUMERIC, "");

    if (!(p = (lct_subnet<ipv6_addr> *)calloc(sizeof(lct_subnet<ipv6_addr>), BGP_MAX_ENTRIES))) {
        fprintf(stderr, "Could not allocate subnet input buffer\n");
        exit(EXIT_FAILURE);
    }

    // read in the ASN prefixes
    int rc;
    printf("Reading prefixes from %s...\n\n", input_file);
    if (0 > (rc = read_prefix_table<ipv6_addr>(input_file, &p[num], BGP_MAX_ENTRIES - num))) {
        fprintf(stderr, "could not read prefix file \"%s\"\n", input_file);
        return rc;
    }
    num += rc;

    // validate subnet prefixes against their netmasks
    // and sort the resulting array
    subnet_mask(p, num);
    qsort(p, num, sizeof(lct_subnet<ipv6_addr>), subnet_cmp<ipv6_addr>);

    // de-duplicate subnets and shrink the buffer down to its
    // actual size and split into prefixes and bases
    num -= subnet_dedup<ipv6_addr>(p, num);
    p = (lct_subnet<ipv6_addr> *)realloc(p, num * sizeof(lct_subnet<ipv6_addr>));

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

    uint32_t subnet_bytes = num * sizeof(lct_subnet<ipv6_addr>);
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
    memset(&t, 0, sizeof(lct<ipv6_addr>));
    lct_build<ipv6_addr>(&t, p, num);
    uint32_t node_bytes = t.ncount * sizeof(lct_node) + t.bcount * sizeof(ipv6_addr);
    printf("The resulting trie has %'u nodes using %u %s memory.\n", t.ncount,
           node_bytes / ((node_bytes > 1024) ? (node_bytes > 1024 * 1024) ? 1024 * 1024 : 1024 : 1),
           (node_bytes > 1024) ? (node_bytes > 1024 * 1024) ? "mB" : "kB" : "B");
    printf("The trie's shortest base subnet to match is %hhu bits long\n", t.shortest);

    printf("\nBeginning test suite...\n\n");
    // TODO run some basic tests with known data sets to test that we're matching base subnets, prefix subnets
    //
    // TODO run some performance tests by looping for an interval and counting how many lookups we can make in
    //      that period.  Tally up the address types matched and print those statistics.

    const char *test_addr[] = {
                               "600:6001:ee3:1::",
                               "2002:1::",
                               "2003:1::",
                               "2001:2000:1::",
                               "2a01:1000:1::",
                               "2400:4000:1::",
                               "2a02:b000:1::",
                               "2001:1c00:1::",
                               "2c0f:fff0:1::",
                               "2001:1208:1::",
                               "2c0f:fce8:4000:1::",
                               "2001:1288:2000:1::",
                               "2c0f:fe78:5000:1::",
                               "2001:12e0:800:1::",
                               "2c0f:fb08:ff00:1::",
                               "2001:16a6:c100:1::",
                               "2c0f:f7e8:1::",
                               "2001:1200:0:1::",
                               "2a09:bd00:1fe:1::",
                               "2001:1670:8:4000:1::",
                               "2620:8f:8000:c000:1::",
                               "2001:1938:0:5000:1::",
                               "2401:7400:6801:1::",
                               "2001:418:141f:100:1::",
                               "2a01:5a8:3:1::",
                               "2620:0:50a:1::",
                               "2620:0:50a:60:1::",
                               "2001:8b0:0:40:1::",
                               "2a0b:7280:0:4:1::",
                               "2001:1490:0:1000:1::",
                               "2a00:4120:8000:70::",
                               "2403:2c00:cfff:0:0:0:0:1",
                               "2a00:1760:6007::f8",
                               "2403:2c00:7:1::1",
                               "2a03:d000:299f:e000::15",
                               NULL
    };
    printf("Testing trie matches for address various subnet prefix lengths...\n");
    for (int i = 0; test_addr[i] != NULL; ++i) {
        printf("%s is in ", test_addr[i]);

        if (!inet_pton(AF_INET6, test_addr[i], (void *) &prefix)) {
            fprintf(stderr, "ERROR: %s\n", strerror(errno));
            continue;
        }

        subnet = lct_find<ipv6_addr>(&t, ntoh(prefix));
        print_subnet(subnet);
    }
    printf("Finished printed trie subnet matches.\n\n");

    printf("Performance testing, might take a while...\n");

    // init zero stats and seed the RNG
    unsigned int nlookup = 0, nhit = 0, nmiss = 0;
    srand(time(NULL));  // not crypto secure, but we don't need that

    // create array of random addresses to be looked up
    std::vector<ipv6_addr> address_vector;
    constexpr size_t num_addrs = 50000000;
    address_vector.reserve(num_addrs);
    for (size_t i = 0; i < num_addrs; i++) {
        address_vector.push_back(random_ipv6_addr());
    }

    // start the stop clock
    struct timeval start, now;
    gettimeofday(&start, NULL);
    for (auto addr : address_vector) {
        // record the lookup, hit, and miss stats
        ++nlookup;
        subnet = lct_find(&t, addr);
        if (subnet) {
            ++nhit;
        }
        else {
            ++nmiss;
        }

    }
    // get the current time
    gettimeofday(&now, NULL);
    unsigned long took_ms = 1000 * (now.tv_sec - start.tv_sec) + (now.tv_usec - start.tv_usec) / 1000;
    // timer has millisecond accuracy

    printf("Complete.\n");
    printf("%'u IPv6 lookups with %'u hits and %'u misses in %ldms.\n", nlookup, nhit, nmiss,
           took_ms);
    printf("%'lu IPv6 lookups/sec.\n\n", nlookup / took_ms * 1000);

    printf("Pausing to allow for system analysis.\n");
    printf("Hit enter key to continue...\n");
#ifdef PAUSE
    getc(stdin);
#endif

    // we're done with the subnets, stats, and trie;  dump them.
    lct_free<ipv6_addr>(&t);
    free(stats);
    free(p);

    return 0;
}


int main(int argc, char *argv[]) {

    if (argc != 2) {
        fprintf(stderr, "usage: %s <BGP Prefixes File>\n", basename(argv[0]));
        exit(EXIT_FAILURE);
    }

    test_ipv4<uint32_t>(argv[1]);

    test_ipv6("bgp/data-raw-ipv6");

    return 0;
}
