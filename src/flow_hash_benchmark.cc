///
/// \file flow_hash_benchmark.cc
///
/// Benchmark and distribution checks for candidate flow-key hash functions.
///
/// This is an exploratory standalone driver; it is intentionally not part of
/// the default test suite.
///
/// Copyright (c) 2026 Cisco Systems, Inc. All rights reserved.
/// License at https://github.com/cisco/mercury/blob/master/LICENSE
///

#include "libmerc/flow_key.h"
#include "libmerc/universal61.hpp"
#include "libmerc/universal61_bytes.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#if defined(__GNUC__) || defined(__clang__)
#define MERCURY_NOINLINE __attribute__((noinline))
#else
#define MERCURY_NOINLINE
#endif

namespace {

volatile uint64_t hash_sink = 0;

struct splitmix64 {
    uint64_t state;

    explicit splitmix64(uint64_t seed) : state{seed} {}

    uint64_t next() {
        uint64_t z = (state += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }
};

struct benchmark_key {
    key flow_key;
    universal61::limb_array limbs;
};

struct benchmark_string {
    std::string value;
};

uint64_t random_field_element(splitmix64 &rng) {
    const uint64_t limit = std::numeric_limits<uint64_t>::max()
        - (std::numeric_limits<uint64_t>::max() % universal61::prime);

    uint64_t value = 0;
    do {
        value = rng.next();
    } while (value >= limit);

    return value % universal61::prime;
}

universal61::flow_key_hash_secret deterministic_secret(uint64_t seed) {
    splitmix64 rng{seed};
    universal61::flow_key_hash_secret secret{{}, 0};

    for (uint64_t &value : secret.coefficient) {
        value = random_field_element(rng);
    }
    secret.offset = random_field_element(rng);
    return secret;
}

universal61::byte_hash_secret deterministic_byte_secret(uint64_t seed) {
    splitmix64 rng{seed};
    uint64_t multiplier = 0;
    while (multiplier == 0) {
        multiplier = random_field_element(rng);
    }
    return {multiplier, random_field_element(rng)};
}

MERCURY_NOINLINE uint64_t baseline_read(const benchmark_key &item);
MERCURY_NOINLINE uint64_t mercury_legacy_hash(const benchmark_key &item);

std::size_t mercury_legacy_flow_hash(const key &flow_key) {
    constexpr size_t multiplier = 2862933555777941757ULL;

    std::size_t x = 0;
    if (flow_key.ip_vers == 4) {
        const uint32_t sa = flow_key.addr.ipv4.src;
        const uint32_t da = flow_key.addr.ipv4.dst;
        const uint16_t sp = flow_key.src_port;
        const uint16_t dp = flow_key.dst_port;
        const uint8_t pr = flow_key.protocol;
        x = (static_cast<uint64_t>(sp) * da) + (static_cast<uint64_t>(dp) * sa);
        x *= multiplier;
        x += sa + da + sp + dp + pr;
        x *= multiplier;
    } else {
        uint64_t sa[2] = {};
        uint64_t da[2] = {};
        std::memcpy(sa, &flow_key.addr.ipv6.src, sizeof(sa));
        std::memcpy(da, &flow_key.addr.ipv6.dst, sizeof(da));
        const uint16_t sp = flow_key.src_port;
        const uint16_t dp = flow_key.dst_port;
        const uint8_t pr = flow_key.protocol;
        x = (static_cast<uint64_t>(sp) * da[0] * da[1])
            + (static_cast<uint64_t>(dp) * sa[0] * sa[1]);
        x *= multiplier;
        x += sa[0] + sa[1] + da[0] + da[1] + sp + dp + pr;
        x *= multiplier;
    }

    return x;
}

MERCURY_NOINLINE uint64_t baseline_read(const benchmark_key &item) {
    return item.limbs[0];
}

MERCURY_NOINLINE uint64_t mercury_legacy_hash(const benchmark_key &item) {
    return mercury_legacy_flow_hash(item.flow_key);
}

MERCURY_NOINLINE uint64_t universal_flow_hash_from_limbs(const benchmark_key &item,
                                                         const universal61::flow_key_hasher &hasher) {
    return hasher.hash_limbs_reduce_each(item.limbs);
}

MERCURY_NOINLINE uint64_t universal_flow_hash_from_limbs_accumulate(const benchmark_key &item,
                                                                    const universal61::flow_key_hasher &hasher) {
    return hasher.hash_limbs_accumulate_once(item.limbs);
}

MERCURY_NOINLINE uint64_t universal_flow_hash_from_key(const benchmark_key &item,
                                                       const universal61::flow_key_hasher &hasher) {
    return hasher.hash_limbs_accumulate_once(universal61::flow_key_to_limbs(item.flow_key));
}

MERCURY_NOINLINE uint64_t universal_flow_hash_from_key_fused(const benchmark_key &item,
                                                            const universal61::flow_key_hasher &hasher) {
    return hasher.hash64(item.flow_key);
}

MERCURY_NOINLINE uint64_t universal_byte_hash(const benchmark_string &item,
                                              const universal61::byte_hasher &hasher) {
    return hasher(item.value);
}

uint16_t nonzero_u16(uint64_t value) {
    uint16_t result = static_cast<uint16_t>(value);
    return result == 0 ? 1 : result;
}

ipv6_address make_ipv6(splitmix64 &rng) {
    ipv6_address address{{static_cast<uint32_t>(rng.next()),
                          static_cast<uint32_t>(rng.next()),
                          static_cast<uint32_t>(rng.next()),
                          static_cast<uint32_t>(rng.next())}};
    return address;
}

benchmark_key make_ipv4_random(splitmix64 &rng) {
    key flow_key{nonzero_u16(rng.next()),
                 nonzero_u16(rng.next()),
                 static_cast<uint32_t>(rng.next()),
                 static_cast<uint32_t>(rng.next()),
                 static_cast<uint8_t>((rng.next() & 1) ? 6 : 17)};
    return {flow_key, universal61::flow_key_to_limbs(flow_key)};
}

benchmark_key make_ipv6_random(splitmix64 &rng) {
    key flow_key{nonzero_u16(rng.next()),
                 nonzero_u16(rng.next()),
                 make_ipv6(rng),
                 make_ipv6(rng),
                 static_cast<uint8_t>((rng.next() & 1) ? 6 : 17)};
    return {flow_key, universal61::flow_key_to_limbs(flow_key)};
}

benchmark_key make_ipv4_port_sweep(size_t index) {
    const uint16_t src_port = static_cast<uint16_t>((index % 65535) + 1);
    const uint16_t dst_port = static_cast<uint16_t>(((index / 65535) % 65535) + 1);
    key flow_key{src_port, dst_port, 0x0a000001U, 0xc0000201U, 6};
    return {flow_key, universal61::flow_key_to_limbs(flow_key)};
}

benchmark_key make_ipv6_port_sweep(size_t index) {
    const uint16_t src_port = static_cast<uint16_t>((index % 65535) + 1);
    const uint16_t dst_port = static_cast<uint16_t>(((index / 65535) % 65535) + 1);
    const ipv6_address src{{0x20010db8U, 0x00000000U, 0x00000000U, 0x00000001U}};
    const ipv6_address dst{{0x20010db8U, 0x00000000U, 0x00000000U, 0x00000002U}};
    key flow_key{src_port, dst_port, src, dst, 6};
    return {flow_key, universal61::flow_key_to_limbs(flow_key)};
}

std::vector<benchmark_key> make_dataset(const std::string &name, size_t count, uint64_t seed) {
    std::vector<benchmark_key> keys;
    keys.reserve(count);

    splitmix64 rng{seed};
    for (size_t i = 0; i < count; i++) {
        if (name == "ipv4-random") {
            keys.push_back(make_ipv4_random(rng));
        } else if (name == "ipv6-random") {
            keys.push_back(make_ipv6_random(rng));
        } else if (name == "ipv4-port-sweep") {
            keys.push_back(make_ipv4_port_sweep(i));
        } else if (name == "ipv6-port-sweep") {
            keys.push_back(make_ipv6_port_sweep(i));
        }
    }

    return keys;
}

std::vector<benchmark_string> make_string_dataset(size_t length, size_t count, uint64_t seed) {
    std::vector<benchmark_string> strings;
    strings.reserve(count);

    splitmix64 rng{seed};
    for (size_t i = 0; i < count; i++) {
        std::string value(length, '\0');
        for (char &byte : value) {
            byte = static_cast<char>(rng.next());
        }
        strings.push_back({std::move(value)});
    }

    return strings;
}

struct latency_result {
    const char *name;
    double ns_per_hash;
    uint64_t checksum;
};

template <typename Item, typename HashFunction>
latency_result measure_latency(const char *name,
                               const std::vector<Item> &keys,
                               size_t repeats,
                               size_t trials,
                               HashFunction hash_function) {
    double best_ns_per_hash = std::numeric_limits<double>::max();
    uint64_t best_checksum = 0;

    for (size_t trial = 0; trial < trials; trial++) {
        uint64_t warmup = 0;
        for (const Item &item : keys) {
            warmup ^= hash_function(item);
        }
        hash_sink ^= warmup;

        uint64_t checksum = 0;
        const auto start = std::chrono::steady_clock::now();
        for (size_t repeat = 0; repeat < repeats; repeat++) {
            for (const Item &item : keys) {
                checksum ^= hash_function(item) + 0x9e3779b97f4a7c15ULL + (checksum << 6) + (checksum >> 2);
            }
        }
        const auto finish = std::chrono::steady_clock::now();

        hash_sink ^= checksum;

        const auto elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(finish - start).count();
        const double hash_count = static_cast<double>(keys.size()) * static_cast<double>(repeats);
        const double ns_per_hash = static_cast<double>(elapsed_ns) / hash_count;
        if (ns_per_hash < best_ns_per_hash) {
            best_ns_per_hash = ns_per_hash;
            best_checksum = checksum;
        }
    }

    return {name, best_ns_per_hash, best_checksum};
}

struct distribution_result {
    const char *name;
    double chi_square;
    double reduced_chi_square;
    double bucket_stddev;
    double collision_pair_ratio;
    uint64_t max_bucket = 0;
    uint64_t empty_buckets = 0;
};

template <typename HashFunction>
distribution_result measure_distribution(const char *name,
                                         const std::vector<benchmark_key> &keys,
                                         size_t bucket_count,
                                         HashFunction hash_function) {
    std::vector<uint64_t> buckets(bucket_count);
    for (const benchmark_key &item : keys) {
        buckets[hash_function(item) % bucket_count]++;
    }

    const double expected = static_cast<double>(keys.size()) / static_cast<double>(bucket_count);
    double chi_square = 0.0;
    double bucket_variance = 0.0;
    long double collision_pairs = 0.0L;
    uint64_t max_bucket = 0;
    uint64_t empty_buckets = 0;

    for (uint64_t count : buckets) {
        const double delta = static_cast<double>(count) - expected;
        chi_square += (delta * delta) / expected;
        bucket_variance += delta * delta;
        collision_pairs += (static_cast<long double>(count)
                            * static_cast<long double>(count - 1)) / 2.0L;
        max_bucket = std::max(max_bucket, count);
        if (count == 0) {
            empty_buckets++;
        }
    }

    const double expected_pairs = (static_cast<double>(keys.size())
                                  * static_cast<double>(keys.size() - 1))
        / (2.0 * static_cast<double>(bucket_count));
    const double observed_pairs = static_cast<double>(collision_pairs);

    return {name,
            chi_square,
            chi_square / static_cast<double>(bucket_count - 1),
            std::sqrt(bucket_variance / static_cast<double>(bucket_count)),
            observed_pairs / expected_pairs,
            max_bucket,
            empty_buckets};
}

void print_usage(const char *program) {
    std::printf("usage: %s [--count N] [--string-count N] [--repeats N] [--trials N] [--buckets N] [--seed HEX]\n", program);
    std::printf("\n");
    std::printf("default: --count 262144 --string-count 4096 --repeats 40 --trials 3 --buckets 10273 --seed 0x123456789abcdef0\n");
    std::printf("\n");
    std::printf("datasets: ipv4-random, ipv6-random, ipv4-port-sweep, ipv6-port-sweep\n");
}

bool parse_size(const char *text, size_t &value) {
    char *end = nullptr;
    const unsigned long long parsed = std::strtoull(text, &end, 0);
    if (end == text || *end != '\0') {
        return false;
    }
    value = static_cast<size_t>(parsed);
    return true;
}

bool parse_u64(const char *text, uint64_t &value) {
    char *end = nullptr;
    const unsigned long long parsed = std::strtoull(text, &end, 0);
    if (end == text || *end != '\0') {
        return false;
    }
    value = static_cast<uint64_t>(parsed);
    return true;
}

} // namespace

int main(int argc, char **argv) {
    size_t count = 262144;
    size_t string_count = 4096;
    size_t repeats = 40;
    size_t trials = 3;
    size_t bucket_count = 10273;
    uint64_t seed = 0x123456789abcdef0ULL;

    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (i + 1 >= argc) {
            print_usage(argv[0]);
            return 1;
        }
        if (std::strcmp(argv[i], "--count") == 0) {
            if (!parse_size(argv[++i], count)) {
                return 1;
            }
        } else if (std::strcmp(argv[i], "--string-count") == 0) {
            if (!parse_size(argv[++i], string_count)) {
                return 1;
            }
        } else if (std::strcmp(argv[i], "--repeats") == 0) {
            if (!parse_size(argv[++i], repeats)) {
                return 1;
            }
        } else if (std::strcmp(argv[i], "--trials") == 0) {
            if (!parse_size(argv[++i], trials)) {
                return 1;
            }
        } else if (std::strcmp(argv[i], "--buckets") == 0) {
            if (!parse_size(argv[++i], bucket_count)) {
                return 1;
            }
        } else if (std::strcmp(argv[i], "--seed") == 0) {
            if (!parse_u64(argv[++i], seed)) {
                return 1;
            }
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (count < 2 || string_count == 0 || repeats == 0 || trials == 0 || bucket_count < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const universal61::flow_key_hasher universal_hasher{deterministic_secret(seed)};
    const universal61::byte_hasher byte_hasher{
        deterministic_byte_secret(seed ^ 0x6a09e667f3bcc909ULL)};
    const std::array<std::string, 4> datasets{
        "ipv4-random",
        "ipv6-random",
        "ipv4-port-sweep",
        "ipv6-port-sweep",
    };

    std::printf("flow hash benchmark\n");
    std::printf("count=%zu string_count=%zu repeats=%zu trials=%zu buckets=%zu seed=0x%016" PRIx64 "\n",
                count, string_count, repeats, trials, bucket_count, seed);
    std::printf("\n");

    size_t errors = 0;

    for (const std::string &dataset_name : datasets) {
        std::vector<benchmark_key> keys = make_dataset(dataset_name, count, seed ^ dataset_name.size());

        const latency_result baseline_latency = measure_latency(
            "baseline-read",
            keys,
            repeats,
            trials,
            [](const benchmark_key &item) { return baseline_read(item); });
        const latency_result mercury_legacy_latency = measure_latency(
            "mercury-legacy",
            keys,
            repeats,
            trials,
            [](const benchmark_key &item) { return mercury_legacy_hash(item); });
        const latency_result universal_prepacked_reduce_latency = measure_latency(
            "universal61-prepacked-reduce",
            keys,
            repeats,
            trials,
            [&universal_hasher](const benchmark_key &item) {
                return universal_flow_hash_from_limbs(item, universal_hasher);
            });
        const latency_result universal_prepacked_accum_latency = measure_latency(
            "universal61-prepacked-accum",
            keys,
            repeats,
            trials,
            [&universal_hasher](const benchmark_key &item) {
                return universal_flow_hash_from_limbs_accumulate(item, universal_hasher);
            });
        const latency_result universal_from_key_pack_latency = measure_latency(
            "universal61-from-key-pack",
            keys,
            repeats,
            trials,
            [&universal_hasher](const benchmark_key &item) {
                return universal_flow_hash_from_key(item, universal_hasher);
            });
        const latency_result universal_from_key_fused_latency = measure_latency(
            "universal61-from-key-fused",
            keys,
            repeats,
            trials,
            [&universal_hasher](const benchmark_key &item) {
                return universal_flow_hash_from_key_fused(item, universal_hasher);
            });

        if (universal_prepacked_reduce_latency.checksum != universal_prepacked_accum_latency.checksum
            || universal_prepacked_reduce_latency.checksum != universal_from_key_pack_latency.checksum
            || universal_prepacked_reduce_latency.checksum != universal_from_key_fused_latency.checksum) {
            std::fprintf(stderr, "error: universal hash checksum mismatch for %s\n", dataset_name.c_str());
            errors++;
        }

        const distribution_result mercury_legacy_distribution = measure_distribution(
            "mercury-legacy",
            keys,
            bucket_count,
            [](const benchmark_key &item) { return mercury_legacy_hash(item); });
        const distribution_result universal_distribution = measure_distribution(
            "universal61",
            keys,
            bucket_count,
            [&universal_hasher](const benchmark_key &item) {
                return universal_flow_hash_from_limbs(item, universal_hasher);
            });

        std::printf("[%s]\n", dataset_name.c_str());
        std::printf("  latency best ns/hash:\n");
        std::printf("    %-24s %9.3f  checksum=0x%016" PRIx64 "\n",
                    baseline_latency.name, baseline_latency.ns_per_hash, baseline_latency.checksum);
        std::printf("    %-24s %9.3f  checksum=0x%016" PRIx64 "\n",
                    mercury_legacy_latency.name,
                    mercury_legacy_latency.ns_per_hash,
                    mercury_legacy_latency.checksum);
        std::printf("    %-24s %9.3f  checksum=0x%016" PRIx64 "\n",
                    universal_prepacked_reduce_latency.name,
                    universal_prepacked_reduce_latency.ns_per_hash,
                    universal_prepacked_reduce_latency.checksum);
        std::printf("    %-24s %9.3f  checksum=0x%016" PRIx64 "\n",
                    universal_prepacked_accum_latency.name,
                    universal_prepacked_accum_latency.ns_per_hash,
                    universal_prepacked_accum_latency.checksum);
        std::printf("    %-24s %9.3f  checksum=0x%016" PRIx64 "\n",
                    universal_from_key_pack_latency.name,
                    universal_from_key_pack_latency.ns_per_hash,
                    universal_from_key_pack_latency.checksum);
        std::printf("    %-24s %9.3f  checksum=0x%016" PRIx64 "\n",
                    universal_from_key_fused_latency.name,
                    universal_from_key_fused_latency.ns_per_hash,
                    universal_from_key_fused_latency.checksum);

        std::printf("  bucket distribution:\n");
        std::printf("    %-16s chi2=%10.2f reduced_chi2=%7.3f stddev=%7.3f max=%" PRIu64
                    " empty=%" PRIu64 " collision_pair_ratio=%7.3f\n",
                    mercury_legacy_distribution.name,
                    mercury_legacy_distribution.chi_square,
                    mercury_legacy_distribution.reduced_chi_square,
                    mercury_legacy_distribution.bucket_stddev,
                    mercury_legacy_distribution.max_bucket,
                    mercury_legacy_distribution.empty_buckets,
                    mercury_legacy_distribution.collision_pair_ratio);
        std::printf("    %-16s chi2=%10.2f reduced_chi2=%7.3f stddev=%7.3f max=%" PRIu64
                    " empty=%" PRIu64 " collision_pair_ratio=%7.3f\n",
                    universal_distribution.name,
                    universal_distribution.chi_square,
                    universal_distribution.reduced_chi_square,
                    universal_distribution.bucket_stddev,
                    universal_distribution.max_bucket,
                    universal_distribution.empty_buckets,
                    universal_distribution.collision_pair_ratio);
        std::printf("\n");
    }

    std::printf("byte-string hash benchmark\n");
    std::printf("  count=%zu lengths=0,1,7,8,16,32,64,128,256,512,1024,2048\n", string_count);
    std::printf("  latency best ns/hash:\n");
    const std::array<size_t, 12> string_lengths{{0, 1, 7, 8, 16, 32, 64, 128, 256, 512, 1024, 2048}};
    for (size_t length : string_lengths) {
        const std::vector<benchmark_string> strings = make_string_dataset(
            length, string_count, seed ^ length);
        const latency_result standard_latency = measure_latency(
            "std::hash<string>",
            strings,
            repeats,
            trials,
            [](const benchmark_string &item) {
                return std::hash<std::string>{}(item.value);
            });
        const latency_result universal_latency = measure_latency(
            "universal61::byte_hasher",
            strings,
            repeats,
            trials,
            [&byte_hasher](const benchmark_string &item) {
                return universal_byte_hash(item, byte_hasher);
            });

        std::printf("    length=%4zu  %-27s %9.3f  checksum=0x%016" PRIx64 "\n",
                    length,
                    standard_latency.name,
                    standard_latency.ns_per_hash,
                    standard_latency.checksum);
        std::printf("    length=%4zu  %-27s %9.3f  checksum=0x%016" PRIx64 "\n",
                    length,
                    universal_latency.name,
                    universal_latency.ns_per_hash,
                    universal_latency.checksum);
    }

    return errors != 0 || hash_sink == std::numeric_limits<uint64_t>::max() ? 2 : 0;
}
