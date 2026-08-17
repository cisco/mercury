///
/// \file universal61.hpp
///
/// \brief Keyed universal hashing over flow keys.
///
/// \details
/// Hash tables that use separate chaining can be forced into worst-case lookup
/// behavior when an attacker can precompute many distinct keys that map to the
/// same hash bucket.  Crosby and Wallach describe this as an algorithmic
/// complexity denial-of-service attack and demonstrate it against network-facing
/// software.  A packet-processing flow table is a natural target because the
/// attacker may control many flow-key fields while each packet lookup must be
/// completed on the data path.
///
/// This header implements an affine multilinear hash family over the field
/// `F_p`, where `p = 2^61 - 1`.  A flow key is first packed into field elements
/// `x[0] ... x[n-1]`, each less than `p`.  A process-local secret contains
/// independently selected coefficients `a[0] ... a[n-1]` and offset `b`, and the
/// hash is
///
///     h(x) = b + sum_i a[i] * x[i] mod p.
///
/// For any two distinct packed flow keys `x != y`, the equation `h(x) = h(y)`
/// has probability exactly `1/p` over the random coefficients.  The offset also
/// makes each individual hash value uniform over `F_p`.  Thus an attacker who
/// does not know the secret cannot precompute a colliding set of flow keys
/// offline from the public source code and bucket count.  When the hash table
/// later maps the 61-bit result into its implementation-specific bucket count,
/// bucket locations are near-uniform and secret-dependent.
///
/// This is a randomized data-structure defense, not a cryptographic PRF.  If an
/// attacker had an exact oracle for raw hash values over chosen flow keys, the
/// affine structure would reveal linear equations in the secret.  In this use
/// case the exposed side channel is packet-processing latency or bucket-chain
/// effects.  Bar-Yosef and Wool studied such remote attacks against randomized
/// hash tables and showed that small secrets can be recovered by interacting
/// with a device.  Under normal OS-random keying, this implementation uses a
/// much larger per-process secret and never exposes raw hash outputs.  If OS
/// randomness is unavailable, the weak fallback is only a best-effort
/// availability measure and should not be treated as equivalent protection.
///
/// Efficient modular arithmetic is the reason for the `2^61 - 1` modulus.  For
/// a Mersenne prime `p = 2^k - 1`, `2^k == 1 (mod p)`.  A product can therefore
/// be reduced by folding high bits back into the low `k` bits instead of using a
/// division.  For `k = 61`, an accumulator `z` is reduced by adding the chunks
/// `z[0..60]`, `z[61..121]`, and the remaining top bits, then folding once more
/// if needed.  This makes the field dot product fast on 64-bit CPUs while
/// retaining the collision bound of arithmetic over a prime field.
///
/// \par References
/// - S. A. Crosby and D. S. Wallach, "Denial of Service via Algorithmic
///   Complexity Attacks," USENIX Security 2003.
///   https://static.usenix.org/event/sec03/tech/full_papers/crosby/crosby_html/
/// - N. Bar-Yosef and A. Wool, "Remote Algorithmic Complexity Attacks against
///   Randomized Hash Tables," SECRYPT 2007.
///   https://doi.org/10.5220/0002118101170124
/// - J. L. Carter and M. N. Wegman, "Universal Classes of Hash Functions,"
///   Journal of Computer and System Sciences 18(2), 1979.
///   https://doi.org/10.1016/0022-0000(79)90044-8
/// - M. N. Wegman and J. L. Carter, "New Classes and Applications of Hash
///   Functions," FOCS 1979.
///   https://research.ibm.com/publications/new-classes-and-applications-of-hash-functions
/// - T. Krovetz, "UMAC: Message Authentication Code using Universal Hashing,"
///   RFC 4418, 2006.
///   https://www.rfc-editor.org/rfc/rfc4418
/// - O. Kaser and D. Lemire, "Strongly Universal String Hashing is Fast,"
///   The Computer Journal 57(11), 2014.
///   https://doi.org/10.1093/comjnl/bxt070
/// - D. Lemire and O. Kaser, "Faster 64-bit Universal Hashing using
///   Carry-Less Multiplications," Journal of Cryptographic Engineering 6,
///   2016.
///   https://doi.org/10.1007/s13389-015-0098-8
///
/// Copyright (c) 2026 Cisco Systems, Inc. All rights reserved.
/// License: see the repository LICENSE file.
///

#ifndef UNIVERSAL61_HPP
#define UNIVERSAL61_HPP

#include "flow_key.h"
#include "random.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

#if defined(_WIN32)
#if defined(_MSC_VER)
#include <intrin.h>
#if defined(_M_X64)
#pragma intrinsic(_umul128)
#elif defined(_M_ARM64)
#pragma intrinsic(__umulh)
#endif
#endif
#endif

namespace universal61 {

/// \namespace universal61
/// \brief Pairwise-universal hashing over packed flow keys.
///
/// \details
/// The public interface exposes the field modulus, packed limb representation,
/// explicit hash secret, and stateful hasher.

/// \brief The Mersenne prime used as the universal-hash field modulus.
///
static constexpr uint64_t prime = (uint64_t{1} << 61) - 1;

/// \brief Number of field elements needed for the largest supported flow key.
///
static constexpr size_t limb_count = 6;

/// \brief Packed flow-key field elements.
///
/// Each limb is strictly smaller than \ref prime, so the array can be used as a
/// vector over the field `F_p`.
///
using limb_array = std::array<uint64_t, limb_count>;

namespace detail {

/// \namespace universal61::detail
/// \brief Implementation helpers for universal61 arithmetic and key generation.
///
/// \details
/// These helpers are kept in the header for inlining.  They are implementation
/// details and are not intended as a stable API.

#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
/// \brief Native 128-bit unsigned accumulator.
///
/// \details
/// Used on GCC/Clang targets where `unsigned __int128` is available.  The
/// numeric value is used only for bounded dot-product accumulation before the
/// final Mersenne-prime reduction.
///
using accumulator = unsigned __int128;
#else
/// \brief Portable 128-bit unsigned accumulator.
///
/// \details
/// Used on compilers without a native unsigned 128-bit integer type.  The value
/// represented is `high * 2^64 + low`.
///
struct accumulator {
    /// Low 64 bits of the accumulator.
    uint64_t low;
    /// High 64 bits of the accumulator.
    uint64_t high;
};
#endif

/// \brief Create an accumulator from a 64-bit value.
///
/// \param value The low 64-bit value to place in the accumulator.
/// \return An accumulator whose numeric value is \p value.
///
inline accumulator make_accumulator(uint64_t value) noexcept {
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
    return static_cast<accumulator>(value);
#else
    return {value, 0};
#endif
}

/// \brief Multiply two 64-bit values into a 128-bit product.
///
/// \details
/// The implementation uses native `unsigned __int128` where available, MSVC
/// intrinsics on 64-bit Windows targets, and a portable 32-bit partial-product
/// fallback otherwise.
///
/// \param left The left multiplicand.
/// \param right The right multiplicand.
/// \return The full 128-bit product `left * right`.
///
inline accumulator multiply_64_to_128(uint64_t left, uint64_t right) noexcept {
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
    return static_cast<accumulator>(left) * right;
#elif defined(_MSC_VER) && defined(_M_X64)
    uint64_t high = 0;
    const uint64_t low = _umul128(left, right, &high);
    return {low, high};
#elif defined(_MSC_VER) && defined(_M_ARM64)
    return {left * right, __umulh(left, right)};
#else
    const uint64_t left_low = static_cast<uint32_t>(left);
    const uint64_t left_high = left >> 32;
    const uint64_t right_low = static_cast<uint32_t>(right);
    const uint64_t right_high = right >> 32;

    const uint64_t product_low = left_low * right_low;
    const uint64_t product_mid1 = left_low * right_high;
    const uint64_t product_mid2 = left_high * right_low;
    const uint64_t product_high = left_high * right_high;

    const uint64_t middle = (product_low >> 32)
        + static_cast<uint32_t>(product_mid1)
        + static_cast<uint32_t>(product_mid2);
    const uint64_t low = (product_low & 0xffffffffULL) | (middle << 32);
    const uint64_t high = product_high
        + (product_mid1 >> 32)
        + (product_mid2 >> 32)
        + (middle >> 32);

    return {low, high};
#endif
}

/// \brief Add a 64-by-64 product to an accumulator.
///
/// \param accumulator_ The accumulator to update.
/// \param left The left multiplicand.
/// \param right The right multiplicand.
///
inline void add_product(accumulator &accumulator_, uint64_t left, uint64_t right) noexcept {
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
    accumulator_ += static_cast<accumulator>(left) * right;
#else
    const accumulator product = multiply_64_to_128(left, right);
    const uint64_t previous = accumulator_.low;
    accumulator_.low += product.low;
    accumulator_.high += product.high + (accumulator_.low < previous ? 1 : 0);
#endif
}

/// \brief Generate one field element for hash-key material.
///
/// \details
/// The function samples 64 random bits and rejects values in the high tail that
/// would bias reduction modulo \ref prime.  Bytes are obtained from \ref
/// os_random::fill_bytes_with_fallback, which uses the OS CSPRNG when available
/// and weak process-local entropy only if that fails.
///
/// \return A value uniformly distributed in `[0, prime)` when OS randomness is
/// available; otherwise a best-effort weak fallback value in that range.
///
inline uint64_t random_field_element() noexcept {
    const uint64_t limit = std::numeric_limits<uint64_t>::max()
        - (std::numeric_limits<uint64_t>::max() % prime);

    uint64_t value = 0;
    do {
        os_random::fill_bytes_with_fallback(&value, sizeof(value));
    } while (value >= limit);

    return value % prime;
}

} // namespace detail

/// \brief Secret coefficients for a universal61 flow-key hash.
///
struct flow_key_hash_secret {
    /// Dot-product coefficients selected in `F_p`.
    limb_array coefficient;
    /// Affine offset selected in `F_p`.
    uint64_t offset;
};

/// \brief Return a randomly keyed hash secret.
///
/// The normal path uses the operating system CSPRNG. If that is unavailable,
/// construction falls back to weak process-local entropy so that initialization
/// can continue without using a fixed public key.
///
/// \return A hash secret containing \ref limb_count coefficients and one offset.
///
inline flow_key_hash_secret random_secret() noexcept {
    flow_key_hash_secret secret{{}, 0};

    for (uint64_t &value : secret.coefficient) {
        value = detail::random_field_element();
    }
    secret.offset = detail::random_field_element();
    return secret;
}

/// \brief Reduce an accumulator modulo `2^61 - 1`.
///
/// \details
/// Since `2^61 == 1 (mod 2^61 - 1)`, high bits can be folded into the low
/// 61-bit word with shifts and additions.  The input accumulators produced by
/// this header are small enough that two folds and one conditional subtraction
/// produce the canonical field element.
///
/// \param value The accumulator to reduce.
/// \return `value mod prime`, in canonical range `[0, prime)`.
///
inline uint64_t reduce_mersenne61(detail::accumulator value) noexcept {
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
    uint64_t reduced = static_cast<uint64_t>(value & prime)
        + static_cast<uint64_t>((value >> 61) & prime)
        + static_cast<uint64_t>(value >> 122);
#else
    uint64_t reduced = (value.low & prime)
        + (((value.low >> 61) | (value.high << 3)) & prime)
        + (value.high >> 58);
#endif

    reduced = (reduced & prime) + (reduced >> 61);
    if (reduced >= prime) {
        reduced -= prime;
    }
    return reduced;
}

/// \brief Add two field elements modulo `2^61 - 1`.
///
/// \param left The left field element.
/// \param right The right field element.
/// \return `(left + right) mod prime`, in canonical range `[0, prime)`.
///
inline uint64_t add_mod_mersenne61(uint64_t left, uint64_t right) noexcept {
    uint64_t sum = left + right;
    sum = (sum & prime) + (sum >> 61);
    if (sum >= prime) {
        sum -= prime;
    }
    return sum;
}

/// \brief Pack a flow key into field elements smaller than `2^61 - 1`.
///
/// \details
/// IPv4 keys use two nonzero limbs and four zero limbs.  IPv6 keys use all six
/// limbs.  Keys whose `ip_vers` is neither 4 nor 6 are packed with zero
/// addresses, avoiding reads from an inactive union member.
///
/// \param flow_key The flow key to pack.
/// \return Field elements representing \p flow_key.
///
inline limb_array flow_key_to_limbs(const key &flow_key) noexcept {
    const uint64_t header = static_cast<uint64_t>(flow_key.ip_vers)
        | (static_cast<uint64_t>(flow_key.protocol) << 8)
        | (static_cast<uint64_t>(flow_key.src_port) << 16)
        | (static_cast<uint64_t>(flow_key.dst_port) << 32);

    std::array<uint32_t, 4> src{};
    std::array<uint32_t, 4> dst{};

    if (flow_key.ip_vers == 4) {
        src[0] = flow_key.addr.ipv4.src;
        dst[0] = flow_key.addr.ipv4.dst;
        return {
            header | (static_cast<uint64_t>(src[0] & 0x000000ffU) << 48),
            (static_cast<uint64_t>(src[0]) >> 8)
                | (static_cast<uint64_t>(dst[0]) << 24),
            0,
            0,
            0,
            0,
        };
    } else if (flow_key.ip_vers == 6) {
        for (size_t i = 0; i < src.size(); i++) {
            src[i] = flow_key.addr.ipv6.src.a[i];
            dst[i] = flow_key.addr.ipv6.dst.a[i];
        }
    }

    return {
        header | (static_cast<uint64_t>(src[0] & 0x0000000fU) << 48),
        (static_cast<uint64_t>(src[0]) >> 4)
            | (static_cast<uint64_t>(src[1] & 0x00ffffffU) << 28),
        (static_cast<uint64_t>(src[1]) >> 24)
            | (static_cast<uint64_t>(src[2]) << 8)
            | (static_cast<uint64_t>(src[3] & 0x00000fffU) << 40),
        (static_cast<uint64_t>(src[3]) >> 12)
            | (static_cast<uint64_t>(dst[0]) << 20),
        static_cast<uint64_t>(dst[1])
            | (static_cast<uint64_t>(dst[2] & 0x000fffffU) << 32),
        (static_cast<uint64_t>(dst[2]) >> 20)
            | (static_cast<uint64_t>(dst[3]) << 12),
    };
}

/// \brief Keyed pairwise-universal hash over flow keys.
///
/// \details
/// A hasher owns the secret coefficients for one hash table.  The default
/// constructor obtains a fresh secret, while the explicit constructor is
/// intended for tests and benchmarks that need a known key.  Once constructed,
/// all hashing operations are `noexcept` and perform only packing,
/// multiplication, addition, and Mersenne-prime reduction.
///
class flow_key_hasher {
    /// Dot-product coefficients in `F_p`.
    limb_array coefficient;
    /// Affine offset in `F_p`.
    uint64_t offset;

public:

    /// \brief Construct a hasher with fresh process-local key material.
    ///
    /// \details
    /// The normal path obtains the secret from the OS CSPRNG through \ref
    /// os_random::fill_bytes.  If OS randomness is unavailable, initialization
    /// falls back to weak process-local entropy through \ref
    /// os_random::fill_bytes_with_fallback.  This preserves availability and
    /// avoids a fixed public key, but the fallback does not provide the same
    /// protection as OS-random keying.
    ///
    flow_key_hasher() noexcept :
        flow_key_hasher{random_secret()} {}

    /// \brief Construct a hasher from an explicit secret.
    ///
    /// \param secret The coefficients and offset to copy into this hasher.
    ///
    explicit flow_key_hasher(const flow_key_hash_secret &secret) noexcept :
        coefficient{secret.coefficient},
        offset{secret.offset} {}

    /// \brief Hash already-packed limbs with reduction after each product.
    ///
    /// \details
    /// This reference-style path is useful for testing and benchmarking.  The
    /// production hot path should normally use \ref hash64, which fuses packing
    /// and accumulation.
    ///
    /// \param limbs The packed flow-key limbs.
    /// \return The field hash value in `[0, prime)`.
    ///
    uint64_t hash_limbs_reduce_each(const limb_array &limbs) const noexcept {
        uint64_t hash_value = offset;
        for (size_t i = 0; i < limb_count; i++) {
            const uint64_t term = reduce_mersenne61(
                detail::multiply_64_to_128(coefficient[i], limbs[i]));
            hash_value = add_mod_mersenne61(hash_value, term);
        }
        return hash_value;
    }

    /// \brief Hash already-packed limbs with one final reduction.
    ///
    /// \details
    /// Products are accumulated in a 128-bit accumulator and reduced once at the
    /// end.  This is faster than reducing each product separately while
    /// producing the same result for the bounded inputs used here.
    ///
    /// \param limbs The packed flow-key limbs.
    /// \return The field hash value in `[0, prime)`.
    ///
    uint64_t hash_limbs_accumulate_once(const limb_array &limbs) const noexcept {
        detail::accumulator accumulator = detail::make_accumulator(offset);
        for (size_t i = 0; i < limb_count; i++) {
            detail::add_product(accumulator, coefficient[i], limbs[i]);
        }
        return reduce_mersenne61(accumulator);
    }

    /// \brief Hash a flow key to a 61-bit field element.
    ///
    /// \details
    /// This is the primary hot-path implementation.  It packs IPv4 and IPv6
    /// fields directly into limbs and accumulates products without materializing
    /// a temporary \ref limb_array.
    ///
    /// \param flow_key The flow key to hash.
    /// \return The field hash value in `[0, prime)`.
    ///
    uint64_t hash64(const key &flow_key) const noexcept {
        const uint64_t header = static_cast<uint64_t>(flow_key.ip_vers)
            | (static_cast<uint64_t>(flow_key.protocol) << 8)
            | (static_cast<uint64_t>(flow_key.src_port) << 16)
            | (static_cast<uint64_t>(flow_key.dst_port) << 32);

        if (flow_key.ip_vers == 4) {
            return hash_ipv4(header, flow_key.addr.ipv4.src, flow_key.addr.ipv4.dst);
        }
        if (flow_key.ip_vers == 6) {
            return hash_ipv6(header, flow_key.addr.ipv6.src.a, flow_key.addr.ipv6.dst.a);
        }

        const uint32_t zero_address[4]{};
        return hash_ipv6(header, zero_address, zero_address);
    }

    /// \brief Hash a flow key for use by C++ hash tables.
    ///
    /// \param flow_key The flow key to hash.
    /// \return The field hash value converted to `std::size_t`.
    ///
    std::size_t operator()(const key &flow_key) const noexcept {
        return static_cast<std::size_t>(hash64(flow_key));
    }

private:

    /// \brief Hash an IPv4 flow key from already loaded scalar fields.
    ///
    /// \param header Packed version, protocol, source port, and destination port.
    /// \param src IPv4 source address in network byte order.
    /// \param dst IPv4 destination address in network byte order.
    /// \return The field hash value in `[0, prime)`.
    ///
    uint64_t hash_ipv4(uint64_t header, uint32_t src, uint32_t dst) const noexcept {
        const uint64_t limb0 = header | (static_cast<uint64_t>(src & 0x000000ffU) << 48);
        const uint64_t limb1 = (static_cast<uint64_t>(src) >> 8)
            | (static_cast<uint64_t>(dst) << 24);

        detail::accumulator accumulator = detail::make_accumulator(offset);
        detail::add_product(accumulator, coefficient[0], limb0);
        detail::add_product(accumulator, coefficient[1], limb1);
        return reduce_mersenne61(accumulator);
    }

    /// \brief Hash an IPv6 flow key from already loaded scalar fields.
    ///
    /// \param header Packed version, protocol, source port, and destination port.
    /// \param src IPv6 source address words in network byte order.
    /// \param dst IPv6 destination address words in network byte order.
    /// \return The field hash value in `[0, prime)`.
    ///
    uint64_t hash_ipv6(uint64_t header, const uint32_t src[4], const uint32_t dst[4]) const noexcept {
        const uint64_t limb0 = header | (static_cast<uint64_t>(src[0] & 0x0000000fU) << 48);
        const uint64_t limb1 = (static_cast<uint64_t>(src[0]) >> 4)
            | (static_cast<uint64_t>(src[1] & 0x00ffffffU) << 28);
        const uint64_t limb2 = (static_cast<uint64_t>(src[1]) >> 24)
            | (static_cast<uint64_t>(src[2]) << 8)
            | (static_cast<uint64_t>(src[3] & 0x00000fffU) << 40);
        const uint64_t limb3 = (static_cast<uint64_t>(src[3]) >> 12)
            | (static_cast<uint64_t>(dst[0]) << 20);
        const uint64_t limb4 = static_cast<uint64_t>(dst[1])
            | (static_cast<uint64_t>(dst[2] & 0x000fffffU) << 32);
        const uint64_t limb5 = (static_cast<uint64_t>(dst[2]) >> 20)
            | (static_cast<uint64_t>(dst[3]) << 12);

        detail::accumulator accumulator = detail::make_accumulator(offset);
        detail::add_product(accumulator, coefficient[0], limb0);
        detail::add_product(accumulator, coefficient[1], limb1);
        detail::add_product(accumulator, coefficient[2], limb2);
        detail::add_product(accumulator, coefficient[3], limb3);
        detail::add_product(accumulator, coefficient[4], limb4);
        detail::add_product(accumulator, coefficient[5], limb5);
        return reduce_mersenne61(accumulator);
    }
};

/// \brief Unit test for deterministic universal61 flow-key hashing.
///
/// \details
/// The test uses an explicit fixed secret so that it does not depend on the
/// operating-system random source.  It checks that packed limbs are valid field
/// elements and that the reference and fused hashing paths agree for IPv4,
/// IPv6, and a zeroized IPv4 key.
///
/// \return True if all universal61 self-checks pass.
///
inline bool unit_test() noexcept {
    const flow_key_hash_secret test_secret{{
        0x0123456789abcdefULL,
        0x0fedcba987654321ULL,
        0x13579bdf2468ace0ULL,
        0x1a2b3c4d5e6f7890ULL,
        0x0102030405060708ULL,
        0x1020304050607080ULL,
    }, 0x0f0e0d0c0b0a0908ULL};
    const flow_key_hasher hasher{test_secret};

    const key ipv4_key{12345, 443, 0x0a000001U, 0xc0000201U, 6};
    const ipv6_address ipv6_src{{0x20010db8U, 0x00000000U, 0x00000000U, 0x00000001U}};
    const ipv6_address ipv6_dst{{0x20010db8U, 0x00000000U, 0x00000000U, 0x00000002U}};
    const key ipv6_key{12345, 443, ipv6_src, ipv6_dst, 6};
    key zeroized_ipv4_key{12345, 443, 0x0a000001U, 0xc0000201U, 6};
    zeroized_ipv4_key.zeroize();

    const std::array<key, 3> test_keys{{ipv4_key, ipv6_key, zeroized_ipv4_key}};
    for (const key &test_key : test_keys) {
        const limb_array limbs = flow_key_to_limbs(test_key);
        for (uint64_t limb : limbs) {
            if (limb >= prime) {
                return false;
            }
        }
        const uint64_t reduce_each = hasher.hash_limbs_reduce_each(limbs);
        const uint64_t accumulate_once = hasher.hash_limbs_accumulate_once(limbs);
        const uint64_t fused = hasher.hash64(test_key);
        if (reduce_each != accumulate_once || reduce_each != fused) {
            return false;
        }
    }

    return true;
}

} // namespace universal61

#endif // UNIVERSAL61_HPP
