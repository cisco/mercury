/*
 * universal61_bytes.hpp
 *
 * Keyed universal hashing for arbitrary byte strings using the universal61
 * field arithmetic.
 *
 * Copyright (c) 2026 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

/// \file universal61_bytes.hpp
///
/// \brief Keyed universal hashing for arbitrary byte strings.
///
/// \details
/// This header implements a keyed polynomial hash for byte strings over the
/// Mersenne-prime field `F_p`, where `p = 2^61 - 1`.  A byte string is encoded
/// as its length followed by little-endian seven-byte field elements.  The
/// hash evaluates that sequence with Horner's method:
///
///     h_0 = offset
///     h_{i+1} = h_i * multiplier + element_i (mod p)
///
/// The multiplier is selected from the nonzero field elements and the offset
/// is selected from the whole field.  Hashing is not cryptographic; the key is
/// intended to prevent an attacker from constructing a collision set for an
/// internal hash table without first learning the process-local secret.
///
/// Eight Horner steps are evaluated as one expression and reduced once.  For
/// eight elements `x[0] ... x[7]`, the batched expression is
///
///     h * k^8 + x[0] * k^7 + ... + x[6] * k + x[7] (mod p)
///
/// This is algebraically identical to eight individual Horner steps.  The
/// implementation also uses smaller batches for short tails and precomputes
/// powers of the multiplier when the hasher is constructed.
///
/// For two distinct encoded strings, the difference of their hash polynomials
/// is nonzero.  If the larger encoding contains `d` field elements, that
/// polynomial has at most `d - 1` roots, so a uniformly selected nonzero
/// multiplier gives collision probability at most `(d - 1) / (p - 1)`.
/// The random offset does not change this collision bound, but makes each
/// individual field output secret-dependent.
///
/// The construction follows the universal-hashing literature, especially the
/// polynomial hashing approach described by Carter and Wegman and the
/// performance considerations for string hashing described by Kaser and
/// Lemire.  The application is motivated by work on algorithmic-complexity
/// denial-of-service attacks against hash tables.
///
/// \par References
/// - J. L. Carter and M. N. Wegman, "Universal Classes of Hash Functions,"
///   Journal of Computer and System Sciences 18(2), 1979.
///   https://doi.org/10.1016/0022-0000(79)90044-8
/// - O. Kaser and D. Lemire, "Strongly Universal String Hashing is Fast,"
///   The Computer Journal 57(11), 2014.
///   https://doi.org/10.1093/comjnl/bxt070
/// - S. A. Crosby and D. S. Wallach, "Denial of Service via Algorithmic
///   Complexity Attacks," USENIX Security 2003.
///   https://static.usenix.org/event/sec03/tech/full_papers/crosby/crosby_html/
/// - N. Bar-Yosef and A. Wool, "Remote Algorithmic Complexity Attacks against
///   Randomized Hash Tables," SECRYPT 2007.
///   https://doi.org/10.5220/0002118101170124

#ifndef UNIVERSAL61_BYTES_HPP
#define UNIVERSAL61_BYTES_HPP

#include "universal61.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <random>
#include <string>
#include <string_view>

namespace universal61 {

/// \brief Secret material for a byte-string universal hash.
///
/// \details
/// The multiplier is selected from the nonzero elements of `F_p`; the offset
/// is selected from all of `F_p`.  The two values together form the
/// process-local secret for one hash table.
///
struct byte_hash_secret {
    uint64_t multiplier;
    uint64_t offset;

    /// \brief Generate byte-hash secret material from an operating-system
    /// random device.
    ///
    /// \param random_device The source of operating-system randomness.
    /// \return A randomly selected byte-hash secret.
    ///
    static byte_hash_secret from_random(std::random_device &random_device) {
        uint64_t multiplier = 0;
        while (multiplier == 0) {
            multiplier = detail::random_field_element(random_device);
        }
        return {multiplier, detail::random_field_element(random_device)};
    }
};

/// \brief Return randomly selected secret material for a byte-string hash.
///
inline byte_hash_secret random_byte_hash_secret() {
    std::random_device random_device;
    return byte_hash_secret::from_random(random_device);
}

/// \brief Incremental state for a universal61 byte hash.
///
/// \details
/// Input fields are encoded as a length followed by seven-byte little-endian
/// blocks. Seven bytes are used because every block is strictly smaller than
/// the universal61 field modulus. The little-endian representation is an
/// intentional implementation choice for the little-endian platforms on
/// which Mercury runs.
///
class byte_hash_state {
    uint64_t value;
    uint64_t multiplier;
    std::array<uint64_t, 8> powers;

    static uint64_t load_block(const char *data, size_t length) noexcept {
        uint64_t block = 0;
        std::memcpy(&block, data, length);
        return block;
    }

public:
    /// \brief Construct an empty hash state.
    ///
    /// \param hash_multiplier The nonzero field multiplier.
    /// \param hash_offset The initial field offset.
    /// \param hash_powers Powers one through eight of the multiplier.
    ///
    byte_hash_state(uint64_t hash_multiplier,
                    uint64_t hash_offset,
                    const std::array<uint64_t, 8> &hash_powers) noexcept :
        value{hash_offset},
        multiplier{hash_multiplier},
        powers{hash_powers} {}

    /// \brief Append one field element to the polynomial hash.
    ///
    /// \param field_element The field element to append.
    ///
    void append(uint64_t field_element) noexcept {
        detail::accumulator accumulator = detail::make_accumulator(field_element);
        detail::add_product(accumulator, value, multiplier);
        value = reduce_mersenne61(accumulator);
    }

    /// \brief Append two field elements with one modular reduction.
    ///
    /// \param element0 First field element to append.
    /// \param element1 Second field element to append.
    void append_two(uint64_t element0, uint64_t element1) noexcept {
        detail::accumulator accumulator = detail::make_accumulator(element1);
        detail::add_product(accumulator, value, powers[1]);
        detail::add_product(accumulator, element0, powers[0]);
        value = reduce_mersenne61(accumulator);
    }

    /// \brief Append four field elements with one modular reduction.
    ///
    /// \param element0 First field element to append.
    /// \param element1 Second field element to append.
    /// \param element2 Third field element to append.
    /// \param element3 Fourth field element to append.
    void append_four(uint64_t element0,
                     uint64_t element1,
                     uint64_t element2,
                     uint64_t element3) noexcept {
        detail::accumulator accumulator = detail::make_accumulator(element3);
        detail::add_product(accumulator, value, powers[3]);
        detail::add_product(accumulator, element0, powers[2]);
        detail::add_product(accumulator, element1, powers[1]);
        detail::add_product(accumulator, element2, powers[0]);
        value = reduce_mersenne61(accumulator);
    }

    /// \brief Append seven field elements with one modular reduction.
    ///
    /// \param element0 First field element to append.
    /// \param element1 Second field element to append.
    /// \param element2 Third field element to append.
    /// \param element3 Fourth field element to append.
    /// \param element4 Fifth field element to append.
    /// \param element5 Sixth field element to append.
    /// \param element6 Seventh field element to append.
    void append_seven(uint64_t element0,
                      uint64_t element1,
                      uint64_t element2,
                      uint64_t element3,
                      uint64_t element4,
                      uint64_t element5,
                      uint64_t element6) noexcept {
        detail::accumulator accumulator = detail::make_accumulator(element6);
        detail::add_product(accumulator, value, powers[6]);
        detail::add_product(accumulator, element0, powers[5]);
        detail::add_product(accumulator, element1, powers[4]);
        detail::add_product(accumulator, element2, powers[3]);
        detail::add_product(accumulator, element3, powers[2]);
        detail::add_product(accumulator, element4, powers[1]);
        detail::add_product(accumulator, element5, powers[0]);
        value = reduce_mersenne61(accumulator);
    }

    /// \brief Append eight field elements with one modular reduction.
    ///
    /// \details
    /// If the current value is `h`, this computes
    /// `h*k^8 + element0*k^7 + ... + element6*k + element7` modulo `p`.
    ///
    /// \param element0 First field element to append.
    /// \param element1 Second field element to append.
    /// \param element2 Third field element to append.
    /// \param element3 Fourth field element to append.
    /// \param element4 Fifth field element to append.
    /// \param element5 Sixth field element to append.
    /// \param element6 Seventh field element to append.
    /// \param element7 Eighth field element to append.
    ///
    void append_eight(uint64_t element0,
                      uint64_t element1,
                      uint64_t element2,
                      uint64_t element3,
                      uint64_t element4,
                      uint64_t element5,
                      uint64_t element6,
                      uint64_t element7) noexcept {
        detail::accumulator accumulator = detail::make_accumulator(element7);
        detail::add_product(accumulator, value, powers[7]);
        detail::add_product(accumulator, element0, powers[6]);
        detail::add_product(accumulator, element1, powers[5]);
        detail::add_product(accumulator, element2, powers[4]);
        detail::add_product(accumulator, element3, powers[3]);
        detail::add_product(accumulator, element4, powers[2]);
        detail::add_product(accumulator, element5, powers[1]);
        detail::add_product(accumulator, element6, powers[0]);
        value = reduce_mersenne61(accumulator);
    }

    /// \brief Append the platform-independent representation of a length.
    ///
    /// \details
    /// Lengths below `p` use one field element.  Larger `size_t` values use a
    /// remainder and quotient, both of which are field elements.
    ///
    /// \param length The byte length to append.
    ///
    void append_length(size_t length) noexcept {
        const uint64_t value = static_cast<uint64_t>(length);
        append(value % prime);
        if (value >= prime) {
            append(value / prime);
        }
    }

    /// \brief Append arbitrary bytes in seven-byte field blocks.
    ///
    /// \details
    /// The final partial block is zero-extended.  The preceding length field
    /// makes the encoding injective, so a string and the same string with
    /// trailing zero bytes remain distinct inputs to the polynomial hash.
    ///
    /// \param bytes The bytes to append.
    ///
    void append_bytes(std::string_view bytes) noexcept {
        const char *data = bytes.data();
        size_t remaining = bytes.size();

        while (remaining >= 56) {
            append_eight(load_block(data, 7),
                         load_block(data + 7, 7),
                         load_block(data + 14, 7),
                         load_block(data + 21, 7),
                         load_block(data + 28, 7),
                         load_block(data + 35, 7),
                         load_block(data + 42, 7),
                         load_block(data + 49, 7));
            data += 56;
            remaining -= 56;
        }
        if (remaining >= 49) {
            append_seven(load_block(data, 7),
                         load_block(data + 7, 7),
                         load_block(data + 14, 7),
                         load_block(data + 21, 7),
                         load_block(data + 28, 7),
                         load_block(data + 35, 7),
                         load_block(data + 42, 7));
            data += 49;
            remaining -= 49;
        }
        while (remaining >= 28) {
            append_four(load_block(data, 7),
                        load_block(data + 7, 7),
                        load_block(data + 14, 7),
                        load_block(data + 21, 7));
            data += 28;
            remaining -= 28;
        }
        while (remaining >= 14) {
            append_two(load_block(data, 7), load_block(data + 7, 7));
            data += 14;
            remaining -= 14;
        }
        if (remaining > 7) {
            append_two(load_block(data, 7), load_block(data + 7, remaining - 7));
            return;
        }
        if (remaining == 7) {
            append(load_block(data, 7));
            return;
        }
        if (remaining != 0) {
            append(load_block(data, remaining));
        }
    }

    /// \brief Return the current field hash value.
    ///
    /// \return The hash value in `[0, prime)`.
    ///
    uint64_t finish() const noexcept {
        return value;
    }
};

/// \brief Stateful universal61 hash for arbitrary byte strings.
///
/// \details
/// A hasher owns one secret for one hash table. Hashing performs no allocation
/// and does not access the random device; random material is obtained only
/// while constructing the hasher.  The multiplier powers used by the batched
/// evaluator are also computed once during construction.
///
class byte_hasher {
    uint64_t multiplier;
    uint64_t offset;
    std::array<uint64_t, 8> powers;

public:
    /// \brief Construct a hasher with fresh process-local key material.
    ///
    byte_hasher() : byte_hasher{random_byte_hash_secret()} {}

    /// \brief Construct a hasher from explicit secret material.
    ///
    /// \param secret The multiplier and offset to use.  Values are normalized
    ///                 into the field; a zero multiplier is replaced by one.
    ///
    explicit byte_hasher(const byte_hash_secret &secret) noexcept :
        multiplier{secret.multiplier % prime},
        offset{secret.offset % prime},
        powers{} {
        if (multiplier == 0) {
            multiplier = 1;
        }
        powers[0] = multiplier;
        for (size_t i = 1; i < powers.size(); i++) {
            powers[i] = reduce_mersenne61(
                detail::multiply_64_to_128(powers[i - 1], multiplier));
        }
    }

    /// \brief Begin an incremental hash using this hasher's secret.
    ///
    /// \return A hash state initialized with this hasher's secret.
    ///
    byte_hash_state begin() const noexcept {
        return {multiplier, offset, powers};
    }

    /// \brief Hash arbitrary bytes.
    ///
    /// \param bytes The bytes to hash.
    /// \return The hash value converted to `std::size_t`.
    ///
    std::size_t hash(std::string_view bytes) const noexcept {
        byte_hash_state state = begin();
        state.append_length(bytes.size());
        state.append_bytes(bytes);
        return static_cast<std::size_t>(state.finish());
    }

    /// \brief Hash a string for standard unordered containers.
    ///
    /// \param value The string to hash.
    /// \return The hash value converted to `std::size_t`.
    ///
    std::size_t operator()(const std::string &value) const noexcept {
        return hash(std::string_view{value});
    }
};

// LCOV_EXCL_START
/// \brief Test byte hashing against deterministic known-answer vectors.
///
/// \return True if all byte-hash checks pass.
///
inline bool byte_unit_test() noexcept {
    const byte_hasher hasher{{
        0x0123456789abcdefULL,
        0x0f0e0d0c0b0a0908ULL,
    }};

    const std::array<uint64_t, 11> expected{{
        0x019e64444f972c1fULL,
        0x0e897cdc88086e39ULL,
        0x1646e1e93c6471d3ULL,
        0x069d73298289e943ULL,
        0x13abaa48af503b72ULL,
        0x109fb0a9a4056ddbULL,
        0x1cf03127e77b64a3ULL,
        0x08be8f5a7253c9b9ULL,
        0x1fca010363675982ULL,
        0x1a79455b0a6c5f14ULL,
        0x1dab1944a10cad68ULL,
    }};
    std::array<char, 128> data{};
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = static_cast<char>(i * 37 + 11);
    }

    const std::array<size_t, 11> lengths{{0, 1, 7, 8, 14, 15, 28, 49, 56, 64, 128}};
    for (size_t i = 0; i < lengths.size(); i++) {
        if (hasher.hash({data.data(), lengths[i]}) != expected[i]) {
            return false;
        }
    }

    const char embedded_nul[] = {'a', '\0', 'b'};
    if (hasher.hash({embedded_nul, sizeof(embedded_nul)})
        == hasher.hash(std::string_view{"a"})) {
        return false;
    }

    byte_hash_state state = hasher.begin();
    state.append_length(15);
    state.append_bytes({data.data(), 15});
    if (state.finish() != expected[5]) {
        return false;
    }

    return true;
}
// LCOV_EXCL_STOP

} // namespace universal61

#endif // UNIVERSAL61_BYTES_HPP
