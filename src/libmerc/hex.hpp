/// \file hex.hpp
///
/// The user-defined literals `_hex` and `_hexvector` declare a
/// `std::array<uint8_t,N>` and a `std::vector<uint8_t>`,
/// respectively.  Examples:
///
/// \code
///   constexpr std::array a = 0x0123456789abcdef_hex;
///
///   std::array<uint8_t, 8> b = 0x0123456789abcdef_hex;
///
///   auto c = 0x0123456789abcdef_hex;
///
///   std::vector<uint8_t> d = 0x0123456789abcdef_hexvector;
///
///   constexpr std::array<uint8_t, 144> PLAINTEXT
///        = 0x8177d79c8f239178186b4dc5f1df2ea7fee7d0db535489ef983aefb3b2029aeb_hex
///        + 0xa0bb2b46a2b18c94a1417a33cbeb41ca7ea9c73a677fccd2eb5470c3c500f6d3_hex
///        + 0xf1a6c755c944ba586f88921f6ae6c9d194e78c7233c406126633e144c3810ad2_hex
///        + 0x3ee1b5af4c04a22d49e99e7017f74c2309492569ff49be17d2804920f2ac5f51_hex
///        + 0x4d13fd3e7318cc7cf80ca5101a465428_hex;
/// \endcode
///
/// To use these functions, `#include "libmerc/hex.hpp"`.  The
/// implementation is a self-contained header-only library.
///
/// C++17 or a later version is required.
///
/// \note For background on user-defined literals, see
/// https://en.cppreference.com/w/cpp/language/user_literal.
///

#ifndef HEX_HPP
#define HEX_HPP

#if (__cplusplus < 201703L)
#error "hex.hpp requires C++17 or later"
#endif

#include <cstdint>
#include <array>
#include <vector>
#include <stdexcept>

//
// \cond EXCLUDE_FROM_DOXYGEN
//

// class hex_bytes represents a contiguous sequence of bytes defined
// at compile time that can be converted into a `std::array<uint8_t,
// N>` or `std::vector<uint8_t>`.
//
//
template <char... hex_digits>
class hex_bytes {

public:

    // returns a `std::array<uint8_t, N>`
    //
    static constexpr auto array() {
        constexpr std::array<char, sizeof...(hex_digits)> data{hex_digits...};
        std::array<uint8_t, (sizeof...(hex_digits) / 2)-1> result{};
        parse_hex(data.begin(), data.end(), result.begin());
        return result;
    }

    // conversion to a `std::array<uint8_t, N>`
    //
    constexpr operator std::array<uint8_t, (sizeof...(hex_digits) / 2)-1>() const {
        return array();
    }

    // returns a `std::vector<uint8_t>`
    //
    std::vector<uint8_t> vector() const {
        auto tmp = array();
        return std::vector<uint8_t>{tmp.begin(), tmp.end()};
    }

    // conversion to a `std::vector<uint8_t>`
    //
    operator std::vector<uint8_t>() const {
        return vector();
    }

private:

    // parses the characters between `begin` and `end` as a sequence
    // of hex digits (preceded by `0x` and followed by `\0`) and
    // writes the corresponding byte sequence to `out`
    //
    template <typename I, typename O>
    static constexpr auto parse_hex(I begin, I end, O out) {

        // validate input
        //
        if (end - begin <= 2) {
            throw std::logic_error{"invalid prefix"};
        }
        if (begin[0] != '0' || (begin[1] != 'x' && begin[1] != 'X')) {
            throw std::logic_error{"invalid prefix: must be 0x or 0X"};
        }
        if ((end - begin) % 2 != 0) {
            throw std::logic_error{"invalid input: number of hex digits must be even"};
        }

        // advance past the "0x" prefix
        //
        begin += 2;

        while (begin != end) {
            *out = hex_pair_value(*begin, *(begin + 1));
            begin += 2;
            ++out;
        }

        return out;
    }

public:

    // returns the value of a character interpreted as a hex digit
    //
    static constexpr uint8_t hex_value(char c) {
        if ('0' <= c && c <= '9') {
            return c - '0';
        }
        if ('A' <= c && c <= 'F') {
            return 10 + c - 'A';
        }
        if ('a' <= c && c <= 'f') {
            return 10 + c - 'a';
        }

#if defined(__GNUC__) && (__GNUC__ < 9)
#warning omitting error check to avoid g++ version < 9 bug
#else
        throw std::logic_error{"invalid hex digit"};
#endif

        //
        // the flow of execution should never get here, but we return
        // 0 in order to keep the compiler happy
        //
        return 0;
    }

    // returns the `uint8_t` corresponding to the pair of hex digits
    // \param first_digit and \param second_digit
    //
    // \example `assert(`hex_pair_value('1','a') == 0x1a);`
    //
    static constexpr uint8_t hex_pair_value(char first_digit, char second_digit) {
        return (hex_value(first_digit) << 4) | hex_value(second_digit);
    }

};

//
// \endcond
//

/// Construct a `std::array<uint8_t, N>` from the user-defined literal
/// that starts with `0x`, contains an even number of hexadecimal
/// digit characters, and ends with `_hex`.  Uppercase or lowercase
/// letters may be used for the `0X` prefix or the hexadecimal digits.
///
/// Example:
/// \code
///   constexpr std::array a = 0x0123456789abcdef_hex;
/// \endcode
///
template <char... hex_digits>
constexpr auto operator"" _hex() {
    static_assert(sizeof...(hex_digits) % 2 == 0, "error: number of hex digits must be even");
    return hex_bytes<hex_digits...>{}.array();
}

/// Construct a `std::vector<uint8_t>` from the user-defined literal
/// that starts with `0x`, contains an even number of hexadecimal
/// digit characters, and ends with `_hexvector`.  Uppercase letters
/// may be used for the `0X` prefix or the hexadecimal digits.
///
/// Example:
/// \code
///   std::vector<uint8_t> d = 0x0123456789abcdef_hexvector;
/// \endcode
///
template <char... hex_digits>
auto operator"" _hexvector() {
    static_assert(sizeof...(hex_digits) % 2 == 0, "error: number of hex digits must be even");
    return hex_bytes<hex_digits...>{}.vector();
}

//
// \cond EXCLUDE_FROM_DOXYGEN
//

// start of helper functions for `operator+(const
// std::array<uint8_t,M> &, std::array<uint8_t,N>)`
//
template <typename InputIt, typename OutputIt>
constexpr OutputIt constexpr_copy(InputIt first, InputIt last, OutputIt d_first) {
    while (first != last) {
        *d_first++ = *first++;
    }
    return d_first;
}

template <typename T, std::size_t... Ns>
constexpr std::array<T, (Ns + ...)> concat(const std::array<T, Ns>&... arrs) {
    std::array<T, (Ns + ...)> result{}; // Initialize with default values
    std::size_t offset = 0;

    // use a fold expression to iterate over the arrays and copy their
    // elements
    //
    ((constexpr_copy(arrs.begin(),
                     arrs.end(),
                     result.begin() + offset),
      offset += arrs.size()),
      ...);

    return result;
}

//
// \endcond
//


/// \brief Returns the concatenation of `x` and `y`
///
/// This is a convenience function that can be used with the `_hex`
/// user-defined literal to minimize redundancy or visually simplify
/// the definition of arrays across multiple lines.
///
/// \param x first input
/// \param y second input
///
/// \return The `std::array<uint8_t,P>` formed by concatenating `x`
/// and `y`, where `P = M + N` and `M` and `N` are the lengths of `x`
/// and `y`, respectively.
///
///
/// This function is `constexpr`
///
template<size_t M, size_t N>
constexpr std::array<uint8_t, M + N> operator+(const std::array<uint8_t, M> &x,
                                               const std::array<uint8_t, N> &y) {
    return concat(x,y);
}



// unit tests, available when NDEBUG is not defined
//
#ifndef NDEBUG

/// \brief Runs unit tests on the `_hex` and `_hexvector` user-defined
/// literals and returns `true` if the unit tests pass, and `false`
/// otherwise
///
inline bool hex_udl_unit_tests() {

    constexpr std::array<uint8_t, 3> array_ref{ 0xab, 0xcd, 0xef };
    constexpr std::array<uint8_t, 3> array = 0xabcdef_hex;
    if (array != array_ref) {
        return false;
    }
    auto auto_array = 0xabcdef_hex;
    if (auto_array != array_ref) {
        return false;
    }
    std::vector<uint8_t> vector = 0x0102030405060708abcdef_hexvector;
    std::vector<uint8_t> vector_ref{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xab, 0xcd, 0xef };
    if (vector != vector_ref) {
        return false;
    }
    auto auto_vector = 0x0102030405060708abcdef_hexvector;
    if (auto_vector != vector_ref) {
        return false;
    }
    auto uppercase_array = 0x51D179BF61E464841E0E8D3B56CFF2417A5F2BCCA6724F862A5F25C5C7BD9BA1_hex;
    std::array<uint8_t, 32> uppercase_array_ref{
        0x51, 0xD1, 0x79, 0xBF, 0x61, 0xE4, 0x64, 0x84,
        0x1E, 0x0E, 0x8D, 0x3B, 0x56, 0xCF, 0xF2, 0x41,
        0x7A, 0x5F, 0x2B, 0xCC, 0xA6, 0x72, 0x4F, 0x86,
        0x2A, 0x5F, 0x25, 0xC5, 0xC7, 0xBD, 0x9B, 0xA1
    };
    if (uppercase_array != uppercase_array_ref) {
        return false;
    }

    // test array concatenation operator+
    //
    constexpr auto concatenated = array_ref + array;
    std::array<uint8_t, 6> concatenated_ref{ 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef };
    if (concatenated != concatenated_ref) {
        return false;
    }

    return true;
}

#endif // NDEBUG

#endif // HEX_HPP
