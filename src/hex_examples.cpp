// hex_examples.cpp
//
// example usage of the _hex User-Defined Literal, which simplifies
// the use of statically defined byte strings.
//
// compilation: g++ -Wall hex_examples.cpp -o hex_examples


#include <cstdio>
#include <cassert>

#include "libmerc/hex.hpp"


// convenience function for printing out examples
//
template <typename T>
void print(T hex_values) {
    for (const uint8_t & x : hex_values) {
        printf("%02x", x);
    }
    fputc('\n', stdout);
}

int main(int argc, char *argv[]) {

    // to create a std::array<uint8_t, N> that is initialized to a
    // particular value, declare a `std::array` (no need to declare
    // the `uint8_t` or the `N`) and define it to be equal to the
    // user-defined literal starting with "0x", ending with "_hex",
    // and containing an even number of hexadecimal digits in between
    //
    std::array array = 0xabcdef_hex;
    print(array);

    // if you want to specify N, include the template specialization
    // `<uint8_t,N>` in the declaration
    //
    std::array<uint8_t, 3> array_with_uint8_N = 0xabcdef_hex;
    print(array_with_uint8_N);

    // you can also use `auto`, and the `_hex` user-defined literal
    // can be used in `constexpr` initializations
    //
    constexpr auto auto_array = 0xabcdef_hex;
    print(auto_array);

    // all three of the above definitions are equivalent
    assert(array == array_with_uint8_N);
    assert(array == auto_array);

    // the `_hex` user-defined literal also accepts uppercase letters
    //
    auto uppercase_array = 0x51D179BF61E464841E0E8D3B56CFF2417A5F2BCCA6724F862A5F25C5C7BD9BA1_hex;
    print(uppercase_array);

    // declaring a std::vector<uint8_t> works similarly, with the
    // `_hexvector` user-defined literal
    //
    std::vector<uint8_t> vector = 0x0102030405060708abcdef_hexvector;
    print(vector);

    // a `std::vector` of `std::vector<uint8_t>`s can be declared
    // using the _hexvector user-defined literal
    //
    std::vector<std::vector<uint8_t>> values {
        0xabcdef_hexvector,
        0x0123456789_hexvector,
    };
    for (const auto &x : values) {
        print(x);
    }

    // a `std::vector<uint8_t>` can also be declared with the auto
    //  type specifier
    //
    auto auto_vector = 0x0102030405060708abcdef_hexvector;
    print(auto_vector);

    // With very long literals, it may be desirable to introduce line
    // breaks to improve readability.  That effect can be achieved by
    // concatenating a sequence of `std::array<uint8_t>`s with `+`.
    // The apprpriate `constexpr` operator overload is provided in
    // `hex.hpp`.
    //
    // These examples are taken from the NIST CAVS 11.1 AESVS MMT test
    // data for ECB
    // (csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program)
    //
    constexpr std::array<uint8_t, 16> KEY
        = 0xb80bcc929052cb5450479442e2b809ce_hex;
    constexpr std::array<uint8_t, 144> PLAINTEXT
        = 0x8177d79c8f239178186b4dc5f1df2ea7fee7d0db535489ef983aefb3b2029aeb_hex
        + 0xa0bb2b46a2b18c94a1417a33cbeb41ca7ea9c73a677fccd2eb5470c3c500f6d3_hex
        + 0xf1a6c755c944ba586f88921f6ae6c9d194e78c7233c406126633e144c3810ad2_hex
        + 0x3ee1b5af4c04a22d49e99e7017f74c2309492569ff49be17d2804920f2ac5f51_hex
        + 0x4d13fd3e7318cc7cf80ca5101a465428_hex;
    constexpr std::array<uint8_t, 144> CIPHERTEXT
        = 0x5befb3062a7a7246af1f77b0ec0ac614e28be06ac2c81b19e5a0481bf160f9f2_hex
        + 0xbc43f28f6548787639e4ce3e0f1e95475f0e81ceb793004c8e46670ebd48b866_hex
        + 0xd5b43d104874ead4be8a236bf90b48f862f7e252dec4475fdbb841a662efcd25_hex
        + 0xed64b2910e9baaea9466e413a4241438b31df0bd3df9a16f4641636754e25986_hex
        + 0x1728aa7ddf435cc51f54f79a1db25f52_hex;
    print(KEY);
    print(PLAINTEXT);
    print(CIPHERTEXT);

    // the function hex_udl_unit_tests() is defined whenever NDEBUG is
    // not defined; it performs unit tests on the _hex user-defined
    // literal and returns true only when they all pass
    //
    assert(hex_udl_unit_tests() == true);
    printf("hex_udl_unit_tests(): %s\n", hex_udl_unit_tests() == true ? "passed" : "failed");

    return 0;
}
