// hex.h
//
// user-defined literals for initializing std::array objects at
// compile time

#ifndef HEX_H
#define HEX_H

#include <array>
#include <type_traits>
#include <tuple>

struct HexArrayHelper {
    static constexpr bool valid(char c) { return ('0' <= c && c <= '9') || ('A' <= c && c <= 'F') || ('a' <= c && c <= 'f'); }
    static constexpr char hex_value(char c) {
        return ('0' <= c && c <= '9') ? c - '0'
             : ('A' <= c && c <= 'F') ? c - 'A' + 10
             : c - 'a' + 10;
    }
    static constexpr char build(char a, char b) {
        return (hex_value(a) << 4) + hex_value(b);
    };
};

template <char... cs>
struct HexArray {
    static constexpr std::array<uint8_t, sizeof...(cs)> to_array() { return {cs...}; }
    //    static constexpr std::tuple<std::integral_constant<char, cs>...> to_tuple() { return {}; }
};

template <typename T, char... cs>
struct HexArrayBuilder : T {};

template <char... built, char a, char b, char... cs>
struct HexArrayBuilder<HexArray<built...>, a, b, cs...> : HexArrayBuilder<HexArray<built..., HexArrayHelper::build(a, b)>, cs...> {
    static_assert(HexArrayHelper::valid(a) && HexArrayHelper::valid(b), "Invalid hex character");
};

template <char zero, char x, char... cs>
struct HexByteArray : HexArrayBuilder<HexArray<>, cs...> {
    static_assert(zero == '0' && (x == 'x' || x == 'X'), "Invalid prefix");
    // static_assert(std::conjunction<std::bool_constant<HexArrayHelper::valid(cs)>...>::value, "Invalid hex character");
};

template <char... cs>
constexpr auto operator"" _hex() -> std::array<uint8_t, sizeof...(cs) / 2 - 1> {
    static_assert(sizeof...(cs) % 2 == 0 && sizeof...(cs) >= 2, "Must be an even number of chars");
    return HexByteArray<cs...>::to_array();
}

#endif // HEX_H
