/*
 * bytestring.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef BYTESTRING_H
#define BYTESTRING_H

#include <string>
#include <string_view>
#include <cstdint>

// Provide a std::char_traits<uint8_t> specialization so that
// std::basic_string<uint8_t> compiles with libc++.  Newer libc++
// versions (e.g., Apple Xcode 16.3) removed the non-standard generic
// base template for char_traits, so basic_string<uint8_t> will not
// compile without an explicit specialization.  On libstdc++ (GCC)
// the generic base template still exists and we leave it alone.
//
// _LIBCPP_VERSION is defined by libc++ (LLVM/Apple) after including
// any standard header; it is not defined by libstdc++ (GCC).
//
#ifdef _LIBCPP_VERSION
#include <cstring>   // memmove, memcpy, memset
#include <cwchar>    // std::mbstate_t
#include <iosfwd>    // std::streamoff, std::streampos
namespace std {
    template <>
    struct char_traits<uint8_t> {
        using char_type  = uint8_t;
        using int_type   = unsigned int;
        using off_type   = streamoff;
        using pos_type   = streampos;
        using state_type = mbstate_t;

        static constexpr void assign(char_type &dst, const char_type &src) noexcept { dst = src; }
        static constexpr bool eq(char_type a, char_type b) noexcept { return a == b; }
        static constexpr bool lt(char_type a, char_type b) noexcept { return a < b; }

        static constexpr int compare(const char_type *s1, const char_type *s2, size_t n) {
            for (size_t i = 0; i < n; ++i) {
                if (lt(s1[i], s2[i])) return -1;
                if (lt(s2[i], s1[i])) return  1;
            }
            return 0;
        }
        static constexpr size_t length(const char_type *s) {
            size_t n = 0;
            while (!eq(s[n], char_type())) ++n;
            return n;
        }
        static constexpr const char_type *find(const char_type *s, size_t n, const char_type &c) {
            for (size_t i = 0; i < n; ++i) {
                if (eq(s[i], c)) return s + i;
            }
            return nullptr;
        }
        static char_type *move(char_type *dst, const char_type *src, size_t n) {
            return static_cast<char_type *>(memmove(dst, src, n));
        }
        static char_type *copy(char_type *dst, const char_type *src, size_t n) {
            return static_cast<char_type *>(memcpy(dst, src, n));
        }
        static char_type *assign(char_type *dst, size_t n, char_type c) {
            return static_cast<char_type *>(memset(dst, c, n));
        }
        static constexpr int_type not_eof(int_type c) noexcept { return eq_int_type(c, eof()) ? 0 : c; }
        static constexpr char_type to_char_type(int_type c) noexcept { return static_cast<char_type>(c); }
        static constexpr int_type to_int_type(char_type c) noexcept { return static_cast<int_type>(c); }
        static constexpr bool eq_int_type(int_type a, int_type b) noexcept { return a == b; }
        static constexpr int_type eof() noexcept { return static_cast<int_type>(-1); }
    };
}
#endif // _LIBCPP_VERSION

// Tell the C++ STL how to hash a basic_string<uint8_t>, by hashing
// its raw bytes through std::hash<string_view>.
//
namespace std {
    template <>  struct hash<std::basic_string<uint8_t>>  {
        size_t operator()(const basic_string<uint8_t>& k) const {
            const char *data = reinterpret_cast<const char *>(k.data());
            return hash<string_view>{}({data, k.size()});
        }
    };
}

#endif // BYTESTRING_H
