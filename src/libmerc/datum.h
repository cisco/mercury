///
/// \file datum.h
///
/// Copyright (c) 2019-2020 Cisco Systems, Inc. All rights reserved.
/// License at https://github.com/cisco/mercury/blob/master/LICENSE
///

#ifndef DATUM_H
#define DATUM_H

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
#include <unistd.h>
#endif
#include <array>
#include <vector>
#include <bitset>
#include <limits>
#include <string>
#include <cassert>
#include <memory>
#include "buffer_stream.h"

/// `mercury_debug` is a compile-time option that turns on debugging output
///
/// the macro `mercury_debug` accepts `printf()` style arguments, and
/// prints out debugging information only if DEBUG is `#defined` at
/// compile time, and otherwise prints out nothing
///
#ifndef DEBUG
#define mercury_debug(...)
#else
#define mercury_debug(...)  (fprintf(stdout, __VA_ARGS__))
#endif

/// \defgroup byteorder Integer Byte Order Operations
/// @{
///
/// Byte re-ordering operations on `uint16_t`, `uint32_t`, and
/// `uint64_t` integers.
///

#ifndef HAVE_HTON_DEF
#define HAVE_HTON_DEF

#ifdef _WIN32

static constexpr bool host_little_endian = true;

/// returns an integer equal to x with its byte order reversed (from
/// little endian to big endian or vice-versa)
///
inline static uint16_t swap_byte_order(uint16_t x) { return _byteswap_ushort(x); }

/// returns an integer equal to x with its byte order reversed (from
/// little endian to big endian or vice-versa)
///
inline static  uint32_t swap_byte_order(uint32_t x) { return _byteswap_ulong(x); }

/// returns an integer equal to x with its byte order reversed (from
/// little endian to big endian or vice-versa)
///
inline static uint64_t swap_byte_order(uint64_t x) { return _byteswap_uint64(x); }

#else

static constexpr bool host_little_endian = (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__);

/// returns an integer equal to x with its byte order reversed (from
/// little endian to big endian or vice-versa)
///
inline static constexpr uint16_t swap_byte_order(uint16_t x) { return __builtin_bswap16(x); }

/// returns an integer equal to x with its byte order reversed (from
/// little endian to big endian or vice-versa)
///
inline static constexpr uint32_t swap_byte_order(uint32_t x) { return __builtin_bswap32(x); }

/// returns an integer equal to x with its byte order reversed (from
/// little endian to big endian or vice-versa)
///
inline static constexpr uint64_t swap_byte_order(uint64_t x) { return __builtin_bswap64(x); }

#endif

/// when `x` is in network byte order, `ntoh(x)` returns the value of
/// `x` in host byte order
///
/// Given an unsigned integer variable `x` in network byte order, the
/// template function `ntoh(x)` returns an unsigned integer in host
/// byte order with the same type and value.
///
#ifdef _WIN32
template <typename T>
inline static T ntoh(T x) { if (host_little_endian) { return swap_byte_order(x); } return x; }
#else
template <typename T>
inline static constexpr T ntoh(T x) { if (host_little_endian) { return swap_byte_order(x); } return x; }
#endif

/// when `x` is in host byte order, `hton(x)` returns the value of `x`
/// in network byte order
///
/// Given an unsigned variable `x` in host byte order, the template
/// function `hton(x)` returns an unsigned integer in network byte
/// order with the same type and value.
///
/// To apply `hton()` to an unsigned literal, use the appropriate
/// template specialization.  For instance, `hton<uint16_t>(443)`
/// obtains a `uint16_t` in network byte order for the literal 443.
/// The specialization must be used because otherwise a compiler error
/// will result from amiguity over the integer type.
///
#ifdef _WIN32
template <typename T>
inline static T hton(T x) { if (host_little_endian) { return swap_byte_order(x); } return x; }
#else
template <typename T>
inline static constexpr T hton(T x) { if (host_little_endian) { return swap_byte_order(x); } return x; }
#endif

#endif
/// @} -- end of integeroperations

/// returns the lowercase ASCII character corresponding to `x`, if `x`
/// is an uppercase ASCII character, and otherwise returns `x`.
///
inline uint8_t lowercase(uint8_t x) {
    if (x >= 'A' && x <= 'Z') {
        return x + ('a' - 'A');
    }
    return x;
}

/// \struct datum
///
/// datum is a lightweight, non-owning structure that represents a
/// readable sequence of bytes in memory, suitable for use in data
/// parsing.
///
/// Datums are well suited for use in representing data to be parsed,
/// or data resulting from a parsing.  We say that a class or function
/// *accepts* a type `T` from a datum when it successfully reads and
/// parses the bytes corresponding to `T` from the datum.
/// Each datum is in one of the states `null`, `readable`, or `empty`
///
/// A datum can be constructed
///
/// * from pointers to the bounding bytes of a region, with the
/// constructors \ref datum(const uint8_t *first, const uint8_t *last)
/// where `first` is a pointer to the first valid byte of the region,
/// and `last` is a pointer to the byte following the last valid byte of
/// the region,
///
/// * from a `std::pair` of pointers using \ref datum(std::pair<const
/// uint8_t *, const uint8_t *> p),
///
/// * by reading/accepting bytes from another datum with the
/// constructor \ref datum(datum &d, ssize_t length),
///
/// * from a `std::array<uint8_t, N>` with the constructor \ref
/// datum(const std::array<uint8_t, N> &a);
///
/// * a null datum can also be constructed with \ref datum().
///
/// To read an unsigned type `T` from a datum, use \ref encoded<T>.
///
/// To lookahead an unsigned type `T` from a datum, use \ref
/// lookahead<T>.
///
/// A datum is *non-owning* in the sense that it holds pointers to the
/// start and end of a region in memory, but does not own the memory
/// itself.  If the memory referenced by a datum is freed (e.g. by
/// `free()` or `delete`), or if the variable owning the memory goes
/// out of scope, then the datum will be invalid.
///
/// A datum contains a pointer `data` to the first byte and a pointer
/// `data_end` to the byte immediately following the last valid byte of the
/// datum.  The `data_end` element acts as a placeholder; attempting to access
/// it may result in undefined behavior.  When a datum is read, for instance
/// to accept an object, these pointers are checked to verify that
/// `data` is not `nullptr` and the operation will not read past
/// `data_end`.  When an accept operation is successful, the `data`
/// pointer is advanced.  When an accept operation fails because the
/// data does not have the correct length or format, then the datum is
/// set to a `null` state.
///
/// Each datum is in one of the states `null`, `readable`, or `empty`:
///
///   |    State        | data          |   data_end   |
///   |-----------------|---------------|--------------|
///   |    null         | `nullptr`     |   `nullptr`  |
///   |    readable     | `!= nullptr`  |   `> data`   |
///   |    empty        | `!= nullptr`  |   `== data`  |
///
/// A readable datum is not necessarily complete, in the sense that it
/// might contain data that has been truncated, such as the first ten
/// bytes of a 20-byte TCP header.
///
/// If an accept operation on a datum fails, then the datum will be
/// set to the null state.  In contrast, a lookahead operation
/// attempts to parse a type `T` from a datum, but if that attempt
/// fails, it leaves the datum unchanged.
///
/// A datum can be used in range-based for loops and other STL
/// constructs, as a sequence of `uint8_t`s, because the functions
/// \ref begin(), \ref end(), \ref cbegin(), and \ref cend() provide
/// the needed interface.
///
struct datum {
    const unsigned char *data;          ///< the start of the data in memory, or `nullptr`
    const unsigned char *data_end;      ///< the end of data in memory, or `nullptr`

    /// construct a null datum
    ///
    datum() : data{NULL}, data_end{NULL} {}

    /// construct a datum representing the sequence between `first` and `last`
    ///
    datum(const uint8_t *first, const uint8_t *last) : data{first}, data_end{last} {}

    /// construct a datum representing the null-terminated character
    /// string \param str
    ///
    explicit datum(const char *str) : data{NULL}, data_end{NULL} {
        if (str) {
            data = (uint8_t *)str;
            data_end = data + strlen(str);
        }
    }

    /// construct a datum representing the `std::string` \param str
    ///
    explicit datum(const std::string &str) : data{(uint8_t *)str.c_str()}, data_end{data + str.length()} { }

    /// construct a datum by accepting \p length bytes from datum \p d
    ///
    /// \param d      the datum to accept bytes from
    /// \param length the number of bytes to be accepted
    ///
    /// If `length < d.length()`, then \p length bytes from \p d are read and
    /// accepted into this datum, regardless of their format.
    ///
    /// If `length >  d.length()`, or `length < 0`, then \p d
    /// is set to the null state.
    ///
    datum(datum &d, ssize_t length) {
        parse(d, length);
    }

    /// constructs a datum from a `std::array` of `uint8_t`s
    ///
    template <size_t N> datum(const std::array<uint8_t, N> &a) : data{a.data()}, data_end{data + a.size()} { }

    /// constructs a datum from the C array of `uint8_t`s \param arr
    ///
    template <size_t N> datum(const uint8_t (&arr)[N]) : data{arr}, data_end{data + N} { }

    /// constructs a datum from a `std::pair` of pointers
    ///
    datum(std::pair<const uint8_t *, const uint8_t *> p) : data{p.first}, data_end{p.second} {}

    /// implicitly converts this datum to a `std::pair` of pointers
    ///
    operator std::pair<const uint8_t *, const uint8_t *> () const { return { data, data_end }; }

    /// returns a `std::string` that contains a copy of the data in this datum
    ///
    const std::string get_string() const { std::string s((char *)data, (int) (data_end - data)); return s;  }

    /// returns a `std::basic_string<uint8_t>` that contains a copy of the data in this datum
    ///
    const std::basic_string<uint8_t> get_bytestring() const { std::basic_string<uint8_t> s((uint8_t *)data, (int) (data_end - data)); return s;  }

    bool is_null() const { return data == NULL; }
    bool is_not_null() const { return data != NULL; }
    bool is_not_empty() const { return data != NULL && data < data_end; }
    bool is_readable() const { return data != NULL && data < data_end; }
    bool is_not_readable() const { return data == NULL || data == data_end; }
    bool is_empty() const { return data != NULL && data == data_end; }
    void set_empty() { data = data_end; }
    void set_null() { data = data_end = NULL; }
    ssize_t length() const { return data_end - data; }
    void parse(struct datum &r, ssize_t num_bytes) {
        if (r.length() < num_bytes || num_bytes < 0) {
            r.set_null();
            set_null();
            //fprintf(stderr, "warning: not enough data in parse (need %zu, have %zd)\n", num_bytes, length());
            return;
        }
        data = r.data;
        data_end = r.data + num_bytes;
        r.data += num_bytes;
    }
    void parse_soft_fail(struct datum &r, size_t num_bytes) {
        if (r.length() < (ssize_t)num_bytes) {
            num_bytes = r.length();  // only parse bytes that are available
        }
        data = r.data;
        data_end = r.data + num_bytes;
        r.data += num_bytes;
    }
    void parse_up_to_delim(struct datum &r, uint8_t delim) {
        if (r.is_not_readable()) {
            r.set_null();
            set_null();
            return;
        }

        data = r.data;
        const unsigned char* c = static_cast<const unsigned char*>(memchr(r.data, delim, r.length()));
        if (c) {
            data_end = r.data = c;
            return;
        }

        data_end = r.data_end;
    }
    uint8_t parse_up_to_delimiters(struct datum &r, uint8_t delim1, uint8_t delim2) {
        data = r.data;
        while (r.data < r.data_end) {
            if (*r.data == delim1) { // found first delimiter
                data_end = r.data;
                return delim1;
            }
            if (*r.data == delim2) { // found second delimiter
                data_end = r.data;
                return delim2;
            }
            r.data++;
        }
        data_end = r.data_end;
        return 0;
    }
    uint8_t parse_up_to_delimiters(struct datum &r, uint8_t delim1, uint8_t delim2, uint8_t delim3) {
        data = r.data;
        while (r.data < r.data_end) {
            if (*r.data == delim1) { // found first delimiter
                data_end = r.data;
                return delim1;
            }
            if (*r.data == delim2) { // found second delimiter
                data_end = r.data;
                return delim2;
            }
            if (*r.data == delim3) { // found third delimiter
                data_end = r.data;
                return delim2;
            }
            r.data++;
        }
        return 0;
    }
    bool skip(size_t length) {
        data += length;
        if (data > data_end) {
            data = data_end;
            return false;
        }
        return true;
    }
    void trim(size_t length) {
        data_end -= length;
        if (data_end < data) {
            data_end = data;
        }
    }
    void trim_to_length(size_t length) {
        if (data && (data + length <= data_end)) {
            data_end = data + length;
        }
    }
    template <size_t N>
    bool matches(std::array<uint8_t, N> a) const {
        const uint8_t *d = data;
        for (uint8_t x : a) {
            if (d < data_end && *d == x) {
                d++;
            } else {
                return false;
            }
        }
        return true;
    }
    bool case_insensitive_match(const struct datum r) const {
        if (length() != r.length()) {
            return false;
        } else {
            const uint8_t *tmp_l = data;
            const uint8_t *tmp_r = r.data;
            while (tmp_l < data_end) {
                if (*tmp_l++ != lowercase(*tmp_r++)) {
                    return false;
                }
            }
            return true;
        }
    }

    bool case_insensitive_match(const char * name) const {
        if (name == nullptr) return false;
        const uint8_t *d = data;
        const char *k = name;
        while (d < data_end) {
            if (tolower(*d) != *k || *k == '\0') { // mismatch
                return false;
            }
            d++;
            k++;
        }
        if (*k == '\0' && d == data_end) {
            return true;
        }
        return false;            // no matches found
    }

    /// Compares this \ref datum to `p` lexicographically, and returns
    /// an integer less than, equal to, or greater than zero if this
    /// is found to be less than, to match, or to be greater than `p`,
    /// respectively.  If both this `datum` and `p` are null, then
    /// zero is returned.  If this `datum` is null and `p` is not,
    /// `-1` is returned.
    ///
    /// For a nonzero return value, the sign is determined by the sign
    /// of the difference between the first pair of bytes (interpreted
    /// as `uint8_t`) that differ in `this` and `p`.  If
    /// `this->length()` and `p.length()` are both zero, the return
    /// value is zero.  If one datum is a prefix of the other, the
    /// prefix is considered lesser.
    ///
    /// Examples:
    ///
    ///     std::array<uint8_t, 4> A{ 0x50, 0x55, 0x53, 0x48 };
    ///     std::array<uint8_t, 4> B{ 0x50, 0x4f, 0x53, 0x54 };
    ///     std::array<uint8_t, 5> C{ 0x50, 0x55, 0x53, 0x48, 0x20 };
    ///     std::array<uint8_t, 0> D{ };
    ///     datum a{A};
    ///     datum b{B};
    ///     datum c{C};
    ///     datum d{D};
    ///     assert(a.cmp(b) > 0);
    ///     assert(a.cmp(c) < 0);
    ///     assert(a.cmp(d) > 0);
    ///     assert(d.cmp(d) == 0);
    ///
    int cmp(const datum &p) const {
        if (is_null()) {
            if (p.is_null()) {
                return 0;      // two null datums are equal
            }
            return -1;         // a null datum is less than any other datum
        }
        if (p.is_null()) {
            return 1;          // any non-null datum is greater than a null datum
        }
        int cmp = ::memcmp(data, p.data, std::min(length(), p.length()));
        if (cmp == 0) {
            return length() - p.length();
        }
        return cmp;
    }

    /// compares this \ref datum to `a` lexicographically, and returns
    /// `true` if it exactly matches, and `false` otherwise
    ///
    /// For lexicographic comparison examples, see \ref
    /// datum::cmp(const datum &p) const
    ///
    template <size_t N>
    bool equals(const std::array<uint8_t, N> a) const {
        if (length() == N) {
            return ::memcmp(data, a.data(), N) == 0;
        }
        return false;
    }

    /// returns `true` if this is lexicographically less than `p`, and
    /// `false` otherwise.  It is suitable for use in `std::sort()`.
    ///
    bool operator<(const datum &p) const {
        return cmp(p) < 0;
     }

    /// returns true if the bytes represented by this datum are
    /// identical to those represented by `p`, and false otherwise.
    ///
    bool operator==(const datum &p) const {
        return cmp(p) == 0;
     }

    /// returns false if the bytes represented by this datum are
    /// identical to those represented by `p`, and true otherwise.
    ///
    bool operator!=(const datum &p) const {
        return cmp(p) != 0;
     }

    unsigned int bits_in_data() const {                  // for use with (ASN1) integers
        unsigned int bits = (data_end - data) * 8;
        const unsigned char *d = data;
        while (d < data_end) {
            for (unsigned char c = 0x80; c > 0; c=c>>1) {
                if (*d & c) {
                    return bits;
                }
                bits--;
            }
            d++;
        }
        return bits;
    }

    /// looks for the delimiter `d` with length `l` in this \ref
    /// datum, until it reaches the delimiter `d` or `data_end`,
    /// whichever comes first.  In the first case, the function
    /// returns the number of bytes to the delimiter; in the second
    /// case, the function returns the number of bytes to the end of
    /// the data buffer.
    ///
    int find_delim(const unsigned char *delim, size_t length)
    {
        /* find delimiter, if present */
        const unsigned char *tmp_data = data;
        const unsigned char *pattern = delim;
        const unsigned char *pattern_end = delim + length;

        while (pattern < pattern_end && tmp_data < data_end)
        {
            if (*tmp_data != *pattern)
            {
                pattern = delim - 1; /* reset pattern to the start of the delimiter string */
            }
            tmp_data++;
            pattern++;
        }
        if (pattern == pattern_end)
        {
            return tmp_data - data;
        }
        return -(tmp_data - data);
    }

    int find_delim(uint8_t delim) {
        if (is_not_readable()) {
            return -1;
        }
        const unsigned char* c = static_cast<const unsigned char*>(memchr(data, delim, length()));
        if (c) {
            return c - data;
        }
        return -1;
    }

    void skip_up_to_delim(uint8_t delim) {
        while (data < data_end) {
            if (*data == delim) { // found delimiter
                return;
            }
            data++;
        }
    }
    bool skip_up_to_delim(const unsigned char delim[], size_t length)
    {
        int delim_index = find_delim(delim, length);

        if (delim_index >= 0)
        {
            return skip(delim_index);
        }

        return false;
    }

    void trim_leading_whitespace() {
        while(data < data_end and (*data == ' ' or *data == '\t')) {
            data++;
        }
    }

    /// skips/trims all instances of the trailing character `t`
    ///
    void trim_trail(unsigned char trail) {
        if (!is_not_empty())
            return;
        const unsigned char *tmp_data = data_end - 1;
        if (*tmp_data != trail) {
            return;
        }
        while (tmp_data >= data) {
            if (*tmp_data != trail) { // end of trailing delimiter
                data_end = tmp_data + 1;
                return;
            }
            tmp_data--;
        }
    }

    bool isupper() {
        const uint8_t *d = data;
        while (d < data_end) {
            if (::isupper(*d)) {
                ++d;
            } else {
                return false;
            }
        }
        return true;
    }

    bool is_alnum() const {
        for (const auto & d : *this) {
            if (!isalnum(d)) {
                return false;
            }
        }
        return true;
    }

    /// returns true if the data contains any alphabetic characters
    ///
    bool is_any_alpha() const {
        for (const auto & d : *this) {
            if (isalpha(d)) {
                return true;
            }
        }
        return false;
    }

    bool accept(uint8_t byte) {
        if (data_end > data) {
            uint8_t value = *data;
            if (byte == value) {
                data += 1;
                return false;
            }
        }
        set_null();
        return true;
    }

    bool accept_byte(const uint8_t *alternatives, uint8_t *output) {
        // TODO: This function should also accept a length parameter for the alternatives array to prevent issues when the array is not null-terminated.
        if (data_end > data) {
            uint8_t value = *data;
            while (*alternatives != 0) {
                if (*alternatives == value) {
                    data += 1;
                    *output = value;
                    return false;
                }
                alternatives++;
            }
        }
        set_null();
        return true;
    }

    /// reads and accepts a `std::array` of `uint8_t`s of length
    /// \param N; otherwise, sets this \ref datum to `null`.
    ///
    template <size_t N>
    void accept(const std::array<uint8_t, N> &a) {
        if (data and data + N <= data_end) {
            if (memcmp(data, a.data(), N) == 0) {
                data += N;
                return;
            }
        }
        set_null();
    }

    /// reads a `uint8_t` in network byte order, without advancing the
    /// data pointer
    ///
    void lookahead_uint8(uint8_t *output) {
        if (data_end > data) {
            *output = *data;
            return;
        }
        set_null();
        *output = 0;
    }

    // [[nodiscard]]
    bool lookahead_uint(unsigned int num_bytes, uint64_t *output)
    {
        if (data + num_bytes <= data_end)
        {
            uint64_t tmp = 0;
            const unsigned char *c;

            for (c = data; c < data + num_bytes; c++)
            {
                tmp = (tmp << 8) + *c;
            }
            *output = tmp;
            return true;
        }
        return false;
    }

    /// returns a pointer to type `T` and advances the data pointer,
    /// if there are `sizeof(T)` bytes available, and otherwise
    /// returns `nullptr`
    ///
    /// if `T` is a struct, then it SHOULD be defined using the
    /// `__attribute__((__packed__))` to ensure that the compiler
    /// omits unexpected padding bytes
    ///
    template <typename T>
    T* get_pointer() {
        if (data + sizeof(T) <= data_end) {
            T *tmp = (T *)data;
            data += sizeof(T);
            return tmp;
        }
        return nullptr;
    }

    /// reads a `uint8_t` in network byte order, and advances the data pointer
    ///
    [[deprecated("Use encoded<uint8_t> instead.")]]
    bool read_uint8(uint8_t *output) {
        if (data_end > data) {
            *output = *data;
            data += 1;
            return true;
        }
        set_null();
        *output = 0;
        return false;
    }

    /// reads a `uint16_t` in network byte order, and advances the data pointer
    ///
    [[deprecated("Use encoded<uint16_t> instead.")]]
    bool read_uint16(uint16_t *output) {
        if (length() >= (int)sizeof(uint16_t)) {
            uint16_t *tmp = (uint16_t *)data;
            *output = ntoh(*tmp);
            data += sizeof(uint16_t);
            return true;
        }
        set_null();
        *output = 0;
        return false;
    }

    /// reads a `uint32_t` in network byte order, and advances the data pointer
    ///
    [[deprecated("Use encoded<uint32_t> instead.")]]
    bool read_uint32(uint32_t *output) {
        if (length() >= (int)sizeof(uint32_t)) {
            uint32_t *tmp = (uint32_t *)data;
            *output = ntoh(*tmp);
            data += sizeof(uint32_t);
            return true;
        }
        set_null();
        *output = 0;
        return false;
    }

    /// reads a length `num_bytes` unsigned integer in network byte
    /// order, and advances the data pointer
    ///
    [[deprecated("Use encoded<> instead.")]]
    bool read_uint(uint64_t *output, unsigned int num_bytes) {

        if (data && data + num_bytes <= data_end) {
            uint64_t tmp = 0;
            const unsigned char *c;

            for (c = data; c < data + num_bytes; c++) {
                tmp = (tmp << 8) + *c;
            }
            *output = tmp;
            data = c;
            return true;
        }
        set_null();
        *output = 0;
        return false;
    }

    template <size_t N>
    void read_array(std::array<uint8_t, N> a) {
        if (data && data + N <= data_end) {
            memcpy(a.data(), data, N);
            data += N;
            return;
        }
        set_null();
        memset(a.data(), 0, N);
    }

    [[deprecated("Use datum(datum &d, ssize_t length) instead.")]]
    void init_from_outer_parser(struct datum *outer,
                                unsigned int data_len) {
        if (!outer->is_not_empty()) {
            return;
        }
        const unsigned char *inner_data_end = outer->data + data_len;

        data = outer->data;
        data_end = inner_data_end > outer->data_end ? outer->data_end : inner_data_end;
        outer->data = data_end;
    }

    bool copy(char *dst, ssize_t dst_len) {
        if (length() > dst_len) {
            memcpy(dst, data, dst_len);
            return false;
        }
        memcpy(dst, data, length());
        return true;
    }

    bool copy(unsigned char *dst, ssize_t dst_len) {
        if (length() > dst_len) {
            memcpy(dst, data, dst_len);
            return false;
        }
        memcpy(dst, data, length());
        return true;
    }

    bool strncpy(char *dst, ssize_t dst_len) {
        if (length() + 1 > dst_len) {
            memcpy(dst, data, dst_len - 1);
            dst[dst_len-1] = '\0'; // null termination
            return false;
        }
        memcpy(dst, data, length());
        dst[length()] = '\0'; // null termination
        return true;
    }

    int compare(const void *x, ssize_t x_len) {
        if (data && length() == x_len) {
            return ::memcmp(x, data, x_len);
        }
        return (std::numeric_limits<int>::min)();
    }

    bool compare_nbytes(const void *x, ssize_t x_len) {
        if (data && length() >= x_len) {
            return (::memcmp(x, data, x_len) == 0);
        }
        return false;
    }

    void fprint_hex(FILE *f, size_t length=0) const {
        if (data == nullptr || f == nullptr) { return; }
        const uint8_t *x = data;
        const uint8_t *end = data_end;
        if (length) {
            end = data + length;
            end = end < data_end ? end : data_end;
        }
        while (x < end) {
            fprintf(f, "%02x", *x++);
        }
    }

    void fprint_c_array(FILE *f, const char *name) const {
        if (f == nullptr || name == nullptr) { return; }
        size_t count = 1;
        const uint8_t *x = data;
        fprintf(f, "uint8_t %s[%zd] = {\n    ", name, length());
        while (x < data_end - 1) {
            fprintf(f, "0x%02x,", *x++);
            if (count++ % 8 == 0) {
                fputs("\n    ", f);
            } else {
                fputc(' ', f);
            }
        }
        fprintf(f, "0x%02x", *x);
        fputs("\n};\n", f);
    }

    void fprint(FILE *f, size_t length=0) const {
        if (f == nullptr) { return; }
        const uint8_t *x = data;
        const uint8_t *end = data_end;
        if (length) {
            end = data + length;
            end = end < data_end ? end : data_end;
        }
        while (x < end) {
            if (isprint(*x)) {
                fputc(*x, f);
            } else {
                fputc('.', f);
            }
            x++;
        }
    }

    /// writes the readable part of this `data_buffer` to the file
    /// descriptor `fd` and then returns the number of bytes written
    /// on success, and `-1` on error; in the latter case, `errno`
    /// indicates the cause of the error
    ///
    ssize_t write(int fd) {
        if (is_null()) {
            return -1;
        }
        return ::write(fd, data, length());
    }

    /// writes the entire datum out to the `FILE *f`, and on
    /// success, returns the number of bytes written; otherwise, 0 is
    /// returned.
    ///
    /// This function can be used to write out seed files for fuzz
    /// testing.
    ///
    size_t fwrite(FILE *f) const {
        if (f == nullptr) {
            return 0;  // error
        }
        return ::fwrite(data, sizeof(uint8_t), length(), f);
    }

    ssize_t write_to_buffer(uint8_t *buffer, ssize_t len) {
        if (data) {
            ssize_t copy_len = length() < len ? length() : len;
            memcpy(buffer, data, copy_len);
            return copy_len;
        }
        return -1;
    }

    ssize_t write_hex(char *out, size_t num_bytes, bool null_terminated=false) {

        // check for writeable room; output length is twice the input
        // length
        //
        ssize_t terminator = null_terminated ? 1 : 0;
        if (is_null() or (data_end - data) + terminator > 2 * (ssize_t)num_bytes) {
            return -1;
        }

        uint8_t hex_table[] = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
        };

        const uint8_t *d = data;
        while (d < data_end) {
            *out++ = hex_table[(*d & 0xf0) >> 4];
            *out++ = hex_table[*d++ & 0x0f];
        }
        if (null_terminated) {
            *out++ = '\0';
        }
        return data_end - data + terminator;
    }

    bool is_printable() const {
        for (const auto & c: *this) {
            if (!isprint(c)) {
                return false;
            }
        }
        return true;
    }

    // member functions that can be used in STL algorithms
    //

    /// returns a pointer to the start of the data in this datum.
    ///
    const uint8_t *begin() const { return data; }

    /// returns a pointer to the end of the data in this datum.
    ///
    const uint8_t *end()   const { return data_end; }

    /// returns a `const` pointer to the start of the data in this datum.
    ///
    const uint8_t *cbegin() const { return data; }

    /// returns a `const` pointer to the end of the data in this datum.
    ///
    const uint8_t *cend()   const { return data_end; }

};

// sanity checks on class datum
//
static_assert(sizeof(datum) == 2 * sizeof(uint8_t *));


/// returns a datum that corresponds to the `std::string s`.
///
/// \note A \ref datum indicates a sequence of bytes in memory, but
/// does not own that data.  Any changes to `s` will change the
/// sequence of bytes to which the `datum` corresponds.  Additionally,
/// if `s` goes out of scope, then the `datum` will become invalid.
///
static inline datum get_datum(const std::string &s) {
    uint8_t *data = (uint8_t *)s.c_str();
    return { data, data + s.length() };
}

/// returns a datum that corresponds to the null-terminated character
/// string `c`.  The value of `c` must not be `nullptr`, and the
/// sequence of bytes pointed to by `c` must be null-terminated.
///
/// \note A \ref datum indicates a sequence of bytes in memory, but
/// does not own that data.  Any changes to `c`, or the sequence of
/// bytes it points to, will change the sequence of bytes to which the
/// `datum` corresponds.  Additionally, if `c` goes out of scope, then
/// the `datum` will become invalid.
///
static inline datum get_datum(const char *c) {
    uint8_t *data = (uint8_t *)c;
    return { data, data + strlen(c) };
}

/// given inputs \ref datum \param outer and \ref datum \param inner
/// such that \param inner is contained entirely within \param outer,
/// returns a `std::pair` of `datum`s, the first of which is the
/// portion of \param outer that preceeds \param inner, and the second
/// of which is the portion of \param outer that follows \param inner;
/// either the first or second `datum` may be empty.  If either \param
/// outer or \param inner are null, or \param inner is not entirely
/// contained within \param outer, then each `datum` in the returned
/// `std::pair` will be null.
///
inline std::pair<datum,datum> symmetric_difference(datum outer, datum inner) {
    //
    // verify input conditions
    //
    if (outer.is_null() or
        inner.is_null() or
        outer.data > inner.data or
        inner.data_end > outer.data_end) {
        return {
            { nullptr, nullptr },
            { nullptr, nullptr }
        };
    }
    return {
        { outer.data , inner.data },
        { inner.data_end, outer.data_end }
    };
}



/// \class writeable
///
/// tracks a contiguous region of memory to which data can be written sequentially
///
/// \ref writeable is a lightweight, non-owning class that represents
/// a region of memory to which data can be written sequentially.  A
/// writeable object tracks the extent of the region as data is
/// written, and verifies that there is sufficient room before a write
/// operation.
///
/// Each writeable object is in one of the states `null`, `writeable`,
/// or `full`:
///
///   |    State        | data          |   data_end   |
///   |-----------------|---------------|--------------|
///   |    null         | `nullptr`     |   `nullptr`  |
///   |    writeable    | `!= nullptr`  |   `> data`   |
///   |    full         | `!= nullptr`  |   `== data`  |
///
class writeable {
protected:

    uint8_t *data;
    uint8_t *data_end;

    // return true if this `writeable` is in a valid state (writeable,
    // full, or null) and false if it is in an invalid state (data >
    // data_end)
    //
    bool is_invalid() const {
        // fprintf(stderr, "{%p,%p}\n", data, data_end);
        return data > data_end;
    }

public:

    /// constructs a writeable object that tracks data being written to the
    /// region between `begin` and `end`
    ///
    writeable(uint8_t *begin, uint8_t *end) : data{begin}, data_end{end} { }

    /// constructs a writeable object that tracks data being written to the
    /// `std::array` \param a.
    ///
    template <size_t N>
    constexpr writeable(std::array<uint8_t, N> &a) : data{a.data()}, data_end{data + N} { }

    /// constructs a writeable object that tracks data being written to the
    /// region between \param buf and `buf + len`.
    ///
    constexpr writeable(uint8_t *buf, size_t len) : data{buf}, data_end{buf + len} { }

    /// constructs a null writeable object
    ///
    writeable() : data{nullptr}, data_end{nullptr} { }

    /// returns true if the writeable object is in the null state, and false otherwise
    ///
    bool is_null() const { return data == nullptr || data_end == nullptr; }

    /// returns true if the writeable object is not full, and false otherwise
    ///
    bool is_not_full() const { return data < data_end; }

    /// returns the number of bytes in the writeable region to which
    /// data can be written
    ///
    ssize_t writeable_length() const { return data_end - data; }

    /// sets this writeable object to the null state
    ///
    void set_null() {
        data = nullptr;
        data_end = nullptr;
    }

    /// sets this writeable object to the full state
    ///
    void set_full() { data = data_end; }

    /// Copies the single `uint8_t` \param x into this `writeable`, if
    /// there is room; otherwise, sets it to the null state.
    ///
    void copy(uint8_t x) {
        if (data + 1 > data_end) {
            set_null();
            return;  // not enough room
        }
        *data++ = x;
        assert(!is_invalid());
    }

    /// Copies \p num_bytes bytes from location \p rdata into this
    /// `writeable`, if there is room; otherwise, sets it to the
    /// null state.
    ///
    void copy(const uint8_t *rdata, size_t num_bytes) {
        if (rdata == nullptr or writeable_length() < (ssize_t)num_bytes) {
            set_null();
            return;
        }
        memcpy(data, rdata, num_bytes);
        data += num_bytes;
        assert(!is_invalid());
    }

    /// Copies the contents of `datum` \p d into this `writeable`, if
    /// there is room; otherwise, sets it to the null state.
    ///
    void copy(datum d) {
        copy(d.data, d.length());
        assert(!is_invalid());
    }

    /// writes a hexidecimal representation of the \p num_bytes bytes
    /// at location \p rdata into this `writeable`, if there is room
    /// for all `2*num_bytes` hex characters; otherwise, sets it to
    /// the empty state
    ///
    void write_hex(const uint8_t *src, size_t num_bytes) {

        // check for writeable room; output length is twice the input
        // length
        //
        if (is_null() or writeable_length() < 2 * (ssize_t)num_bytes) {
            set_null();
            return;
        }

        char hex_table[] = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
        };

        for (size_t i=0; i < num_bytes; i++) {
            *data++ = hex_table[(*src & 0xf0) >> 4];
            *data++ = hex_table[*src++ & 0x0f];
        }
        assert(!is_invalid());
    }

    /// writes a quote-enclosed hexidecimal representation of the \p
    /// num_bytes bytes at location \p rdata into this `writeable`,
    /// if there is room for all `2*num_bytes + 2` characters;
    /// otherwise, sets it to the null state
    ///
    void write_quote_enclosed_hex(const uint8_t *src, size_t num_bytes) {
        copy('"');
        write_hex(src, num_bytes);
        copy('"');
    }

    /// writes a quote-enclosed hexidecimal representation of the
    /// bytes in the datum \p d into this `writeable`, if there is
    /// room for all `2*num_bytes + 2` characters; otherwise, sets it
    /// to the null state
    ///
    void write_quote_enclosed_hex(datum d) {
        write_quote_enclosed_hex(d.data, d.length());
    }

    template <typename Type>
    void write_hex(Type T) {
        T.write_hex(*this);
    }

    template <typename Type>
    void write_quote_enclosed_hex(Type T) {
        copy('"');
        write_hex(T);
        copy('"');
    }

    /// writes a raw representation of the hexadecimal string with \p
    /// num_digits characters at location \p src into this
    /// `writeable`, if `num_digits` is even and there is room for
    /// all `num_digits/2` bytes; otherwise, sets it to the empty
    /// state
    ///
    void copy_from_hex(const uint8_t *src, size_t num_digits) {

        // check for writeable room; output length is twice the input
        // length
        //
        if (is_null() or data_end - data < ((ssize_t)num_digits/2) or (num_digits&1) == 1 ) {
            set_null();
            return;
        }

        const uint8_t *src_end = src + num_digits;
        while (src < src_end) {
            uint8_t hi = *src++;
            uint8_t lo = *src++;
            uint8_t result;
            if (hi >= '0' && hi <= '9') {
                result = (hi - '0') << 4;
            } else if (hi >= 'a' && hi <= 'f') {
                result = (hi - 'a' + 10) << 4;
            } else if (hi >= 'A' && hi <= 'F') {
                result = (hi - 'A' + 10) << 4;
            } else {
                //
                // error; character hi is not a hex digit
                //
                set_null();
                return;
            }
            if (lo >= '0' && lo <= '9') {
                result |= (lo - '0');
            } else if (lo >= 'a' && lo <= 'f') {
                result |= (lo - 'a' + 10);
            } else if (lo >= 'A' && lo <= 'F') {
                result |= (lo - 'A' + 10);
            } else {
                //
                // error; character lo is not a hex digit
                //
                set_null();
                return;
            }
            *data++ = result;

        }
        assert(!is_invalid());
    }

    /// copies `num_bytes` out of `r` and into this \ref writeable,
    /// and advances `r`, if this `writeable` has enough room for the
    /// data and `r` contains at least `num_bytes`.  If `r` is null or
    /// `r.length() < num_bytes` or `this->length() < num_bytes`, then
    /// this `writeable` is set to null.
    ///
    void parse(struct datum &r, size_t num_bytes) {
        if (r.is_null() or writeable_length() < (ssize_t)num_bytes) {
            set_null();
            return;
        }
        if (r.length() < (ssize_t)num_bytes) {
            r.set_null();
            return;
        }
        memcpy(data, r.data, num_bytes);
        data += num_bytes;
        r.data += num_bytes;
        assert(!is_invalid());
    }
    void parse(struct datum &r) {
        parse(r, r.length());
    }

    template <typename Type>
    writeable & operator<<(Type t) {
        t.write(*this);
        return *this;
    }

    /// template specialization for datum
    ///
    writeable & operator<<(datum d) {
        copy(d);
        return *this;
    }

    /// template specialization for char
    ///
    writeable & operator<<(char c) {
        copy(c);
        return *this;
    }

};

/// `data_buffer<T>` is a contiguous sequence of `T` bytes into which data can
/// be written/copied sequentially.
///
/// A data_buffer object contains a fixed-size data buffer, and tracks
/// the start of the data (`buffer`), the first location to which data
/// can be written (`writeable.data`), and the end of the data buffer
/// (`writeable.data_end`), which is also end of the writeable part.
/// It can be illustrated as
///
/// ```
///      +-- start of buffer               end of buffer --+
///      v                                                 v
///      +--------------------+----------------------------+
///      |   readable part    |       writeable part       |
///      +--------------------+----------------------------+
///                           ^                            ^
///                           +-- start of writeable       |
///                                                        |
///                                     end of writeable --+
/// ```
///
/// The readable part can be obtained by \ref contents()
///
template <size_t T> struct data_buffer : public writeable {
    unsigned char buffer[T];

    /// constructs a data_buffer with a fixed length of `T` bytes
    ///
    data_buffer() : writeable{buffer, buffer+T} { }

    /// reset this `data_buffer` so that the writeable part contains
    /// `T` bytes and the readable part is empty (zero length)
    ///
    void reset() {
        data = buffer;
        data_end = buffer + T;
        assert(!is_invalid());
    }

    /// returns true if the readable part is not empty
    ///
    bool is_not_empty() const { return data != buffer && data < data_end; }

    /// data_buffer::readable_length() returns the number of bytes in
    /// the readable region, if the writeable region is not null;
    /// otherwise, zero is returned
    ///
    ssize_t readable_length() const {
        if (writeable::is_null()) {
            return 0;
        }
        else {
            return data - buffer;
        }
    }

    /// returns a datum representing the readable part of the
    /// data_buffer, if the writeable part is not null; otherwise, a
    /// null datum is returned
    ///
    datum contents() const {
        if (writeable::is_null()) {
            return {nullptr, nullptr};
        } else {
            return {buffer, data};
        }
    }

};

/// dynamic_buffer is a writeable that can be dynamically sized
///
class dynamic_buffer : public writeable {
    std::vector<uint8_t> buffer;

public:

    /// constructs a `dynamic_buffer` with an initial size of
    /// \param initial_size bytes
    ///
    dynamic_buffer(size_t initial_size) :
        buffer(initial_size)
    {
        data = buffer.data();
        data_end = data + buffer.size();
    }

    /// reset this `dynamic_buffer` so that the readable part is empty
    /// (zero length) and the writeable part contains all available
    /// bytes.
    ///
    void reset() {
        data = buffer.data();
        data_end = data + buffer.size();
        assert(!is_invalid());
    }

    /// returns true if the readable part is not empty
    ///
    bool is_not_empty() const { return data != buffer.data() && data < data_end; }

    /// `dynamic_buffer::readable_length()` returns the number of bytes in
    /// the readable region, if the writeable region is not null;
    /// otherwise, zero is returned
    ///
    ssize_t readable_length() const {
        if (writeable::is_null()) {
            return 0;
        }
        else {
            return data - buffer.data();
        }
    }

    /// returns a \ref datum representing the readable part of the
    /// \ref dynamic_buffer, if the writeable part is not null;
    /// otherwise, a null `datum` is returned
    ///
    datum contents() const {
        if (writeable::is_null()) {
            return {nullptr, nullptr};
        } else {
            return {buffer.data(), data};
        }
    }

};

#ifndef NDEBUG

// unit tests for class `writeable`, class `data_buffer`, and class
// `dynamic_buffer`
//
namespace writeable_unit_test {

    // B must be data_buffer or dynamic_buffer
    //
    template <typename B>
    bool test_copy_uint8(B &buf, FILE *f=nullptr) {
        bool result = true;

        // reset buffer
        //
        buf.reset();

        // verify buffer size
        //
        if (buf.writeable_length() != 1) {
            if (f) {
                fprintf(f, "%s error: buffer size wrong size for test (%zu bytes)\n", __func__, buf.writeable_length());
            }
            return false;
        }

        // test writeable::copy(uint8_t) in writeable state
        //
        buf.copy('a');
        if (buf.contents().cmp(datum{"a"}) != 0) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '%s'\n", __func__, "a", buf.contents().get_string().c_str());
            }
            result &= false;
        }

        // test writeable::copy(uint8_t) in full state
        //
        buf.set_full();
        buf.copy('a');
        if (buf.is_null() != true) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '%s'\n", __func__, "a", buf.contents().get_string().c_str());
            }
            result &= false;
        }

        // test writeable::copy(uint8_t) in null state
        //
        buf.set_null();
        buf.copy('a');
        if (buf.is_null() != true) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '%s'\n", __func__, "a", buf.contents().get_string().c_str());
            }
            result &= false;
        }

        return result;
    }

    // B must be data_buffer or dynamic_buffer
    //
    template <typename B>
    bool test_copy_datum(B &buf, FILE *f=nullptr) {
        bool result = true;

        // reset buffer
        //
        buf.reset();

        // verify buffer size
        //
        if (buf.writeable_length() != 1) {
            if (f) {
                fprintf(f, "%s error: buffer size wrong for test (%zu bytes)\n", __func__, buf.writeable_length());
            }
            return false;
        }

        // test writeable::copy(datum) in writeable state
        //
        buf.copy(datum{"a"});
        if (buf.contents().cmp(datum{"a"}) != 0) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '%s'\n", __func__, "a", buf.contents().get_string().c_str());
            }
            result &= false;
        }

        // test writeable::copy(datum) in full state
        //
        buf.set_full();
        buf.copy(datum{"a"});
        if (buf.is_null() != true) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '%s'\n", __func__, "(null)", buf.contents().get_string().c_str());
            }
            result &= false;
        }

        // test writeable::copy(datum) in null state
        //
        buf.set_null();
        buf.copy(datum{"a"});
        if (buf.is_null() != true) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '%s'\n", __func__, "(null)", buf.contents().get_string().c_str());
            }
            result &= false;
        }

        return result;
    }

    // B must be data_buffer or dynamic_buffer
    //
    template <typename B>
    bool test_write_hex(B &buf, FILE *f=nullptr) {
        bool result = true;

        // reset buffer
        //
        buf.reset();

        // verify buffer size
        //
        if (buf.writeable_length() < 4) {
            if (f) {
                fprintf(f, "%s error: buffer size too small for test (%zu bytes)\n", __func__, buf.writeable_length());
            }
            return false;
        }

        std::array<uint8_t,2> raw{ 0xab, 0xcd };
        std::array<uint8_t,4> hex{ 'a', 'b', 'c', 'd' };

        // test writeable::write_hex() in writeable state
        //
        buf.write_hex(raw.data(), raw.size());
        if (buf.contents().cmp(datum{hex}) != 0) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '%s'\n", __func__, "abcd", buf.contents().get_string().c_str());
            }
            result &= false;
        }

        // test writeable::write_hex() in full state
        //
        buf.set_full();
        buf.write_hex(raw.data(), raw.size());
        if (buf.is_null() != true) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '%s'\n", __func__, "(null)", buf.contents().get_string().c_str());
            }
            result &= false;
        }

        // test writeable::write_hex() in null state
        //
        buf.set_null();
        buf.write_hex(raw.data(), raw.size());
        if (buf.is_null() != true) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '%s'\n", __func__, "(null)", buf.contents().get_string().c_str());
            }
            result &= false;
        }

        return result;
    }

    // B must be data_buffer or dynamic_buffer
    //
    template <typename B>
    bool test_copy_from_hex(B &buf, FILE *f=nullptr) {
        bool result = true;

        // reset buffer
        //
        buf.reset();

        // verify buffer size
        //
        if (buf.writeable_length() < 4) {
            if (f) {
                fprintf(f, "%s error: buffer size too small for test (%zu bytes)\n", __func__, buf.writeable_length());
            }
            return false;
        }

        std::array<uint8_t,4> raw{ 0xab, 0xcd, 0x01, 0x23 };
        std::array<uint8_t,8> hex{ 'a', 'b', 'c', 'd', '0', '1', '2', '3' };

        // test writeable::copy_from_hex() in writeable state
        //
        buf.copy_from_hex(hex.data(), hex.size());
        if (buf.contents().cmp(datum{raw}) != 0) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '%s'\n", __func__, "abcd", buf.contents().get_string().c_str());
            }
            result &= false;
        }

        // test writeable::copy_from_hex() in full state
        //
        buf.set_full();
        buf.copy_from_hex(hex.data(), hex.size());
        if (buf.is_null() != true) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '%s'\n", __func__, "(null)", buf.contents().get_string().c_str());
            }
            result &= false;
        }

        // test writeable::copy_from_hex() in null state
        //
        buf.set_null();
        buf.copy_from_hex(hex.data(), hex.size());
        if (buf.is_null() != true) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '%s'\n", __func__, "(null)", buf.contents().get_string().c_str());
            }
            result &= false;
        }

        return result;
    }

    // B must be data_buffer or dynamic_buffer
    //
    template <typename B>
    bool test_parse(B &buf, FILE *f=nullptr) {
        bool result = true;

        // reset buffer
        //
        buf.reset();

        // verify buffer size
        //
        if (buf.writeable_length() < 4) {
            if (f) {
                fprintf(f, "%s error: buffer size too small for test (%zu bytes)\n", __func__, buf.writeable_length());
            }
            return false;
        }

        std::array<uint8_t,4> raw_data{ 0xab, 0xcd, 0x01, 0x23 };
        std::array<uint8_t,4> expected = raw_data;

        // test writeable::parse() in writeable state
        //
        datum raw = datum{raw_data};
        buf.parse(raw, raw.length());
        if (buf.contents().cmp(datum{expected}) != 0) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '", __func__, "abcd0123");
                buf.contents().fprint_hex(f);
                fprintf(f, "'\n");
            }
            result &= false;
        }

        // test writeable::parse() in full state
        //
        buf.set_full();
        raw = datum{raw_data};
        buf.parse(raw, raw.length());
        if (buf.is_null() != true) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '", __func__, "(null)");
                buf.contents().fprint_hex(f);
                fprintf(f, "'\n");
            }
            result &= false;
        }

        // test writeable::parse() in null state
        //
        buf.set_null();
        raw = datum{raw_data};
        buf.parse(raw, raw.length());
        if (buf.is_null() != true) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '", __func__, "(null)");
                buf.contents().fprint_hex(f);
                fprintf(f, "'\n");
            }
            result &= false;
        }

        //
        // repeat tests with the input datum in empty state
        //

        buf.reset();
        datum empty = datum{raw};
        empty.set_empty();         // create an empty datum to be used in the following tests

        // test writeable::parse() in writeable state
        //
        buf.parse(empty);
        if (buf.contents().length() != 0) {
            if (f) {
                fprintf(f, "%s error: expected '', got '%s", __func__, "");
                buf.contents().fprint_hex(f);
                fprintf(f, "'\n");
            }
            result &= false;
        }

        // test writeable::parse() in full state
        //
        raw = datum{raw_data};
        buf.copy(raw);                      // fill buffer before test
        buf.parse(empty);                   // test: parse empty buffer
        //
        // expected output: buf.contents == expected, since parsing an
        // empty datum should not change the writeable
        //
        if (buf.contents().cmp(datum{expected}) != 0) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '", __func__, "abcd0123");
                buf.contents().fprint_hex(f);
                fprintf(f, "'\n");
            }
            result &= false;
        }

        // test writeable::parse() in null state
        //
        // expected output: buf.contents == null, since parsing an empty
        // datum should not change the writeable from being in null state
        //
        buf.set_null();
        buf.parse(empty);
        if (buf.is_null() != true) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '", __func__, "(null)");
                buf.contents().fprint_hex(f);
                fprintf(f, "'\n");
            }
            result &= false;
        }

        //
        // repeat tests with the input datum in null state
        //

        buf.reset();
        datum null = datum{raw};
        null.set_null();         // create an null datum to be used in the following tests

        // test writeable::parse() in writeable state
        //
        buf.parse(null);
        if (buf.is_null() != true) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '", __func__, "(null)");
                buf.contents().fprint_hex(f);
                fprintf(f, "'\n");
            }
            result &= false;
        }

        // test writeable::parse() in full state
        //
        raw = datum{raw_data};
        buf.copy(raw);                      // fill buffer before test
        buf.parse(null);                    // test: parse null
        //
        // expected output: buf.contents == expected, since parsing an
        // empty datum should not change the writeable
        //
        if (buf.is_null() != true) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '", __func__, "(null)");
                buf.contents().fprint_hex(f);
                fprintf(f, "'\n");
            }
            result &= false;
        }

        // test writeable::parse() in null state
        //
        // expected output: buf.contents == null, since parsing an empty
        // datum should not change the writeable from being in null state
        //
        buf.set_null();
        buf.parse(null);
        if (buf.is_null() != true) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '", __func__, "(null)");
                buf.contents().fprint_hex(f);
                fprintf(f, "'\n");
            }
            result &= false;
        }


        //
        // repeat tests with input datum in readable state, in which
        // the parse asks to read more data than is in the input
        //

        // test writeable::parse() in writeable state
        //
        raw = datum{raw_data};
        buf.parse(raw, raw.length() + 100);
        if (buf.contents().is_null() != true) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '", __func__, "(null)");
                buf.contents().fprint_hex(f);
                fprintf(f, "'\n");
            }
            result &= false;
        }

        // test writeable::parse() in full state
        //
        buf.set_full();
        raw = datum{raw_data};
        buf.parse(raw, raw.length() + 100);
        if (buf.is_null() != true) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '", __func__, "(null)");
                buf.contents().fprint_hex(f);
                fprintf(f, "'\n");
            }
            result &= false;
        }

        // test writeable::parse() in null state
        //
        buf.set_null();
        raw = datum{raw_data};
        buf.parse(raw, raw.length() + 100);
        if (buf.is_null() != true) {
            if (f) {
                fprintf(f, "%s error: expected '%s', got '", __func__, "(null)");
                buf.contents().fprint_hex(f);
                fprintf(f, "'\n");
            }
            result &= false;
        }

        return result;
    }


    /// Run unit tests on `class writeable` and returns `true` if all
    /// succeeded and `false` otherwise
    ///
    /// \note Running this function with `valgrind --leak-check=full` or
    /// compiling it with `-fsanitize=address` provides additional
    /// verification.
    ///
    bool run(FILE *verbose_output=nullptr) {
        bool result = true;

        dynamic_buffer dynamic_buf{1};
        result &= test_copy_uint8(dynamic_buf, verbose_output);
        result &= test_copy_datum(dynamic_buf, verbose_output);

        dynamic_buffer dynamic_buf_2{4};
        result &= test_write_hex(dynamic_buf_2, verbose_output);
        result &= test_copy_from_hex(dynamic_buf_2, verbose_output);
        result &= test_parse(dynamic_buf_2, verbose_output);

        data_buffer<1> data_buf;
        result &= test_copy_uint8(data_buf, verbose_output);
        result &= test_copy_datum(data_buf, verbose_output);

        data_buffer<4> data_buf_2;
        result &= test_write_hex(data_buf_2, verbose_output);
        result &= test_copy_from_hex(data_buf_2, verbose_output);
        result &= test_parse(data_buf_2, verbose_output);

        return result;
    }
};

#endif // NDEBUG


/// `pad_len(length)` returns the number that, when added to length,
/// rounds that value up to the smallest number that is at least as
/// large as `length` and is a multiple of four.
///
static inline size_t pad_len(size_t length) {
    switch (length % 4) {
    case 3: return 1;
    case 2: return 2;
    case 1: return 3;
    case 0:
    default:
        ;
    }
    return 0;
}

/// `class pad` reads and ignores padding data
///
class pad {
    size_t padlen;
public:

    /// constructor for reading (and ignoring) padding data
    ///
    pad(datum &d, size_t n) : padlen{n} {
        d.data += padlen;
        if (d.data > d.data_end) {
            d.set_null();
        }
    }

    /// constructor for writing (all-zero) padding data
    ///
    pad(size_t n) : padlen{n} { }

    void write(writeable &w) {
        uint8_t zero[4] = {0, 0, 0, 0};
        w.copy(zero, padlen);
        assert(padlen <= 5);
    }
};


/// \defgroup bitoperations Bit Operations
/// @{

/// returns the number of bits in `x`
///
#define bitsizeof(x) (sizeof(x) * 8)

/// returns the unsigned integer represented by the bits of `x` in
/// between `i` and `j-1`, inclusive, where zero denotes the leftmost
/// (most significant) bit.  This indexing scheme is compatible with
/// that used in IETF standard notation (see RFC 1700).  For example,
/// `slice<4,12>(0xa1b2c3d4)` is `0x1b`, and the bitfields `A`, `B`,
/// `C`, and `D` of the 16-bit integer `x` with the format defined by
///
/// ```
///     0                   1
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |A| B |    C    |     D         |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// can be accessed as
///
///     A = slice<0,1>(x);
///     B = slice<1,3>(x);
///     C = slice<3,8>(x);
///     D = slice<8,16>(x);
///
//
// Implementation note: the cast to type T is essential so that types
// smaller than 'unsigned integer' will not be promoted to a larger
// type.  That size promotion, if allowed, would break this function.
//
template <size_t i, size_t j, typename T>
constexpr T slice(T s) {
    return ((T)(s << i)) >> (bitsizeof(T)-(j-i));
}

/// returns the value of the `i`th bit of `s`, as a boolean, where an
/// index of zero denotes the leftmost (most significant) bit.
///
/// The indexing scheme is the same as that of \ref slice<i, j, T>(T x).
///
template <size_t i, typename T>
bool bit(T s) {
    return (bool) slice<i,i+1>(s);
}

/// returns a value of type \param T with only the `i`th bit set,
/// where an index of zero denotes the leftmost (most significant)
/// bit.
///
template <size_t i, typename T>
T bit() {
    return (T)1 << (bitsizeof(T)-1-i);
}

/// @} - end of Bit Operations group

/// represents an unsigned integer type `T` that is read from a byte
/// stream
///
template <typename T>
class encoded {
    T val;    ///< the value, if decoding was successful

    static_assert(std::is_unsigned_v<T>, "T must be an unsigned integer");

public:

    /// constructs an `encoded<T>` by accepting/reading an unsigned
    /// integer type `T` from the datum `d`.  The value is read in
    /// network byte order, unless the optional argument
    /// `little_endian=true` is provided.
    ///
    encoded(datum &d, bool little_endian=false) {
        if (d.data == nullptr || d.data + sizeof(T) > d.data_end) {
            d.set_null();
            val = 0;
            return;
        }
        if (little_endian) {
            if constexpr (std::is_same_v<T, uint8_t>) {
                val = d.data[0];
            } else if constexpr (std::is_same_v<T, uint16_t>) {
                val = (T)d.data[0] | (T)d.data[1] << 8;
            } else if constexpr (std::is_same_v<T, uint32_t>) {
                val = (T)d.data[0] | (T)d.data[1] << 8 | (T)d.data[2] << 16 | (T)d.data[3] << 24;
            } else if constexpr (std::is_same_v<T, uint64_t>) {
                val = (T)d.data[0] | (T)d.data[1] << 8 | (T)d.data[2] << 16 | (T)d.data[3] << 24 |
                      (T)d.data[4] << 32 | (T)d.data[5] << 40 | (T)d.data[6] << 48 | (T)d.data[7] << 56;
            }
        } else { // big endian
            if constexpr (std::is_same_v<T, uint8_t>) {
                val = d.data[0];
            } else if constexpr (std::is_same_v<T, uint16_t>) {
                val = (T)d.data[1] | (T)d.data[0] << 8;
            } else if constexpr (std::is_same_v<T, uint32_t>) {
                val = (T)d.data[3] | (T)d.data[2] << 8 | (T)d.data[1] << 16 | (T)d.data[0] << 24;
            } else if constexpr (std::is_same_v<T, uint64_t>) {
                val = (T)d.data[7] | (T)d.data[6] << 8 | (T)d.data[5] << 16 | (T)d.data[4] << 24 |
                      (T)d.data[3] << 32 | (T)d.data[2] << 40 | (T)d.data[1] << 48 | (T)d.data[0] << 56;
            }
        }
        d.data += sizeof(T);
    }

    encoded(const T& rhs) {
        val = rhs;
    }

    operator T() const { return val; }

    T value() const { return val; }

    /// reverses the byte order of this encoded integer, from big
    /// endian to little endian or vice-versa.
    ///
    void swap_byte_order() {
        if constexpr (sizeof(val) == 8) {
            val = ::swap_byte_order(val);
        } else if constexpr (sizeof(val) == 4) {
            val = ::swap_byte_order(val);
        } else if constexpr (sizeof(val) == 2) {
            val = ::swap_byte_order(val);
        }
    }

    /// returns the unsigned integer given by the bits in between `i`
    /// and `j-1`, inclusive, where zero denotes the leftmost (most
    /// significant) bit.  This indexing scheme is compatible with
    /// that used in IETF standard notation (RFC 1700).  See the
    /// examples in \ref slice<i, j, T>(T x).
    ///
    template <size_t i, size_t j>
    T slice() const {
        return ::slice<i,j>(val);
    }

    /// `bit<i>() const` returns the ith bit of the value, where zero denotes
    /// the leftmost (most significant) bit.
    ///
    template <size_t i>
    bool bit() const {
        return (bool) slice<i,i+1>();
    }

    /// encoded<T>::unit_test() returns true if there is a unit test
    /// for typename T defined and that test passed; otherwise, it
    /// returns false.  The unit test functions are template
    /// specializations, and they are only defined when NDEBUG is not
    /// `#defined`.
    ///
    static bool unit_test() {
        return false;
    }

    // TODO: add a function slice<i,j>(T newvalue) that sets the bits
    // associated with a slice

    void write(writeable &buf, bool swap_byte_order=false) const {
        encoded<T> tmp = val;
        if (swap_byte_order) {
            tmp.swap_byte_order();
        }
        buf.copy((uint8_t *)&tmp, sizeof(T));

        // TODO: rewrite function to eliminate cast
    }

    /// write_hex() writes a hexadecimal representation of this
    /// unsigned integer in network byte order
    ///
    void write_hex(writeable &w) const {
        encoded<T> tmp = val;
        tmp.swap_byte_order();                        // TODO: write endian-generic version
        w.write_hex((uint8_t *)&tmp, sizeof(T));
    }
};

/// `class type_codes` is a wrapper class that can be used to print
/// type codes.
///
/// `class type_codes` has a member function to write to json_object,
/// a string depending on known typecodes for that class. The class
/// utilises the json_object template function print_key_value to
/// write a type_code string. The type_code class to be wrapped must
/// have a type_code, and functions: template T get_code() to return
/// code value and char* print_code_str() to return code str or
/// returns null for unknown code
///
template <typename T>
class type_codes {
    const T &code;

public:
    type_codes(const T &type_code) : code{type_code} {}

    void print_code(buffer_stream &b, encoded<uint8_t> code) {
        b.write_uint8(code.value());
    }

    void print_code(buffer_stream &b, encoded<uint16_t> code) {
        b.write_uint16(code.value());
    }

    void print_code(buffer_stream &b, uint8_t code) {
        b.write_uint8(code);
    }

    void print_code(buffer_stream &b, uint16_t code) {
        b.write_uint16(code);
    }

    // template function for code types with custom code writing functions
    template <typename code_type>
    void print_code(buffer_stream &b, code_type code) {
        code.write_code(b);
    }

    template <typename code_type>
    void print_unknown_code(buffer_stream &b, code_type code) {
        b.puts("UNKNOWN (");
        print_code(b, code);
        b.puts(")");
    }

    /// write a textual representation of this type_code into \param b
    ///
    void write(buffer_stream &b) {
        const char* code_str = code.get_code_str();
        if (!code_str) {
            print_unknown_code(b, code.get_code());
        }
        else {
            b.puts(code_str);
        }
    }
};

/// `class byte_alternatives` attempts to read an
/// encoded<uint8_t> element from a datum, and if
/// successful, verifies that its value is one of the provided
/// alternatives.  If either step fails, the `datum` is set to `null`.
/// Otherwise, the value of the decoded `uint8_t` is available through
/// the encoded<uint8_t>::value() function.
///
template <char ... Values>
class byte_alternatives : public encoded<uint8_t> {
public:

    byte_alternatives(datum &d) : encoded<uint8_t>{d} {
        if (d.is_not_null() and ((this->value() == Values) || ...)) {
            return;
        }
        d.set_null();
    }

};


/// returns a `std::array<uint8_t,N>` formed from the successive
/// \param Args
///
/// \example `to_array<'G', 'E', 'T'>` returns `std::array<uint8_t,3>{
/// 0x47, 0x45, 0x54 }`
///
template<typename T, typename... Args>
constexpr auto to_array(Args&&... args) {
    std::array<T, sizeof...(Args)> result{};
    size_t index = 0;
    ((result[index++] = static_cast<T>(args)), ...);
    return result;
}

/// class literal accepts a literal `std::array` of `uint8_t`s
///
template <uint8_t... Args>
class literal {
public:
    literal(datum &d) {
        d.accept(to_array<uint8_t>(Args...));
    }
};

/// `class literal_byte<arg1, arg2, ...>` accepts a variable number of
/// input bytes, and sets `d` to null if the expected input is not found
///
template<uint8_t... args>
class literal_byte {
public:

    /// construct a `literal_byte<arg1, arg2, ...>` by accepting the
    /// literal bytes `arg1, arg2, ...`, and set `d` to null if the expected
    /// input is not found
    ///
    literal_byte(datum &d) {
        (d.accept(args),...);
    }
};

/// `class skip_bytes<N>` skips `N` bytes in the given datum
///
template <size_t N>
class skip_bytes {
public:
    skip_bytes (datum &d) {
        d.skip(N);
    }
    skip_bytes (datum &d, size_t n) {
        d.skip(n);
    }
};

// sanity checks on class encoded<T>
//
static_assert(sizeof(encoded<uint8_t>)  == 1);
static_assert(sizeof(encoded<uint16_t>) == 2);
static_assert(sizeof(encoded<uint32_t>) == 4);
static_assert(sizeof(encoded<uint64_t>) == 8);

#ifndef NDEBUG

// @name Template specializations of encoded<T>::unit_test()
// @{
//
//   To provide unit test functions for each supported type `T`,
//   `encoded<T>::unit_test()` is defined.  To use these tests, do
//   not define `NDEBUG` (or undefine that variable by e.g. passing
//   the compiler flag `-UNDEBUG`), and call each one inside of an
//   `assert()` macro, or whatever unit test function is appropriate.

// returns `true` if that template specialization class passes its
// unit test, and `false` otherwise.
//
template <>
inline bool encoded<uint8_t>::unit_test() {
    encoded<uint8_t> x{0xaa};
    return
        x.bit<0>() == 1 &&
        x.bit<1>() == 0 &&
        x.bit<2>() == 1 &&
        x.bit<3>() == 0 &&
        x.bit<4>() == 1 &&
        x.bit<5>() == 0 &&
        x.bit<6>() == 1 &&
        x.bit<7>() == 0;
}

// `encoded<uint16_t>::unit_test()` returns `true` if that class
// passes its unit test, and `false` otherwise.
//
template <>
inline bool encoded<uint16_t>::unit_test() {
    encoded<uint16_t> x{0x9f00};
    return
        x.slice<0,1>()  == 1  &&
        x.slice<1,3>()  == 0  &&
        x.slice<3,8>()  == 31 &&
        x.slice<8,16>() == 0;
}

// `encoded<uint32_t>::unit_test()` returns `true` if that class
// passes its unit test, and `false` otherwise.
//
template <>
inline bool encoded<uint32_t>::unit_test() {
    encoded<uint32_t> y = 0xa1b2c3df;
    return
        ::slice<0,32>(y.value())  == 0xa1b2c3df &&
        ::slice<0,8>(y.value())   == 0xa1       &&
        ::slice<4,12>(y.value())  == 0x1b       &&
        ::slice<8,16>(y.value())  == 0xb2       &&
        ::slice<24,32>(y.value()) == 0xdf       &&
        ::slice<16,32>(y.value()) == 0xc3df     &&
        y.slice<0,32>()  == 0xa1b2c3df &&
        y.slice<0,8>()   == 0xa1       &&
        y.slice<4,12>()  == 0x1b       &&
        y.slice<8,16>()  == 0xb2       &&
        y.slice<24,32>() == 0xdf       &&
        y.slice<16,32>() == 0xc3df;
}

// `encoded<uint64_t>::unit_test()` returns `true` if that class
// passes its unit test, and `false` otherwise.
//
template <>
inline bool encoded<uint64_t>::unit_test() {
    encoded<uint64_t> y = 0xa1b2c3dfaabbccdd;
    return
        ::slice<0,32>(y.value())  == 0xa1b2c3df &&
        ::slice<0,8>(y.value())   == 0xa1       &&
        ::slice<4,12>(y.value())  == 0x1b       &&
        ::slice<8,16>(y.value())  == 0xb2       &&
        ::slice<24,32>(y.value()) == 0xdf       &&
        ::slice<16,32>(y.value()) == 0xc3df     &&
        y.slice<0,32>()  == 0xa1b2c3df &&
        y.slice<0,8>()   == 0xa1       &&
        y.slice<4,12>()  == 0x1b       &&
        y.slice<8,16>()  == 0xb2       &&
        y.slice<24,32>() == 0xdf       &&
        y.slice<16,32>() == 0xc3df     &&
        y.slice<56,64>() == 0xdd;
}

// @}

#endif // NDEBUG

/// `class lookahead<T>` attempts to read an element of type `T` from
/// a datum, without modifying that datum.  If the read succeeded,
/// then casting the lookahead object to a `bool` returns `true`;
/// otherwise, it returns `false`.  On success, the value of the
/// element can be accessed through the public `value` member.  To
/// advance the datum forward (e.g. to accept the lookahead object),
/// set its value to that returned by the `advance()` function.
///
/// NOTE: `advance()` will return a null datum if the read did not
/// succeed.
///
template <typename T>
class lookahead {
public:
    T value;
private:
    datum tmp;
public:

    /// construct a lookahead<T> object by parsing the datum d.
    ///
    lookahead(datum d) : value{d}, tmp{d} { }

    /// construct a lookahead<T> object by parsing the datum held by
    /// another lookahead<> object.
    ///
    template <typename T2>
    lookahead(lookahead<T2> &l) : value{l.tmp}, tmp{l.tmp} { }

    /// construct a lookahead<T> object by parsing the datum d while
    /// passing the parameter p of type P to the constructor of the T
    /// object.
    ///
    template <typename P>
    lookahead(datum d, P p) : value{d}, tmp{d, p} { }

    explicit operator bool() const { return tmp.is_not_null(); }

    datum advance() const { return tmp; }

    /// get_parsed_data() returns the datum that indicates the bytes
    /// that were read in order to construct the element \ref value,
    /// if that read succeeded; otherwise, it returns a null datum.
    ///
    datum get_parsed_data(datum &d) const {
        if (tmp.is_not_null()) {
            return { d.data, tmp.data };
        }
        return { nullptr, nullptr };
    }

};

/// class `acceptor<T>` attempts to read an element of type `T` from a
/// datum reference.  If the read succeeded, the datum is advanced
/// forward, and casting the `acceptor<T>` object to a `bool` returns
/// `true`; otherwise, that cast returns `false`.  On success, the
/// value of the element can be accessed through the public \ref value
/// member.
///
template <typename T>
class acceptor {
public:
    T value;       ///< the accepted value, if `valid == true`
private:
    bool valid;    ///< true only if an object of type `T` could be accepted
public:

    /// construct an `acceptor<T>` object by parsing an object of type
    /// `T` from the `datum d`.
    ///
    acceptor(datum &d) : value{d}, valid{d.is_not_null()} { }

    /// cast an `acceptor<T>` object to bool to determine if an object
    /// of type `T` was successfully parsed (accepted), in which case
    /// `true` is returned.  Otherwise, `false` is returned.
    ///
    operator bool() const { return valid; }
};

/// class optional<T> attempts to read an element of type T from a
/// datum reference.  If the read succeeds, the datum is advanced
/// forward, and casting the optional<T> object to a bool returns true;
/// otherwise, that cast returns false.  On success, the value of the
/// element can be accessed through the public value member.  If the
/// read fails, the datum is left unchanged (it is neither advanced nor
/// set to null).
///
template <typename T>
class optional {
    datum tmp;
public:
    T value;
private:
    bool valid;
public:

    optional(datum &d) :
        tmp{d},
        value{tmp},
        valid{tmp.is_not_null()}
    {
        if (valid) {
            d = tmp;
        }
    }

};

/// parses a data element of type `T`, but then ignores (does not
/// store) its value.  It can be used to check the format of data that
/// need not be stored, or to create an object that will write out `T`
/// null (0x00) bytes to a \ref writeable..
///
// TODO: the parameter T should be able to accept any class, not just
// unsigned integer types
//
template <typename T>
class ignore {

public:

    ignore(datum &d, bool little_endian=false) {
        (void)little_endian;
        T{d};
    }

    ignore() { }

    /// writes out null value
    ///
    void write(writeable &w) {
        uint8_t zero[sizeof(T)] = { 0, };
        w.copy(zero, sizeof(T));
    }
};

/// parses a sequence of objects of type `T` from a datum, when used in
/// a range-based for loop.
///
/// \note Objects of type `T` must be constructible from a \ref datum
/// reference.
///
/// The following example shows how to read four \ref
/// encoded<uint16_t> objects from a buffer.
///
/// \code
///     uint8_t buffer[] = {
///         0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
///     };
///     datum d{buffer, buffer + sizeof(buffer)};
///     for (encoded<uint16_t> x : sequence<encoded<uint16_t>>{d}) {
///         printf("%04x\n", x.value());
///     }
/// \endcode
///
template <typename T>
class sequence {
    datum tmp;
    T value;

    static_assert(std::is_constructible_v<T, datum &>, "T must be constructible from a datum reference");

    struct iterator {
        sequence *seq;

        void operator++() { seq->value = T{seq->tmp}; }

        T& operator* () { return seq->value; }

        bool operator!= (const iterator &) const { return seq->tmp.is_not_null(); }

    };

public:

    sequence(const datum &d) : tmp{d}, value{tmp} { }

    iterator begin() { return { this }; }

    iterator end() { return { nullptr }; }

};

namespace {

    [[maybe_unused]] int datum_fuzz_test(const uint8_t *data, size_t size) {
        datum d{data, data+size};
        d.isupper();
        d.is_alnum();
        d.is_any_alpha();
        d.is_printable();
        uint8_t output;
        d.lookahead_uint8(&output);
        auto str = std::make_unique<char[]>(size + 1);
        str[size] = '\0';
        datum d2{str.get()};
        return 0;
    }

    [[maybe_unused]] int datum_trim_leading_whitespace_fuzz_test(const uint8_t *data, size_t size) {
        datum d{data, data+size};
        d.trim_leading_whitespace();
        return 0;
    }

    [[maybe_unused]] int datum_bits_in_data_fuzz_test(const uint8_t *data, size_t size) {
        datum d{data, data+size};
        d.bits_in_data();
        return 0;
    }

    [[maybe_unused]] int datum_parse_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum d1;
        datum d2{data1, data1+size1};
        ssize_t num_bytes;
        memcpy(&num_bytes, data2, std::min(sizeof(ssize_t), size2));
        d1.parse(d2, num_bytes);
        return 0;
    }

    [[maybe_unused]] int datum_parse_soft_fail_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum d1;
        datum d2{data1, data1+size1};
        size_t num_bytes;
        memcpy(&num_bytes, data2, std::min(sizeof(size_t), size2));
        d1.parse_soft_fail(d2, num_bytes);
        return 0;
    }

    [[maybe_unused]] int datum_parse_up_to_delim_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum d1;
        datum d2{data1, data1+size1};
        uint8_t delim;
        memcpy(&delim, data2, std::min(sizeof(uint8_t), size2));
        d1.parse_up_to_delim(d2, delim);
        return 0;
    }

    [[maybe_unused]] int datum_skip_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum d{data1, data1+size1};
        size_t length;
        memcpy(&length, data2, std::min(sizeof(size_t), size2));
        d.skip(length);
        return 0;
    }

    [[maybe_unused]] int datum_trim_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum d{data1, data1+size1};
        size_t length;
        memcpy(&length, data2, std::min(sizeof(size_t), size2));
        d.trim(length);
        return 0;
    }

    [[maybe_unused]] int datum_trim_to_length_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum d{data1, data1+size1};
        size_t length;
        memcpy(&length, data2, std::min(sizeof(size_t), size2));
        d.trim_to_length(length);
        return 0;
    }

    [[maybe_unused]] int datum_case_insensitive_match_1_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum d1{data1, data1+size1};
        datum d2{data2, data2+size2};
        d1.case_insensitive_match(d2);
        return 0;
    }

    [[maybe_unused]] int datum_case_insensitive_match_2_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum d{data1, data1+size1};
        auto name = std::make_unique<char []>(size2 + 1);
        memcpy(name.get(), data2, size2);
        name[size2] = '\0';
        d.case_insensitive_match(name.get());
        return 0;
    }

    [[maybe_unused]] int datum_cmp_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum d1{data1, data1+size1};
        datum d2{data2, data2+size2};
        d1.cmp(d2);
        return 0;
    }


    [[maybe_unused]] int datum_find_delim_1_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum d{data1, data1+size1};
        d.find_delim(reinterpret_cast<const unsigned char*>(data2), size2);
        return 0;
    }

    [[maybe_unused]] int datum_find_delim_2_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, [[maybe_unused]] size_t size2) {
        datum d{data1, data1+size1};
        const uint8_t delim = data2[0];
        d.find_delim(delim);
        return 0;
    }

    [[maybe_unused]] int datum_skip_up_to_delim_1_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, [[maybe_unused]] size_t size2) {
        datum d{data1, data1+size1};
        const uint8_t delim = data2[0];
        d.skip_up_to_delim(delim);
        return 0;
    }

    [[maybe_unused]] int datum_skip_up_to_delim_2_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum d{data1, data1+size1};
        d.skip_up_to_delim(reinterpret_cast<const unsigned char*>(data2), size2);
        return 0;
    }

    [[maybe_unused]] int datum_trim_trail_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, [[maybe_unused]] size_t size2) {
        datum d{data1, data1+size1};
        unsigned char trail = data2[0];
        d.trim_trail(trail);
        return 0;
    }

    [[maybe_unused]] int datum_accept_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, [[maybe_unused]] size_t size2) {
        datum d{data1, data1+size1};
        uint8_t byte = data2[0];
        d.accept(byte);
        return 0;
    }

    [[maybe_unused]] int datum_accept_byte_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum d{data1, data1+size1};
        auto alternative = std::make_unique<uint8_t []>(size2 + 1);
        uint8_t output;
        memcpy(alternative.get(), data2, size2);
        alternative[size2] = 0;
        d.accept_byte(alternative.get(), &output);
        return 0;
    }


    [[maybe_unused]] int datum_lookahead_uint_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum d{data1, data1+size1};
        unsigned int num_bytes;
        memcpy(&num_bytes, data2, std::min(sizeof(unsigned int), size2));
        uint64_t output;
        d.lookahead_uint(num_bytes, &output);
        return 0;
    }

    [[maybe_unused]] int datum_compare_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum d{data1, data1 + size1};
        d.compare(data2, size2);
        return 0;
    }

    [[maybe_unused]] int datum_fprint_hex_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum d{data1, data1 + size1};
        size_t length;
        memcpy(&length, data2, std::min(sizeof(size_t), size2));
        FILE *temp_file = tmpfile();
        d.fprint_hex(temp_file, length);
        fclose(temp_file);
        return 0;
    }

    [[maybe_unused]] int datum_fprint_c_array_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum d{data1, data1 + size1};
        auto name = std::make_unique<char []>(size2 + 1);
        memcpy(name.get(), data2, size2);
        name[size2] = '\0';
        FILE *temp_file = tmpfile();
        d.fprint_c_array(temp_file, name.get());
        fclose(temp_file);
        return 0;
    }

    [[maybe_unused]] int datum_fprint_fuzz_2_test(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        datum d{data1, data1 + size1};
        size_t length;
        memcpy(&length, data2, std::min(sizeof(size_t), size2));
        FILE *temp_file = tmpfile();
        d.fprint(temp_file, length);
        fclose(temp_file);
        return 0;
    }

    [[maybe_unused]] int writeable_copy_1_fuzz_2_test([[maybe_unused]] const uint8_t *data1, size_t size1, const uint8_t *data2, [[maybe_unused]] size_t size2) {
        auto buffer = std::make_unique<uint8_t []>(size1);
        writeable w{buffer.get(), buffer.get()+size1};
        uint8_t x = data2[0];
        w.copy(x);
        return 0;
    }

    [[maybe_unused]] int writeable_copy_2_fuzz_2_test([[maybe_unused]] const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        auto buffer = std::make_unique<uint8_t []>(size1);
        writeable w{buffer.get(), buffer.get()+size1};
        w.copy(data2, size2);
        return 0;
    }

    [[maybe_unused]] int writeable_write_hex_fuzz_2_test( [[maybe_unused]] const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        auto buffer = std::make_unique<uint8_t []>(size1);
        writeable w{buffer.get(), buffer.get()+size1};
        w.write_hex(data2, size2);
        return 0;
    }


    [[maybe_unused]] int writeable_write_quote_enclosed_hex_1_fuzz_2_test([[maybe_unused]] const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        auto buffer = std::make_unique<uint8_t []>(size1);
        writeable w{buffer.get(), buffer.get()+size1};
        w.write_quote_enclosed_hex(data2, size2);
        return 0;
    }

    [[maybe_unused]] int writeable_write_quote_enclosed_hex_2_fuzz_2_test([[maybe_unused]] const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        auto buffer = std::make_unique<uint8_t []>(size1);
        writeable w{buffer.get(), buffer.get()+size1};
        datum d{data2, data2+size2};
        w.write_quote_enclosed_hex(d);
        return 0;
    }


    [[maybe_unused]] int writeable_copy_from_hex_fuzz_2_test([[maybe_unused]] const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
        auto buffer = std::make_unique<uint8_t []>(size1);
        writeable w{buffer.get(), buffer.get()+size1};
        w.copy_from_hex(data2, size2);
        return 0;
    }


    [[maybe_unused]] int dynamic_buffer_fuzz_test(const uint8_t *data, [[maybe_unused]] size_t size) {
        size_t initial_capacity = data[0];
        dynamic_buffer buffer(initial_capacity);

        buffer.reset();
        buffer.is_not_empty();
        buffer.readable_length();
        buffer.contents();

        return 0;
    }
};

#endif /* DATUM_H */
