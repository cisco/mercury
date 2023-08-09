/*
 * datum.h
 *
 * Copyright (c) 2019-2020 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef DATUM_H
#define DATUM_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <array>
#include <bitset>
#include <limits>
#include <string>
#include <cassert>
#include "libmerc.h"  // for enum status
#include "buffer_stream.h"

/*
 * The mercury_debug macro is useful for debugging (but quite verbose)
 */
#ifndef DEBUG
#define mercury_debug(...)
#else
#define mercury_debug(...)  (fprintf(stdout, __VA_ARGS__))
#endif

// portable ntoh/hton/swap_byte_order functions for uint16_t,
// uint32_t, and uint64_t
//
// swap_byte_order(x) returns an integer equal to x with its byte
// order reversed (from little endian to big endian or vice-versa)
//
// ntoh(x) - 'network to host byte order' - when x is in network byte
// order, ntoh(x) returns x in host byte order
//
// hton(x) - 'host to network byte order' - when x is in host byte
// order, hton(x) returns x in network byte order
//
// Given an unsigned integer variable x in host byte order, hton(x)
// returns an unsigned integer in network byte order with the same
// type and value.  Similarly, given an unsigned integer variable x in
// network byte order, ntoh(x) returns an unsigned integer in host
// byte order with the same type and value.  hton() and ntoh() are
// template functions with specializations for uint16_t, uint32_t, and
// uint64_t.
//
// To apply hton() or ntos() to an unsigned integer literal, use the
// appropriate template specialization.  For instance,
// hton<uint16_t>(443) obtains a uint16_t in network byte order for
// the unsigned integer 443.  The specialization must be used because
// otherwise a compiler error will result from the amiguity.
//
#ifdef _WIN32

static constexpr bool host_little_endian = true;

inline static uint16_t swap_byte_order(uint16_t x) { return _byteswap_ushort(x); }
inline static uint32_t swap_byte_order(uint32_t x) { return _byteswap_ulong(x); }
inline static uint64_t swap_byte_order(uint64_t x) { return _byteswap_uint64(x); }

#else

static constexpr bool host_little_endian = (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__);

inline static uint16_t swap_byte_order(uint16_t x) { return __builtin_bswap16(x); }
inline static uint32_t swap_byte_order(uint32_t x) { return __builtin_bswap32(x); }
inline static uint64_t swap_byte_order(uint64_t x) { return __builtin_bswap64(x); }

#endif

template <typename T>
inline static T ntoh(T x) { if (host_little_endian) { return swap_byte_order(x); } return x; }

template <typename T>
inline static T hton(T x) { if (host_little_endian) { return swap_byte_order(x); } return x; }


inline uint8_t lowercase(uint8_t x) {
    if (x >= 'A' && x <= 'Z') {
        return x + ('a' - 'A');
    }
    return x;
}

struct datum {
    const unsigned char *data;          /* data being parsed/copied  */
    const unsigned char *data_end;      /* end of data buffer        */

    const uint8_t *begin() const { return data; }
    const uint8_t *end() const { return data_end; }
    const uint8_t *cbegin() const { return data; }
    const uint8_t *cend()   const { return data_end; }

    datum() : data{NULL}, data_end{NULL} {}
    datum(const unsigned char *first, const unsigned char *last) : data{first}, data_end{last} {}
    datum(datum &d, ssize_t length) {
        parse(d, length);
    }
    datum(std::pair<const unsigned char *, const unsigned char *> p) : data{p.first}, data_end{p.second} {}
    template <size_t N> datum(const std::array<uint8_t, N> &a) : data{a.data()}, data_end{data + a.size()} { }

    // implicit converstion to a pair of pointers
    //
    operator std::pair<const unsigned char *, const unsigned char *> () const { return { data, data_end }; }

    //parser(const unsigned char *d, const unsigned char *e) : data{d}, data_end{e} {}
    //parser(const unsigned char *d, size_t length) : data{d}, data_end{d+length} {}
    const std::string get_string() const { std::string s((char *)data, (int) (data_end - data)); return s;  }
    const std::basic_string<uint8_t> get_bytestring() const { std::basic_string<uint8_t> s((uint8_t *)data, (int) (data_end - data)); return s;  }
    bool is_null() const { return data == NULL; }
    bool is_not_null() const { return data != NULL; }
    bool is_not_empty() const { return data != NULL && data < data_end; }
    bool is_readable() const { return data != NULL && data < data_end; }
    bool is_not_readable() const { return data == NULL || data == data_end; }
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
        data = r.data;
        while (r.data < r.data_end) {
            if (*r.data == delim) { // found delimeter
                data_end = r.data;
                return;
            }
            r.data++;
        }
        data_end = r.data;
    }
    uint8_t parse_up_to_delimeters(struct datum &r, uint8_t delim1, uint8_t delim2) {
        data = r.data;
        while (r.data < r.data_end) {
            if (*r.data == delim1) { // found first delimeter
                data_end = r.data;
                return delim1;
            }
            if (*r.data == delim2) { // found second delimeter
                data_end = r.data;
                return delim2;
            }
            r.data++;
        }
        return 0;
    }
    uint8_t parse_up_to_delimeters(struct datum &r, uint8_t delim1, uint8_t delim2, uint8_t delim3) {
        data = r.data;
        while (r.data < r.data_end) {
            if (*r.data == delim1) { // found first delimeter
                data_end = r.data;
                return delim1;
            }
            if (*r.data == delim2) { // found second delimeter
                data_end = r.data;
                return delim2;
            }
            if (*r.data == delim3) { // found third delimeter
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
    // datum::memcmp(datum &p) compares this datum to p
    // lexicographically, and returns an integer less than, equal to,
    // or greater than zero if this is found to be less than, to
    // match, or to be greater than p, respectively.
    //
    // For a nonzero return value, the sign is determined by the sign
    // of the difference between the first pair of bytes (interpreted
    // as unsigned char) that differ in this and p.  If this->length()
    // and p.length() are both zero, the return value is zero.  If one
    // datum is a prefix of the other, the prefix is considered
    // lesser.
    //
    // Examples (in hexadecimal, where {} is the zero-length string):
    //
    //    A = 50555348, B = 504f5354:    A.memcmp(B) < 0
    //    A = 50555348, B = 5055534820:  A.memcmp(B) < 0
    //    A = 50555348, B = {}:          A.memcmp(B) > 0
    //    A = {}, B = {}:                A.memcmp(B) == 0
    //
    int cmp(const datum &p) const {
        int cmp = ::memcmp(data, p.data, std::min(length(), p.length()));
        if (cmp == 0) {
            return length() - p.length();
        }
        return cmp;
    }

    // operator<(const datum &p) returns true if this is
    // lexicographically less than p, and false otherwise.  It is
    // suitable for use in std::sort().
    //
    bool operator<(const datum &p) const {
        return cmp(p) < 0;
     }

    template <size_t N>
    bool cmp(const std::array<uint8_t, N> a) const {
        if (length() == N) {
            return ::memcmp(data, a.data, N) == 0;
        }
        return false;
    }

    bool operator==(const datum &rhs) const {
        return data == rhs.data && data_end == rhs.data_end;
    }
    bool operator!=(const datum &rhs) const {
        return data != rhs.data || data_end != rhs.data_end;
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
    /*
     * find_delim(d, l) looks for the delimiter d with length l
     * in the parser p's data buffer, until it reaches the delimiter d or
     * the end of the data in the parser, whichever comes first.  In the
     * first case, the function returns the number of bytes to the
     * delimiter; in the second case, the function returns the number of
     * bytes to the end of the data buffer.
     */
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
                pattern = delim - 1; /* reset pattern to the start of the delimeter string */
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
        const unsigned char *tmp_data = data;
        while (tmp_data < data_end) {
            if (*tmp_data == delim) {
                return tmp_data - data;
            }
            tmp_data++;
        }
        return -1;
    }
    void skip_up_to_delim(uint8_t delim) {
        while (data <= data_end) {
            if (*data == delim) { // found delimeter
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

// trim_trail(t) skips/trims all instance of trailing char t
//
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

    // lookahead_uint8() reads a uint8_t in network byte order,
    // without advancing the data pointer
    //
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

    // get_pointer<T> returns a pointer to type T and advances the
    // data pointer, if there are sizeof(T) bytes available, and
    // otherwise it returns nullptr
    //
    // if T is a struct, it SHOULD use the __attribute__((__packed__))
    //
    template <typename T>
    T* get_pointer() {
        if (data + sizeof(T) <= data_end) {
            T *tmp = (T *)data;
            data += sizeof(T);
            return tmp;
        }
        return nullptr;
    }

    // read_uint8() reads a uint8_t in network byte order, and advances the data pointer
    //
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

    // read_uint16() reads a uint16_t in network byte order, and advances the data pointer
    //
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

    // read_uint32() reads a uint32_t in network byte order, and advances the data pointer
    //
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

    // read_uint() reads a length num_bytes uint in network byte order, and advances the data pointer
    //
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

    bool read_bytestring(unsigned int num_bytes, uint8_t *output_string)
    {
        if (data + num_bytes <= data_end)
        {
            const unsigned char *c;

            for (c = data; c < data + num_bytes; c++)
            {
                *output_string++ = *c;
            }
            data += num_bytes;
            return true;
        }
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

    bool set_uint(size_t *output, unsigned int num_bytes) {

        if (data && data + num_bytes <= data_end) {
            size_t tmp = 0;
            const unsigned char *c;

            for (c = data; c < data + num_bytes; c++) {
                tmp = (tmp << 8) + *c;
            }
            *output = tmp;
            return true;
        }
        return false;
    }

    void init_from_outer_parser(struct datum *outer,
                                unsigned int data_len) {
        if (!outer->is_not_empty()) {
            return;
        }
        const unsigned char *inner_data_end = outer->data + data_len;

        data = outer->data;
        data_end = inner_data_end > outer->data_end ? outer->data_end : inner_data_end;
        outer->data = data_end; // PROVISIONAL; NEW APPROACH
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
        return std::numeric_limits<int>::min();
    }

    void fprint_hex(FILE *f, size_t length=0) const {
        if (data == nullptr) { return; }
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
        size_t count = 1;
        const uint8_t *x = data;
        fprintf(f, "uint8_t %s[] = {\n    ", name);
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

    // fwrite(f) writes the entire datum out to the FILE *f, and on
    // success, returns the number of bytes written; otherwise, 0 is
    // returned.  This function can be used to write out seed files
    // for fuzz testing.
    //
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

};

// sanity checks on class datum
//
static_assert(sizeof(datum) == 2 * sizeof(uint8_t *));


// class writeable represents a writeable region of memory
//
class writeable {
public:
    uint8_t *data;
    uint8_t *data_end;      // TODO: const?

    writeable(uint8_t *begin, uint8_t *end) : data{begin}, data_end{end} { }

    bool is_null() const { return data == nullptr || data_end == nullptr; }

    bool is_not_empty() const { return data < data_end; }

    ssize_t writeable_length() const { return data_end - data; }

    void update(ssize_t length) {
        // a length less than zero is considered an error state
        //
        if (length < 0) {
            set_null();
            return;
        }
        data += length;
    }

    //    ptrdiff_t length() const { return data_end - data; }

    void set_null() { data = data_end = nullptr; }

    void set_empty() { data = data_end; }

    void copy(uint8_t x) {
        if (data + 1 > data_end) {
            set_null();
            return;  // not enough room
        }
        *data++ = x;
    }
    void copy(const uint8_t *rdata, size_t num_bytes) {
        if (data_end - data < (ssize_t)num_bytes) {
            set_null();
            return;
        }
        memcpy(data, rdata, num_bytes);
        data += num_bytes;
    }

    void write_hex(const uint8_t *src, size_t num_bytes) {

        // check for writeable room; output length is twice the input
        // length
        //
        if (is_null() or data_end - data < 2 * (ssize_t)num_bytes) {
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
    }

    void write_quote_enclosed_hex(const uint8_t *src, size_t num_bytes) {
        copy('"');
        write_hex(src, num_bytes);
        copy('"');
    }

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

    // parse(r, num_bytes) copies num_bytes out of r and into this, and
    // advances r, if this writeable has enough room for the data and
    // r contains at least num_bytes.  If r.length() < num_bytes, then
    // r is set to null, and if this->length() < num_bytes, then this
    // is set to null.
    //
    void parse(struct datum &r, size_t num_bytes) {
        if (r.length() < (ssize_t)num_bytes) {
            r.set_null();
            // fprintf(stderr, "warning: not enough data in parse\n");
            return;
        }
        if (data_end - data < (int)num_bytes) {
            set_null();
            return;
        }
        memcpy(data, r.data, num_bytes);
        data += num_bytes;
        r.data += num_bytes;
    }
    void parse(struct datum &r) {
        parse(r, r.length());
    }

    template <typename Type>
    writeable & operator<<(Type t) {
        t.write(*this);
        return *this;
    }

    // template specialization for datum
    //
    writeable & operator<<(datum d) {
        if (d.is_not_null()) {
            parse(d);
        }
        return *this;
    }

};

// data_buffer is a contiguous sequence of bytes into which data can
// be copied sequentially; the data structure tracks the start of the
// data (buffer), the location to which data can be written (writeable.data),
// and the end of the data buffer (writeable.data_end)
//
template <size_t T> struct data_buffer : public writeable {
    unsigned char buffer[T];                                     // TODO: make buffer private

    data_buffer() : writeable{buffer, buffer+T} { }

    void reset() { data = buffer; }
    bool is_not_empty() const { return data != buffer && data < data_end; }

    // data_buffer::readable_length() returns the number of bytes in
    // the readable region, if the writeable region is not null;
    // otherwise, zero is returned
    //
    ssize_t readable_length() const {
        if (writeable::is_null()) {
            return 0;
        }
        else {
            return data - buffer;
        }
    }

    datum contents() const {
        if (writeable::is_null()) {
            return {nullptr, nullptr};
        } else {
            return {buffer, data};
        }
    }

    ssize_t write(int fd) { return ::write(fd, buffer, data - buffer);  }

    template <size_t S>
    bool operator==(const data_buffer<S> &rhs) {
        return readable_length() == rhs.readable_length() &&
            memcmp(buffer, rhs.buffer, readable_length()) == 0;
    }
    template <size_t S>
    bool operator!=(const data_buffer<S> &rhs) {
        return readable_length() != rhs.readable_length() ||
            memcmp(buffer, rhs.buffer, readable_length()) != 0;
    }

    // TODO:
    //  * add data != nullptr checks
    //  * add set_null() function
    //  * use null state to indicate write failure
    //  * add assert() macros to support debugging
    //  * add [[nodiscard]] as appropriate

};

// pad_len(length) returns the number that, when added to length,
// rounds that value up to the next multiple of four
//
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

// class pad reads and ignores padding data
//
class pad {
    size_t padlen;
public:

    // constructor for reading (and ignoring) padding data
    //
    pad(datum &d, size_t n) : padlen{n} {
        d.data += padlen;
        if (d.data > d.data_end) {
            d.set_null();
        }
    }

    // constructor for writing (all-zero) padding data
    //
    pad(size_t n) : padlen{n} { }

    void write(writeable &w) {
        uint8_t zero[4] = {0, 0, 0, 0};
        w.copy(zero, padlen);
        assert(padlen <= 5);
    }
};


// integer decoding
//
#define bitsizeof(x) (sizeof(x) * 8)

// slice<i, j>(x) returns the unsigned integer represented by the bits
// of x in between i and j-1, inclusive, where zero denotes the
// leftmost (most significant) bit.  This indexing scheme is
// compatible with that used in IETF standard notation (see RFC 1700).
//
// For example, slice<4,12>(0xa1b2c3d4) is 0x1b
//
// For example, the bitfields A, B, C, and D defined by
//
//     0                   1
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |A| B |    C    |     D         |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// can be accessed as
//
//    A = slice<0,1>
//    B = slice<1,3>
//    C = slice<3,8>
//    D = slice<8,16>
//
// Implementation note: the cast to type T is essential so that types
// smaller than 'unsigned integer' will not be promoted to a larger
// type.  That size promotion, if allowed, would break this function.
//
template <size_t i, size_t j, typename T>
constexpr T slice(T s) {
    return ((T)(s << i)) >> (bitsizeof(T)-(j-i));
}

// bit<i>(x) returns the value of the ith bit of x, as a boolean.
//
template <size_t i, typename T>
bool bit(T s) {
    return (bool) slice<i,i+1>(s);
}

// encoded<T> represents an unsigned integer type T that is read from
// a byte stream
//
template <typename T>
class encoded {
    T val;

    static_assert(std::is_unsigned_v<T>, "T must be an unsigned integer");

public:

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

    // swap_byte_order() reverses the byte order of the integer val,
    // from big endian to little endian or vice-versa.
    //
    // Note: this operation is only the same as hton() if the host
    // byte order is little-endian.
    //
    void swap_byte_order() {
        if constexpr (sizeof(val) == 8) {
            val = ::swap_byte_order(val);
        } else if constexpr (sizeof(val) == 4) {
            val = ::swap_byte_order(val);
        } else if constexpr (sizeof(val) == 2) {
            val = ::swap_byte_order(val);
        }
    }

    // slice<i, j>() returns the unsigned integer given by the bits in
    // between i and j-1, inclusive, where zero denotes the leftmost
    // (most significant) bit.  This indexing scheme is compatible
    // with that used in IETF standard notation (RFC 1700).  See the
    // examples above.
    //
    template <size_t i, size_t j>
    T slice() const {
        return ::slice<i,j>(val);
    }

    // bit<i>() returns the ith bit of the value, where zero denotes
    // the leftmost (most significant) bit.
    //
    template <size_t i>
    bool bit() const {
        return (bool) slice<i,i+1>();
    }

    // encoded<T>::unit_test() returns true if there is a unit test
    // for typename T defined and that test passed; otherwise, it
    // returns false.  The unit test functions are template
    // specializations, and they are only defined when NDEBUG is not
    // #defined.
    //
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

    // write_hex() writes a hexadecimal representation of this
    // unsigned integer in network byte order
    //
    void write_hex(writeable &w) const {
        encoded<T> tmp = val;
        tmp.swap_byte_order();                        // TODO: write endian-generic version
        w.write_hex((uint8_t *)&tmp, sizeof(T));
    }
};

// class type_codes is a wrapper class and can be used to print typecodes. It inherently has a function
// to write to json_object, a string depending on known typecodes for that class. The class utilises the json_object template function
// print_key_value to write a type_code string. The type_code class to be wrapped must have a type_code, and functions:
// template T get_code() to return code value and
// char* print_code_str() to return code str or returns null for unknown code
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

    void fingerprint(buffer_stream &b) {
        const char* code_str = code.get_code_str();
        if (!code_str) {
            print_unknown_code(b, code.get_code());
        }
        else {
            b.puts(code_str);
        }
    }
};

// class literal is a literal std::array of characters
//
template <size_t N>
class literal {
public:
    literal(datum &d, const std::array<uint8_t, N> &a) {
        for (const auto &c : a) {
            d.accept(c);
        }
    }
};

// class literal_bytes accepts the variable number of input bytes,
// setting d to null if the expected input is not found
//

template<uint8_t... args>
class literal_byte {
public:
    literal_byte(datum &d) {
        (d.accept(args),...);
    }
};

/* class skip_bytes skips N number of bytes in the given datum*/
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

// template specializations of the encoded<T>::unit_test() functions,
// for several unsigned integer types.  To use these tests, do not
// define NDEBUG (or undefine that variable), and call each one inside of
// an assert() macro, or whatever unit test function is appropriate.
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

template <>
inline bool encoded<uint16_t>::unit_test() {
    encoded<uint16_t> x{0x9f00};
    return
        x.slice<0,1>()  == 1  &&
        x.slice<1,3>()  == 0  &&
        x.slice<3,8>()  == 31 &&
        x.slice<8,16>() == 0;
}

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

#endif // NDEBUG

// class lookahead<T> attempts to read an element of type T from a
// datum, without modifying that datum.  If the read succeeded, then
// casting the lookahead object to a bool returns true; otherwise, it
// returns false.  On success, the value of the element can be
// accessed through the public value member.  To advance the datum
// forward (e.g. to accept the lookahead object), set its value to
// that returned by the advance() function.
//
// NOTE: advance() will return a null value if the read did not
// succeed.
//
template <typename T>
class lookahead {
public:
    T value;
private:
    datum tmp;
public:

    lookahead(datum d) : value{d}, tmp{d} { }

    explicit operator bool() const { return tmp.is_not_null(); }

    datum advance() const { return tmp; }

};

// class accept<T> attempts to read an element of type T from a datum
// reference.  If the read succeeded, the datum is advanced forward,
// and casting the accept<T> object to a bool returns true; otherwise,
// that cast returns false.  On success, the value of the element can be
// accessed through the public value member.
//
template <typename T>
class acceptor {
public:
    T value;
private:
    bool valid;
public:

    acceptor(datum &d) : value{d}, valid{d.is_not_null()} { }

    operator bool() const { return valid; }
};

// class optional<T> attempts to read an element of type T from a
// datum reference.  If the read succeeds, the datum is advanced
// forward, and casting the optional<T> object to a bool returns true;
// otherwise, that cast returns false.  On success, the value of the
// element can be accessed through the public value member.  If the
// read fails, the datum is left unchanged (it is neither advanced nor
// set to null).
//
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

// class ignore<T> parses a data element of type T, but then ignores
// (does not store) its value.  It can be used to check the format of
// data that need not be stored.
//
// TODO: the parameter T should be able to accept any class, not just
// unsigned integer types
//
template <typename T>
class ignore {

public:

    ignore(datum &d, bool little_endian=false) {
        (void)little_endian;
        size_t tmp;
        d.read_uint(&tmp, sizeof(T));
    }

    ignore() { }

    // write out null value
    //
    void write(writeable &w) {
        uint8_t zero[sizeof(T)] = { 0, };
        w.copy(zero, sizeof(T));
    }
};

#endif /* DATUM_H */
