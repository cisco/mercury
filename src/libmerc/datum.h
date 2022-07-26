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
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <array>
#include <bitset>
#include <limits>
#include <string>
#include "libmerc.h"  // for enum status

/*
 * The mercury_debug macro is useful for debugging (but quite verbose)
 */
#ifndef DEBUG
#define mercury_debug(...)
#else
#define mercury_debug(...)  (fprintf(stdout, __VA_ARGS__))
#endif

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
    datum(datum &d, size_t length) {
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
    bool is_not_readable() const { return data == NULL || data == data_end; }
    void set_empty() { data = data_end; }
    void set_null() { data = data_end = NULL; }
    ssize_t length() const { return data_end - data; }
    void parse(struct datum &r, size_t num_bytes) {
        if (r.length() < (ssize_t)num_bytes) {
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
        while (r.data <= r.data_end) {
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
        while (r.data <= r.data_end) {
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
        while (r.data <= r.data_end) {
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
    int memcmp(const datum &p) const {
        return ::memcmp(data, p.data, length());
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
        set_empty();
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
        set_empty();
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
            mercury_debug("%s: num_bytes: %u, value (hex) %08x (decimal): %zd\n", __func__, num_bytes, (unsigned)tmp, tmp);
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
    bool read_uint16(uint16_t *output) {
        if (length() >= (int)sizeof(uint16_t)) {
            uint16_t *tmp = (uint16_t *)data;
            *output = ntohs(*tmp);
            data += sizeof(uint16_t);
            return true;
        }
        set_null();
        *output = 0;
        return false;
    }

    // read_uint32() reads a uint32_t in network byte order, and advances the data pointer
    //
    bool read_uint32(uint32_t *output) {
        if (length() >= (int)sizeof(uint32_t)) {
            uint32_t *tmp = (uint32_t *)data;
            *output = ntohl(*tmp);
            data += sizeof(uint32_t);
            return true;
        }
        set_null();
        *output = 0;
        return false;
    }

    // read_uint() reads a length num_bytes uint in network byte order, and advances the data pointer
    //
    bool read_uint(uint64_t *output, unsigned int num_bytes) {

        if (data && data + num_bytes <= data_end) {
            uint64_t tmp = 0;
            const unsigned char *c;

            for (c = data; c < data + num_bytes; c++) {
                tmp = (tmp << 8) + *c;
            }
            *output = tmp;
            data = c;
            mercury_debug("%s: num_bytes: %u, value (hex) %08x (decimal): %zu\n", __func__, num_bytes, (unsigned)tmp, tmp);
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

    ssize_t write_to_buffer(uint8_t *buffer, ssize_t len) {
        if (data) {
            ssize_t copy_len = length() < len ? length() : len;
            memcpy(buffer, data, copy_len);
            return copy_len;
        }
        return -1;
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

    //    ptrdiff_t length() const { return data_end - data; }

    void set_null() { data = data_end = nullptr; }

    void set_empty() { data = data_end; }

        void copy(uint8_t x) {
        if (data + 1 > data_end) {
            return;  // not enough room
        }
        *data++ = x;
    }
    void copy(const uint8_t *rdata, size_t num_bytes) {
        if (data_end - data < (ssize_t)num_bytes) {
            num_bytes = data_end - data;
        }
        memcpy(data, rdata, num_bytes);
        data += num_bytes;
    }
    void copy(struct datum &r, size_t num_bytes) {
        if (r.length() < (ssize_t)num_bytes) {
            r.set_null();
            // fprintf(stderr, "warning: not enough data in parse\n");
            return;
        }
        if (data_end - data < (int)num_bytes) {
            num_bytes = data_end - data;
        }
        memcpy(data, r.data, num_bytes);
        data += num_bytes;
        r.data += num_bytes;
    }
    void copy(struct datum &r) {
        copy(r, r.length());
    }

    template <typename Type>
    writeable & operator<<(Type t) {
        fprintf(stderr, "writeable: {%p,%p}\tlength: %zd\n", data, data_end, data_end-data);
        t.write(*this);
        return *this;
    }

    // template specialization for datum
    //
    writeable & operator<<(datum d) {
        fprintf(stderr, "writeable: {%p,%p}\tlength: %zd\n", data, data_end, data_end-data);
        if (d.is_not_null()) {
            copy(d);
        }
        return *this;
    }

};

// data_buffer is a contiguous sequence of bytes into which data can
// be copied sequentially; the data structure tracks the start of the
// data (buffer), the location to which data can be written (data),
// and the end of the data buffer (data_end)
//
template <size_t T> struct data_buffer : public writeable {
    unsigned char buffer[T];
    // unsigned char *data;                /* data being written        */
    // const unsigned char *data_end;      /* end of data buffer        */

    data_buffer() : writeable{buffer, buffer+T} { }


    //void reset() { data = buffer; }
    bool is_not_empty() const { return data != buffer && data < data_end; }
    void set_empty() { data_end = data = buffer; }
    ssize_t length() const { return data - buffer; } // TODO: return readable datum

    datum contents() const { return {buffer, data}; }

    ssize_t writeable_length() const { return data_end - data; }

    ssize_t write(int fd) { return ::write(fd, buffer, data - buffer);  }

#if 0 // DELETEME
    template <typename Type>
    data_buffer<T> & operator<<(Type t) {
        fprintf(stderr, "data_buffer: {%p,%p,%p}\treadable: %zd\twriteable: %zd\n", buffer, data, data_end, data-buffer, data_end-data);
        t.write(*this);
        return *this;
    }

    // template specialization for datum
    //
    data_buffer<T> & operator<<(datum d) {
        fprintf(stderr, "data_buffer: {%p,%p,%p}\treadable: %zd\twriteable: %zd\n", buffer, data, data_end, data-buffer, data_end-data);
        if (d.is_not_null()) {
            copy(d);
        }
        return *this;
    }
#endif // DELETEME

    // TODO:
    //  * add data != nullptr checks
    //  * add set_null() function
    //  * use null state to indicate write failure
    //  * add assert() macros to support debugging
    //  * add [[nodiscard]] as appropriate

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
        size_t tmp;
        d.read_uint(&tmp, sizeof(val));
        val = tmp;
        if (little_endian) {
            swap_byte_order();
        }
    }
    //
    // TODO: re-implement constructor in a way that avoids a temporary
    // size_t variable, especially for smaller integer types; make it
    // constexpr

    encoded(const T& rhs) {
        val = rhs;
    }

    operator T() const { return val; }

    T value() const { return val; }

    void swap_byte_order() {
        if constexpr (sizeof(val) == 8) {
            val = htobe64(val);
        } else if constexpr (sizeof(val) == 4) {
            val = ntohl(val);
        } else if constexpr (sizeof(val) == 2) {
            val = ntohs(val);
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

    void write(writeable &buf, bool swap_byte_order=false) {
        encoded<T> tmp = val;
        if (swap_byte_order) {
            tmp.swap_byte_order();
        }
        buf.copy((uint8_t *)&tmp, sizeof(T));

        // TODO: rewrite function to eliminate cast
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

#endif // NDEBUG

#endif /* DATUM_H */
