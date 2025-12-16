// \file decimal_int.hpp


#ifndef DECIMAL_INT_HPP
#define DECIMAL_INT_HPP

#include <type_traits>
#include <limits>
#include <cstdio>
#include "datum.h"


namespace {

    // double_width<T>::type is the integral type with twice as many
    // bits as T that is signed (unsigned) if T is signed (unsigned)
    //
    template <typename T> struct double_width { using type = void; };

    template <> struct double_width<uint8_t>  { using type = uint16_t; };
    template <> struct double_width<uint16_t> { using type = uint32_t; };
    template <> struct double_width<uint32_t> { using type = uint64_t; };

    template <> struct double_width<int8_t>  { using type = int16_t; };
    template <> struct double_width<int16_t> { using type = int32_t; };
    template <> struct double_width<int32_t> { using type = int64_t; };
}


/// parses a sequence of decimal digits that can be represented as an
/// integral type \param T, and provides its value through \ref
/// get_value().
///
/// A `decimal_integer<T>` consists of one or more digits [0-9] that
/// represent a number no greater than `std::numeric_limits<T>::max()`
/// and no less than `std::numeric_limits<T>::min()`.  \param T can be
/// any integral type except `int64_t` and `uint64_t`.
///
template <typename T>
struct decimal_integer {

    static_assert(!std::is_same<T, uint64_t>::value, "64-bit integers not currently supported");
    static_assert(!std::is_same<T, int64_t>::value, "64-bit integers not currently supported");

    using double_width_t = typename double_width<T>::type;
    double_width_t value = 0;

    /// construct a \ref decimal_integer object by parsing text from
    /// the input \ref datum \param d, and set \param d to `null` if
    /// it does not contain a valid decimal integer.
    ///
    decimal_integer(datum &d);
    decimal_integer() = delete;  // delete the default constructor

    /// if the input \ref datum is not `null`, return the value of
    /// this object as the appropriate integral type; otherwise, the
    /// return value is undefined.
    ///
    T get_value() const { return (T)value; }

};

// anonymous namespace to encapsulate implementation details for decimal_integers
//
namespace {

    // accepts zero or more decimal digits from \param d and
    // accumulates their value into \param value in the positive direction
    //
    // \note: this function stops reading from \param d when it
    // encounters the end of the \ref datum, or a character not in the
    // range [0-9], whichever comes first
    //
    template <typename T>
    inline void accumulate_digits(T &value, datum &d) {
        static_assert(std::is_integral_v<std::remove_reference_t<T>>, "T must be an integral type.");

        while (d.data < d.data_end) {
            unsigned x = *d.data - '0';
            if (x > 9) {
                break;
            }
            value = value * 10 + x;
            d.data++;
        }
    }

    // accepts zero or more decimal digits from \param d and
    // accumulates their value into \param value in the negative direction
    //
    // \note: this function stops reading from \param d when it
    // encounters the end of the \ref datum, or a character not in the
    // range [0-9], whichever comes first
    //
    template <typename T>
    inline void accumulate_digits_negative(T &value, datum &d) {
        static_assert(std::is_integral_v<std::remove_reference_t<T>>, "T must be an integral type.");

        while (d.data < d.data_end) {
            unsigned x = *d.data - '0';
            if (x > 9) {
                break;
            }
            value = value * 10 - x;
            d.data++;
        }
    }

    // at compile time, returns the maximum number of significant decimal digits
    // that can appear in an integral type T.  this number does not include the
    // sign or any leading zeros.
    //
    template <typename T>
    constexpr size_t max_digits() {
        static_assert(std::is_integral_v<std::remove_reference_t<T>>, "T must be an integral type.");

        T n = std::numeric_limits<T>::max();
        size_t count = 0;
        while (n > 0) {
            n /= 10;
            count++;
        }
        return count;
    }

    // advance past any leading ASCII zeros in \param d; return true if at least
    // one zero was skipped
    //
    inline bool skip_leading_zeros(datum &d) {
        bool consumed_zero = false;
        while (d.is_readable() && d.data[0] == '0') {
            consumed_zero = true;
            d.data++;
        }
        return consumed_zero;
    }

}

template <typename T>
inline decimal_integer<T>::decimal_integer(datum &d) {

    bool negative = false;
    if constexpr (std::is_signed_v<T>) {
        if (!d.is_readable()) {
            d.set_null();
            return;
        }
        if (d.data[0] == '-' || d.data[0] == '+') {
            negative = (d.data[0] == '-');
            d.data++;
        }
    }

    if (!d.is_readable()) {
        d.set_null();
        return;
    }

    // skip any leading zeros; remember if we consumed any for the zero-only case
    bool consumed_leading_zero = skip_leading_zeros(d);

    const uint8_t *sig_start = d.data; // start of significant digits (first non-zero)

    // try to read the magnitude of the integer (starting with the first
    // non-zero digit) now that d is past the sign and any leading zeros; apply
    // the sign during accumulation
    bool consumed_nonzero = false;
    if (d.is_readable()) {
        uint8_t first_value = d.data[0] - '0';  // digits map to 0-9; others > 9
        if (first_value <= 9) {
            // zeros were already skipped, so any digit here is non-zero
            consumed_nonzero = true;
            d.data++;
            if constexpr (std::is_signed_v<T>) {
                if (negative) {
                    value = -first_value;
                    // accumulate remaining digits in the negative direction
                    accumulate_digits_negative<double_width_t>(value, d);
                } else {
                    value = first_value;
                    // accumulate remaining digits in the positive direction
                    accumulate_digits<double_width_t>(value, d);
                }
            } else {
                value = first_value;
                // accumulate remaining digits in the positive direction
                accumulate_digits<double_width_t>(value, d);
            }
        }
    }

    // if no non-zero digits seen, it's valid only when we saw leading zero(s)
    if (!consumed_nonzero) {
        if (consumed_leading_zero) {
            value = 0;
        } else {
            d.set_null();
            return;
        }
    }

    ptrdiff_t sig_digits = d.data - sig_start;
    if (sig_digits > (ptrdiff_t)max_digits<T>()) {
        d.set_null();
        return;
    }

    if (value > std::numeric_limits<T>::max() or value < std::numeric_limits<T>::min()) {
        d.set_null();
    }

}

#ifndef NDEBUG

template <typename T>
struct decimal_integer_test_case {
    datum text;
    bool is_not_null;
    T value;

    bool run_test(FILE *f=nullptr) const {
        datum tmp{text};
        decimal_integer<T> integer{tmp};
        if constexpr (std::is_signed_v<T>) {
            if (tmp.is_not_null() != is_not_null or (is_not_null and (integer.get_value() != value))) {
                if (f) {
                    fprintf(f, "input: \""); text.fprint(f); fputs("\"\t", f);
                    fprintf(f, "error in unit test: expected (%u,%" PRId64 "), got (%u,%" PRId64 ")\n",
                            is_not_null, (int64_t)value,
                            tmp.is_not_null(), (int64_t)integer.get_value());
                }
                return false;
            }
        } else {
            if (tmp.is_not_null() != is_not_null or (is_not_null and (integer.get_value() != value))) {
                if (f) {
                    fprintf(f, "error in unit test: expected (%u,%" PRIu64 "), got (%u,%" PRIu64 ")\n",
                            is_not_null, (uint64_t)value,
                            tmp.is_not_null(), (uint64_t)integer.get_value());
                }
                return false;
            }
        }
        return true;
    }

};

inline bool decimal_integer_unit_test(FILE *f=nullptr) {

    bool result = true;

    decimal_integer_test_case<int8_t> test_case_array_int8[] = {
        { datum{"127"}, true, 127 },
        { datum{"-128"}, true, -128 },
        { datum{"-0"}, true, 0 },
        { datum{"128"}, false, 0 },
        { datum{"-129"}, false, 0 },
        { datum{"-05"}, true, -5 },
        { datum{"-0001"}, true, -1 },
        { datum{"-000"}, true, 0 },
        { datum{"0000"}, true, 0 },
        { datum{"bad"}, false, 0 },
        { datum{"+a"}, false, 0 },
        { datum{"-a"}, false, 0 },
    };
    for (auto & tc : test_case_array_int8) {
        result &= tc.run_test(f);
    }

    decimal_integer_test_case<uint8_t> test_case_array_uint8[] = {
        { datum{"1000"}, false, 0 },
        { datum{"255"}, true, 255 },
        { datum{"000"}, true, 0 },
        { datum{"-88"}, false, 0 },
        { datum{"255"}, true, 255 },
        { datum{"0"}, true, 0 },
        { datum{"0000000255"}, true, 255 },
        { datum{"0000000"}, true, 0 },
        { datum{"-0"}, false, 0 },
        { datum{"256"}, false, 0 },
        { datum{"-1"}, false, 0 },
        { datum{"2256"}, false, 0 },
        { datum{"-10"}, false, 0 },
        { datum{"22256"}, false, 0 },
        { datum{"-100"}, false, 0 },
    };
    for (auto & tc : test_case_array_uint8) {
        result &= tc.run_test(f);
    }

    decimal_integer_test_case<int16_t> test_case_array_int16[] = {
        { datum{"32767"}, true, 32767 },
        { datum{"-32768"}, true, -32768 },
        { datum{"-0"}, true, 0 },
        { datum{"32768"}, false, 0 },
        { datum{"-32769"}, false, 0 },
    };
    for (auto & tc : test_case_array_int16) {
        result &= tc.run_test(f);
    }

    decimal_integer_test_case<uint16_t> test_case_array_uint16[] = {
        { datum{"65535"}, true, 65535 },
        { datum{"0"}, true, 0 },
        { datum{"-0"}, false, 0 },
        { datum{"65536"}, false, 0 },
        { datum{"-1"}, false, 0 },
    };
    for (auto & tc : test_case_array_uint16) {
        result &= tc.run_test(f);
    }

    decimal_integer_test_case<int32_t> test_case_array_int32[] = {
        { datum{"2147483647"}, true, 2147483647 },
        { datum{"-2147483648"}, true, -2147483648 },
        { datum{"-0"}, true, 0 },
        { datum{"2147483648"}, false, 0 },
        { datum{"-2147483649"}, false, 0 },
    };
    for (auto & tc : test_case_array_int32) {
        result &= tc.run_test(f);
    }

    decimal_integer_test_case<uint32_t> test_case_array_uint32[] = {
        { datum{"4294967295"}, true, 4294967295 },
        { datum{"0"}, true, 0 },
        { datum{"-0"}, false, 0 },
        { datum{"4294967296"}, false, 0 },
        { datum{"-1"}, false, 0 },
    };

    for (auto & tc : test_case_array_uint32) {
        result &= tc.run_test(f);
    }

    // verify that decimal_integer<> only consumes as many input bytes
    // as appropriate
    //
    datum x0{"5\r\n"};
    decimal_integer<uint32_t> y0{x0};
    if (x0.cmp(datum{std::array<uint8_t,2>{'\r', '\n'}}) != 0) {
        result &= false;
    }

    datum x1{"-5\r\n"};
    decimal_integer<int32_t> y1{x1};
    if (x1.cmp(datum{std::array<uint8_t,2>{'\r', '\n'}}) != 0) {
        result &= false;
    }

    datum x2{"555\r\n"};
    decimal_integer<int32_t> y2{x2};
    if (x2.cmp(datum{std::array<uint8_t,2>{'\r', '\n'}}) != 0) {
        result &= false;
    }

    datum x3{"-555\r\n"};
    decimal_integer<int32_t> y3{x3};
    if (x3.cmp(datum{std::array<uint8_t,2>{'\r', '\n'}}) != 0) {
        result &= false;
    }

    datum x4{"0\r\n"};
    decimal_integer<int32_t> y4{x4};
    if (x4.cmp(datum{std::array<uint8_t,2>{'\r', '\n'}}) != 0) {
        result &= false;
    }

    datum x5{"-0\r\n"};
    decimal_integer<int32_t> y5{x5};
    if (x5.cmp(datum{std::array<uint8_t,2>{'\r', '\n'}}) != 0) {
        result &= false;
    }

    datum x6{"000\r\n"};
    decimal_integer<uint32_t> y6{x6};
    if (x6.cmp(datum{std::array<uint8_t,2>{'\r', '\n'}}) != 0) {
        result &= false;
    }

    datum x7{"+0\r\n"};
    decimal_integer<int32_t> y7{x7};
    if (x7.cmp(datum{std::array<uint8_t,2>{'\r', '\n'}}) != 0) {
        result &= false;
    }

    return result;
}

#endif // NDEBUG

[[maybe_unused]] static int decimal_integer_fuzz_test(const uint8_t *data, size_t size) {
    datum text_integer{data, data+size};

    datum copy1{text_integer};
    decimal_integer<int8_t>{copy1};
    datum copy2{text_integer};
    decimal_integer<uint8_t>{copy2};
    datum copy3{text_integer};
    decimal_integer<int16_t>{copy3};
    datum copy4{text_integer};
    decimal_integer<uint16_t>{copy4};
    datum copy5{text_integer};
    decimal_integer<int32_t>{copy5};
    datum copy6{text_integer};
    decimal_integer<uint32_t>{copy6};

    return 0;
}


#endif  // DECIMAL_INT_HPP
