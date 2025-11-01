// decimal_int.hpp


#ifndef DECIMAL_INT_HPP
#define DECIMAL_INT_HPP


/// parses a sequence of decimal digits that can be represented as an
/// integral type \param T, and provides its value through \ref
/// get_value().
///
/// A decimal_integer<T> consists of one or more digits [9-0] that
/// represent a number no greater than `std::numeric_limits<T>::max()`
/// and no less than `std::numeric_limits<T>::min()`.
///
template<typename T>
class decimal_integer {
    T value;

    static_assert(std::is_integral_v<T>, "T must be an integral type");

public:

    /// construct a \ref decimal_integer object by parsing text from
    /// the input \ref datum \param d, and set \param d to `null` if
    /// it does not contain a valid decimal integer.
    ///
    decimal_integer(datum &d) : value{parse(d)} { }

    /// if the input \ref datum is not `null`, return the value of
    /// this object as the appropriate integral type; otherwise, the
    /// return value is undefined.
    ///
    T get_value() const { return value; }

    /// parse a \ref decimal_integer object by parsing text from the
    /// input \ref datum \param d, and set \param d to `null` if it
    /// does not contain a valid decimal integer; otherwise, return
    /// the value of that integer as the appropriate integral type.
    ///
    static T parse(datum &d) {

        // process the first digit - there must be at least one
        //
        if (!d.is_readable()) {
            d.set_null();
            return 0;
        }
        unsigned x = d.data[0] - '0';
        if (x > 9) {
            d.set_null();         // unexpected initial character
            return 0;
        }
        d.data++;
        T result = x;

        while (d.data < d.data_end) {
            unsigned x = *d.data++ - '0';
            if (x > 9) {
                break;
            }
            if (result > std::numeric_limits<T>::max() / 10) {
                d.set_null();     // multiplication overflow
                break;
            }
            result *= 10;
            if (x > (T)(std::numeric_limits<T>::max() - result)) {
                d.set_null();     // addition overflow
                break;
            }
            result += x;
        }
        return result;
    }

};


/// parses a sequence of decimal digits, with an optional sign (-/+)
/// that can be represented as an integral type \param T, and provides
/// its value through \ref get_value().
///
template<typename T>
class signed_decimal_integer {
    bool negative;
    decimal_integer<T> integer;

    static_assert(std::is_signed_v<T>, "T must be a signed integral type");

public:

    signed_decimal_integer(datum &d) :
        negative{parse_sign(d)},
        integer{d}
    { }

    T get_value() const { return negative ? -integer.get_value() : integer.get_value(); }

    static bool parse_sign(datum &d) {
        bool negative = false;

        if (!d.is_readable()) {
            return 0;
        }

        switch(d.data[0]) {
        case '-':
            negative = true;   [[fallthrough]];
        case '+':
            d.data++;
        default:
            ;
        }
        return negative;
    }

};


#ifndef NDEBUG

template <typename T>
struct test_case {
    datum text;
    bool is_not_null;
    T value;

    bool run_test(FILE *f=nullptr) const {
        datum tmp{text};
        if constexpr (std::is_signed_v<T>) {
            signed_decimal_integer<T> integer{tmp};
            if (tmp.is_not_null() != is_not_null or (is_not_null and (integer.get_value() != value))) {
                if (f) {
                    fprintf(f, "error in unit test: expected (%u,%ld), got (%u,%ld)\n",
                            is_not_null, (int64_t)value,
                            tmp.is_not_null(), (int64_t)integer.get_value());
                }
                return false;
            }
        } else {
            decimal_integer<T> integer{tmp};
            if (tmp.is_not_null() != is_not_null or (is_not_null and (integer.get_value() != value))) {
                if (f) {
                    fprintf(f, "error in unit test: expected (%u,%lu), got (%u,%lu)\n",
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

    test_case<int64_t> test_case_array_int64[] = {
        { datum{"1000"}, true, 1000 },
        { datum{"1"}, true, 1 },
        { datum{"000"}, true, 0 },
        { datum{"9223372036854775807"}, true, 9223372036854775807 },
        { datum{"9223372036854775808"}, false, 0 },
        { datum{"-9223372036854775807"}, true, -9223372036854775807 },
        { datum{"-9223372036854775808"}, false, 0 },
    };

    bool result = true;
    for (auto & tc : test_case_array_int64) {
        result &= tc.run_test(f);
    }

    test_case<uint8_t> test_case_array_uint8[] = {
        { datum{"1000"}, false, 0 },
        { datum{"255"}, true, 255 },
        { datum{"000"}, true, 0 },
        { datum{"-88"}, false, 0 },
    };

    result = true;
    for (auto & tc : test_case_array_uint8) {
        result &= tc.run_test(f);
    }

    return result;
}


#endif // NDEBUG

#endif  // DECIMAL_INT_HPP
