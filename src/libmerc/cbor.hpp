// cbor.hpp
//
// compact binary object representation (cbor) decoding

#ifndef CBOR_HPP
#define CBOR_HPP

#include "datum.h"
#include <variant>


// a simple CBOR decoder, following RFC 8949
//
namespace cbor {

    static constexpr uint8_t unsigned_integer_type = 0;
    static constexpr uint8_t negative_integer_type = 1;
    static constexpr uint8_t byte_string_type      = 2;
    static constexpr uint8_t text_string_type      = 3;
    static constexpr uint8_t array_type            = 4;
    static constexpr uint8_t map_type              = 5;
    static constexpr uint8_t tagged_item_type      = 6;
    static constexpr uint8_t simple_or_float_type  = 7;

    // The initial byte of each encoded data item contains both
    // information about the major type (the high-order 3 bits,
    // described in Section 3.1) and additional information (the
    // low-order 5 bits). With a few exceptions, the additional
    // information's value describes how to load an unsigned integer
    // "argument":
    //
    // Less than 24: the argument's value is the value of the
    // additional information.
    //
    // 24, 25, 26, or 27: the argument's value is held in the
    // following 1, 2, 4, or 8 bytes, respectively, in network byte
    // order. For major type 7 and additional information value 25,
    // 26, 27, these bytes are not used as an integer argument, but as
    // a floating-point value (see Section 3.3).
    //
    // 28, 29, 30: these values are reserved for future additions to
    // the CBOR format. In the present version of CBOR, the encoded
    // item is not well-formed.
    //
    // 31: no argument value is derived. If the major type is 0, 1, or
    // 6, the encoded item is not well-formed. For major types 2 to 5,
    // the item's length is indefinite, and for major type 7, the byte
    // does not constitute a data item at all but terminates an
    // indefinite-length item; all are described in Section 3.2.

    class initial_byte {
        encoded<uint8_t> value;
    public:

        // read an initial byte from `d`
        //
        initial_byte(datum &d) : value{d} {
            if (d.is_not_null()) {
                // printf("major_type: %u\n", major_type());
                // printf("additional_info: %u\n", additional_info());
            }
        }

        // construct an initial_byte for writing
        //
        initial_byte(uint8_t type, uint8_t info) :
            value{type << 5 | info}
        {
            printf("major_type: %u\n", major_type());
            printf("additional_info: %u\n", additional_info());
        }

        uint8_t major_type() const{ return value.slice<0,3>(); }

        uint8_t additional_info() const{ return value.slice<3,8>(); }

        // a break indicates the end of a variable-length array, map,
        // byte string, or text string
        //
        bool is_break() const {
            return value == 0b11111111;
        }

        bool is_array_indefinite_length() const {
            return value == 0x9f;
        }

        bool is_byte_string() const {
            return major_type() == byte_string_type;
        }

        void write(writeable &buf) const {
            buf << value;
        }

    };

    // Major type 0: An unsigned integer in the range 0..2^64-1
    // inclusive. The value of the encoded item is the argument
    // itself.
    //
    class uint64 {
        initial_byte ib;
        uint64_t value__;

    public:
        uint64(datum &d, uint8_t type=unsigned_integer_type) : ib{d} {

            if (ib.major_type() != type) {
                d.set_null();
                return;
            }

            uint8_t ai = ib.additional_info();
            if (ai < 24) {
                value__ = ai;
            }
            if (ai == 24) {
                value__ = encoded<uint8_t>{d}.value();
            }
            if (ai == 25) {
                value__ = encoded<uint16_t>{d}.value();
            }
            if (ai == 26) {
                value__ = encoded<uint32_t>{d}.value();
            }
            if (ai == 27) {
                value__ = encoded<uint64_t>{d}.value();
            }

        }

        // construct a uint64 for writing; the type is
        // unsigned_integer by default, but can be set to other types
        //
        uint64(uint64_t x, uint8_t type=unsigned_integer_type) :
            ib{type, additional_info(x)},
            value__{x}
        { }

        uint8_t additional_info(uint64_t x) {
            if (x < 24) {
                return x;
            }
            if (x < 0x100) {
                return 24;          // one-byte uint
            }
            if (x < 0x10000) {
                return 25;          // two-byte uint
            }
            if (x < 0x100000000) {
                return 26;          // four-byte uint
            }
            return 27;              // eight-byte uint
        }

        uint64_t value() const {
            return value__;
        }

        void write(writeable &buf) const {
            ib.write(buf);
            switch (ib.additional_info()) {
            case 24:
                encoded<uint8_t>{value__}.write(buf, true);
                break;
            case 25:
                encoded<uint16_t>{value__}.write(buf, true);
                break;
            case 26:
                encoded<uint32_t>{value__}.write(buf, true);
                break;
            case 27:
                encoded<uint64_t>{value__}.write(buf, true);
                break;
            default:
                ;
            }
        }

    };

    // Major type 1: A negative integer in the range -2^64..-1
    // inclusive. The value of the item is -1 minus the argument.
    //
    class int64 {
        initial_byte ib;
        uint64_t value__;

    public:
        int64(datum &d, uint8_t type=unsigned_integer_type) : ib{d} {

            if (ib.major_type() != type) {
                d.set_null();
                return;
            }

            uint8_t ai = ib.additional_info();
            if (ai < 24) {
                value__ = ai;
            }
            if (ai == 24) {
                value__ = encoded<uint8_t>{d}.value();
            }
            if (ai == 25) {
                value__ = encoded<uint16_t>{d}.value();
            }
            if (ai == 26) {
                value__ = encoded<uint32_t>{d}.value();
            }
            if (ai == 27) {
                value__ = encoded<uint64_t>{d}.value();
            }

        }

        uint64_t value() const {
            return value__;   // implicit -1
        }

    };

    // Major type 2: A byte string. The number of bytes in the string
    // is equal to the argument.
    //
    class byte_string {
        uint64 length;
        datum value__;

    public:

        byte_string(datum &d) :
            length{d, byte_string_type},
            value__{d, length.value()}
        { }

        // construct a byte_string for writing (probably needs
        // named-constructor idiom)
        //
        byte_string(const datum &d) :
            length{d.length(), byte_string_type},
            value__{d}
        {
            fprintf(stderr, "using constructor for writing\n");
        }

        datum value() const { return value__; }

        void write(writeable &buf) const {
            length.write(buf);
            buf << value__;
        }

    };

    // Major type 3: A text string (Section 2) encoded as UTF-8
    // [RFC3629]. The number of bytes in the string is equal to the
    // argument. A string containing an invalid UTF-8 sequence is
    // well-formed but invalid (Section 1.2). This type is provided
    // for systems that need to interpret or display human-readable
    // text, and allows the differentiation between unstructured bytes
    // and text that has a specified repertoire (that of Unicode) and
    // encoding (UTF-8). In contrast to formats such as JSON, the
    // Unicode characters in this type are never escaped. Thus, a
    // newline character (U+000A) is always represented in a string as
    // the byte 0x0a, and never as the bytes 0x5c6e (the characters
    // "\" and "n") nor as 0x5c7530303061 (the characters "\", "u",
    // "0", "0", "0", and "a").
    //
    class text_string {
        uint64 length;
        datum value__;

    public:

        text_string(datum &d) :
            length{d, text_string_type},
            value__{d, length.value()}
        { }

        // construct a text_string for writing
        //
        text_string(const datum &d) :
            length{d.length(), text_string_type},
            value__{d}
        { }

        datum value() const { return value__; }

        void write(writeable &buf) const {
            length.write(buf);
            buf << value__;
        }

    };

    // Major type 4: An array of data items. In other formats, arrays
    // are also called lists, sequences, or tuples (a "CBOR sequence"
    // is something slightly different, though [RFC8742]). The
    // argument is the number of data items in the array. Items in an
    // array do not need to all be of the same type. For example, an
    // array that contains 10 items of any type would have an initial
    // byte of 0b100_01010 (major type 4, additional information 10
    // for the length) followed by the 10 remaining items.
    //
    class array {
        initial_byte ib;
        datum body;

    public:

        array(datum &d) : ib{d} {
            if (ib.major_type() != array_type or ib.additional_info() != 31) {   // for now, we only support indefinite length arrays
                d.set_null();
                return;
            }
            body = d;
        }

        template <typename T>
        T get() {
            T tmp{body};
            return tmp;
        }

        datum& value() { return body; }

    };

    // Major type 5: A map of pairs of data items. Maps are also
    // called tables, dictionaries, hashes, or objects (in JSON). A
    // map is comprised of pairs of data items, each pair consisting
    // of a key that is immediately followed by a value. The argument
    // is the number of pairs of data items in the map. For example, a
    // map that contains 9 pairs would have an initial byte of
    // 0b101_01001 (major type 5, additional information 9 for the
    // number of pairs) followed by the 18 remaining items. The first
    // item is the first key, the second item is the first value, the
    // third item is the second key, and so on. Because items in a map
    // come in pairs, their total number is always even: a map that
    // contains an odd number of items (no value data present after
    // the last key data item) is not well-formed. A map that has
    // duplicate keys may be well-formed, but it is not valid, and
    // thus it causes indeterminate decoding; see also Section 5.6.
    //
    class map {
        initial_byte ib;
        datum body;

    public:

        map(datum &d) : ib{d} {
            if (ib.major_type() != map_type or ib.additional_info() != 31) {   // for now, we only support indefinite length maps
                d.set_null();
                return;
            }
            body = d;
        }

        datum& value() { return body; }

    };

    // an element is a cbor-encoded element
    //
    // note that for any element e, e.index() is equal to the
    // major_type of e plus one
    //
    using element = std::variant<std::monostate,
                                 uint64,
                                 int64,
                                 byte_string,
                                 text_string,
                                 array,
                                 map>;

    // decode and return the element (`std::variant` for all cbor
    // types) from `d`; if no element could be decoded,
    // `std::monostate` is returned.
    //
    inline element decode(datum &d) {
        if (lookahead<initial_byte> ib{d}) {
            switch (ib.value.major_type()) {
            case unsigned_integer_type:
                {
                    uint64 tmp{d};
                    if (d.is_not_null()) {
                        return tmp;
                    }
                }
                break;
            case negative_integer_type:
                {
                    int64 tmp{d};
                    if (d.is_not_null()) {
                        return tmp;
                    }
                }
                break;
            case byte_string_type:
                {
                    byte_string tmp{d};
                    if (d.is_not_null()) {
                        return tmp;
                    }
                }
                break;
            case text_string_type:
                {
                    text_string tmp{d};
                    if (d.is_not_null()) {
                        return tmp;
                    }
                }
                break;
            case array_type:
                {
                    array tmp{d};
                    if (d.is_not_null()) {
                        return tmp;
                    }
                }
                break;
            case map_type:
                {
                    map tmp{d};
                    if (d.is_not_null()) {
                        return tmp;
                    }
                }
                break;
            case simple_or_float_type:
                {
                    if (ib.value.is_break()) {
                        return std::monostate{};
                    }
                }
                break;
            default:
                ;
            }
        }
        return std::monostate{};
    }

    inline uint8_t major_type(const element &e) {
        return e.index() - 1;
    }

    inline void printf(FILE *f, const element &e) {
        ;;;
    }

};     // end of namespace cbor


namespace cbor::output {

    // Major type 4: An array of data items. In other formats, arrays
    // are also called lists, sequences, or tuples (a "CBOR sequence"
    // is something slightly different, though [RFC8742]). The
    // argument is the number of data items in the array. Items in an
    // array do not need to all be of the same type. For example, an
    // array that contains 10 items of any type would have an initial
    // byte of 0b100_01010 (major type 4, additional information 10
    // for the length) followed by the 10 remaining items.
    //
    class array {
        writeable &w;

    public:

        // construct an indefinite-length array for writing
        //
        array(writeable &buf) : w{buf} {
            w << initial_byte{array_type, 31};  // 0x9f
        }

        void close() {
            w << initial_byte{simple_or_float_type, 31}; // 0xff
        }

        template <typename T>
        void write(const T &t) const {
            t.write(w);
        }
    };

};

#endif // CBOR_HPP
