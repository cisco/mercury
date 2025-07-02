// cbor.hpp
//
// compact binary object representation (cbor) decoding

#ifndef CBOR_HPP
#define CBOR_HPP

#include "datum.h"
#include "lex.h"
#include <cstdio>
#include <string>
#include <stdexcept>

// a simple CBOR decoder, following RFC 8949
//
namespace cbor {

    enum class major_type : uint8_t {
        unsigned_integer = 0,
        negative_integer = 1,
        byte_string      = 2,
        text_string      = 3,
        array            = 4,
        map              = 5,
        tagged_item      = 6,
        simple_or_float  = 7,
    };

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
        encoded<uint8_t> value__;

    public:

        // read an initial byte from `d`
        //
        initial_byte(datum &d) : value__{d} {
            if (d.is_not_null()) {
                // printf("major_type: %u\n", major_type());
                // printf("additional_info: %u\n", additional_info());
            }
        }

        // construct an initial_byte for writing
        //
        initial_byte(uint8_t type, uint8_t info) :
            value__{(uint8_t)(type << 5 | info)}
        {
            // printf("major_type: %u\n", major_type());
            // printf("additional_info: %u\n", additional_info());
        }

        uint8_t major_type() const{ return value__.slice<0,3>(); }

        uint8_t additional_info() const{ return value__.slice<3,8>(); }

        // a break indicates the end of a variable-length array, map,
        // byte string, or text string
        //
        bool is_break() const {
            return value__ == 0b11111111;
        }

        bool is_array_indefinite_length() const {
            return value__ == 0x9f;
        }

        bool is_byte_string() const {
            return major_type() == byte_string_type;
        }

        void write(writeable &buf) const {
            buf << value__;
        }

        uint8_t value() const { return value__; }

        // "simple values" associated with major_type simple_or_float
        //
        static constexpr uint8_t False = 20;
        static constexpr uint8_t True = 21;
        static constexpr uint8_t null = 22;
        static constexpr uint8_t undefined = 23;
        static constexpr uint8_t break_code = 31;

    };

    static void read_break(datum &d) {
        initial_byte ib{d};
        if (!ib.is_break()) {
            d.set_null();
        }
    }

    // Major type 0: An unsigned integer in the range 0..2^64-1
    // inclusive. The value of the encoded item is the argument
    // itself.
    //
    class uint64 {
        initial_byte ib;
        uint64_t value__{0};

    public:

        /// construct a uint64 object by decoding it from the \ref
        /// datum \param d
        ///
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

        /// construct a uint64 object, suitable for encoding, with the
        /// value \param x and the major_type \param type; the type is
        /// an unsigned_integer by default, but can be set to other
        /// types
        ///
        uint64(uint64_t x, uint8_t type=unsigned_integer_type) :
            ib{type, additional_info(x)},
            value__{x}
        { }

        /// decode a uint64 object, accepting only values that are no
        /// greater than \param value_max.
        ///
        /// If the decoded `uint64` is greater than `value_max`, then
        /// `d` is set to `null`, and the value returned MUST be
        /// ignored.
        ///
        static uint64 decode_max(datum &d, uint64_t value_max) {
            uint64 tmp{d};
            if (tmp.value() > value_max) {
                d.set_null();
            }
            return tmp;
        }

        // returns a `uint8_t` containing the appropriate additional
        // information field for encoding a `uint64_t` with the value
        // \param x
        //
        static uint8_t additional_info(uint64_t x) {
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

        /// returns the value of this object as a `uint64_t`
        ///
        uint64_t value() const {
            return value__;
        }

        /// encode this object into the \ref writeable \param buf
        ///
        void write(writeable &buf) const {
            ib.write(buf);
            switch (ib.additional_info()) {
            case 24:
                encoded<uint8_t>{(uint8_t)value__}.write(buf, true);
                break;
            case 25:
                encoded<uint16_t>{(uint16_t)value__}.write(buf, true);
                break;
            case 26:
                encoded<uint32_t>{(uint32_t)value__}.write(buf, true);
                break;
            case 27:
                encoded<uint64_t>{(uint64_t)value__}.write(buf, true);
                break;
            default:
                ;
            }
        }

        /// `cbor::uint64::unit_test()` performs unit tests on the
        /// class \ref cbor::uint64 and returns `true` if they all pass,
        /// and `false` otherwise.  If \param f == `nullptr`, then no
        /// outupt is written; otherwise, output is written to \param
        /// f.
        ///
        static bool unit_test(FILE *f=nullptr);

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

        // The Named Constructor Idiom
        // (https://isocpp.org/wiki/faq/ctors#named-ctor-idiom) is
        // used to avoid ambiguity; construct a `byte_string` using
        // \ref decode() when decoding data, and using \ref
        // construct() when preparing an object to be encoded.
        //
        byte_string(uint64 len, datum value) :
            length{len},
            value__{value}
        { }

    public:

        /// construct and return a \ref byte_string object by decoding
        /// it from the \ref datum \param d
        ///
        static byte_string decode(datum &d) {
            uint64 len{d, byte_string_type};
            datum val{d, (ssize_t)len.value()};
            return byte_string{len, val};
        }

        /// construct and return a byte_string corresponding to the
        /// bytes in the \ref datum \param d
        ///
        static byte_string construct(const datum &d) {
            uint64 len{(uint64_t)d.length(), byte_string_type};
            datum val{d};
            return byte_string{len, val};
        }

        // byte_string(datum &d) :
        //     length{d, byte_string_type},
        //     value__{d, length.value()}
        // { }

        // // construct a byte_string for writing (probably needs
        // // named-constructor idiom)
        // //
        // byte_string(const datum &d) :
        //     length{d.length(), byte_string_type},
        //     value__{d}
        // {
        //     fprintf(stderr, "using constructor for writing\n");
        // }

        datum value() const { return value__; }

        void write(writeable &buf) const {
            length.write(buf);
            buf << value__;
        }

        /// `cbor::byte_string::unit_test()` performs unit tests on
        /// the class \ref cbor::byte_string and returns `true` if
        /// they all pass, and `false` otherwise.  If \param f ==
        /// `nullptr`, then no outupt is written; otherwise, output is
        /// written to \param f.
        ///
        static bool unit_test(FILE *f=nullptr);

    };

    class byte_string_from_hex {
        uint64 length;
        datum hex_value;

    public:

        byte_string_from_hex(const hex_digits &hex_string) :
            length{((uint64_t)hex_string.length()) / 2, byte_string_type},
            hex_value{hex_string}
        { }

        void write(writeable &buf) const {
            length.write(buf);
            buf.copy_from_hex(hex_value.data, hex_value.length());
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

        static datum datum_from_str(const char *null_terminated_string) {
            if (null_terminated_string == nullptr) {
                return { nullptr, nullptr };
            }
            return {
                (uint8_t *)null_terminated_string,
                (uint8_t *)null_terminated_string + strlen(null_terminated_string)
            };
        }

        // The Named Constructor Idiom
        // (https://isocpp.org/wiki/faq/ctors#named-ctor-idiom) is
        // used to avoid ambiguity; construct a `text_string` using
        // \ref decode() when decoding data, and using \ref
        // construct() when preparing an object to be encoded.
        //
        text_string(uint64 len, datum value) :
            length{len},
            value__{value}
        { }

    public:

        /// construct and return a \ref text_string object by decoding
        /// it from the \ref datum \param d
        ///
        static text_string decode(datum &d) {
            uint64 len{d, text_string_type};
            datum val{d, (ssize_t)len.value()};
            return text_string{len, val};
        }

        /// construct and return a text_string corresponding to the
        /// bytes in the \ref datum \param d
        ///
        static text_string construct(const datum &d) {
            uint64 len{(uint64_t)d.length(), text_string_type};
            datum val{d};
            return text_string{len, val};
        }

        // text_string(datum &d) :
        //     length{d, text_string_type},
        //     value__{d, length.value()}
        // { }

        // // construct a text_string for writing
        // //
        // text_string(const datum &d) :
        //     length{d.length(), text_string_type},
        //     value__{d}
        // { }

        // construct a text_string for writing
        //
        text_string(const char *null_terminated_string) :
            length{(uint64_t)(datum_from_str(null_terminated_string).length()), text_string_type},
            value__{datum_from_str(null_terminated_string)}
        { }

        datum value() const { return value__; }

        void write(writeable &buf) const {
            length.write(buf);
            buf << value__;
        }

        bool is_valid() const { return value__.is_not_null(); }

        // operator bool() const { return value__.is_not_null(); }

        /// `cbor::_textstring::unit_test()` performs unit tests on
        /// the class \ref cbor::_textstring and returns `true` if
        /// they all pass, and `false` otherwise.  If \param f ==
        /// `nullptr`, then no outupt is written; otherwise, output is
        /// written to \param f.
        ///
        static bool unit_test(FILE *f=nullptr);

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
        datum &body;

    public:

        array(datum &d) : ib{d}, body{d} {
            if (ib.major_type() != array_type or ib.additional_info() != 31) {   // for now, we only support indefinite length arrays
                d.set_null();
                return;
            }
            // body = d;
        }

        template <typename T>
        T get() {
            T tmp{body};
            return tmp;
        }

        datum& value() { return body; }

        operator datum& () { return body; }

        void close() { read_break(body); }

    };


    /// a `cbor::dictionary` is an ordered list of text strings that is
    /// used to map short unsigned integers to readable values
    ///
    template <size_t N>
    class dictionary {
        std::array<const char *, N> strings;

    public:

        constexpr dictionary(const std::array<const char *, N> &a) : strings{a} { }

        constexpr const char *get_string(uint64_t u) const {
            if (u < N) {
                return strings[u];
            }
            return "unknown_key";
        }
        constexpr uint64_t get_uint(const char *s) const {
            for (const auto &c : strings) {
                if (strcmp(c, s) == 0) {
                    return &c - &strings[0];
                }
            }
            throw std::logic_error{std::string{"error: string not in dictionary: "}.append(s)};
        }

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
        datum& body;

    public:

        map(datum &d) : ib{d}, body{d} {
            if (ib.major_type() != map_type or ib.additional_info() != 31) {   // for now, we only support indefinite length maps
                d.set_null();
                return;
            }
            //  body = d;
        }

        datum& value() { return body; }

        void close() { read_break(body); }

    };

    // Major type 6: A tagged data item ("tag") whose tag number, an
    // integer in the range 0..2^64-1 inclusive, is the argument and
    // whose enclosed data item (tag content) is the single encoded
    // data item that follows the head.
    //
    class tag {
        uint64 number;
    public:

        tag(datum &d) : number{d, tagged_item_type} { }

        tag(uint64_t num) : number{num, tagged_item_type} { }

        uint64_t value() const { return number.value(); }

        void write(writeable &buf) const {
            buf << number;
        }

    };

    // compact_map is a map that contains a dictionary of strings, to
    // enable the encoding to use short integers instead of text
    // strings as keys
    //
    template <size_t N>
    class compact_map : public map {
    public:
        compact_map(const std::array<const char *, N> &a, datum &d) : map{d} { }
    };

    static inline bool decode_data(datum &d, FILE *f, int r=0) {
        char tabs[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t";
        if (r > (int)sizeof(tabs)) {
            return false;  // error: recursion depth too high
        }

        while (d.is_readable()) {
            if (lookahead<initial_byte> ib{d}) {
                //fprintf(f, "initial_byte: %02x\tmajor_type: %u\n", ib.value.value(), ib.value.major_type());
                switch (ib.value.major_type()) {
                case unsigned_integer_type:
                    {
                        uint64 tmp{d};
                        if (d.is_null()) { return false; }
                        fprintf(f, "%.*sunsigned integer: %zu\n", r, tabs, tmp.value());
                    }
                    break;
                case byte_string_type:
                    {
                        byte_string tmp = byte_string::decode(d);
                        if (d.is_null()) { return false; }
                        fprintf(f, "%.*sbyte string: ", r, tabs);
                        tmp.value().fprint_hex(f);
                        fputc('\n', f);
                    }
                    break;
                case text_string_type:
                    {
                        text_string tmp = text_string::decode(d);
                        if (d.is_null()) { return false; }
                        fprintf(f, "%.*stext string: \"", r, tabs);
                        tmp.value().fprint(f);
                        fputc('"', f);
                        fputc('\n', f);
                    }
                    break;
                case array_type:
                    {
                        array tmp{d};
                        if (d.is_null()) { return false; }
                        d = ib.advance();   // ??????????????????????????????????????????
                        fprintf(f, "%.*sarray: [\n", r, tabs);
                        bool success = decode_data(d, f, r+1);
                        fprintf(f, "%.*s]\n", r, tabs);
                        if (!success) { return false; }
                    }
                    break;
                case map_type:
                    {
                        map tmp{d};
                        if (d.is_null()) { return false; }
                        d = ib.advance();
                        fprintf(f, "%.*smap: {\n", r, tabs);
                        bool success = decode_data(d, f, r+1);    // note: no attempt to enforce key/value pairs
                        fprintf(f, "%.*s}\n", r, tabs);
                        if (!success) { return false; }
                    }
                    break;
                case tagged_item_type:
                    {
                        tag tmp{d};
                        if (d.is_null()) { return false; }
                        fprintf(f, "%.*stag: %zu\n", r, tabs, tmp.value());
                    }
                    break;
                case simple_or_float_type:
                    if (ib.value.value() == 0xff) {
                        d = ib.advance();
                        return true;
                    }
                    [[fallthrough]];
                default:
                    fprintf(f, "unknown initial byte: 0x%02x\n", ib.value.value());
                    return false;
                }
            }
        }
        return true;
    }

    /// decode the sequence of CBOR items in the \ref datum \param d,
    /// and print a human-readable description of the items to \param f.
    ///
    /// \return `true if all of the items in \param d could be
    /// decoded, and `false` otherwise
    ///
    static inline bool decode_fprint(datum d, FILE *f) {
        return decode_data(d, f);
    }

    // inline uint8_t major_type(const element &e) {
    //     return e.index() - 1;
    // }

    // inline void printf(FILE *f, const element &e) {
    //     ;;; // TODO
    // }

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

        // template <typename T>
        // void write(const T &t) const {
        //     t.write(w);
        // }

        operator writeable & () { return w; }

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
        writeable &w;

    public:

        // construct an indefinite-length map for writing
        //
        map(writeable &buf) : w{buf} {
            w << initial_byte{map_type, 31};  // 0xbf
        }

        void close() {
            w << initial_byte{simple_or_float_type, 31}; // 0xff
        }

        // encode a key and value to the map
        //
        template <typename K, typename V>
        void encode(const K &k, const V &v) const {
            k.write(w);
            v.write(w);
        }

        operator writeable & () { return w; }
    };

};

namespace cbor {

    static inline bool reencode_data(datum &d, writeable &w, size_t r=0, bool is_map=false) {

        constexpr size_t max_recursion_depth = 256;
        if (r > max_recursion_depth) {
            return false;  // error: recursion depth too high
        }

        size_t num_elements = 0;
        while (d.is_readable()) {
            if (lookahead<initial_byte> ib{d}) {
                switch (ib.value.major_type()) {
                case unsigned_integer_type:
                    {
                        uint64 tmp{d};
                        if (d.is_null()) { return false; }
                        tmp.write(w);
                        num_elements++;
                    }
                    break;
                case byte_string_type:
                    {
                        byte_string tmp = byte_string::decode(d);
                        if (d.is_null()) { return false; }
                        tmp.write(w);
                        num_elements++;
                    }
                    break;
                case text_string_type:
                    {
                        text_string tmp = text_string::decode(d);
                        if (d.is_null()) { return false; }
                        tmp.write(w);
                        num_elements++;
                    }
                    break;
                case array_type:
                    {
                        array tmp{d};
                        if (d.is_null()) { return false; }
                        d = ib.advance();
                        cbor::output::array output_array{w};
                        bool success = reencode_data(d, output_array, r+1);
                        initial_byte b{d};
                        if (d.is_null() or !b.is_break()) {
                            success = false; // missing break at end of array
                        }
                        output_array.close();
                        if (!success) { return false; }
                        num_elements++;
                    }
                    break;
                case map_type:
                    {
                        map tmp{d};
                        if (d.is_null()) { return false; }
                        d = ib.advance();
                        cbor::output::map output_map{w};
                        bool success = reencode_data(d, output_map, r+1, true);
                        initial_byte b{d};
                        if (d.is_null() or !b.is_break()) {
                            success = false; // missing break at end of map
                        }
                        output_map.close();
                        if (!success) { return false; }
                        num_elements++;
                    }
                    break;
                case simple_or_float_type:
                    if (ib.value.is_break()) {
                        if (is_map and (num_elements & 1)) {
                            return false;  // a map must contain an even number of entries
                        }
                        return true;
                    }
                    [[fallthrough]];
                default:
                    return false;   // unknown initial byte
                }
            }
        }
        return true;
    }

    static inline bool reencode_unit_test(FILE *f) {
        std::vector<uint8_t> valid_cbor_examples[] = {
            {
                0x9f, // initial byte
                0x42, // version: length two byte string
                0x03,
                0x01,
                0x4a, // ciphersuites: length ten byte string
                0x00,
                0x16,
                0x00,
                0x2f,
                0x00,
                0x0a,
                0x00,
                0x05,
                0x00,
                0xff,
                0x9f, // start of extensions (initial byte of indefinite-length array)
                0x42, // extension: length two byte string
                0x00,
                0x00,
                0x42, // extension: length two byte string
                0x00,
                0x23,
                0xff, // end of extensions (break)
                0xff  // break
            },
            { 0xbf, 0x64, 0x49, 0x45, 0x54, 0x46, 0x6c, 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!', 0xff }, // {_ "IETF", "Hello world!" }
        };

        bool all_tests_passed = true;

        auto run_test = [&f, &all_tests_passed](const std::vector<uint8_t> &e, bool is_valid) {
            datum d{e.data(), e.data() + e.size()};
            data_buffer<1024> reencoded_buf;
            if (d.length() > 1024) {
                if (f) {
                    fprintf(f, "error: data_buffer too small to hold re-encoded data\n");
                }
                return;  // could not run test
            }
            bool success = cbor::reencode_data(d, reencoded_buf);
            if (is_valid == false) {
                //
                // negative test case; only perform decoding, and expect failure
                //
                if (success) {
                    if (f) {
                        fprintf(f, "error: invalid encoded data was accepted by decoder\n");
                    }
                    all_tests_passed = false;
                }
                return;
            }

            // positive test case; expect success, and compare the
            // re-encoded result to original
            //
            if (!success) {
                if (f) {
                    fprintf(f, "error: encoded data could not be re-encoded\n");
                }
                all_tests_passed = false;
            }
            d = {e.data(), e.data() + e.size()};
            if (f) {
                fprintf(f, "encoded:     ");
                d.fprint_hex(f);
                fprintf(f, "\nre-encoded:  ");
                reencoded_buf.contents().fprint_hex(f); fputc('\n', f);
            }
            if (d.cmp(reencoded_buf.contents()) != 0) {
                if (f) {
                    fprintf(f, "error: re-encoded data does not match original data\n");
                }
                all_tests_passed = false;
            }
        };

        std::vector<uint8_t> invalid_cbor_examples[] = {
            {
                0x9f,
                0x42,
                0x03,
                0x01,
                0x4a,
                0x00,
                0x16,
                0x00,
                0x2f,
                0x00,
                0x0a,
                0x00,
                0x05,
                0x00,
                0xff,
                0x9f,
            },
            { 0xbf, 0x64, 0x49, 0x45, 0x54, 0x46, 0xff }, // {_ "IETF", "Hello world!" }
        };

        // run reencode_data on valid_cbor_examples
        //
        if (f) {
            fprintf(f, "cbor::reencode_data test cases:\n");
        }
        for (const auto & e : valid_cbor_examples) {
            run_test(e, true);
        }

        // run reencode_data on invalid_cbor_examples
        //
        if (f) {
            fprintf(f, "cbor::reencode_data negative test cases:\n");
        }
        for (const auto & e : invalid_cbor_examples) {
            run_test(e, false);
        }

        return all_tests_passed;
    }

    /// unit_test() performs unit testing on all classes in the cbor
    /// namespace and returns true if they all pass, and false
    /// otherwise.  If \param f == `nullptr`, then no outupt is
    /// written; otherwise, output is written to \param f.
    ///
    static inline bool unit_test(FILE *f=nullptr) {
        return uint64::unit_test(f)
            and byte_string::unit_test(f)
            and text_string::unit_test(f)
            and reencode_unit_test(f);
    }

    // static unit test function for cbor::uint64
    //
    inline bool cbor::uint64::unit_test(FILE *f) {

        // valid input and output pairs
        //
        std::vector<std::pair<std::vector<uint8_t>,uint64_t>> test_cases = {
            {
                { { 0x00 }, 0 },
                { { 0x01 }, 1 },
                { { 0x0a }, 10 },
                { { 0x17 }, 23 },
                { { 0x18, 0x18 }, 24 },
                { { 0x18, 0x19 }, 25 },
                { { 0x18, 0x64 }, 100 },
                { { 0x19, 0x03, 0xe8 }, 1000 },
                { { 0x1a, 0x00, 0x0f, 0x42, 0x40 }, 1000000 },
                { { 0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00 }, 1000000000000 },
            }
        };

        bool no_tests_failed = true;
        if (f) { fprintf(f, "cbor::uint64 test cases:\n"); }
        for (const auto & tc : test_cases) {
            datum d{tc.first.data(), tc.first.data() + tc.first.size()};
            cbor::uint64 u{d};
            bool decoding_passed = (u.value() == tc.second);

            data_buffer<64> dbuf;
            u.write(dbuf);
            d = {tc.first.data(), tc.first.data() + tc.first.size()};
            bool encoding_passed = (dbuf.contents().cmp(d) == 0);
            bool passed = decoding_passed and encoding_passed;
            no_tests_failed &= passed;

            if (f) {
                fprintf(f, "encoded: ");
                for (const auto & ee : tc.first) { fprintf(f, "%02x", ee);  }
                fprintf(f, "\tdecoded: %zu\tre-encoded: ", u.value());
                for (const auto & ee : dbuf.contents()) { fprintf(f, "%02x", ee);  }
                fprintf(f, "\t%s\n", passed ? "passed" : "failed");
            }
        }

        // negative test cases (invalid input)
        //
        std::vector<std::vector<uint8_t>> negative_test_cases = {
            {
                { 0x64, 0x49, 0x45, 0x54, 0x46 },   // text string "IETF"
                { 0x44, 0x01, 0x02, 0x03, 0x04  },  // byte string 0x01020304
            }
        };
        if (f) { fprintf(f, "cbor::uint64 negative test cases:\n"); }
        for (const auto & tc : negative_test_cases) {
            datum d{tc.data(), tc.data() + tc.size()};
            cbor::uint64 u{d};
            bool passed = d.is_null();
            no_tests_failed &= passed;
            if (f) {
                fprintf(f, "encoded: ");
                for (const auto & ee : tc) { fprintf(f, "%02x", ee);  }
                fprintf(f, "\t%s\n", passed ? "passed (input rejected)" : "failed (input accepted)");
            }
        }
        if (f) { fprintf(f, "cbor::uint64::unit_test: %s\n", no_tests_failed ? "passed" : "failed"); }

        return no_tests_failed;
    }

    // static unit test function for cbor::byte_string
    //
    inline bool cbor::byte_string::unit_test(FILE *f) {

        // valid input and output pairs
        //
        std::vector<std::pair<std::vector<uint8_t>,std::vector<uint8_t>>> test_cases = {
            { { 0x44, 0x01, 0x02, 0x03, 0x04 }, { 0x01, 0x02, 0x03, 0x04 } },
        };
        bool no_tests_failed = true;
        if (f) { fprintf(f, "cbor::byte_string test cases:\n"); }
        for (const auto & tc : test_cases) {
            datum d{tc.first.data(), tc.first.data() + tc.first.size()};
            cbor::byte_string bs = cbor::byte_string::decode(d);
            datum expected{tc.second.data(), tc.second.data() + tc.second.size()};
            bool decoding_passed = (bs.value().cmp(expected) == 0);
            data_buffer<64> dbuf;
            bs.write(dbuf);
            d = {tc.first.data(), tc.first.data() + tc.first.size()};
            bool encoding_passed = (dbuf.contents().cmp(d) == 0);
            bool passed = decoding_passed and encoding_passed;
            no_tests_failed &= passed;

            if (f) {
                fprintf(f, "encoded: ");
                for (const auto & ee : tc.first) { fprintf(f, "%02x", ee);  }
                fprintf(f, "\tdecoded: ");
                expected.fprint_hex(f);
                fprintf(f, "\tre-encoded: ");
                for (const auto & ee : dbuf.contents()) { fprintf(f, "%02x", ee);  }
                fprintf(f, "\t%s\n", passed ? "passed" : "failed");
            }
        }
        if (f) { fprintf(f, "%s: %s\n", __func__, no_tests_failed ? "passed" : "failed"); }

        // negative test cases (invalid input)
        //
        std::vector<std::vector<uint8_t>> negative_test_cases = {
            {
                { 0x64, 0x49, 0x45, 0x54, 0x46 },   // text string "IETF"
                { 0x1a, 0x00, 0x0f, 0x42, 0x40 },   // uint64 1000000
            }
        };
        if (f) { fprintf(f, "cbor::byte_string negative test cases:\n"); }
        for (const auto & tc : negative_test_cases) {
            datum d{tc.data(), tc.data() + tc.size()};
            byte_string::decode(d);
            bool passed = d.is_null();
            no_tests_failed &= passed;
            if (f) {
                fprintf(f, "encoded: ");
                for (const auto & ee : tc) { fprintf(f, "%02x", ee);  }
                fprintf(f, "\t%s\n", passed ? "passed (input rejected)" : "failed (input accepted)");
            }
        }

        return no_tests_failed;
    }

    // static unit test function for cbor::text_string
    //
    inline bool cbor::text_string::unit_test(FILE *f) {

        // valid input and output pairs
        //
        std::vector<std::pair<std::vector<uint8_t>,std::vector<uint8_t>>> test_cases = {
            {
                { 0x64, 0x49, 0x45, 0x54, 0x46 },
                { 0x49, 0x45, 0x54, 0x46 }  // IETF
            },
            {
                { 0x6c, 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!' },
                { 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!' }
            },
        };
        bool no_tests_failed = true;
        if (f) { fprintf(f, "cbor::text_string test cases:\n"); }
        for (const auto & tc : test_cases) {
            datum d{tc.first.data(), tc.first.data() + tc.first.size()};
            cbor::text_string bs = cbor::text_string::decode(d);
            datum expected{tc.second.data(), tc.second.data() + tc.second.size()};
            bool decoding_passed = (bs.value().cmp(expected) == 0);
            data_buffer<64> dbuf;
            bs.write(dbuf);
            d = {tc.first.data(), tc.first.data() + tc.first.size()};
            bool encoding_passed = (dbuf.contents().cmp(d) == 0);
            bool passed = decoding_passed and encoding_passed;
            no_tests_failed &= passed;

            if (f) {
                fprintf(f, "encoded: ");
                for (const auto & ee : tc.first) { fprintf(f, "%02x", ee);  }
                fprintf(f, "\tdecoded: ");
                expected.fprint_hex(f);
                fprintf(f, "\tre-encoded: ");
                for (const auto & ee : dbuf.contents()) { fprintf(f, "%02x", ee);  }
                fprintf(f, "\t%s\n", passed ? "passed" : "failed");
            }
        }
        if (f) { fprintf(f, "%s: %s\n", __func__, no_tests_failed ? "passed" : "failed"); }

        // negative test cases (invalid input)
        //
        std::vector<std::vector<uint8_t>> negative_test_cases = {
            {
                { 0x44, 0x01, 0x02, 0x03, 0x04 },   // byte string
                { 0x1a, 0x00, 0x0f, 0x42, 0x40 },   // uint64 1000000
            }
        };
        if (f) { fprintf(f, "cbor::text_string negative test cases:\n"); }
        for (const auto & tc : negative_test_cases) {
            datum d{tc.data(), tc.data() + tc.size()};
            text_string::decode(d);
            bool passed = d.is_null();
            no_tests_failed &= passed;
            if (f) {
                fprintf(f, "encoded: ");
                for (const auto & ee : tc) { fprintf(f, "%02x", ee);  }
                fprintf(f, "\t%s\n", passed ? "passed (input rejected)" : "failed (input accepted)");
            }
        }

        return no_tests_failed;
    }

};

#endif // CBOR_HPP
