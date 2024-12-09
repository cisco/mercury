// utf8.hpp

#ifndef UTF8_HPP
#define UTF8_HPP

#include "datum.h"
#include <vector> // used for unit test cases

/// class utf8_string represents a sequence of UTF-8 code points in
/// memory, and can write out a JSON-escaped representation with \ref
/// utf8_string::write().
///
class utf8_string : public datum {
public:

    /// construct a utf8_string from a datum by copying
    ///
    utf8_string(const datum &d) : datum{d} { }

    /// construct a utf8_string from the first byte \param d, and the
    /// byte immedately after its end \param d_end
    ///
    utf8_string(const uint8_t *d, const uint8_t *d_end) : datum{d, d_end} { }

    // code sequences used to represent invalid byte sequences
    //
    static const constexpr char *replacement_character   = "\\ufffd";
#if true
    //
    // use the replacement character to represent invalid byte sequences
    //
    static const constexpr char *sequence_too_short      = replacement_character;
    static const constexpr char *invalid_or_overlong     = replacement_character;
    static const constexpr char *invalid_or_private      = replacement_character;
    static const constexpr char *unexpected_continuation = replacement_character;
    static const constexpr char *invalid_surrogate       = replacement_character;

#else
    //
    // use a distinct private-usage codepoint for each type of invalid
    // byte sequences, so that error types can be tracked
    //
    static const constexpr char *sequence_too_short      = "\\ue000";
    static const constexpr char *invalid_or_overlong     = "\\ue001";
    static const constexpr char *invalid_or_private      = "\\ue002";
    static const constexpr char *unexpected_continuation = "\\ue003";
    static const constexpr char *invalid_surrogate       = "\\ue004";
#endif

    /// write the \param len bytes at location \param data as a UTF-8
    /// string with the JSON special characters (quotation mark,
    /// reverse solidus, solidus, backspace, form feed, line feed,
    /// carriage return, tab) escaped as per RFC 8259 Section 7.
    ///
    /// Invalid byte sequences are replaced with private-usage
    /// codepoints that describe why the sequence was invalid (see above).
    ///
    /// 'Noncharacters' are accepted.
    ///
    /// \return `true` if the input bytes formed a valid UTF-8
    /// sequence, `false` otherwise.
    ///
    static inline bool write(buffer_stream &b, const uint8_t *data, unsigned int len);

    /// write this utf8 string into a buffer_stream, handling JSON
    /// special characters, invalid byte sequences, and private-usage
    /// codepoints as with utf8_string::write().
    ///
    /// This operation may fail if there is not enough room in
    /// the buffer stream
    ///
    /// \note 'fingerprint' is an awkward name used for historical
    /// reasons; it should be changed to 'write' or something similar.
    ///
    inline void fingerprint(struct buffer_stream &b) const {
        if (datum::is_not_null()) {
            write(b, data, length());
        }
    }

    // return true if x is a continuation byte, and false otherwise
    //
    static inline bool is_continuation(uint8_t x);

    // write the uint16_t value as a '\uXXXX'-encoded codepoint
    //
    static inline void write_codepoint(buffer_stream &b, uint16_t codepoint) {
        b.write_char('\\');
        b.write_char('u');
        b.write_hex_uint(codepoint);
    }

    /// runs the unit tests for \ref utf8_string and returns `true` if
    /// and only if all test cases pass.  If a non-null `FILE *`
    /// argument is passed, then a brief description of each test case
    /// run is written to that `FILE`.
    ///
    static inline bool unit_test(FILE *f=nullptr);

    // implements a test case for \ref utf8_string
    //
    class test_case {
        std::vector<uint8_t> s_in;   // string to be parsed
        bool valid;                  // true is s_in is valid utf8; false otherwise

    public:

        test_case(const std::vector<uint8_t> input, bool is_valid) :
            s_in{input},
            valid{is_valid}
        { }

        bool is_valid() const { return valid; }

        bool test() const {
            datum s_data{s_in.data(), s_in.data() + s_in.size()};
            utf8_string s_utf8{s_data};
            char data[4096];
            buffer_stream buf{data, sizeof(data)};
            return s_utf8.write(buf, s_utf8.data, s_utf8.length()) == valid;
        }

        void fprint(FILE *) const {
            datum s_data{s_in.data(), s_in.data() + s_in.size()};
            utf8_string s_utf8{s_data};

            // char data[4096];
            // buffer_stream buf{data, sizeof(data)};
            // json_object record{&buf};

            // record.print_key_value("utf8", s_utf8);
            // record.print_key_hex("hex", s_utf8);
            // record.print_key_bool("valid", valid);
            // record.print_key_bool("passed", test());
            // record.close();
            // buf.write_line(f);

        }

    };

};

[[maybe_unused]] static int utf8_fuzz_test(const uint8_t *data, size_t size) {
    struct datum utf8_data{data, data+size};
    utf8_string s_utf8{utf8_data};
    char out_data[4096];
    buffer_stream buf{out_data, sizeof(out_data)};
    s_utf8.write(buf, s_utf8.data, s_utf8.length());

    return 0;
}


// UTF-8 is a variable-length encoding scheme that represents unicode
// code points in sequences of one to four bytes.  It is backwards
// compatible with ASCII.
//
// Code Points and the byte sequences that encode them
//
//          First    Last
//          Code     Code
//   Bits   Point    Point       Bytes  Byte 1      Byte 2      Byte 3      Byte 4
//   --------------------------------------------------------------------------------
//     7    U+0000   U+007F      1      0xxxxxxx
//    11    U+0080   U+07FF      2      110xxxxx    10xxxxxx
//    16    U+0800   U+FFFF      3      1110xxxx    10xxxxxx    10xxxxxx
//    21    U+10000  U+1FFFFF    4      11110xxx    10xxxxxx    10xxxxxx    10xxxxxx
//
//          First    Last
//          Code     Code
//   Bits   Point    Point      Byte 1      Byte 2      Byte 3      Byte 4
//   ------------------------------------------------------------------------
//     7    U+0000   U+007F     0x00-0x7f   -           -           -
//    11    U+0080   U+07FF     0xc0-0xdf   0x80-0xbf   -           -
//    16    U+0800   U+FFFF     0xe0-0xef   0x80-0xbf   0x80-0xbf   -
//    21    U+10000  U+1FFFFF   0xf0-0xf7   0x80-0xbf   0x80-0xbf   0x80-0xbf
//
// Legal UTF-8 Byte Sequences, following http://www.unicode.org/versions/corrigendum1.html
//
//  Code Points         1st Byte  2nd Byte   3rd Byte    4th Byte
//  ---------------------------------------------------------------
//  U+0000..U+007F      00..7F    -          -           -
//  U+0080..U+07FF      C2..DF    80..BF     -           -
//  U+0800..U+0FFF      E0        A0..BF     80..BF      -
//  U+1000..U+FFFF      E1..EF    80..BF     80..BF      -
//  U+10000..U+3FFFF    F0        90..BF     80..BF      80..BF
//  U+40000..U+FFFFF    F1..F3    80..BF     80..BF      80..BF
//  U+100000..U+10FFFF  F4        80..8F     80..BF      80..BF
//
inline bool utf8_string::write(buffer_stream &b, const uint8_t *data, unsigned int len) {
    bool valid = true;

    const uint8_t *x = data;
    const uint8_t *end = data + len;
    while (x < end) {

        if (*x >= 0x80) {            // non-ASCII/multi-byte characters

            uint32_t codepoint = 0;
            if (*x >= 0xc2) {        // 0xc0 and 0xc1 are invalid (overlong encodings)

                if (*x >= 0xe0) {

                    if (*x >= 0xf0) {
                        if (x >= end - 3) {
                            b.puts(sequence_too_short); // indicate error with private use codepoint
                            valid = false;
                            break;                 // error; too few bytes for code point
                        }
                        uint8_t byte1 = *x++;
                        uint8_t byte2 = *x++;
                        uint8_t byte3 = *x++;
                        uint8_t byte4 = *x;
                        if (is_continuation(byte2) && is_continuation(byte3) && is_continuation(byte4)) {
                            codepoint = (byte1 & 0x07);
                            codepoint = (byte2 & 0x3f) | (codepoint << 6);
                            codepoint = (byte3 & 0x3f) | (codepoint << 6);
                            codepoint = (byte4 & 0x3f) | (codepoint << 6);

                            // check for overlong encodings using
                            // the first code point for 4-byte
                            // sequences
                            //
                            if (codepoint < 0x10000) {
                                codepoint = 0;
                            }
                        }
                    } else {
                        if (x >= end - 2) {
                            b.puts(sequence_too_short); // indicate error with private use codepoint
                            valid = false;
                            break;                 // error; too few bytes for code point
                        }
                        uint8_t byte1 = *x++;
                        uint8_t byte2 = *x++;
                        uint8_t byte3 = *x;
                        if (is_continuation(byte2) && is_continuation(byte3)) {
                            codepoint = (byte1 & 0x0f);
                            codepoint = (byte2 & 0x3f) | (codepoint << 6);
                            codepoint = (byte3 & 0x3f) | (codepoint << 6);

                            // check for overlong encodings using
                            // the first code point for 3-byte
                            // sequences
                            //
                            if (codepoint < 0x0800) {
                                codepoint = 0;
                            }
                        }
                    }

                } else {
                    if (x >= end - 1) {
                        b.puts(sequence_too_short); // indicate error with private use codepoint
                        valid = false;
                        break;                 // error; too few bytes for code point
                    }
                    uint8_t byte1 = *x++;
                    uint8_t byte2 = *x;
                    if (is_continuation(byte2) && ((byte1 & 0x1f) != 0)) {
                        codepoint = ((byte1 & 0x1f) << 6);
                        codepoint |= byte2 & 0x3f;
                    }
                }
                if (codepoint == 0x0) {
                    //
                    // error: an invalid continuation byte was
                    // encountered in a multi-byte sequence, or an
                    // overlong encoding was encountered
                    //
                    b.puts(invalid_or_overlong); // indicate error with private use codepoint
                    valid = false;

                } else if (codepoint < 0x10fffd) {

                    // Private-Use Code Point Ranges:
                    //   U+E000..U+F8FF
                    //   U+F0000..U+FFFFD and
                    //   U+100000..U+10FFFD.
                    //
                    if ((codepoint >= 0xe000 && codepoint <= 0xf8ff) ||
                        (codepoint >= 0xf0000 && codepoint <= 0xffffd) ||
                        (codepoint >= 0x100000 && codepoint <= 0x10fffd)) {
                        //
                        // error: invalid or private codepoint
                        //
                        b.puts(invalid_or_private); // indicate error with private use codepoint
                        valid = false;

                    } else if (codepoint >= 0xd800 && codepoint <= 0xdfff) {
                        //
                        // invalid surrogate half
                        //
                        b.puts(invalid_surrogate); // indicate error with private use codepoint
                        valid = false;

                    } else if (codepoint > 0xffff) {
                        //
                        // surrogate pair
                        //
                        codepoint -= 0x10000;
                        uint32_t hi = (codepoint >> 10) + 0xd800;
                        uint32_t lo = (codepoint & 0x3ff) + 0xdc00;
                        write_codepoint(b, hi);
                        write_codepoint(b, lo);

                    } else {
                        //
                        // basic multilingual plane
                        //
                        write_codepoint(b, codepoint);
                    }

                }

            } else {
                //
                // error: initial byte in range 0x80 - 0xbf
                //
                b.puts(unexpected_continuation); // indicate error with private use codepoint
                valid = false;
            }

        } else {    // *x < 0x80; ASCII

            if (*x < 0x20 || *x == 0x7f) {       // escape control characters
                write_codepoint(b, *x);

            } else {
                if (*x == '"' || *x == '\\') {   // escape json special characters
                    b.write_char('\\');
                }
                b.write_char(*x);                // print out ascii character
            }
        }
        x++;
    }
    return valid;
}

inline bool utf8_string::is_continuation(uint8_t x) {
    if (x < 0x80 || x > 0xbf) {
        return false;
    }
    return true;
}

inline bool utf8_string::unit_test(FILE *output) {

    // note: output=nullptr by default, but can be set to stdout or
    // another FILE* to enable verbose output

    // UTF-8 test cases, including some adapted from the "UTF-8
    // decoder capability and stress test", Markus Kuhn
    // <http://www.cl.cam.ac.uk/~mgk25/>, 2015-08-28, which is CC BY
    // 4.0.  Test cases from that set with five or six byte sequences
    // were removed, as they are no longer valid UTF-8.
    //
    utf8_string::test_case utf8_test_cases[] = {

        // correct ASCII-US
        //
        {
            {
                0x50, 0x6c, 0x65, 0x69, 0x73, 0x74, 0x6f, 0x63, 0x65, 0x6e, 0x65
            },
            true
        },
        //
        // ASCII printable characters
        //
        {
            {
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
                0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
                0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
                0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e
            },
            true
        },
        //
        // ASCII control characters
        //
        {
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x7f
            },
            true
        },

        // correct UTF-8
        //
        {
            {
                0xce, 0xba, 0xe1, 0xbd, 0xb9, 0xcf, 0x83, 0xce,
                0xbc, 0xce, 0xb5
            },
            true
        },
        //
        // '\uXXXX'-encoded code points corresponding to the previous
        // test case
        //
        {
            {
                0x5c, 0x75, 0x30, 0x33, 0x62, 0x61, 0x5c, 0x75, 0x31, 0x66, 0x37, 0x39,
                0x5c, 0x75, 0x30, 0x33, 0x63, 0x33, 0x5c, 0x75, 0x30, 0x33, 0x62, 0x63,
                0x5c, 0x75, 0x30, 0x33, 0x62, 0x35
            },
            true
        },
        //
        // G-clef, which should be represented as the surrogate pair "\ud834\udd1e"
        //
        {
            {
                0xf0, 0x9d, 0x84, 0x9e
            },
            true
        },

        // first possible sequence of a certain length
        //
        {
            {
                0x00
            },
            true
        },
        {
            {
                0xc2, 0x80
            },
            true
        },
        {
            {
                0xe0, 0xa0, 0x80
            },
            true
        },
        {
            {
                0xf0, 0x90, 0x80, 0x80
            },
            true
        },

        // last possible sequence of a certain length
        //
        {
            {
                0x7f
            },
            true
        },
        {
            {
                0xdf, 0xbf
            },
            true
        },
        {
            {
                0xef, 0xbf, 0xbf
            },
            true
        },
        {
            {
                0xf7, 0xbf, 0xbf, 0xbf
            },
            true
        },

        // other boundary conditions
        //
        {
            {
                0xed, 0x9f, 0xbf
            },
            true
        },
        {
            {
                0xee, 0x80, 0x80  // private code point 0xe000
            },
            false
        },
        {
            {
                0xef, 0xbf, 0xbd
            },
            true
        },
        {
            {
                0xf4, 0x8f, 0xbf, 0xbf
            },
            true
        },
        {
            {
                0xf4, 0x90, 0x80, 0x80
            },
            true
        },

        // overlong sequences
        //
        {
            {
                0xc0, 0xaf
            },
            false
        },
        {
            {
                0xe0, 0x80, 0xaf
            },
            false
        },
        {
            {
                0xf0, 0x80, 0x80, 0xaf
            },
            false
        },

        // maximum overlong sequences
        //
        {
            {
                0xc1, 0xbf
            },
            false
        },
        {
            {
                0xe0, 0x9f, 0xbf
            },
            false
        },
        {
            {
                0xf0, 0x8f, 0xbf, 0xbf
            },
            false
        },

        // unexpected continuation bytes
        //
        {
            {
                0x80
            },
            false
        },
        {
            {
                0x80, 0xbf
            },
            false
        },
        {
            {
                0x80, 0xbf, 0x80
            },
            false
        },
        {
            {
                0x80, 0xbf, 0x80, 0xbf
            },
            false
        },
        {
            {
                0x80, 0xbf, 0x80, 0xbf, 0x80
            },
            false
        },
        {
            {
                0x80, 0xbf, 0x80, 0xbf, 0x80, 0xbf
            },
            false
        },

        // sequence of all possible continuation bytes
        {
            {
                0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
                0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
                0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
                0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf
            },
            false
        },

        // lonely start characters
        //
        {
            {
                0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
                0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
                0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
                0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf
            },
            false
        },
        {
            {
                0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
                0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef
            },
            false
        },
        {
            {
                0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7
            },
            false
        },
        {
            {
                0xf8, 0xf9, 0xfa, 0xfb
            },
            false
        },
        {
            {
                0xfc, 0xfd
            },
            false
        },

        // sequences with the last continuation byte missing
        //
        {
            {
                0xc0
            },
            false
        },
        {
            {
                0xe0, 0x80
            },
            false
        },
        {
            {
                0xf0, 0x80, 0x80
            },
            false
        },
        {
            {
                0xf8, 0x80, 0x80, 0x80
            },
            false
        },
        {
            {
                0xdf
            },
            false
        },
        {
            {
                0xef, 0xbf
            },
            false
        },
        {
            {
                0xf7, 0xbf, 0xbf
            },
            false
        },

        // concatenation of incomplete sequences
        //
        {
            {
                0xc0, 0xe0, 0x80, 0xf0, 0x80, 0x80, 0xf8, 0x80,
                0x80, 0x80, 0xdf, 0xef, 0xbf, 0xf7, 0xbf, 0xbf
            },
            false
        },
        {
            {
                0xef, 0xbf, 0xf7, 0xbf, 0xbf, 0xfb, 0xbf, 0xbf,
                0xbf, 0xfd, 0xbf, 0xbf, 0xbf, 0Xbf
            },
            false
        },

        // impossible bytes
        //
        {
            {
                0xfe
            },
            false
        },
        {
            {
                0xff
            },
            false
        },
        {
            {
                0xfe, 0xfe, 0xff, 0xff
            },
            false
        },

        // overlong NULL (0)
        //
        {
            {
                0xc0, 0x80
            },
            false
        },
        {
            {
                0xe0, 0x80, 0x80
            },
            false
        },
        {
            {
                0xf0, 0x80, 0x80, 0x80
            },
            false
        },

        // single UTF-16 surrogates
        //
        {
            {
                0xed, 0xa0, 0x80
            },
            false
        },
        {
            {
                0xed, 0xad, 0xbf
            },
            false
        },
        {
            {
                0xed, 0xae, 0x80
            },
            false
        },
        {
            {
                0xed, 0xaf, 0xbf
            },
            false
        },
        {
            {
                0xed, 0xb0, 0x80
            },
            false
        },
        {
            {
                0xed, 0xbe, 0x80
            },
            false
        },
        {
            {
                0xed, 0xbf, 0xbf
            },
            false
        },

        // paired UTF-16 surrogates
        //
        {
            {
                0xed, 0xa0, 0x80, 0xed, 0xb0, 0x80
            },
            false
        },
        {
            {
                0xed, 0xa0, 0x80, 0xed, 0xbf, 0xbf
            },
            false
        },
        {
            {
                0xed, 0xad, 0xbf, 0xed, 0xb0, 0x80
            },
            false
        },
        {
            {
                0xed, 0xad, 0xbf, 0xed, 0xbf, 0xbf
            },
            false
        },
        {
            {
                0xed, 0xae, 0x80, 0xed, 0xb0, 0x80
            },
            false
        },
        {
            {
                0xed, 0xae, 0x80, 0xed, 0xbf, 0xbf
            },
            false
        },
        {
            {
                0xed, 0xaf, 0xbf, 0xed, 0xb0, 0x80
            },
            false
        },
        {
            {
                0xed, 0xaf, 0xbf, 0xed, 0xbf, 0xbf
            },
            false
        },

        // 'problematic' noncharacters, which we count as valid (see
        // http://www.unicode.org/faq/private_use.html#nonchar1 and
        // https://www.unicode.org/faq/private_use.html#sentinel6)
        //
        {
            {
                0xef, 0xbf, 0xbe   // U+FFFE
            },
            true
        },
        {
            {
                0xef, 0xbf, 0xbf   // U+FFFF
            },
            true
        },

        //
        // all of the noncharacters in the BMP range U+FDD0..U+FDEF,
        // in sequence
        //
        {
            {
                0xef, 0xb7, 0x90, 0xef, 0xb7, 0x91, 0xef, 0xb7,
                0x92, 0xef, 0xb7, 0x93, 0xef, 0xb7, 0x94, 0xef,
                0xb7, 0x95, 0xef, 0xb7, 0x96, 0xef, 0xb7, 0x97,
                0xef, 0xb7, 0x98, 0xef, 0xb7, 0x99, 0xef, 0xb7,
                0x9a, 0xef, 0xb7, 0x9b, 0xef, 0xb7, 0x9c, 0xef,
                0xb7, 0x9d, 0xef, 0xb7, 0x9e, 0xef, 0xb7, 0x9f,
                0xef, 0xb7, 0xa0, 0xef, 0xb7, 0xa1, 0xef, 0xb7,
                0xa2, 0xef, 0xb7, 0xa3, 0xef, 0xb7, 0xa4, 0xef,
                0xb7, 0xa5, 0xef, 0xb7, 0xa6, 0xef, 0xb7, 0xa7,
                0xef, 0xb7, 0xa8, 0xef, 0xb7, 0xa9, 0xef, 0xb7,
                0xaa, 0xef, 0xb7, 0xab, 0xef, 0xb7, 0xac, 0xef,
                0xb7, 0xad, 0xef, 0xb7, 0xae, 0xef, 0xb7, 0xaf
            },
            true
        },

        //
        // all of the noncharacters in the last two code points of
        // each of the 16 supplementary planes: U+1FFFE, U+1FFFF,
        // U+2FFFE, U+2FFFF, ... U+10FFFE, U+10FFFF
        //
        {
            {
                0xf0, 0x9f, 0xbf, 0xbe, 0xf0, 0x9f, 0xbf, 0xbf,
                0xf0, 0xaf, 0xbf, 0xbe, 0xf0, 0xaf, 0xbf, 0xbf,
                0xf0, 0xbf, 0xbf, 0xbe, 0xf0, 0xbf, 0xbf, 0xbf,
                0xf1, 0x8f, 0xbf, 0xbe, 0xf1, 0x8f, 0xbf, 0xbf,
                0xf1, 0x9f, 0xbf, 0xbe, 0xf1, 0x9f, 0xbf, 0xbf,
                0xf1, 0xaf, 0xbf, 0xbe, 0xf1, 0xaf, 0xbf, 0xbf,
                0xf1, 0xbf, 0xbf, 0xbe, 0xf1, 0xbf, 0xbf, 0xbf,
                0xf2, 0x8f, 0xbf, 0xbe, 0xf2, 0x8f, 0xbf, 0xbf,
                0xf2, 0x9f, 0xbf, 0xbe, 0xf2, 0x9f, 0xbf, 0xbf,
                0xf2, 0xaf, 0xbf, 0xbe, 0xf2, 0xaf, 0xbf, 0xbf,
                0xf2, 0xbf, 0xbf, 0xbe, 0xf2, 0xbf, 0xbf, 0xbf,
                0xf3, 0x8f, 0xbf, 0xbe, 0xf3, 0x8f, 0xbf, 0xbf,
                0xf3, 0x9f, 0xbf, 0xbe, 0xf3, 0x9f, 0xbf, 0xbf,
                0xf3, 0xaf, 0xbf, 0xbe, 0xf3, 0xaf, 0xbf, 0xbf,
                0xf3, 0xbf, 0xbf, 0xbe, 0xf3, 0xbf, 0xbf, 0xbf,
                0xf4, 0x8f, 0xbf, 0xbe, 0xf4, 0x8f, 0xbf, 0xbf
            },
            true
        },

    };

    bool passed = true;
    for (const auto & tc : utf8_test_cases) {
        passed &= tc.test();
        if (output) {
            tc.fprint(output);
        }
    }
    return passed;
}

/// a class that constructs and holds a UTF-8 encoded string that is
/// safe for use in JSON, if possible.  This class is suitable for
/// processing potentially unsafe data (e.g. from packets).
///
template <size_t N>
class utf8_safe_string {
    output_buffer<N> buf;

public:

    /// constructs a \ref utf8_safe_string, if possible, from a
    /// potentially unsafe string in the \ref datum \param
    /// unsafe_string
    ///
    utf8_safe_string(const datum &unsafe_string) {
        if (utf8_string::write(buf, unsafe_string.data, unsafe_string.length())) {
            buf.add_null();
        } else {
            buf.trunc = 1;  // mark buffer as truncated to prevent its use
        }
    }

    /// returns a JSON-escaped utf8 string, or the \param
    /// default_string specified by the caller
    ///
    const char *get_string_or_default(const char* default_string) const {
        if (buf.trunc == 1) {
            return default_string;
        }
        return buf.get_buffer_start();
    }

    /// performs unit tests for \ref class utf8_safe_string and
    /// returns `true` if they all pass, and `false` otherwise
    ///
    static bool unit_test() {

        // verify that correct utf8 is processed correctly and
        // accepted if it fits into the output buffer; here we use the
        // ancient greek word for cosmos
        //
        const uint8_t good_utf8[] = {
            0xce, 0xba, 0xe1, 0xbd, 0xb9, 0xcf, 0x83, 0xce,
            0xbc, 0xce, 0xb5
        };
        datum good{good_utf8, good_utf8 + sizeof(good_utf8)};
        utf8_safe_string<32> safe{good};
        const char *default_str = "default";
        if (safe.get_string_or_default(default_str) != safe.buf.get_buffer_start()) {
            return false;
        }

        // verify that correct utf8 is processed correctly and
        // rejected if it does not fit into the output buffer
        //
        utf8_safe_string<4> safe2{good};
        if (safe2.get_string_or_default(default_str) != default_str) {
            return false;
        }

        // verify that incorrect utf8 is processed correctly; here we
        // use an unexpected continuation byte
        //
        const uint8_t bad_utf8[] = {
            0x80, 0xbf, 0x80
        };
        datum bad{bad_utf8, bad_utf8 + sizeof(bad_utf8)};
        utf8_safe_string<32> safe3{bad};
        if (safe3.get_string_or_default(default_str) != default_str) {
            return false;
        }

    }

};


#endif // UTF8_HPP
