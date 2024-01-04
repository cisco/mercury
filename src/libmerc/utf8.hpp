// utf8.hpp

#ifndef UTF8_HPP
#define UTF8_HPP

class utf8_string : public datum {
public:

    // construct a utf8_string from a datum by copying its 'begin' and
    // 'end' locations
    //
    utf8_string(datum &d) : datum{d} { }

    // these private-usage codepoints are used to indicate invalid
    // byte sequences
    //
    static const constexpr char *sequence_too_short      = "\\ue000";
    static const constexpr char *invalid_or_overlong     = "\\ue001";
    static const constexpr char *invalid_or_private      = "\\ue002";
    static const constexpr char *unexpected_continuation = "\\ue003";
    static const constexpr char *invalid_surrogate       = "\\ue004";

    // write the len bytes at location data as a UTF-8 string with the
    // JSON special characters (quotation mark, reverse solidus,
    // solidus, backspace, form feed, line feed, carriage return, tab)
    // escaped as per RFC 8259 Section 7.
    //
    // Invalid byte sequences are replaced with private-usage
    // codepoints that describe why the sequence was invalid (see above).
    //
    // 'Noncharacters' are accepted.
    //
    static inline bool write(buffer_stream &b, const uint8_t *data, unsigned int len);

    // write this utf8 string into a buffer_stream, handling JSON
    // special characters, invalid byte sequences, and private-usage
    // codepoints as with utf8_string::write().
    //
    // note that this operation may fail if there is not enough room in
    // the buffer stream
    //
    // note: 'fingerprint' is an awkward name used for historical
    // reasons; it should be changed to 'write' or something similar.
    //
    inline void fingerprint(struct buffer_stream &b) const {
        if (datum::is_not_null()) {
            write(b, data, length());
        }
    }

    // return true if x is a continuation byte, and false otherwise
    //
    static inline bool is_continuation(uint8_t x);

};

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
                        b.snprintf("\\u%04x", hi);
                        b.snprintf("\\u%04x", lo);

                    } else {
                        //
                        // basic multilingual plane
                        //
                        b.snprintf("\\u%04x", codepoint);
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
                b.snprintf("\\u%04x", *x);

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


#endif // UTF8_HPP
