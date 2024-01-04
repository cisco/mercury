// utf8.cpp
//
// test driver for utf8 class

#include <cstdio>
#include <vector>
#include <iostream>
#include <codecvt>
#include <locale>

#include "libmerc/datum.h"
#include "libmerc/json_object.h"
#include "libmerc/utf8.hpp"

class utf8_test_case {
    std::vector<uint8_t> s_in;
    bool valid;

public:

    utf8_test_case(const std::vector<uint8_t> input, bool is_valid) :
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

    void fprint(FILE *f) const {
        datum s_data{s_in.data(), s_in.data() + s_in.size()};
        utf8_string s_utf8{s_data};

        char data[4096];
        buffer_stream buf{data, sizeof(data)};
        json_object record{&buf};

        record.print_key_value("utf8", s_utf8);
        record.print_key_hex("hex", s_utf8);
        record.print_key_bool("valid", valid);
        record.print_key_bool("passed", test());
        record.close();
        buf.write_line(stdout);

        if (false) {
            //
            // attempt to create a utf8 string from the s_utf8 output in buffer_stream
            //
            try {
                std::wstring_convert<std::codecvt_utf8<wchar_t>> cvt;
                std::string tmp{buf.dstr, (size_t)buf.doff};
                auto wstring = cvt.from_bytes(tmp);
            }
            catch (std::exception &e) {

                if (valid) {
                    fprintf(stderr, "error: valid input but caught exception %s\t", e.what());
                    s_data.fprint_hex(stderr);
                    fputc('\n', stderr);
                }
            }
            if (!valid) {
                fprintf(stderr, "error: invalid input but no exception\t");
                s_data.fprint_hex(stderr);
                fputc('\n', stderr);
            }
        }

    }

};

int main(int, char *[]) {

    // UTF-8 test cases adapted from the "UTF-8 decoder capability and
    // stress test", Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/>,
    // 2015-08-28, which is CC BY 4.0.  Test cases that include five
    // or six byte sequences were removed, as they are no longer
    // valid UTF-8.
    //
    std::vector<utf8_test_case> utf8_test_cases {

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

    for (const auto & tc : utf8_test_cases) {
        tc.fprint(stdout);
    }

}
