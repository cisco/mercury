// cbor.cpp

#include <cstdio>
#include <vector>
#include "libmerc/cbor.hpp"


// cbor_fingerprint decodes a CBOR representation of a Network
// Protocol Fingerprint (NPF), which is defined by this correspondence
// to the textual string representation
//
//    * A hex string maps to a byte string (major type 2)
//
//    * A sequence of similar elements maps to an indefinite length
//     array (major type 4)
//
//        - ‘(‘ maps to 0x9f (initial byte of indefinite-length array)
//
//        - ‘)’ maps to 0xff (‘break’, final byte of indefinite-length
//          array)
//
class cbor_fingerprint {
public:
    cbor_fingerprint(datum &d) {
    }

    static void fprint(FILE *f, datum &d) {
        while (lookahead<cbor::initial_byte> ib{d}) {
            if (ib.value.is_byte_string()) {
                cbor::byte_string bs{d};
                fputc('(', stdout);
                bs.value().fprint_hex(stdout);
                fputc(')', stdout);
            } else if (ib.value.is_array_indefinite_length()) {
                d = ib.advance();
                fputc('(', stdout);
                fprint(f, d);          // recursion
                fputc(')', stdout);
            } else if (ib.value.is_break()) {
                d = ib.advance();
                break;
            } else {
                return;  // error: unexpected type
            }
        }
    }

};

int main(int, char *[]) {

    // uint8_t test_data[] = { 0xff, 0xaa };
    // datum d{test_data, test_data + sizeof(test_data)};
    // cbor::uint64 u{d};

    std::vector<uint8_t> uint64_examples[] = {
        { 0x00 },   // 0
        { 0x01 },   // 1
        { 0x0a },   // 10
        { 0x17 },   // 23
        { 0x18, 0x18 }, // 24
        { 0x18, 0x19 }, // 25
        { 0x18, 0x64 }, // 100
        { 0x19, 0x03, 0xe8 }, // 1000
        { 0x1a, 0x00, 0x0f, 0x42, 0x40 }, // 1000000
        { 0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00 } // 1000000000000
    };

    for (const auto & e : uint64_examples) {
        for (const auto & ee : e) {
            printf("%02x\t", ee);
        }
        fputc('\n', stdout);

        datum d{e.data(), e.data() + e.size()};

        cbor::uint64 u{d};
        printf("%lu\n", u.value());

        fputc('\n', stdout);
    }

    std::vector<uint8_t> text_string_examples[] = {
        { 0x64, 0x49, 0x45, 0x54, 0x46 },   // IETF
        { 0x6c, 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!' },
    };
    for (const auto & e : text_string_examples) {
        for (const auto & ee : e) {
            printf("%02x\t", ee);
        }
        fputc('\n', stdout);

        datum d{e.data(), e.data() + e.size()};

        cbor::text_string ts{d};
        ts.value().fprint(stdout); fputc('\n', stdout);

        fputc('\n', stdout);
    }

    std::vector<uint8_t> byte_string_examples[] = {
        { 0x44, 0x01, 0x02, 0x03, 0x04  },   // byte string 0x01020304
    };
    for (const auto & e : byte_string_examples) {
        for (const auto & ee : e) {
            printf("%02x\t", ee);
        }
        fputc('\n', stdout);

        datum d{e.data(), e.data() + e.size()};

        cbor::byte_string bs{d};
        bs.value().fprint_hex(stdout); fputc('\n', stdout);

        fputc('\n', stdout);
    }

    std::vector<uint8_t> array_examples[] = {
        { 0x9f, 0xff  },   // [_ ] - empty indefinite-length array
        { 0x9f, 0x64, 0x49, 0x45, 0x54, 0x46, 0xff  },   // [_ "IETF" ] - indefinite-length array
        { 0x9f, 0x64, 0x49, 0x45, 0x54, 0x46, 0x6c, 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!', 0xff }, // [_ "IETF", "Hello world!" ]
    };
    for (const auto & e : array_examples) {
        for (const auto & ee : e) {
            printf("%02x, ", ee);
        }
        fputc('\n', stdout);

        datum d{e.data(), e.data() + e.size()};

        cbor::array a{d};
        printf("[\n");
        while (a.value().is_not_empty()) {
            cbor::text_string ts{a.value()};
            ts.value().fprint(stdout); fputc('\n', stdout);
        }
        printf("]\n");

        fputc('\n', stdout);
    }

    std::vector<uint8_t> map_examples[] = {
        { 0xbf, 0x64, 0x49, 0x45, 0x54, 0x46, 0x6c, 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!', 0xff }, // {_ "IETF", "Hello world!" }
    };
    for (const auto & e : map_examples) {
        for (const auto & ee : e) {
            printf("%02x, ", ee);
        }
        fputc('\n', stdout);

        datum d{e.data(), e.data() + e.size()};

        cbor::map a{d};
        printf("[\n");
        while (a.value().is_not_empty()) {
            if (lookahead<cbor::initial_byte> ib{a.value()}) {
                if (ib.value.is_break()) {
                    break;
                }
            }
            cbor::text_string key{a.value()};
            cbor::text_string value{a.value()};
            printf("key:\t"); key.value().fprint(stdout); fputc('\n', stdout);
            printf("value:\t"); value.value().fprint(stdout); fputc('\n', stdout);
        }
        printf("]\n");

        fputc('\n', stdout);
    }

    std::vector<uint8_t> fingerprint_examples[] = {
        //
        // tls/1/(0301)(0016002f000a000500ff)[(0000)(0023)]
        //
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
    };
    for (const auto & e : fingerprint_examples) {
        for (const auto & ee : e) {
            printf("%02x, ", ee);
        }
        fputc('\n', stdout);

        datum d{e.data(), e.data() + e.size()};

        cbor_fingerprint::fprint(stdout, d);

        fputc('\n', stdout);
    }

    return 0;
}
