// cbor.cpp

#include <cstdio>
#include <vector>
#include <cctype>
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
                cbor::byte_string bs = cbor::byte_string::decode(d);
                fputc('(', stdout);
                bs.value().fprint_hex(stdout);
                fputc(')', stdout);
            } else if (ib.value.is_array_indefinite_length()) {
                d = ib.advance();
                fputc('[', stdout);
                fprint(f, d);          // recursion
                fputc(']', stdout);
            } else if (ib.value.is_break()) {
                d = ib.advance();
                break;
            } else {
                return;  // error: unexpected type
            }
        }
    }

    static void write_data(datum &d) {
        literal_byte<'('>{d};
        hex_digits{d}.fprint(stdout); fputc('\n', stdout);
        literal_byte<')'>{d};
    }

    static void write_list(datum &d) {
        literal_byte<'('>{d};
        while(lookahead<encoded<uint8_t>> c{d}) {
            if (c.value == ')') {
                break;
            }
            write_data(d);
        }
        literal_byte<')'>{d};
    }

    static void write_sorted_list(datum &d) {
        literal_byte<'['>{d};
        while(lookahead<encoded<uint8_t>> c{d}) {
            if (c.value == ']') {
                break;
            }
            fputc('\t', stdout);
            write_data(d);
        }
        literal_byte<']'>{d};
    }

    static void write_tls_fingerprint(datum &d) {
        write_data(d);         // version
        write_data(d);         // ciphersuites
        write_sorted_list(d);  // extensions
    }

    static void write_cbor_data(datum &d, writeable &w) {
        literal_byte<'('>{d};
        cbor::byte_string_from_hex{hex_digits{d}}.write(w);
        literal_byte<')'>{d};
    }

    static void write_cbor_data(datum &d, cbor::output::array &a) {
        literal_byte<'('>{d};
        cbor::byte_string_from_hex{hex_digits{d}}.write(a);
        // a.write(cbor::byte_string_from_hex{hex_digits{d}});
        literal_byte<')'>{d};
    }

    static void write_cbor_sorted_list(datum &d, writeable &w) {
        literal_byte<'['>{d};
        cbor::output::array a{w};
        while(lookahead<encoded<uint8_t>> c{d}) {
            if (c.value == ']') {
                break;
            }
            write_cbor_data(d, a);
        }
        a.close();
        literal_byte<']'>{d};
    }

    static void write_cbor_tls_fingerprint(datum &d, writeable &w) {
        write_cbor_data(d, w);         // version
        write_cbor_data(d, w);         // ciphersuites
        write_cbor_sorted_list(d, w);  // extensions
    }

};

int main(int, char *[]) {

    //
    // assert(cbor::unit_test() == true);
    //
    FILE *unit_test_output = stderr; // set to nullptr to suppress unit test output
    printf("cbor::unit_test: %s\n", cbor::unit_test(unit_test_output) ? "passed" : "failed");
    return 0;  // EARLY RETURN

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

        cbor::text_string ts = cbor::text_string::decode(d);
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

        cbor::byte_string bs = cbor::byte_string::decode(d);
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
            cbor::text_string ts = cbor::text_string::decode(a.value());
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
            cbor::text_string key = cbor::text_string::decode(a.value());
            cbor::text_string value = cbor::text_string::decode(a.value());
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

    for (const auto & e : fingerprint_examples) {
        for (const auto & ee : e) {
            printf("%02x, ", ee);
        }
        fputc('\n', stdout);

        datum d{e.data(), e.data() + e.size()};

        while (d.is_readable()) {
            cbor::element v = cbor::decode(d);
            if (std::holds_alternative<std::monostate>(v)) {
                break;
            }
            printf("type: %u\n", major_type(v));
        }
    }

    // run generic decoder on fingerprint_examples
    //
    for (const auto & e : fingerprint_examples) {
        fprintf(stdout, "running decode_data() on ");
        for (const auto & ee : e) {
            printf("%02x, ", ee);
        }
        fputc('\n', stdout);

        datum d{e.data(), e.data() + e.size()};

        cbor::decode_data(d);
    }

    // run reencode_data on fingerprint_examples
    //
    for (const auto & e : fingerprint_examples) {
        fprintf(stdout, "running decode_data() on ");
        for (const auto & ee : e) {
            printf("%02x, ", ee);
        }
        fputc('\n', stdout);

        datum d{e.data(), e.data() + e.size()};
        d.fprint_hex(stdout); fputc('\n', stdout);
        data_buffer<1024> reencoded_buf;
        if (d.length() > 1024) {
            fprintf(stderr, "error: data_buffer too small to hold re-encoded data\n");
            return EXIT_FAILURE;
        }
        cbor::reencode_data(d, reencoded_buf);
        reencoded_buf.contents().fprint_hex(stdout); fputc('\n', stdout);
        d = {e.data(), e.data() + e.size()};
        if (d.cmp(reencoded_buf.contents()) != 0) {
            fprintf(stderr, "error: re-encoded data does not match original data\n");
            return EXIT_FAILURE;
        }
    }

    return 0; // EARLY RETURN

    data_buffer<2048> dbuf;
    cbor::initial_byte ib{cbor::unsigned_integer_type, 3};
    ib.write(dbuf);
    dbuf.contents().fprint_hex(stdout); fputc('\n', stdout); dbuf.reset();
    cbor::uint64{0x03}.write(dbuf);
    dbuf.contents().fprint_hex(stdout); fputc('\n', stdout);
    datum contents{dbuf.contents()};
    printf("encoded/decoded: %zu\n", cbor::uint64{contents}.value());
    dbuf.reset();
    cbor::uint64{0x18}.write(dbuf);
    contents = dbuf.contents(); printf("encoded/decoded: %zu\n", cbor::uint64{contents}.value());
    dbuf.contents().fprint_hex(stdout); fputc('\n', stdout); dbuf.reset();
    cbor::uint64{0x100}.write(dbuf);
    contents = dbuf.contents(); printf("encoded/decoded: %zu\n", cbor::uint64{contents}.value());
    dbuf.contents().fprint_hex(stdout); fputc('\n', stdout); dbuf.reset();
    cbor::uint64{0x10000}.write(dbuf);
    contents = dbuf.contents(); printf("encoded/decoded: %zu\n", cbor::uint64{contents}.value());
    dbuf.contents().fprint_hex(stdout); fputc('\n', stdout); dbuf.reset();
    cbor::uint64{0x100000000}.write(dbuf);
    contents = dbuf.contents(); printf("encoded/decoded: %zu\n", cbor::uint64{contents}.value());
    dbuf.contents().fprint_hex(stdout); fputc('\n', stdout); dbuf.reset();

    std::array<uint8_t, 8> bytes{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    datum bytes_data{bytes};
    bytes_data.fprint_hex(stdout); fputc('\n', stdout);
    cbor::byte_string::construct(bytes_data).write(dbuf);
    contents = dbuf.contents(); printf("encoded/decoded: ");
    cbor::byte_string::decode(contents).value().fprint_hex(stdout); fputc('\n', stdout);
    dbuf.contents().fprint_hex(stdout); fputc('\n', stdout); dbuf.reset();

    std::array<uint8_t, 13> text{'H', 'e', 'l', 'l', 'o', ',', ' ', 'w', 'o', 'r', 'l', 'd', '!'};
    datum text_data{text};
    text_data.fprint_hex(stdout); fputc('\n', stdout);
    cbor::text_string::construct(text_data).write(dbuf);
    contents = dbuf.contents(); printf("encoded/decoded: ");
    cbor::text_string::decode(contents).value().fprint(stdout); fputc('\n', stdout);
    dbuf.contents().fprint_hex(stdout); fputc('\n', stdout); dbuf.reset();

    // encode array
    //
    dbuf.reset();
    cbor::output::array a{dbuf};
    cbor::text_string::construct(text_data).write(a);
    cbor::byte_string::construct(bytes_data).write(a);
    a.close();

    // read array
    //
    contents = dbuf.contents();
    cbor::array aa{contents};
    printf("[\n");
    while (aa.value().is_not_empty()) {
        cbor::element v = cbor::decode(aa.value());
        if (std::holds_alternative<std::monostate>(v)) {
            break;
        }
        printf("type: %u\n", major_type(v));
        // cbor::text_string ts{aa.value()};
        // ts.value().fprint(stdout); fputc('\n', stdout);
    }
    printf("]\n");

    // datum contents =  dbuf.contents();
    // if (contents.is_not_null()) {
    //     contents.fprint_hex(stdout); fputc('\n', stdout);
    // } else {
    //     fprintf(stdout, "error: contents is null\n");
    // }

    const char *tls_fp = "(0303)(130213031301c030c02fc02ccca9cca8c0adc02bc0acc024c028c023c027c009c013009dc09d009cc09c003d003c0035002f000700ff)[(000a000c000a001d0017001e00190018)(000b000403000102)(000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602)(0010000b000908687474702f312e31)(0015)(0016)(0017)(002b0009080304030303020301)(002d00020101)(0031)(0033)(3374)]";
    datum tls_fp_data{(uint8_t *)tls_fp, (uint8_t *)tls_fp + strlen(tls_fp)};

    printf("cbor_fingerprint::write_tls_fingerprint: ");
    cbor_fingerprint::write_tls_fingerprint(tls_fp_data);

    tls_fp_data = {(uint8_t *)tls_fp, (uint8_t *)tls_fp + strlen(tls_fp)};
    dbuf.reset();
    cbor_fingerprint::write_cbor_tls_fingerprint(tls_fp_data, dbuf); fputc('\n', stdout);
    printf("cbor_fingerprint::write_cbor_tls_fingerprint:\n");
    dbuf.contents().fprint_hex(stdout); fputc('\n', stdout);

    printf("cbor_fingerprint::fprint:\n");
    contents = dbuf.contents();
    cbor_fingerprint::fprint(stdout, contents); fputc('\n', stdout);

    printf("input:\n%s\n", tls_fp);

    // example fingerprint and destination context (fdc) encoding
    //
    dbuf.reset();
    cbor::output::array fdc{dbuf};
    tls_fp_data = {(uint8_t *)tls_fp, (uint8_t *)tls_fp + strlen(tls_fp)};
    cbor_fingerprint::write_cbor_tls_fingerprint(tls_fp_data, fdc);
    cbor::text_string{"parked-content.godaddy.com"}.write(a);
    a.close();
    printf("fdc:\n"); dbuf.contents().fprint_hex(stdout); fputc('\n', stdout);

    // example cbor::output::map encoding and cbor::map decoding
    //

    constexpr cbor::dictionary dict = std::array<const char *, 5>{{
            "order",
            "family",
            "genus",
            "species",
            "common_name"
        }
    };

    data_buffer<1024> outbuf;
    cbor::output::map map{outbuf};
    map.encode(cbor::uint64{dict.get_uint("genus")}, cbor::text_string{"thryothorus"});
    map.encode(cbor::uint64{dict.get_uint("species")}, cbor::text_string{"ludovicianus"});
    map.encode(cbor::uint64{dict.get_uint("common_name")}, cbor::text_string{"Carolina wren"});
    //
    // map.write(cbor::uint64{dict.get_uint("BOGUS")}, cbor::text_string{"bogus entry"});  // error! BOGUS is not in dictionary
    //
    map.close();
    outbuf.contents().fprint_hex(stdout); fputc('\n', stdout);

    datum map_data{outbuf.contents()};
    cbor::map decoded_map{map_data};
    while (decoded_map.value().is_readable()) {
        cbor::uint64 key{decoded_map.value()};
        cbor::text_string value = cbor::text_string::decode(decoded_map.value());
        if (decoded_map.value().is_null()) {
            break;                             // error decoding key and/or value
        }
        // printf("key: %zu\tvalue: \"%.*s\"\n", key.value(), (int)value.value().length(), value.value().data);
        printf("key: \"%s\"\tvalue: \"%.*s\"\n", dict.get_string(key.value()), (int)value.value().length(), value.value().data);
        if (decoded_map.value().is_empty()) {
            break;                             // no more elements
        }
    }

    // map.write(cbor::uint64{dict.get_uint("genus")}, cbor::text_string{"anas"});
    // map.write(cbor::uint64{dict.get_uint("species")}, cbor::text_string{"platyrhynchos"});
    // map.write(cbor::uint64{dict.get_uint("common_name")}, cbor::text_string{"Mallard"});

    return 0;
}
