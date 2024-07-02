// cbor.cpp

#include <cstdio>
#include <vector>
#include <cctype>
#include <iostream>
#include <fstream>

#include "libmerc/cbor.hpp"
#include "libmerc/fdc.hpp"


int main(int, char *[]) {

    if constexpr (false) {
        data_buffer<256> db;
        cbor::tag{0}.write(db);
        cbor::tag{251}.write(db);
        cbor::output::array out_a{db};
        cbor::uint64{0x12345678}.write(out_a);
        out_a.close();
        db.contents().fprint_hex(stdout); fputc('\n', stdout);
        datum encoded{db.contents()};
        cbor::tag t1{encoded} ;
        cbor::tag t2{encoded} ;
        cbor::array a{encoded};
        cbor::uint64 x{a.value()};
        // printf("t: %zu\tx: %08zx\n", t.value(), x.value());
        printf("t1: %zu\tt2: %zu\n", t1.value(), t2.value());
        cbor::decode_fprint(db.contents(), stdout);

    }

    printf("static_dictionary::unit_test: %s\n", static_dictionary<0>::unit_test(stdout) ? "passed" : "failed");

    //
    // assert(cbor::unit_test() == true);
    //
    FILE *unit_test_output = stderr; // set to nullptr to suppress unit test output
    printf("cbor::unit_test: %s\n", cbor::unit_test(unit_test_output) ? "passed" : "failed");
    assert(cbor_fingerprint::unit_test() == true);

    dynamic_buffer output{1024};
    const char *fp = "tls/1/(0301)(c014c00a00390038c00fc0050035c012c00800160013c00dc003000ac013c00900330032c00ec004002fc011c007c00cc002000500040015001200090014001100080006000300ff)[(0000)(000a00340032000100020003000400050006000700080009000a000b000c000d000e000f0010001100120013001400150016001700180019)(000b000403000102)(0023)]";
    datum{fp}.fprint(stdout); fputc('\n', stdout);
    fdc fdc_object{
        datum{fp},
        nullptr,
        "npmjs.org",
        "104.16.30.34",
        hton<uint16_t>(443)
    };
    fdc_object.encode(output);
    output.contents().fprint_hex(stdout); fputc('\n', stdout);
    for (const auto & x : output.get_value()) {
        fprintf(stdout, "%02x", x);
    }
    fputc('\n', stdout);
    output.contents().fprint(stdout); fputc('\n', stdout);

    datum encoded_fdc{output.contents()};
    encoded_fdc.fprint(stdout); fputc('\n', stdout);
    // fdc decoded_fdc{encoded_fdc};
    // decoded_fdc.fprint(stdout);

    cbor::decode_fprint(encoded_fdc, stdout);

    std::array<uint8_t, 1024> decoded_fp;
    data_buffer<257> decoded_sn;
    data_buffer<512> decoded_ua;
    data_buffer<48> decoded_dst_ip;
    uint16_t dst_port;
    fdc::decode(encoded_fdc,
                decoded_fp,
                decoded_sn,
                decoded_ua,
                decoded_dst_ip,
                dst_port);

    // decoded_fp.contents().fprint(stdout); fputc('\n', stdout);
    fprintf(stdout, "%s\n", decoded_fp.data());
    decoded_sn.contents().fprint(stdout); fputc('\n', stdout);
    decoded_ua.contents().fprint(stdout); fputc('\n', stdout);
    decoded_dst_ip.contents().fprint(stdout); fputc('\n', stdout);
    fprintf(stdout, "%u\n", dst_port);

    //    return 0;
    
    // test cbor fingerprint encoding and decoding
    //
    const auto test_fingerprint = [](const char *fingerprint_string) {
        data_buffer<2048> data_buf;
        datum fp_data{(uint8_t *)fingerprint_string, (uint8_t *)fingerprint_string + strlen(fingerprint_string)};
        cbor_fingerprint::encode_cbor_fingerprint(fp_data, data_buf);

        data_buffer<2048> out_buf;
        datum encoded_data{data_buf.contents()};
        cbor_fingerprint::decode_cbor_fingerprint(encoded_data, out_buf);
        // cbor::decode_fprint(data_buf.contents(), stdout);
        if (out_buf.contents().cmp(fp_data) != 0) {
            printf("ERROR: MISMATCH\n");
            printf("fingerprint:              %s\n", fingerprint_string);
            printf("CBOR encoded fingerprint: ");
            data_buf.contents().fprint_hex(stdout); fputc('\n', stdout);
            printf("decoded fingerprint:      ");
            out_buf.contents().fprint(stdout); fputc('\n', stdout);
            cbor::decode_fprint(data_buf.contents(), stdout);
            return false;
        }
        return true;
    };

    // example fingerprints
    //
    std::vector<const char *> fps = {
        "http/(504f5354)(485454502f312e31)((486f7374)(557365722d4167656e74)(4163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c696d6167652f617669662c696d6167652f776562702c2a2f2a3b713d302e38)(4163636570742d4c616e6775616765)(4163636570742d456e636f64696e673a20677a69702c206465666c617465)(436f6e6e656374696f6e3a206b6565702d616c697665))",
        "tls/1/(0303)(130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035)[(0000)(000500050100000000)(000a00080006001d00170018)(000b00020100)(000d0012001004030804040105030805050108060601)(0010000e000c02683208687474702f312e31)(0012)(0017)(001b0003020002)(0023)(0029)(002b0009080304030303020301)(002d00020101)(0033)(ff01)]",
        "quic/(00000001)(0303)(130113021303)[(000a000a00086399001d00170018)(002b0003020304)((0039)[(01)(03)(04)(05)(06)(07)(08)(09)(0f)(1b)(20)(80004752)(80ff73db)])(4469)]",
        "http/randomized",
        "tls/1/randomized",
        "quic/randomized"
    };
    for (const auto & fp_str : fps) {
        test_fingerprint(fp_str);
    }

    std::ios::sync_with_stdio(false);  // for performance
    std::string line;
    printf("testing CBOR fingerprint encoding and decoding on <stdin>: ");
    size_t line_count = 0;
    size_t num_tests_passed = 0;
    while (std::getline(std::cin, line)) {
        if (line.length() == 0) {
            continue; // ignore empty line
        }
        num_tests_passed += test_fingerprint(line.c_str());
        ++line_count;
    }
    printf("%zu out of %zu tests passed\n", num_tests_passed, line_count);

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

    // for (const auto & e : fingerprint_examples) {
    //     for (const auto & ee : e) {
    //         printf("%02x, ", ee);
    //     }
    //     fputc('\n', stdout);

    //     datum d{e.data(), e.data() + e.size()};

    //     while (d.is_readable()) {
    //         cbor::element v = cbor::decode(d);
    //         if (std::holds_alternative<std::monostate>(v)) {
    //             break;
    //         }
    //         printf("type: %u\n", major_type(v));
    //     }
    // }

    // run generic decoder on fingerprint_examples
    //
    for (const auto & e : fingerprint_examples) {
        fprintf(stdout, "running decode_data() on ");
        for (const auto & ee : e) {
            printf("%02x, ", ee);
        }
        fputc('\n', stdout);

        datum d{e.data(), e.data() + e.size()};

        cbor::decode_fprint(d, stdout);
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
    // contents = dbuf.contents();
    // cbor::array aa{contents};
    // printf("[\n");
    // while (aa.value().is_not_empty()) {
    //     cbor::element v = cbor::decode(aa.value());
    //     if (std::holds_alternative<std::monostate>(v)) {
    //         break;
    //     }
    //     printf("type: %u\n", major_type(v));
    //     // cbor::text_string ts{aa.value()};
    //     // ts.value().fprint(stdout); fputc('\n', stdout);
    // }
    // printf("]\n");

    // datum contents =  dbuf.contents();
    // if (contents.is_not_null()) {
    //     contents.fprint_hex(stdout); fputc('\n', stdout);
    // } else {
    //     fprintf(stdout, "error: contents is null\n");
    // }

    const char *tls_fp = "(0303)(130213031301c030c02fc02ccca9cca8c0adc02bc0acc024c028c023c027c009c013009dc09d009cc09c003d003c0035002f000700ff)[(000a000c000a001d0017001e00190018)(000b000403000102)(000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602)(0010000b000908687474702f312e31)(0015)(0016)(0017)(002b0009080304030303020301)(002d00020101)(0031)(0033)(3374)]";
    datum tls_fp_data{(uint8_t *)tls_fp, (uint8_t *)tls_fp + strlen(tls_fp)};

    // printf("cbor_fingerprint::write_tls_fingerprint: ");
    // cbor_fingerprint::write_tls_fingerprint(tls_fp_data);

    tls_fp_data = {(uint8_t *)tls_fp, (uint8_t *)tls_fp + strlen(tls_fp)};
    dbuf.reset();
    cbor_fingerprint::encode_cbor_tls_fingerprint(tls_fp_data, dbuf); fputc('\n', stdout);
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
    cbor_fingerprint::encode_cbor_tls_fingerprint(tls_fp_data, fdc);
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
