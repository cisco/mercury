// fdc.hpp
//
// fingerprint and destination context encoding and decoding

#ifndef FDC_HPP
#define FDC_HPP

#include "static_dict.hpp"
#include "result.h"
#include "cbor.hpp"
#include "fingerprint.h"  // for fingerprint_type

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
namespace cbor_fingerprint {

    constexpr static_dictionary<3> fp_labels{
        {
            "unknown",
            "randomized",
            "generic"
        }
    };

    inline void fprint(FILE *f, datum &d) {
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

    inline void encode_cbor_data(datum &d, writeable &w) {
        literal_byte<'('>{d};
        if (lookahead<literal_byte<')'>> close{d}) {
            cbor::byte_string::write_empty(w);
            d = close.advance();
        } else {
            cbor::byte_string_from_hex{hex_digits{d}}.write(w);
            literal_byte<')'>{d};
        }
    }

    inline void encode_cbor_list(datum &d, writeable &w) {
        literal_byte<'('>{d};
        cbor::output::array a{w};
        while(lookahead<encoded<uint8_t>> c{d}) {
            if (c.value == ')') {
                break;
            }
            encode_cbor_data(d, a);
        }
        a.close();
         literal_byte<')'>{d};
    }

    constexpr uint64_t tag_sorted_array = 251;  // tag number in "specification required" range

    enum array_type {
        sorted = true,
        unsorted = false
    };

    inline void encode_cbor_sorted_list(datum &d, writeable &w, array_type sorted=array_type::sorted) {
        if (sorted) {
            literal_byte<'['>{d};
        } else {
            literal_byte<'('>{d};
        }
        if (sorted) {
            cbor::tag{tag_sorted_array}.write(w);
        }
        cbor::output::array a{w};
        while(lookahead<encoded<uint8_t>> c{d}) {
            if (c.value == '[') {
                encode_cbor_sorted_list(d, w, array_type::sorted);

            } else if (c.value == ']' or c.value == ')') {
                break;

            } else if (c.value == '(') {
                if (lookahead<encoded<uint8_t>> nextchar{c}) {
                    if (nextchar.value == '(' or nextchar.value == '[') {
                        encode_cbor_sorted_list(d, w, array_type::unsorted);
                    } else {
                        encode_cbor_data(d, a);
                    }
                }
            } else {
                break;
            }
        }
        a.close();
        if (sorted) {
            literal_byte<']'>{d};
        } else {
            literal_byte<')'>{d};
        }
    }

    inline void encode_cbor_tls_fingerprint(datum d, writeable &w) {
        cbor::output::map m{w};

        if (lookahead<literal_byte<'r', 'a', 'n', 'd', 'o', 'm', 'i', 'z', 'e', 'd'>> peek{d}) {
            cbor::uint64{0}.write(m);      // fingerprint version
            constexpr size_t idx = fp_labels.index("randomized");
            cbor::uint64{idx}.write(m);

        } else if (lookahead<literal_byte<'('>>{d}) {
            cbor::uint64{0}.write(m);      // fingerprint version
            cbor::output::array a{m};
            encode_cbor_data(d, a);         // version
            encode_cbor_data(d, a);         // ciphersuites
            encode_cbor_list(d, a);         // extensions
            a.close();

        } else if (lookahead<literal_byte<'1', '/'>> version_one{d}) {
            d = version_one.advance();
            cbor::uint64{1}.write(w);      // fingerprint version

            if (lookahead<literal_byte<'r', 'a', 'n', 'd', 'o', 'm', 'i', 'z', 'e', 'd'>> peek{d}) {
                constexpr size_t idx = fp_labels.index("randomized");
                cbor::uint64{idx}.write(m);
            } else {
                cbor::output::array a{w};
                encode_cbor_data(d, a);         // version
                encode_cbor_data(d, a);         // ciphersuites
                encode_cbor_sorted_list(d, a);  // extensions
                a.close();
            }

        }
        m.close();
     }

    inline void encode_cbor_http_fingerprint(datum d, writeable &w) {
        cbor::output::map m{w};
        if (lookahead<literal_byte<'('>>{d}) {
            cbor::uint64{0}.write(m);      // fingerprint version
            cbor::output::array a{m};
            encode_cbor_data(d, a);         // method
            encode_cbor_data(d, a);         // protocol
            encode_cbor_list(d, a);         // headers
            a.close();

        } else if (lookahead<literal_byte<'r', 'a', 'n', 'd', 'o', 'm', 'i', 'z', 'e', 'd'>>{d}) {
            cbor::uint64{0}.write(m);      // fingerprint version
            constexpr size_t idx = fp_labels.index("randomized");
            cbor::uint64{idx}.write(m);
        }
        m.close();
    }

    inline void encode_cbor_quic_fingerprint(datum d, writeable &w) {
        cbor::output::map m{w};
        if (lookahead<literal_byte<'('>>{d}) {
            cbor::uint64{0}.write(m);      // fingerprint version
            cbor::output::array a{m};
            encode_cbor_data(d, a);         // quic version
            encode_cbor_data(d, a);         // version
            encode_cbor_data(d, a);         // ciphersuites
            encode_cbor_sorted_list(d, a);  // extensions
            a.close();

        } else if (lookahead<literal_byte<'r', 'a', 'n', 'd', 'o', 'm', 'i', 'z', 'e', 'd'>>{d}) {
            cbor::uint64{0}.write(m);      // fingerprint version
            constexpr size_t idx = fp_labels.index("randomized");
            cbor::uint64{idx}.write(m);
        }
        m.close();
    }

    inline void encode_cbor_stun_fingerprint(datum d, writeable &w) {
        cbor::output::map m{w};

        if (lookahead<literal_byte<'1', '/'>> version_one{d}) {
            d = version_one.advance();
            cbor::uint64{1}.write(w);      // fingerprint version

            if (lookahead<literal_byte<'r', 'a', 'n', 'd', 'o', 'm', 'i', 'z', 'e', 'd'>> peek{d}) {
                constexpr size_t idx = fp_labels.index("randomized");
                cbor::uint64{idx}.write(m);
            } else {
                cbor::output::array a{w};
                encode_cbor_data(d, a);         // class
                encode_cbor_data(d, a);         // method
                encode_cbor_data(d, a);         // magic
                encode_cbor_list(d, a);         // attributes
                a.close();
            }

        }
        m.close();
     }

    inline void encode_cbor_ssh_fingerprint(datum d, writeable &w) {
        cbor::output::map m{w};

        cbor::uint64{0}.write(w);      // fingerprint version

        if (lookahead<literal_byte<'r', 'a', 'n', 'd', 'o', 'm', 'i', 'z', 'e', 'd'>> peek{d}) {
            constexpr size_t idx = fp_labels.index("randomized");
            cbor::uint64{idx}.write(m);
        } else {
            cbor::output::array a{w};
            encode_cbor_data(d, a);         // kex_algorithms
            encode_cbor_data(d, a);         // server_host_key_algorithms
            encode_cbor_data(d, a);         // encryption_algorithms_client_to_server
            encode_cbor_data(d, a);         // encryption_algorithms_server_to_client
            encode_cbor_data(d, a);         // mac_algorithms_client_to_server
            encode_cbor_data(d, a);         // mac_algorithms_server_to_client
            encode_cbor_data(d, a);         // compression_algorithms_client_to_server
            encode_cbor_data(d, a);         // compression_algorithms_server_to_client
            encode_cbor_data(d, a);         // languages_client_to_server
            encode_cbor_data(d, a);         // languages_server_to_client
            a.close();
        }

        m.close();
     }

    constexpr uint64_t randomized = 0;
    constexpr uint64_t generic = 1;

    constexpr std::array<const char *, 3> fingerprint_labels = {
        "unknown",
        "randomized",
        "generic"
    };

    template <size_t N>
    size_t constexpr get_index(const std::array<const char *, N> &a, const char *s) {
        for (const auto & x : a) {
            if (strcmp(x, s) == 0) {
                return std::distance(&x, a.begin());
            }
        }
        return 0;
    }

    inline void encode_cbor_tofsee_fingerprint(datum d, writeable &w) {
        cbor::output::map m{w};
        if (lookahead<literal_byte<'1', '/'>> version_one{d}) {
            d = version_one.advance();
            cbor::uint64{1}.write(m);      // fingerprint version
            if (lookahead<literal_byte<'g', 'e', 'n', 'e', 'r', 'i', 'c'>> peek{d}) {
                constexpr size_t idx = fp_labels.index("generic");
                cbor::uint64{idx}.write(m);
            }
        }
    }

    inline void encode_cbor_fingerprint(datum d, writeable &w) {
        fingerprint_type fp_type = fingerprint_type_unknown;
        if (lookahead<literal_byte<'t', 'l', 's', '/'>> tls{d}) {
            fp_type = fingerprint_type_tls;
            cbor::output::map m{w};
            cbor::uint64{(uint64_t)fp_type}.write(w);
            d = tls.advance();
            encode_cbor_tls_fingerprint(d, m);
            m.close();

        } else if (lookahead<literal_byte<'h', 't', 't', 'p', '/'>> http{d}) {
            fp_type = fingerprint_type_http;
            cbor::output::map m{w};
            cbor::uint64{(uint64_t)fp_type}.write(w);
            d = http.advance();
            encode_cbor_http_fingerprint(d, w);
            m.close();

        } else if (lookahead<literal_byte<'q', 'u', 'i', 'c', '/'>> quic{d}) {
            fp_type = fingerprint_type_quic;
            cbor::output::map m{w};
            cbor::uint64{(uint64_t)fp_type}.write(w);
            d = quic.advance();
            encode_cbor_quic_fingerprint(d, w);
            m.close();

        } else if (lookahead<literal_byte<'t', 'o', 'f', 's', 'e', 'e', '/'>> tofsee{d}) {
            fp_type = fingerprint_type_tofsee;
            cbor::output::map m{w};
            cbor::uint64{(uint64_t)fp_type}.write(w);
            d = tofsee.advance();
            encode_cbor_tofsee_fingerprint(d, w);
            m.close();

        } else if (lookahead<literal_byte<'s', 't', 'u', 'n', '/'>> stun{d}) {
            fp_type = fingerprint_type_stun;
            cbor::output::map m{w};
            cbor::uint64{(uint64_t)fp_type}.write(w);
            d = stun.advance();
            encode_cbor_stun_fingerprint(d, w);
            m.close();

        } else if (lookahead<literal_byte<'s', 's', 'h', '/'>> ssh{d}) {
            fp_type = fingerprint_type_ssh;
            cbor::output::map m{w};
            cbor::uint64{(uint64_t)fp_type}.write(w);
            d = ssh.advance();
            encode_cbor_ssh_fingerprint(d, w);
            m.close();

        }
        // fprintf(stderr, "fingerprint type %d\n", fp_type);
    }

    inline void decode_cbor_data(datum &d, writeable &w) {
        cbor::byte_string data = cbor::byte_string::decode(d);
        w.copy('(');
        w.write_hex(data.value().data, data.value().length());
        w.copy(')');
    }

    inline void decode_cbor_list(datum &d, writeable &w) {
        cbor::array a{d};
        w.copy('(');
        while (a.value().is_not_empty()) {
            if (lookahead<cbor::initial_byte> ib{a.value()}) {
                if (ib.value.is_break()) {
                    break;
                }
            }
            decode_cbor_data(a.value(), w);
        }
        w.copy(')');
        a.close();
    }

    inline void decode_cbor_sorted_list(datum &d, writeable &w) {
        char open = '(';
        char close = ')';
        if (lookahead<cbor::tag> tag{d}) {
            if (tag.value.value() == tag_sorted_array) {
                d = tag.advance();
                open = '[';
                close = ']';
            }
        }
        cbor::array a{d};
        w.copy(open);
        while (a.value().is_not_empty()) {
            if (lookahead<cbor::initial_byte> ib{a.value()}) {
                if (ib.value.is_break()) {
                    break;
                } else if (ib.value.major_type() == cbor::array_type
                           or ib.value.major_type() == cbor::tagged_item_type) {
                    decode_cbor_sorted_list(a.value(), w);
                } else {
                    decode_cbor_data(a.value(), w);
                }
            }
        }
        w.copy(close);
        d = a.value();  // TODO: replace this
        cbor::initial_byte{d};
    }

    inline void decode_http_fp(datum &d, writeable &w) {
        cbor::map m{d};
        cbor::uint64 format_version{m.value()};
        if (format_version.value() == 0) {
            if (lookahead<cbor::uint64> label{m.value()}) {
                if (label.value.value() == fp_labels.index("randomized")) {
                    w << datum{"randomized"};
                }
            } else {
                cbor::array a{m.value()};
                decode_cbor_data(m.value(), w); // method
                decode_cbor_data(m.value(), w); // protocol
                decode_cbor_list(m.value(), w); // headers
                a.close();
            }
        }
        m.close();
    }

    inline void decode_tls_fp(datum &d, writeable &w) {
        cbor::map m{d};
        cbor::uint64 format_version{m.value()};
        if (format_version.value() == 0) {
            cbor::array a{m.value()};
            decode_cbor_data(m.value(), w); // version
            decode_cbor_data(m.value(), w); // ciphersuites
            decode_cbor_list(m.value(), w); // extensions
            a.close();

        } else if (format_version.value() == 1) {
            w.copy('1');
            w.copy('/');
            if (lookahead<cbor::uint64> label{m.value()}) {
                if (label.value.value() == fp_labels.index("randomized")) {
                    w << datum{"randomized"};
                }
            } else {
                cbor::array a{m.value()};
                decode_cbor_data(m.value(), w);         // version
                decode_cbor_data(m.value(), w);         // ciphersuites
                decode_cbor_sorted_list(m.value(), w);  // extensions
                a.close();
            }
        }
        m.close();
    }

    inline void decode_quic_fp(datum &d, writeable &w) {
        cbor::map m{d};
        cbor::uint64 format_version{m.value()};
        if (format_version.value() == 0) {
            if (lookahead<cbor::uint64> label{m.value()}) {
                if (label.value.value() == fp_labels.index("randomized")) {
                    w << datum{"randomized"};
                }
            } else {
                cbor::array a{m.value()};
                decode_cbor_data(m.value(), w);        // quic version
                decode_cbor_data(m.value(), w);        // version
                decode_cbor_data(m.value(), w);        // ciphersuites
                decode_cbor_sorted_list(m.value(), w); // extensions
                a.close();
            }
        }
        m.close();
    }

    inline void decode_tofsee_fp(datum &d, writeable &w) {
        cbor::map m{d};
        cbor::uint64 format_version{m.value()};
        if (format_version.value() == 1) {
            w.copy('1');
            w.copy('/');
            if (cbor::uint64{m.value()}.value() == fp_labels.index("generic")) {
                w << datum{"generic"};
            }
        }
        m.close();
    }

    inline void decode_stun_fp(datum &d, writeable &w) {
        cbor::map m{d};
        cbor::uint64 format_version{m.value()};
        if (format_version.value() == 1) {
            w.copy('1');
            w.copy('/');
            if (lookahead<cbor::uint64> label{m.value()}) {
                if (label.value.value() == fp_labels.index("randomized")) {
                    w << datum{"randomized"};
                }
            } else {
                cbor::array a{m.value()};
                decode_cbor_data(m.value(), w);         // class
                decode_cbor_data(m.value(), w);         // method
                decode_cbor_data(m.value(), w);         // magic
                decode_cbor_list(m.value(), w);         // attributes
                a.close();
            }
        }
        m.close();
    }

    inline void decode_ssh_fp(datum &d, writeable &w) {
        cbor::map m{d};
        cbor::uint64 format_version{m.value()};
        if (format_version.value() == 0) {
            if (lookahead<cbor::uint64> label{m.value()}) {
                if (label.value.value() == fp_labels.index("randomized")) {
                    w << datum{"randomized"};
                }
            } else {
                cbor::array a{m.value()};
                decode_cbor_data(m.value(), w);   // kex_algorithms
                decode_cbor_data(m.value(), w);   // server_host_key_algorithms
                decode_cbor_data(m.value(), w);   // encryption_algorithms_client_to_server
                decode_cbor_data(m.value(), w);   // encryption_algorithms_server_to_client
                decode_cbor_data(m.value(), w);   // mac_algorithms_client_to_server
                decode_cbor_data(m.value(), w);   // mac_algorithms_server_to_client
                decode_cbor_data(m.value(), w);   // compression_algorithms_client_to_server
                decode_cbor_data(m.value(), w);   // compression_algorithms_server_to_client
                decode_cbor_data(m.value(), w);   // languages_client_to_server
                decode_cbor_data(m.value(), w);   // languages_server_to_client
                a.close();
            }
        }
        m.close();
    }

    inline void decode_fp(unsigned int fp_type,
                   datum &d,
                   writeable &w) {

        w << datum{fingerprint::get_type_name((fingerprint_type)fp_type)};
        w.copy('/');
        switch(fp_type) {
        case fingerprint_type_http:
            decode_http_fp(d, w);
            break;
        case fingerprint_type_tls:
            decode_tls_fp(d, w);
            break;
        case fingerprint_type_quic:
            decode_quic_fp(d, w);
            break;
        case fingerprint_type_tofsee:
            decode_tofsee_fp(d, w);
            break;
        case fingerprint_type_stun:
            decode_stun_fp(d, w);
            break;
        case fingerprint_type_ssh:
            decode_ssh_fp(d, w);
            break;
        default:
            ;
        }

    }

    inline void decode_cbor_fingerprint(datum &d, writeable &w) {

        cbor::map m{d};
        if (m.value().is_readable()) {
            cbor::uint64 fp_type{m.value()};
            // fprintf(stderr, "decoded fingerprint type %zu\n", fp_type.value());
            decode_fp(fp_type.value(), m.value(), w);
            if (m.value().is_null()) {
                ; // error
            }
        }
        m.close();
    }

    // test cbor fingerprint encoding and decoding
    //
    static bool test_fingerprint(const char *fingerprint_string, FILE *f=nullptr) {
        data_buffer<2048> data_buf;
        datum fp_data{(uint8_t *)fingerprint_string, (uint8_t *)fingerprint_string + strlen(fingerprint_string)};
        cbor_fingerprint::encode_cbor_fingerprint(fp_data, data_buf);

        data_buffer<2048> out_buf;
        datum encoded_data{data_buf.contents()};
        cbor_fingerprint::decode_cbor_fingerprint(encoded_data, out_buf);

        if (out_buf.contents().cmp(fp_data) != 0) {
            if (f) {
                fprintf(f, "ERROR: MISMATCH\n");
                fprintf(f, "fingerprint:              %s\n", fingerprint_string);
                fprintf(f, "CBOR encoded fingerprint: ");
                data_buf.contents().fprint_hex(f); fputc('\n', f);
                fprintf(f, "decoded fingerprint:      ");
                out_buf.contents().fprint(f); fputc('\n', f);
                cbor::decode_fprint(data_buf.contents(), f);
            }
            return false;
        }
        return true;
    };

    // cbor_fingerprint::unit_test() returns `true` if all unit tests
    // pass, `false` otherwise
    //
    [[maybe_unused]] static bool unit_test(FILE *f=nullptr) {

        // example fingerprints
        //
        std::vector<const char *> fps = {
            "http/(504f5354)(485454502f312e31)((486f7374)(557365722d4167656e74)(4163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c696d6167652f617669662c696d6167652f776562702c2a2f2a3b713d302e38)(4163636570742d4c616e6775616765)(4163636570742d456e636f64696e673a20677a69702c206465666c617465)(436f6e6e656374696f6e3a206b6565702d616c697665))",
            "tls/1/(0303)(130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035)[(0000)(000500050100000000)(000a00080006001d00170018)(000b00020100)(000d0012001004030804040105030805050108060601)(0010000e000c02683208687474702f312e31)(0012)(0017)(001b0003020002)(0023)(0029)(002b0009080304030303020301)(002d00020101)(0033)(ff01)]",
            "tls/(0303)(0a0a130113021303c02cc02bcca9c030c02fcca8c00ac009c014c013009d009c0035002f)((0a0a)(0000)(0017)(ff01)(000a000c000a0a0a001d001700180019)(000b00020100)(0010000e000c02683208687474702f312e31)(000500050100000000)(000d0018001604030804040105030203080508050501080606010201)(0012)(0033)(002d00020101)(002b0007060a0a03040303)(001b0003020001)(0a0a)(0015))",
            "quic/(00000001)(0303)(130113021303)[(000a000a00086399001d00170018)(002b0003020304)((0039)[(01)(03)(04)(05)(06)(07)(08)(09)(0f)(1b)(20)(80004752)(80ff73db)])(4469)]",
            "http/randomized",
            "tls/1/randomized",
            "quic/randomized",
            "stun/1/randomized",
            "stun/1/(00)(0001)(01)((8022)(0006)(0020)(0008)(8028))",
            "ssh/(656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f757031342d736861312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d736861312c6469666669652d68656c6c6d616e2d67726f7570312d73686131)(7373682d7273612c7373682d6473732c65636473612d736861322d6e697374703235362c65636473612d736861322d6e697374703338342c65636473612d736861322d6e69737470353231)(6165733132382d6374722c6165733132382d6362632c336465732d6374722c336465732d6362632c626c6f77666973682d6362632c6165733139322d6374722c6165733139322d6362632c6165733235362d6374722c6165733235362d636263)(6165733132382d6374722c6165733132382d6362632c336465732d6374722c336465732d6362632c626c6f77666973682d6362632c6165733139322d6374722c6165733139322d6362632c6165733235362d6374722c6165733235362d636263)(686d61632d6d64352c686d61632d736861312c686d61632d736861322d3235362c686d61632d736861312d39362c686d61632d6d64352d3936)(686d61632d6d64352c686d61632d736861312c686d61632d736861322d3235362c686d61632d736861312d39362c686d61632d6d64352d3936)(6e6f6e65)(6e6f6e65)()()"
        };
        bool all_tests_passed = true;
        for (const auto & fp_str : fps) {
            all_tests_passed &= test_fingerprint(fp_str, f);
        }
        return all_tests_passed;
    }
};

// define types of reassembly or truncation possible in the FDC object.
// Currently has "none", reassembled, "truncated", and "reassembled_truncated"
// With L7 support, there may be a need to specify the truncated elements like "tls_cert"
enum class truncation_status : uint64_t {
    none = 0,
    reassembled = 1,
    truncated = 2,
    reassembled_truncated = 3,
    unknown = 4,
    max = 5
};

static const char* const trunc_str[(uint64_t)truncation_status::max] = {
    "none",
    "reassembled",
    "truncated",
    "reassembled_truncated",
    "unknown"
};

static const char* get_truncation_str(truncation_status status) {
    if ((uint64_t)status < (uint64_t)truncation_status::max) {
        return trunc_str[(uint64_t)status];
    }
    return "unknown";
}

/// represents a fingerprint and destination context
///
class fdc {
    datum fingerprint;
    cbor::text_string user_agent;
    cbor::text_string domain_name;
    cbor::text_string dst_ip_str;
    cbor::uint64 dst_port;
    cbor::uint64 truncation;
    bool valid;

public:

    static constexpr uint64_t fdc_version_one = 1;

    fdc(datum fp,
        const char *ua,
        const char *name,
        const char *d_ip,
        uint16_t d_port,
        truncation_status status) :
        fingerprint{fp},
        user_agent{ua},
        domain_name{name},
        dst_ip_str{d_ip},
        dst_port{d_port},
        truncation{(uint64_t)status},
        valid{
            fingerprint.is_not_null()
            and domain_name.is_valid()
            and dst_ip_str.is_valid()
        }
    { }

    bool is_valid() const { return valid; }

    bool encode(writeable &w) const {
        if (not valid) {
            w.set_null();
            return false;
        }
        cbor::output::map m{w};
        cbor::uint64{fdc_version_one}.write(m);
        cbor::output::array a{m};
        cbor_fingerprint::encode_cbor_fingerprint(fingerprint, a);
        domain_name.write(a);
        dst_ip_str.write(a);
        dst_port.write(a);
        user_agent.write(a);
        truncation.write(a);
        a.close();
        m.close();
        return !w.is_null();
    }

    /// decode an fdc object from \ref datum \param d
    ///
    static bool decode(datum &d,
                       writeable &&fp,
                       writeable &&sn_str,
                       writeable &&dst_ip_str,
                       uint16_t &dst_port,
                       writeable &&ua_str,
                       uint64_t &truncation )
    {
        cbor::map m{d};
        cbor::uint64 fdc_version{d};
        if (!d.is_readable() or fdc_version.value() != fdc_version_one) {
            return false;
        }
        cbor::array a{d};
        cbor_fingerprint::decode_cbor_fingerprint(a, fp);
        fp.copy('\0');
        sn_str << cbor::text_string::decode(a).value() << '\0';
        dst_ip_str << cbor::text_string::decode(a).value() << '\0';
        dst_port = cbor::uint64::decode_max(a, 0xffff).value();
        ua_str << cbor::text_string::decode(a).value() << '\0';

        // truncation is an optional field at the array's end, so we check if it exists
        if (d.is_not_empty() && (lookahead<encoded<uint8_t>>{d}).value != 0xff) {
            truncation = cbor::uint64::decode_max(a, (uint64_t)truncation_status::max).value();
        } else {
            truncation = (uint64_t)truncation_status::unknown;
        }
        a.close();
        m.close();

        return d.is_not_null()
            and !fp.is_null()
            and !ua_str.is_null()
            and !sn_str.is_null()
            and !dst_ip_str.is_null();
    }

    static void decode_version_one(datum &d, struct json_object &record) {
        static const size_t MAX_FP_STR_LEN     = 4096;
        char fp_str[MAX_FP_STR_LEN];
        char dst_ip_str[MAX_ADDR_STR_LEN];
        char sn_str[MAX_SNI_LEN];
        char ua_str[MAX_USER_AGENT_LEN];
        uint16_t dst_port;
        uint64_t truncation;

        bool ok = fdc::decode(d,
                            writeable{(uint8_t*)fp_str, MAX_FP_STR_LEN},
                            writeable{(uint8_t*)sn_str, MAX_SNI_LEN},
                            writeable{(uint8_t*)dst_ip_str, MAX_ADDR_STR_LEN},
                            dst_port,
                            writeable{(uint8_t*)ua_str, MAX_USER_AGENT_LEN},
                            truncation);
        if (ok) {
            json_object fdc_json(record,"fdc");
            fdc_json.print_key_string("fingerprint",fp_str);
            fdc_json.print_key_string("sni",sn_str);
            fdc_json.print_key_string("dst_ip_str",dst_ip_str);
            fdc_json.print_key_int("dst_port",dst_port);
            fdc_json.print_key_string("user_agent",ua_str);
            fdc_json.print_key_string("truncation",get_truncation_str(((truncation_status)truncation)));
            fdc_json.close();
        }
    }

    static void decode_version_two(datum &d, struct json_object &record) {
        decode_version_one(d, record);
    }

    /// perform unit tests on class fdc, returning `true` if they pass
    /// and `false` otherwise
    ///
    static bool unit_test(FILE *f=nullptr) {

        (void)f; // silence warning about unused paramer

        // construct an fpc_object, then encode it into a writeable
        // buffer
        //
        const char *tls_fp = "tls/1/(0301)(c014c00a00390038c00fc0050035c012c00800160013c00dc003000ac013c00900330032c00ec004002fc011c007c00cc002000500040015001200090014001100080006000300ff)[(0000)(000a00340032000100020003000400050006000700080009000a000b000c000d000e000f0010001100120013001400150016001700180019)(000b000403000102)(0023)]";
        const char *http_fp = "http/(434f4e4e454354)(485454502f312e31)((486f7374)(557365722d4167656e74))";
        static constexpr size_t num_tests = 5;
        fdc fdc_object[num_tests]{
            {
                datum{tls_fp},
                nullptr,
                "npmjs.org",
                "104.16.30.34",
                443,
                truncation_status::none
            },
            {
                datum{http_fp},
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "clientservices.googleapis.com:443",
                "72.163.217.105",
                80,
                truncation_status::none
            },
            {
                datum{tls_fp},
                nullptr,
                "npmjs.org",
                "104.16.30.34",
                443,
                truncation_status::truncated
            },
            {
                datum{http_fp},
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "clientservices.googleapis.com:443",
                "72.163.217.105",
                80,
                truncation_status::reassembled_truncated
            },
            {
                datum{http_fp},
                "user-agent with utf8: stra\u00DFe \r\n\"",
                "abc.com",
                "72.163.217.105",
                80,
                truncation_status::reassembled_truncated
            },
        };
        for (size_t i = 0; i < num_tests; i++){

            dynamic_buffer output{1024};
            bool encoding_ok = fdc_object[i].encode(output);
            if (encoding_ok == false) {
                return false;
            }
            datum encoded_fdc{output.contents()};

            // decode the data in the buffer to decoded_fdc
            //
            char fp_str[fingerprint::MAX_FP_STR_LEN];
            char dst_ip_str[MAX_ADDR_STR_LEN];
            char sn_str[MAX_SNI_LEN];
            char ua_str[MAX_USER_AGENT_LEN];
            uint16_t dst_port;
            uint64_t truncation;

            bool decoding_ok = fdc::decode(encoded_fdc,
                                           writeable{(uint8_t*)fp_str, fingerprint::MAX_FP_STR_LEN},
                                           writeable{(uint8_t*)sn_str, MAX_SNI_LEN},
                                           writeable{(uint8_t*)dst_ip_str, MAX_ADDR_STR_LEN},
                                           dst_port,
                                           writeable{(uint8_t*)ua_str, MAX_USER_AGENT_LEN},
                                           truncation );
            if (decoding_ok == false) {
                return false;
            }
            fdc decoded_fdc(datum{fp_str},
                            ua_str,
                            sn_str,
                            dst_ip_str,
                            dst_port,
                            (truncation_status)truncation);

            // compare the decoded_fdc to the original one; the test
            // passes only if they are equal
            //
            if (decoded_fdc == fdc_object[i]) {
                ;
            }
            else {
                return false;
            }
        }
        return true;
    }

private:

    /// compare this \ref fdc object with another, returning `true` if
    /// they are equal, and `false` otherwise
    ///
    bool operator== (fdc &rhs) {
        return fingerprint.cmp(rhs.fingerprint) == 0
            and user_agent.value().cmp(rhs.user_agent.value()) == 0
            and domain_name.value().cmp(rhs.domain_name.value()) == 0
            and dst_ip_str.value().cmp(rhs.dst_ip_str.value()) == 0
            and dst_port.value() == rhs.dst_port.value();
    }

};

class eve_metadata {
public:
 
    static constexpr uint64_t eve_metadata_version = 2;
    static std::string decode_cbor_data(datum d) {
        datum data{d};
        cbor::map m{d};
        cbor::uint64 version{d};
        char buffer[8192];
        struct buffer_stream buf_json(buffer, sizeof(buffer));
        struct json_object record(&buf_json);

        switch(version.value()) {
            case 1:
                fdc::decode_version_one(data, record);
                record.close();
                break;
            case 2:
                decode_version_two(d, record);
                break;
            default:
                return "";
        }
        buf_json.write_char('\0');
        return buf_json.get_string();
    }

    static void decode_version_two(datum d, struct json_object &record) {
        bool is_fdc = false;
        datum buf_copy = d;
        datum buf_copy_key{cbor::text_string::decode(buf_copy).value()};

        if (buf_copy_key.equals(std::array<uint8_t, 3>{'f', 'd', 'c'})) {
            fdc::decode_version_two(buf_copy, record);
            is_fdc = true;
        }
        
        if (is_fdc) {
            d = buf_copy;
            record.comma = true;
        }

        json_buffer o{record};
        cbor::decode_map_and_write_json(d, o);
        record.close();
        return;
    }
};
[[maybe_unused]] inline std::string get_json_decoded_fdc(const char *fdc_blob, ssize_t blob_len) {
    datum fdc_data = datum{(uint8_t*)fdc_blob,(uint8_t*)(fdc_blob+blob_len)};
    return eve_metadata::decode_cbor_data(fdc_data);
}

[[maybe_unused]] static std::string get_json_decoded_fdc_dev(const char *fdc_blob, ssize_t blob_len) {
    datum fdc_data = datum{(uint8_t*)fdc_blob,(uint8_t*)(fdc_blob+blob_len)};
    char fp_str[fingerprint::MAX_FP_STR_LEN];
    char dst_ip_str[MAX_ADDR_STR_LEN];
    char sn_str[MAX_SNI_LEN];
    char ua_str[MAX_USER_AGENT_LEN];
    uint16_t dst_port;
    uint64_t truncation;

    char buffer[10240];
    struct buffer_stream buf_json(buffer, sizeof(buffer));
    struct json_object record(&buf_json);

    bool ok = fdc::decode(fdc_data,
                          writeable{(uint8_t*)fp_str, fingerprint::MAX_FP_STR_LEN},
                          writeable{(uint8_t*)sn_str, MAX_SNI_LEN},
                          writeable{(uint8_t*)dst_ip_str, MAX_ADDR_STR_LEN},
                          dst_port,
                          writeable{(uint8_t*)ua_str, MAX_USER_AGENT_LEN},
                          truncation);
    if (ok) {
        json_object fdc_json(record,"fdc");
        fdc_json.print_key_string("fingerprint", fp_str);
        fdc_json.print_key_json_string("sni", datum{sn_str});
        fdc_json.print_key_json_string("dst_ip_str", datum{dst_ip_str});
        fdc_json.print_key_int("dst_port", dst_port);
        fdc_json.print_key_json_string("user_agent", datum{ua_str});
        fdc_json.print_key_string("truncation", get_truncation_str(((truncation_status)truncation)));
        fdc_json.close();
        record.close();
        buf_json.write_char('\0');  // null terminate
        return buf_json.get_string();

    } else {
        return "";
    }
}



#endif // FDC_HPP
