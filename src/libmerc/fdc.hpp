// fdc.hpp
//
// fingerprint and destination context encoding and decoding

#ifndef FDC_HPP
#define FDC_HPP

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
        literal_byte<')'>{d};
    }

    static void write_cbor_list(datum &d, writeable &w) {
        literal_byte<'('>{d};
        cbor::output::array a{w};
        while(lookahead<encoded<uint8_t>> c{d}) {
            if (c.value == ')') {
                break;
            }
            write_cbor_data(d, a);
        }
        a.close();
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

    static void write_cbor_tls_fingerprint(datum d, writeable &w) {
        if (lookahead<literal_byte<'('>> version_zero{d}) {
            cbor::uint64{0}.write(w);      // fingerprint version
            cbor::output::array a{w};
            write_cbor_data(d, a);         // version
            write_cbor_data(d, a);         // ciphersuites
            write_cbor_list(d, a);         // extensions
            a.close();
        }
        if (lookahead<literal_byte<'1', '/'>> version_one{d}) {
            d  = version_one.advance();
            cbor::uint64{1}.write(w);      // fingerprint version
            cbor::output::array a{w};
            write_cbor_data(d, a);         // version
            write_cbor_data(d, a);         // ciphersuites
            write_cbor_sorted_list(d, a);  // extensions
            a.close();
        }
     }

    static void write_cbor_http_fingerprint(datum d, writeable &w) {
    }

    static void write_cbor_quic_fingerprint(datum d, writeable &w) {
    }

    static void write_cbor_tofsee_fingerprint(datum d, writeable &w) {
    }

    static void write_cbor_fingerprint(datum d, writeable &w) {
        fingerprint_type fp_type = fingerprint_type_unknown;
        if (lookahead<literal_byte<'t', 'l', 's', '/'>> tls{d}) {
            fp_type = fingerprint_type_tls;
            d = tls.advance();
            write_cbor_tls_fingerprint(d, w);

        } else if (lookahead<literal_byte<'h', 't', 't', 'p', '/'>> http{d}) {
            fp_type = fingerprint_type_http;
            d = http.advance();
            write_cbor_http_fingerprint(d, w);

        } else if (lookahead<literal_byte<'q', 'u', 'i', 'c', '/'>> quic{d}) {
            fp_type = fingerprint_type_quic;
            d = quic.advance();
            write_cbor_http_fingerprint(d, w);

        } else if (lookahead<literal_byte<'t', 'o', 'f', 's', 'e', 'e', '/'>> tofsee{d}) {
            fp_type = fingerprint_type_tofsee;
            d = tofsee.advance();
            write_cbor_tofsee_fingerprint(d, w);

        }
        fprintf(stderr, "fingerprint type %d\n", fp_type);
    }

    // cbor_fingerprint::unit_test() returns `true` if all unit tests
    // pass, `false` otherwise
    //
    static bool unit_test() {
        bool all_tests_passed = true;
        const char tls_fp[] = "tls/1/(0301)(0016002f000a000500ff)[(0000)(0023)]";
        datum tls_fp_data{(uint8_t *)tls_fp, (uint8_t *)tls_fp + strlen(tls_fp)};
        tls_fp_data.fprint(stdout); fputc('\n', stdout);
        data_buffer<1024> dbuf;
        write_cbor_fingerprint(tls_fp_data, dbuf);
        if (dbuf.is_null()) {
            all_tests_passed = false;
        }
        dbuf.contents().fprint_hex(stdout); fputc('\n', stdout);

        const char tls_fp0[] = "tls/(0301)(0016002f000a000500ff)((0000)(0023))";
        datum tls_fp0_data{(uint8_t *)tls_fp0, (uint8_t *)tls_fp0 + strlen(tls_fp0)};
        tls_fp0_data.fprint(stdout); fputc('\n', stdout);        dbuf.reset();
        write_cbor_fingerprint(tls_fp0_data, dbuf);
        if (dbuf.is_null()) {
            all_tests_passed = false;
        }
        dbuf.contents().fprint_hex(stdout); fputc('\n', stdout);

        return all_tests_passed;
    }

};

// note: this could be implemented as member functions of
// analysis_context and destination_context
//

class fdc {
    datum fingerprint;
    cbor::text_string user_agent;
    cbor::text_string domain_name;
    cbor::text_string dst_ip_str;
    cbor::uint64 dst_port;
    bool valid;

public:

    fdc(datum fp,
        const char *ua,
        const char *name,
        const char *d_ip,
        uint16_t d_port) :
        fingerprint{fp},
        user_agent{ua},
        domain_name{name},
        dst_ip_str{d_ip},
        dst_port{d_port},
        valid{
            fingerprint.is_not_null()
            and (user_agent.is_valid() xor domain_name.is_valid())
            and dst_ip_str.is_valid()
        }
    { }

    bool is_valid() const { return valid; }

    void encode(writeable &w) const {
        if (not valid) {
            w.set_null();
            return;
        }
        cbor::output::array a{w};
        cbor_fingerprint::write_cbor_tls_fingerprint(fingerprint, a);
        if (user_agent.is_valid()) {
            user_agent.write(a);
        }
        if (domain_name.is_valid()) {
            domain_name.write(a);
        }
        dst_ip_str.write(a);
        dst_port.write(a);
        a.close();
    }

};


#endif // FDC_HPP
