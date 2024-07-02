// fdc.hpp
//
// fingerprint and destination context encoding and decoding

#ifndef FDC_HPP
#define FDC_HPP

#include "static_dict.hpp"
#include "libmerc.h"  // for fingerprint_type

static const char *fingerprint_type_string(fingerprint_type fp_type) {
    switch(fp_type) {
    case fingerprint_type_unknown:     return "unknown";
    case fingerprint_type_tls:         return "tls";
    case fingerprint_type_tls_server:  return "tls_server";
    case fingerprint_type_http:        return "http";
    case fingerprint_type_http_server: return "http_server";
    case fingerprint_type_ssh:         return "ssh";
    case fingerprint_type_ssh_kex:     return "ssh_kex";
    case fingerprint_type_tcp:         return "tcp";
    case fingerprint_type_dhcp:        return "dhcp";
    case fingerprint_type_smtp_server: return "smtp_server";
    case fingerprint_type_dtls:        return "dtls";
    case fingerprint_type_dtls_server: return "dtls_server";
    case fingerprint_type_quic:        return "quic";
    case fingerprint_type_tcp_server:  return "tcp_server";
    case fingerprint_type_openvpn:     return "openvpn";
    case fingerprint_type_tofsee:      return "tofsee";
    default:
        ;
    }
    return "unregistered fingerprint type";
}


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

    void fprint(FILE *f, datum &d) {
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

    void encode_cbor_data(datum &d, writeable &w) {
        literal_byte<'('>{d};
        cbor::byte_string_from_hex{hex_digits{d}}.write(w);
        literal_byte<')'>{d};
    }

    void encode_cbor_list(datum &d, writeable &w) {
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

    void encode_cbor_sorted_list(datum &d, writeable &w, array_type sorted=array_type::sorted) {
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

    void encode_cbor_tls_fingerprint(datum d, writeable &w) {
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

    void encode_cbor_http_fingerprint(datum d, writeable &w) {
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

    void encode_cbor_quic_fingerprint(datum d, writeable &w) {
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

    void encode_cbor_tofsee_fingerprint(datum d, writeable &w) {
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

    void encode_cbor_fingerprint(datum d, writeable &w) {
        fingerprint_type fp_type = fingerprint_type_unknown;
        if (lookahead<literal_byte<'t', 'l', 's', '/'>> tls{d}) {
            fp_type = fingerprint_type_tls;
            cbor::output::map m{w};
            cbor::uint64{fp_type}.write(w);
            d = tls.advance();
            encode_cbor_tls_fingerprint(d, m);
            m.close();

        } else if (lookahead<literal_byte<'h', 't', 't', 'p', '/'>> http{d}) {
            fp_type = fingerprint_type_http;
            cbor::output::map m{w};
            cbor::uint64{fp_type}.write(w);
            d = http.advance();
            encode_cbor_http_fingerprint(d, w);
            m.close();

        } else if (lookahead<literal_byte<'q', 'u', 'i', 'c', '/'>> quic{d}) {
            fp_type = fingerprint_type_quic;
            cbor::output::map m{w};
            cbor::uint64{fp_type}.write(w);
            d = quic.advance();
            encode_cbor_quic_fingerprint(d, w);
            m.close();

        } else if (lookahead<literal_byte<'t', 'o', 'f', 's', 'e', 'e', '/'>> tofsee{d}) {
            fp_type = fingerprint_type_tofsee;
            cbor::output::map m{w};
            cbor::uint64{fp_type}.write(w);
            d = tofsee.advance();
            encode_cbor_tofsee_fingerprint(d, w);
            m.close();

        }
        // fprintf(stderr, "fingerprint type %d\n", fp_type);
    }

    void decode_cbor_data(datum &d, writeable &w) {
        cbor::byte_string data = cbor::byte_string::decode(d);
        //        if (d.is_null()) { return; }
        w.copy('(');
        w.write_hex(data.value().data, data.value().length());
        w.copy(')');
    }

    void decode_cbor_list(datum &d, writeable &w) {
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
    }

    void decode_cbor_sorted_list(datum &d, writeable &w) {
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

    void decode_http_fp(datum &d, writeable &w) {
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

    void decode_tls_fp(datum &d, writeable &w) {
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

    void decode_quic_fp(datum &d, writeable &w) {
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

    void decode_tofsee_fp(datum &d, writeable &w) {
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

    void decode_fp(unsigned int fp_type,
                   datum &d,
                   writeable &w) {

        w << datum{fingerprint_type_string((fingerprint_type)fp_type)};
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
        default:
            ;
        }

    }

    void decode_cbor_fingerprint(datum &d, writeable &w) {

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

    // cbor_fingerprint::unit_test() returns `true` if all unit tests
    // pass, `false` otherwise
    //
    bool unit_test() {
        bool all_tests_passed = true;
        const char tls_fp[] = "tls/1/(0301)(0016002f000a000500ff)[(0000)(0023)]";
        datum tls_fp_data{(uint8_t *)tls_fp, (uint8_t *)tls_fp + strlen(tls_fp)};
        tls_fp_data.fprint(stdout); fputc('\n', stdout);
        data_buffer<1024> dbuf;
        encode_cbor_fingerprint(tls_fp_data, dbuf);
        if (dbuf.is_null()) {
            all_tests_passed = false;
        }
        dbuf.contents().fprint_hex(stdout); fputc('\n', stdout);

        const char tls_fp0[] = "tls/(0301)(0016002f000a000500ff)((0000)(0023))";
        datum tls_fp0_data{(uint8_t *)tls_fp0, (uint8_t *)tls_fp0 + strlen(tls_fp0)};
        tls_fp0_data.fprint(stdout); fputc('\n', stdout);        dbuf.reset();
        encode_cbor_fingerprint(tls_fp0_data, dbuf);
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

    /// decode an fdc object from \ref datum \param d
    ///
    fdc(datum &d) :
        fingerprint{d},
        user_agent{cbor::text_string::decode(d)},
        domain_name{cbor::text_string::decode(d)},
        dst_ip_str{cbor::text_string::decode(d)},
        dst_port{d},
        valid{d.is_not_null() and user_agent.is_valid() xor domain_name.is_valid()}
    { }

    /// decode an fdc object from \ref datum \param d
    ///
    static void decode(datum &d,
                       writeable &&fp,
                       writeable &ua_str, // [MAX_USER_AGENT_LEN],
                       writeable &sn_str, // [MAX_SNI_LEN],
                       writeable &dst_ip_str,
                       uint16_t &dst_port) {

        cbor::array a{d};
        printf("before:\n");
        cbor::decode_fprint(a.value(), stdout);
        cbor_fingerprint::decode_cbor_fingerprint(a.value(), fp);

        printf("after:\n");  a.value().fprint_hex(stdout); fputc('\n', stdout);
        cbor::decode_fprint(a.value(), stdout);
        //ua_str << cbor::text_string::decode(a.value()).value();
        sn_str << cbor::text_string::decode(a.value()).value();
        dst_ip_str << cbor::text_string::decode(a.value()).value();
        printf("last:\n");  a.value().fprint_hex(stdout); fputc('\n', stdout);
        dst_port = cbor::uint64{a.value()}.value();  // TODO: check range
        a.close();
    }

    bool is_valid() const { return valid; }

    void encode(writeable &w) const {
        if (not valid) {
            w.set_null();
            return;
        }
        cbor::output::array a{w};
        cbor_fingerprint::encode_cbor_fingerprint(fingerprint, a);
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

    void fprint(FILE *f) const {
        if (!valid) {
            return;   // error; no valid data to print
        }
        fingerprint.fprint(f); fputc('\n', f);
        if (user_agent.is_valid()) {
            user_agent.value().fprint(f); fputc('\n', f);
        }
        domain_name.value().fprint(f); fputc('\n', f);
        if (dst_ip_str.is_valid()) {
            dst_ip_str.value().fprint(f); fputc('\n', f);
        }
        fprintf(f, "%zu\n", dst_port.value());

    }

};


#endif // FDC_HPP
