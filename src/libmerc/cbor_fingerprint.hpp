///
/// \file cbor_fingerprint.hpp
///
/// CBOR encoding and decoding of Network Protocol Fingerprints (NPF)
///
/// Copyright (c) 2026 Cisco Systems, Inc. All rights reserved.
/// License at https://github.com/cisco/mercury/blob/master/LICENSE
///

#ifndef CBOR_FINGERPRINT_HPP
#define CBOR_FINGERPRINT_HPP

#include <cstring>            // for strlen()
#include "datum.h"
#include "cbor.hpp"
#include "static_dict.hpp"
#include "fingerprint.h"      // for fingerprint::get_type_name()

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
                fputc('(', f);
                bs.value().fprint_hex(f);
                fputc(')', f);
            } else if (ib.value.is_array_indefinite_length()) {
                d = ib.advance();
                fputc('[', f);
                fprint(f, d);          // recursion
                fputc(']', f);
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

    inline void encode_cbor_tls_server_fingerprint(datum d, writeable &w) {
        cbor::output::map m{w};

        if (lookahead<literal_byte<'('>>{d}) {
            cbor::uint64{0}.write(m);      // fingerprint version
            cbor::output::array a{m};
            encode_cbor_data(d, a);         // version
            encode_cbor_data(d, a);         // ciphersuite (single cipher)
            encode_cbor_list(d, a);         // extensions
            a.close();

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

    inline void encode_cbor_http_server_fingerprint(datum d, writeable &w) {
        cbor::output::map m{w};
        if (lookahead<literal_byte<'('>>{d}) {
            cbor::uint64{0}.write(m);      // fingerprint version
            cbor::output::array a{m};
            encode_cbor_data(d, a);         // version
            encode_cbor_data(d, a);         // status_code
            encode_cbor_data(d, a);         // status_reason
            encode_cbor_list(d, a);         // headers
            a.close();
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
        m.close();
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

        } else if (lookahead<literal_byte<'s', 's', 'h', '_', 's', 'e', 'r', 'v', 'e', 'r', '/'>> ssh_server{d}) {
            fp_type = fingerprint_type_ssh_server;
            cbor::output::map m{w};
            cbor::uint64{(uint64_t)fp_type}.write(w);
            d = ssh_server.advance();
            encode_cbor_ssh_fingerprint(d, w);
            m.close();

        } else if (lookahead<literal_byte<'t', 'l', 's', '_', 's', 'e', 'r', 'v', 'e', 'r', '/'>> tls_server{d}) {
            fp_type = fingerprint_type_tls_server;
            cbor::output::map m{w};
            cbor::uint64{(uint64_t)fp_type}.write(w);
            d = tls_server.advance();
            encode_cbor_tls_server_fingerprint(d, m);
            m.close();

        } else if (lookahead<literal_byte<'h', 't', 't', 'p', '_', 's', 'e', 'r', 'v', 'e', 'r', '/'>> http_server{d}) {
            fp_type = fingerprint_type_http_server;
            cbor::output::map m{w};
            cbor::uint64{(uint64_t)fp_type}.write(w);
            d = http_server.advance();
            encode_cbor_http_server_fingerprint(d, m);
            m.close();

        } else if (lookahead<literal_byte<'d', 't', 'l', 's', '/'>> dtls{d}) {
            fp_type = fingerprint_type_dtls;
            cbor::output::map m{w};
            cbor::uint64{(uint64_t)fp_type}.write(w);
            d = dtls.advance();
            // dtls fp uses same format as tls fp
            encode_cbor_tls_fingerprint(d, m);
            m.close();

        } else if (lookahead<literal_byte<'d', 't', 'l', 's', '_', 's', 'e', 'r', 'v', 'e', 'r', '/'>> dtls_server{d}) {
            fp_type = fingerprint_type_dtls_server;
            cbor::output::map m{w};
            cbor::uint64{(uint64_t)fp_type}.write(w);
            d = dtls_server.advance();
            // dtls server fp uses same format as tls server fp
            encode_cbor_tls_server_fingerprint(d, m);
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

    inline void decode_cbor_sorted_list(datum &d, writeable &w, size_t depth = 0) {
        constexpr size_t max_recursion_depth = 256;
        if (depth > max_recursion_depth) {
            d.set_null();   // reject excessively nested input
            w.set_null();
            return;
        }
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
                    decode_cbor_sorted_list(a.value(), w, depth + 1);
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
                    d = label.advance();    // accept the label
                } else {
                    d.set_null();           // an unrecognized label is not a
                    w.set_null();           // fingerprint we can render
                }
            } else {
                cbor::array a{m.value()};
                decode_cbor_data(m.value(), w); // method
                decode_cbor_data(m.value(), w); // protocol
                decode_cbor_list(m.value(), w); // headers
                a.close();
            }
        } else {
            d.set_null();   // unknown format version: consume nothing and
            w.set_null();   // report the failure through both outputs
        }
        m.close();
    }

    inline void decode_http_server_fp(datum &d, writeable &w) {
        cbor::map m{d};
        cbor::uint64 format_version{m.value()};
        if (format_version.value() == 0) {
            cbor::array a{m.value()};
            decode_cbor_data(m.value(), w); // version
            decode_cbor_data(m.value(), w); // status_code
            decode_cbor_data(m.value(), w); // status_reason
            decode_cbor_list(m.value(), w); // headers
            a.close();
        } else {
            d.set_null();   // unknown format version: consume nothing and
            w.set_null();   // report the failure through both outputs
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
                    d = label.advance();    // accept the label
                } else {
                    d.set_null();           // an unrecognized label is not a
                    w.set_null();           // fingerprint we can render
                }
            } else {
                cbor::array a{m.value()};
                decode_cbor_data(m.value(), w);         // version
                decode_cbor_data(m.value(), w);         // ciphersuites
                decode_cbor_sorted_list(m.value(), w);  // extensions
                a.close();
            }
        } else {
            d.set_null();   // unknown format version: consume nothing and
            w.set_null();   // report the failure through both outputs
        }
        m.close();
    }

    inline void decode_tls_server_fp(datum &d, writeable &w) {
        cbor::map m{d};
        cbor::uint64 format_version{m.value()};
        if (format_version.value() == 0) {
            cbor::array a{m.value()};
            decode_cbor_data(m.value(), w); // version
            decode_cbor_data(m.value(), w); // ciphersuite (single cipher)
            decode_cbor_list(m.value(), w); // extensions
            a.close();

        } else {
            d.set_null();   // unknown format version: consume nothing and
            w.set_null();   // report the failure through both outputs
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
                    d = label.advance();    // accept the label
                } else {
                    d.set_null();           // an unrecognized label is not a
                    w.set_null();           // fingerprint we can render
                }
            } else {
                cbor::array a{m.value()};
                decode_cbor_data(m.value(), w);        // quic version
                decode_cbor_data(m.value(), w);        // version
                decode_cbor_data(m.value(), w);        // ciphersuites
                decode_cbor_sorted_list(m.value(), w); // extensions
                a.close();
            }
        } else {
            d.set_null();   // unknown format version: consume nothing and
            w.set_null();   // report the failure through both outputs
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
            } else {
                d.set_null();               // an unrecognized label is not a
                w.set_null();               // fingerprint we can render
            }
        } else {
            d.set_null();   // unknown format version: consume nothing and
            w.set_null();   // report the failure through both outputs
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
                    d = label.advance();    // accept the label
                } else {
                    d.set_null();           // an unrecognized label is not a
                    w.set_null();           // fingerprint we can render
                }
            } else {
                cbor::array a{m.value()};
                decode_cbor_data(m.value(), w);         // class
                decode_cbor_data(m.value(), w);         // method
                decode_cbor_data(m.value(), w);         // magic
                decode_cbor_list(m.value(), w);         // attributes
                a.close();
            }
        } else {
            d.set_null();   // unknown format version: consume nothing and
            w.set_null();   // report the failure through both outputs
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
                    d = label.advance();    // accept the label
                } else {
                    d.set_null();           // an unrecognized label is not a
                    w.set_null();           // fingerprint we can render
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
        } else {
            d.set_null();   // unknown format version: consume nothing and
            w.set_null();   // report the failure through both outputs
        }
        m.close();
    }

    inline void decode_fp(uint64_t fp_type,
                   datum &d,
                   writeable &w) {

        if (fp_type >= fingerprint_type_max) {
            d.set_null();   // unknown fingerprint
            w.set_null();
            return;
        }
        w << datum{fingerprint::get_type_name((fingerprint_type)fp_type).c_str()};
        w.copy('/');
        switch(fp_type) {
        case fingerprint_type_http:
            decode_http_fp(d, w);
            break;
        case fingerprint_type_http_server:
            decode_http_server_fp(d, w);
            break;
        case fingerprint_type_tls:
            decode_tls_fp(d, w);
            break;
        case fingerprint_type_tls_server:
            decode_tls_server_fp(d, w);
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
        case fingerprint_type_ssh_server:
            decode_ssh_fp(d, w);
            break;
        case fingerprint_type_dtls:
            decode_tls_fp(d, w);    // same format as tls fp
            break;
        case fingerprint_type_dtls_server:
            decode_tls_server_fp(d, w); // same format as tls_server fp
            break;
        default:
            // Error: Unknown fingerprint type
            d.set_null();
            w.set_null();
            break;
        }

    }

    inline void decode_cbor_fingerprint(datum &d, writeable &w) {

        cbor::map m{d};
        if (m.value().is_readable()) {
            cbor::uint64 fp_type{m.value()};
            // fprintf(stderr, "decoded fingerprint type %zu\n", fp_type.value());
            decode_fp(fp_type.value(), m.value(), w);
        }
        m.close();

        if (d.is_null()) {
            w.set_null();
        }
    }

    // test cbor fingerprint encoding and decoding
    //
    // LCOV_EXCL_START
    static bool test_fingerprint(const char *fingerprint_string, FILE *f=nullptr) {
        data_buffer<2048> data_buf;
        datum fp_data{(uint8_t *)fingerprint_string, (uint8_t *)fingerprint_string + strlen(fingerprint_string)};
        cbor_fingerprint::encode_cbor_fingerprint(fp_data, data_buf);

        data_buffer<2048> out_buf;
        datum encoded_data{data_buf.contents()};
        cbor_fingerprint::decode_cbor_fingerprint(encoded_data, out_buf);

        // after a correct decode the datum sits at data_end: not null, and with
        // nothing left to read.  A decoder that renders the right string while
        // leaving bytes unconsumed is still broken.
        //
        if (encoded_data.is_null() or encoded_data.is_readable()) {
            if (f) {
                fprintf(f, "ERROR: DECODER DID NOT CONSUME THE ENCODED FINGERPRINT\n");
                fprintf(f, "fingerprint:              %s\n", fingerprint_string);
                fprintf(f, "CBOR encoded fingerprint: ");
                data_buf.contents().fprint_hex(f); fputc('\n', f);
                fprintf(f, "unconsumed:               ");
                if (encoded_data.is_null()) {
                    fprintf(f, "<null datum>");
                } else {
                    encoded_data.fprint_hex(f);
                }
                fputc('\n', f);
            }
            return false;
        }

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

    /// verify that decode_cbor_fingerprint() rejects the cbor fingerprint in
    /// \p encoded, by leaving both of its outputs null.
    ///
    /// A fingerprint that cannot be decoded must report the failure through the
    /// datum *and* the writeable: a caller that renders the partial string, or
    /// one that goes on to read the unconsumed bytes, would both be wrong.
    ///
    /// \param name     names the case in the report
    /// \param encoded  the cbor fingerprint that must be rejected
    /// \param f        where to report a failure, or nullptr to stay silent
    ///
    /// \return `true` if both outputs were left null, and `false` otherwise
    ///
    static bool test_undecodable_fingerprint(const char *name, datum encoded, FILE *f=nullptr) {
        data_buffer<2048> out_buf;
        cbor_fingerprint::decode_cbor_fingerprint(encoded, out_buf);

        if (encoded.is_not_null() or !out_buf.is_null()) {
            if (f) {
                fprintf(f, "ERROR: UNDECODABLE FINGERPRINT WAS NOT REJECTED (%s)\n", name);
                fprintf(f, "datum:     %s\n", encoded.is_not_null() ? "not null" : "null");
                fprintf(f, "writeable: ");
                if (out_buf.is_null()) {
                    fprintf(f, "null\n");
                } else {
                    out_buf.contents().fprint(f); fputc('\n', f);
                }
            }
            return false;
        }
        return true;
    }

    /// \tparam D the nesting depth of the extension list.
    ///
    /// \return a tls/1 fingerprint whose extension list nests \p D arrays
    /// deep, with every break byte present: {1: {1: [h'', h'', \<D nested
    /// arrays\>]}}.  Everything after the opening arrays is a break, so filling
    /// with 0xff writes the D inner breaks and the three that close the list
    /// and the two maps.
    ///
    template <size_t D>
    static inline std::array<uint8_t, 7 + 2 * D + 3> nested_extensions() {
        std::array<uint8_t, 7 + 2 * D + 3> a;
        a.fill(0xff);
        const uint8_t head[] = { 0xbf, 0x01, 0xbf, 0x01, 0x9f, 0x40, 0x40 };
        for (size_t i = 0; i < sizeof(head); i++) { a[i] = head[i]; }
        for (size_t i = 0; i < D; i++) { a[sizeof(head) + i] = 0x9f; }
        return a;
    }

    // cbor_fingerprint::unit_test() returns `true` if all unit tests
    // pass, `false` otherwise
    //
    [[maybe_unused]] static bool unit_test(FILE *f=nullptr) {

        // example fingerprints
        //
        std::vector<const char *> fps = {
            "http/(504f5354)(485454502f312e31)((486f7374)(557365722d4167656e74)(4163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c696d6167652f617669662c696d6167652f776562702c2a2f2a3b713d302e38)(4163636570742d4c616e6775616765)(4163636570742d456e636f64696e673a20677a69702c206465666c617465)(436f6e6e656374696f6e3a206b6565702d616c697665))",
            "http_server/(485454502f312e31)(323030)(4f4b)((5365727665723a204a657474792f342e322e39726332202853756e4f532f352e38207370617263206a6176612f312e342e315f303429)(436f6e74656e742d54797065)(436f6e6e656374696f6e3a20636c6f7365))",
            "tls/1/(0303)(130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035)[(0000)(000500050100000000)(000a00080006001d00170018)(000b00020100)(000d0012001004030804040105030805050108060601)(0010000e000c02683208687474702f312e31)(0012)(0017)(001b0003020002)(0023)(0029)(002b0009080304030303020301)(002d00020101)(0033)(ff01)]",
            "tls/(0303)(0a0a130113021303c02cc02bcca9c030c02fcca8c00ac009c014c013009d009c0035002f)((0a0a)(0000)(0017)(ff01)(000a000c000a0a0a001d001700180019)(000b00020100)(0010000e000c02683208687474702f312e31)(000500050100000000)(000d0018001604030804040105030203080508050501080606010201)(0012)(0033)(002d00020101)(002b0007060a0a03040303)(001b0003020001)(0a0a)(0015))",
            "tls_server/(0303)(c02f)((0000)(ff01)(000b)(0023))",
            "quic/(00000001)(0303)(130113021303)[(000a000a00086399001d00170018)(002b0003020304)((0039)[(01)(03)(04)(05)(06)(07)(08)(09)(0f)(1b)(20)(80004752)(80ff73db)])(4469)]",
            "http/randomized",
            "tls/1/randomized",
            "quic/randomized",
            "stun/1/randomized",
            "ssh/randomized",
            "tofsee/1/generic",
            "stun/1/(00)(0001)(01)((8022)(0006)(0020)(0008)(8028))",
            "ssh/(656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f757031342d736861312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d736861312c6469666669652d68656c6c6d616e2d67726f7570312d73686131)(7373682d7273612c7373682d6473732c65636473612d736861322d6e697374703235362c65636473612d736861322d6e697374703338342c65636473612d736861322d6e69737470353231)(6165733132382d6374722c6165733132382d6362632c336465732d6374722c336465732d6362632c626c6f77666973682d6362632c6165733139322d6374722c6165733139322d6362632c6165733235362d6374722c6165733235362d636263)(6165733132382d6374722c6165733132382d6362632c336465732d6374722c336465732d6362632c626c6f77666973682d6362632c6165733139322d6374722c6165733139322d6362632c6165733235362d6374722c6165733235362d636263)(686d61632d6d64352c686d61632d736861312c686d61632d736861322d3235362c686d61632d736861312d39362c686d61632d6d64352d3936)(686d61632d6d64352c686d61632d736861312c686d61632d736861322d3235362c686d61632d736861312d39362c686d61632d6d64352d3936)(6e6f6e65)(6e6f6e65)()()",
            "dtls/1/(fefd)(c02c)[(000a000c000a001d0017001e00190018)(000b000403000102)(000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602)(0016)]",
            "dtls/(fefd)(c02c)((000b000403000102)(000a000c000a001d0017001e00190018)(0016)(000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602))",
            "dtls_server/(fefd)(0035)((0000)(ff01)(000b))"
        };
        bool all_tests_passed = true;
        for (const auto & fp_str : fps) {
            all_tests_passed &= test_fingerprint(fp_str, f);
        }

        // fingerprints that cannot be decoded, which must be rejected through
        // both outputs rather than reported as a partial success
        //
        // an unknown fingerprint type, a 64-bit type whose low 32 bits alias a
        // type we do decode, and an unknown format version with and without a
        // value after the version key.  The last form is the one that
        // read_break() cannot catch, because both of the break bytes that it
        // reads are really there.
        //
        std::array<uint8_t,25> unknown_type{
            0xbf, 0x18, 0x63, 0xbf, 0x01,                       // {99: {1:
              0x9f, 0x42, 0x03, 0x03, 0x42, 0x13, 0x01,         //   [0303, 1301,
                0xd8, 0xfb,                                     //     tag(251)
                  0x9f, 0x42, 0x00, 0x00, 0x42, 0x00, 0x0a,     //       [0000, 000a
                  0xff,                                         //       ]
              0xff,                                             //   ]
            0xff, 0xff                                          // }}
        };
        std::array<uint8_t,32> aliased_type{
            0xbf, 0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
                                                                //  {0x100000001:
              0xbf, 0x01,                                       //   {1:
                0x9f, 0x42, 0x03, 0x03, 0x42, 0x13, 0x01,       //   [0303, 1301,
                  0xd8, 0xfb,                                   //     tag(251)
                    0x9f, 0x42, 0x00, 0x00, 0x42, 0x00, 0x0a,   //       [0000, 000a
                    0xff,                                       //       ]
                0xff,                                           //   ]
              0xff, 0xff                                        // }}
        };
        std::array<uint8_t,24> unknown_version{
            0xbf, 0x01, 0xbf, 0x07,                             // {1: {7:
              0x9f, 0x42, 0x03, 0x03, 0x42, 0x13, 0x01,         //   [0303, 1301,
                0xd8, 0xfb,                                     //     tag(251)
                  0x9f, 0x42, 0x00, 0x00, 0x42, 0x00, 0x0a,     //       [0000, 000a
                  0xff,                                         //       ]
              0xff,                                             //   ]
            0xff, 0xff                                          // }}
        };
        std::array<uint8_t,6> unknown_version_no_value{
            0xbf, 0x01, 0xbf, 0x07, 0xff, 0xff                  // {1: {7: }}
        };
        all_tests_passed &= test_undecodable_fingerprint("unknown fingerprint type", datum{unknown_type}, f);
        all_tests_passed &= test_undecodable_fingerprint("fingerprint type aliased by truncation", datum{aliased_type}, f);
        all_tests_passed &= test_undecodable_fingerprint("unknown format version", datum{unknown_version}, f);
        all_tests_passed &= test_undecodable_fingerprint("unknown format version, no value", datum{unknown_version_no_value}, f);

        // an extension list nested either side of decode_cbor_sorted_list()'s
        // recursion limit, with every break byte present so that depth is the
        // only thing the deeper one can be rejected for.  A list left unclosed
        // is rejected by the end of the input whether the limit is enforced or
        // not.  257 is the deepest nesting allowed, 258 the shallowest that
        // must fail, and the deeper one must be rejected through both outputs
        // rather than rendered as the partial string the descent built on the
        // way down.
        //
        auto extensions_to_limit   = nested_extensions<257>();
        auto extensions_past_limit = nested_extensions<258>();

        all_tests_passed &=
            test_undecodable_fingerprint("extension list nested past the limit",
                                         datum{extensions_past_limit}, f);

        // the control: the same shape at the deepest nesting the limit allows
        // must decode, so a decoder that rejected every nested list could not
        // pass the case above
        //
        {
            datum encoded{extensions_to_limit};
            data_buffer<2048> out_buf;
            cbor_fingerprint::decode_cbor_fingerprint(encoded, out_buf);
            if (encoded.is_null() or out_buf.is_null()) {
                if (f) {
                    fprintf(f, "ERROR: FINGERPRINT NESTED TO THE LIMIT WAS REJECTED\n");
                }
                all_tests_passed = false;
            }
        }

        // an extension list that runs out before its breaks.  Depth has nothing
        // to do with this one, so it is as small as it can be.
        //
        std::array<uint8_t,10> unterminated_extensions{
            0xbf, 0x01, 0xbf, 0x01, 0x9f, 0x40, 0x40,           // {1: {1: [h'', h'',
              0x9f, 0x9f, 0x9f                                  //   [[[
        };
        all_tests_passed &=
            test_undecodable_fingerprint("extension list truncated before its breaks",
                                         datum{unterminated_extensions}, f);

        // an unrecognized label in place of `randomized` or `generic`.  The
        // second form is a silent success without the label check: every break
        // byte is present, so nothing else notices.
        //
        std::array<uint8_t,7> unknown_tls_label{
            0xbf, 0x01, 0xbf, 0x01, 0x07, 0xff, 0xff            // {1: {1: 7}}
        };
        std::array<uint8_t,7> unknown_tofsee_label{
            0xbf, 0x0f, 0xbf, 0x01, 0x07, 0xff, 0xff            // {15: {1: 7}}
        };
        all_tests_passed &= test_undecodable_fingerprint("unrecognized tls label", datum{unknown_tls_label}, f);
        all_tests_passed &= test_undecodable_fingerprint("unrecognized tofsee label", datum{unknown_tofsee_label}, f);

        // every decoder checks the format version for itself, so each one needs
        // its own envelope.  Version 7 is implemented by none of them; the tls
        // case is unknown_version above.
        //
        std::array<uint8_t,6> http_unknown_version{
            0xbf, 0x03, 0xbf, 0x07, 0xff, 0xff                  // {3: {7: }}
        };
        std::array<uint8_t,6> http_server_unknown_version{
            0xbf, 0x04, 0xbf, 0x07, 0xff, 0xff                  // {4: {7: }}
        };
        std::array<uint8_t,6> tls_server_unknown_version{
            0xbf, 0x02, 0xbf, 0x07, 0xff, 0xff                  // {2: {7: }}
        };
        std::array<uint8_t,6> quic_unknown_version{
            0xbf, 0x0c, 0xbf, 0x07, 0xff, 0xff                  // {12: {7: }}
        };
        std::array<uint8_t,6> tofsee_unknown_version{
            0xbf, 0x0f, 0xbf, 0x07, 0xff, 0xff                  // {15: {7: }}
        };
        std::array<uint8_t,6> stun_unknown_version{
            0xbf, 0x10, 0xbf, 0x07, 0xff, 0xff                  // {16: {7: }}
        };
        std::array<uint8_t,6> ssh_unknown_version{
            0xbf, 0x05, 0xbf, 0x07, 0xff, 0xff                  // {5: {7: }}
        };
        all_tests_passed &= test_undecodable_fingerprint("http, unknown format version", datum{http_unknown_version}, f);
        all_tests_passed &= test_undecodable_fingerprint("http_server, unknown format version", datum{http_server_unknown_version}, f);
        all_tests_passed &= test_undecodable_fingerprint("tls_server, unknown format version", datum{tls_server_unknown_version}, f);
        all_tests_passed &= test_undecodable_fingerprint("quic, unknown format version", datum{quic_unknown_version}, f);
        all_tests_passed &= test_undecodable_fingerprint("tofsee, unknown format version", datum{tofsee_unknown_version}, f);
        all_tests_passed &= test_undecodable_fingerprint("stun, unknown format version", datum{stun_unknown_version}, f);
        all_tests_passed &= test_undecodable_fingerprint("ssh, unknown format version", datum{ssh_unknown_version}, f);

        // an unrecognized label in each of the other decoders that accept one.
        // A label is an index into fp_labels, which holds three entries, so 7
        // is not a label any build of this decoder knows.
        //
        std::array<uint8_t,7> unknown_http_label{
            0xbf, 0x03, 0xbf, 0x00, 0x07, 0xff, 0xff            // {3: {0: 7}}
        };
        std::array<uint8_t,7> unknown_quic_label{
            0xbf, 0x0c, 0xbf, 0x00, 0x07, 0xff, 0xff            // {12: {0: 7}}
        };
        std::array<uint8_t,7> unknown_stun_label{
            0xbf, 0x10, 0xbf, 0x01, 0x07, 0xff, 0xff            // {16: {1: 7}}
        };
        std::array<uint8_t,7> unknown_ssh_label{
            0xbf, 0x05, 0xbf, 0x00, 0x07, 0xff, 0xff            // {5: {0: 7}}
        };
        all_tests_passed &= test_undecodable_fingerprint("unrecognized http label", datum{unknown_http_label}, f);
        all_tests_passed &= test_undecodable_fingerprint("unrecognized quic label", datum{unknown_quic_label}, f);
        all_tests_passed &= test_undecodable_fingerprint("unrecognized stun label", datum{unknown_stun_label}, f);
        all_tests_passed &= test_undecodable_fingerprint("unrecognized ssh label", datum{unknown_ssh_label}, f);

        // a fingerprint type that is in range but has no decoder.  decode_fp()
        // handles eleven of the twenty-one enumerators, so tcp (7) reaches the
        // switch and falls through to its default label.  That is a different
        // path from unknown_type above, which the range check rejects before
        // the switch is entered.
        //
        std::array<uint8_t,7> unhandled_type{
            0xbf, 0x07, 0xbf, 0x00, 0x01, 0xff, 0xff            // {7: {0: 1}}
        };
        all_tests_passed &= test_undecodable_fingerprint("fingerprint type with no decoder", datum{unhandled_type}, f);

        // a tls fingerprint cut off inside its ciphersuite array.  This decoder
        // writes each field as it reads it, so by the time the input runs out the
        // writeable already holds "tls/1/(0303)()()" -- well formed npf for a
        // fingerprint that was never sent, and the reason the failure has to be
        // reported through the writeable and not just the datum.
        //
        std::array<uint8_t,8> truncated_tls{
            0xbf, 0x01, 0xbf, 0x01, 0x9f, 0x42, 0x03, 0x03      // {1: {1: [0303
        };
        all_tests_passed &= test_undecodable_fingerprint("tls fingerprint truncated mid-ciphersuites", datum{truncated_tls}, f);

        // an input that is not a map at all, which cbor::map nulls on its way in,
        // before a fingerprint type has been read or a decoder chosen
        //
        std::array<uint8_t,1> not_a_map{
            0x01                                                // 1
        };
        all_tests_passed &= test_undecodable_fingerprint("not a cbor map", datum{not_a_map}, f);

        return all_tests_passed;
    }
    // LCOV_EXCL_STOP
};

#endif // CBOR_FINGERPRINT_HPP
