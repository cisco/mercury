// bencode.h
//

#include <stdint.h>
#include "datum.h"
#include "json_object.h"

#ifndef BENCODE_H
#define BENCODE_H

#include "datum.h"
#include "json_object.h"

namespace bencoding {

    // Bencoding, following "BitTorrentSpecification - TheoryOrg.html"
    //
    // Bencoding is a way to specify and organize data in a terse
    // format. It supports the following types: byte strings, integers,
    // lists, and dictionaries.
    //

    // Byte strings are encoded as follows:
    // <string length encoded in base ten ASCII>:<string data>
    //
    //


    class byte_string {
        uint64_t len = 0;
        datum val;

    public:

        byte_string(datum &d) {
            // loop over digits and compute value
            //
            uint8_t c;
            while (d.is_not_empty()) {
                d.read_uint8(&c);
                if (c == ':') {
                    break;          // at end; not an error
                }
                if (c < '0' || c > '9') {
                    d.set_null();   // error; input is not a bint
                    break;
                }
                len *= 10;
                len += c - '0';
            }
            val.parse(d, len);
        }

        template <size_t N>
        byte_string(datum &d, std::array<uint8_t, N> k) {
            // loop over digits and compute value
            //
            uint8_t c;
            while (d.is_not_empty()) {
                d.read_uint8(&c);
                if (c == ':') {
                    break;          // at end; not an error
                }
                if (c < '0' || c > '9') {
                    d.set_null();   // error; input is not a bint
                    break;
                }
                len *= 10;
                len += c - '0';
            }
            val.parse(d, len);
            if (!val.matches(k)) {
                d.set_null();
            }
        }

        datum value() const { return val; }

        bool is_printable_ascii() const {
            datum tmp = val;
            while(tmp.is_readable()) {
                encoded<uint8_t> c(tmp);
                if (!c) {
                    return false;
                }
                if (c >= 0x20 and c <= 0x7f) {
                    continue;
                } else {
                    return false;
                }
            }
            return true;
        }

        void fingerprint(struct buffer_stream &b) const {
            if (val.is_readable()) {
                if(is_printable_ascii()) {
                    b.json_string_escaped(val.data, val.length());
                } else {
                    b.json_hex_string(val.data, val.length());
                }
            }
        }
        
        void write_json(struct json_object &o) {
            if (val.is_readable()) {
                if(is_printable_ascii()) {
                    o.print_key_json_string("value", val);
                } else {
                    o.print_key_hex("value_hex", val);
                }
            }
        }
    };


    class minus_sign {
        literal_<'-'> minus;

    public:
        minus_sign(datum &d) : minus(d) { }
    };

    // Lists are encoded as follows:
    // l<bencoded values>e
    //
    // Lists may contain any bencoded type, including integers, strings,
    // dictionaries, and even lists within other lists.

    // Integers are encoded as follows:
    // i<integer encoded in base ten ASCII>e
    //
    //  A signed 64bit integer is mandatory
    //
    class bint {
        int64_t val = 0;
        bool negative_val = false;

    public:
        datum body;
        bint(datum &d) {
            d.accept('i');
            if (lookahead<minus_sign> minus{d}) {
                negative_val = true;
                d = minus.advance();
            }

            body = d;
            while (d.is_not_empty()) {
                encoded<uint8_t> c(d);
                if (c.value() == 'e') {
                    body.data_end = d.data;
                    break;          // at end; not an error
                }
                if (c.value() < '0' || c.value() > '9') {
                    d.set_null();   // error; input is not a bint
                    break;
                }
                val *= 10;
                val += c - '0';
            }

            if (negative_val) {
                val *= -1;
            }
        }
        int64_t value() const { return val; }

        void fingerprint(struct buffer_stream &b) const {
            b.snprintf("%lld", val);
        }

        void write_json(struct json_object &o) {
            o.print_key_int64("value", val);
        }
    };

    class dict_end {
        literal_<'e'> end;

    public:
        dict_end(datum &d) : end{d} { }

    };

    // A list of values is encoded as l<contents>e . The contents
    // consist of the bencoded elements of the list, in order, concatenated.
    class blist {
        datum& body;
        bool valid;

    public:
        blist(datum &d) : body(d) {
            body.accept('l');
            valid = d.is_not_null();
        }

        void fingerprint(struct buffer_stream &b) const;

        void write_json(struct json_object &o);
    };


        
    // class key_and_value represents the key/value pair used in
    // dictionaries
    //
    // TODO: accept only strings that match a statically-defined array
    // of characters
    //
    template <typename T, size_t N=0>
    class key_and_value {
        byte_string key;
        T val;

    public:

        key_and_value(datum &d, std::array<uint8_t, N> k={}) : key{d, k}, val{d} { }

        datum value() const { return val.value(); }
    };

    // Dictionaries are encoded as follows:
    //     d<bencoded string><bencoded element>e
    //
    // The initial d and trailing e are the beginning and ending
    // delimiters. Note that the keys must be bencoded strings. The
    // values may be any bencoded type, including integers, strings,
    // lists, and other dictionaries. Keys must be strings and appear
    // in sorted order (sorted as raw strings, not alphanumerics). The
    // strings should be compared using a binary comparison, not a
    // culture-specific "natural" comparison.
    //
    class dictionary {
        datum &tmp;
        bool valid;

    public:

        dictionary(datum &d) : tmp(d) {
            tmp.accept('d');
            valid = d.is_not_null();
        }

        void fingerprint(struct buffer_stream &b) const;
               
        void write_json(struct json_object &o);
        
    };
};

class bencoded_data {
    datum &body;

public:
    bencoded_data(datum &d) : body(d) { }

    void fingerprint(struct buffer_stream &b) const;

    void write_json(struct json_object &o);

};

#endif // BENCODE_H
