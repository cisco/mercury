/*
 * bencode.h
 *
 * Copyright (c) 2022 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef BENCODE_H
#define BENCODE_H

#include <stdint.h>
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
        static constexpr uint64_t max_len = 256; // restricting the max len of byte string to 256 bytes

    public:

        byte_string(datum &d) {
            // loop over digits and compute value
            //
            while (d.is_not_empty()) {
                encoded<uint8_t> c(d);
                if (c.value() == ':') {
                    break;          // at end; not an error
                }
                if (c.value() < '0' || c.value() > '9') {
                    d.set_null();   // error; input is not a bint
                    break;
                }
                len *= 10;
                len += c.value() - '0';

                if (len > max_len) {
                    // Might be a bad packet.
                    d.set_null();
                    break;
                }
            }
            val.parse(d, len);
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

        void write_json(struct json_object &o) {
            o.print_key_int64("value", val);
        }
    };

    class list_or_dict_end {
        literal_<'e'> end;

    public:
        list_or_dict_end(datum &d) : end{d} { }

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

        bool is_not_empty() { return valid; }

        void write_json(struct json_object &o);
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

        bool is_not_empty() { return valid; }

        void write_json(struct json_object &o);
        
    };
};

class bencoded_data {
    datum &body;
    bool valid;

public:
    bencoded_data(datum &d) : body{d}, valid{d.is_not_null()} { }

    bool is_not_empty() { return valid; }

    void write_json(struct json_object &o);
};

#endif // BENCODE_H
