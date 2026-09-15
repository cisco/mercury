/*
 * bencode.h
 *
 * Copyright (c) 2022 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef BENCODE_H
#define BENCODE_H

#include <stdint.h>
#include <vector>   // unit tests only
#include "datum.h"
#include "json_object.h"
#include "lex.h"

namespace bencoding {

    #define MAX_DEPTH 10

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

        void write_raw_features(writeable &w) {
            w.write_quote_enclosed_hex(val);
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

    // Lists are encoded as follows:
    // l<bencoded values>e
    //
    // Lists may contain any bencoded type, including integers, strings,
    // dictionaries, and even lists within other lists.

    // Integers are encoded as follows:
    // i<integer encoded in base ten ASCII>e
    //
    //
    class bint {
        literal_byte<'i'> start;
        one_or_more<digits> value;
        literal_byte<'e'> end;
        bool valid;

    public:
        bint(datum &d) :
             start(d),
             value(d),
             end(d),
             valid{d.is_not_null()} { }

        void write_raw_features(writeable &w) {
            w.write_quote_enclosed_hex(value.data, value.length());
        }

        void write_json(struct json_object &o) {
            if (!valid) {
                return;
            }

            o.print_key_json_string("value", value.data, value.length());
        }
    };

    class list_or_dict_end {
        literal_byte<'e'> end;

    public:
        list_or_dict_end(datum &d) : end{d} { }

    };

    // A list of values is encoded as l<contents>e . The contents
    // consist of the bencoded elements of the list, in order, concatenated.
    class blist {
        datum body;
        datum &tmp;
        uint8_t nesting_level;
        bool valid;

    public:
        blist(datum &d, uint8_t _nesting_level = 1) : tmp(d), nesting_level(_nesting_level) {
            tmp.accept('l');
            body = tmp; // Create two copies of data.
                        // One for parsing json ouput and other for raw features.
            valid = d.is_not_null();
        }

        bool is_not_empty() { return valid; }

        void write_raw_features(writeable &w);

        void write_json(struct json_object &o);

#ifndef NDEBUG

        // LCOV_EXCL_START
        static bool unit_test() {
            // one level past MAX_DEPTH: the whole output fits, so assert it exactly
            std::vector<uint8_t> deep(MAX_DEPTH + 2, 'l');
            datum d{deep.data(), deep.data() + deep.size()};
            blist list{d};
            data_buffer<2048> buf;
            list.write_raw_features(buf);

            const char expected[] = "[[[[[[[[[[[\"6c\"]]]]]]]]]]]";   // MAX_DEPTH+1 openers
            if (buf.readable_length() != sizeof(expected) - 1
                || memcmp(buf.buffer, expected, sizeof(expected) - 1) != 0) {
                return false;
            }

            // an empty child must emit "[]" without dropping the sibling after it
            unsigned char nested[] = "lle3:abce";
            unsigned char nested_expected[] = "[[],\"616263\"]";
            datum dn{nested, nested + sizeof(nested) - 1};
            blist listn{dn};
            data_buffer<2048> bufn;
            listn.write_raw_features(bufn);
            if (bufn.readable_length() != sizeof(nested_expected) - 1
                || memcmp(bufn.buffer, nested_expected, sizeof(nested_expected) - 1) != 0) {
                return false;
            }

            // an unparsable value must still emit one value (no dangling comma)
            unsigned char bad[] = "lli1eex";
            unsigned char bad_expected[] = "[[\"31\"],\"\"]";
            datum db{bad, bad + sizeof(bad) - 1};
            blist listb{db};
            data_buffer<2048> bufb;
            listb.write_raw_features(bufb);
            if (bufb.readable_length() != sizeof(bad_expected) - 1
                || memcmp(bufb.buffer, bad_expected, sizeof(bad_expected) - 1) != 0) {
                return false;
            }

            // depth-limited list: write_json cutoff must close the object and
            // consume the tail (covers items.close() + tmp.skip on the list path)
            std::vector<uint8_t> deepj(MAX_DEPTH + 2, 'l');
            datum dj{deepj.data(), deepj.data() + deepj.size()};
            blist listj{dj};
            char jbuf[512];
            buffer_stream bsj(jbuf, sizeof(jbuf));
            json_object recj(&bsj);
            listj.write_json(recj);
            unsigned char expected_json[] = "{\"attributes\":[{\"attributes\":[{\"attributes\":[{\"attributes\":[{\"attributes\":[{\"attributes\":[{\"attributes\":[{\"attributes\":[{\"attributes\":[{\"attributes\":[{\"attributes\":[{\"unparsed_value_hex\":\"6c\"}]}]}]}]}]}]}]}]}]}]}]";
            if (recj.b->length() != sizeof(expected_json) - 1
                || memcmp(expected_json, recj.b->dstr, sizeof(expected_json) - 1)) {
                return false;
            }

            // pre-fix this recursed to the input depth and overflowed the stack;
            // the hex overflows the buffer, so only assert it returns
            std::vector<uint8_t> flood(100000, 'l');
            datum d2{flood.data(), flood.data() + flood.size()};
            blist list2{d2};
            data_buffer<2048> buf2;
            list2.write_raw_features(buf2);

            return true;
        }
        // LCOV_EXCL_STOP
#endif //NDEBUG
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
        datum body;
        datum &tmp;
        uint8_t nesting_level;
        bool valid;

    public:

        dictionary(datum &d, uint8_t _nesting_level = 1) : tmp(d), nesting_level(_nesting_level) {
            tmp.accept('d');
            body = tmp; // Create two copies of data.
                        // One for parsing json ouput and other for raw features.
            valid = d.is_not_null();
        }

        bool is_not_empty() { return valid; }

        void write_raw_features(writeable &w);

        void write_json(struct json_object &o);

#ifndef NDEBUG

        // LCOV_EXCL_START
        static bool unit_test() {
            unsigned char data[] = "d1:ad2:idd2:idd2:idd2:idd2:idd2:idd2:idd2:idd2:idd2:id4:testeeeeeeeeeee";
            unsigned char expected_json[] = "{\"attributes\":[{\"key\":\"a\",\"attributes\":[{\"key\":\"id\",\"attributes\":[{\"key\":\"id\",\"attributes\":[{\"key\":\"id\",\"attributes\":[{\"key\":\"id\",\"attributes\":[{\"key\":\"id\",\"attributes\":[{\"key\":\"id\",\"attributes\":[{\"key\":\"id\",\"attributes\":[{\"key\":\"id\",\"attributes\":[{\"key\":\"id\",\"attributes\":[{\"key\":\"id\",\"unparsed_value_hex\":\"343a746573746565656565656565656565\"}]}]}]}]}]}]}]}]}]}]}]";

            // full depth-limited output: balanced brackets, no dangling comma
            unsigned char expected_raw_features[] = "[[\"61\",[[\"6964\",[[\"6964\",[[\"6964\",[[\"6964\",[[\"6964\",[[\"6964\",[[\"6964\",[[\"6964\",[[\"6964\",[[\"6964\",\"343a746573746565656565656565656565\"]]]]]]]]]]]]]]]]]]]]]]";

            struct datum request_data{data, data + sizeof(data) - 1};   // exclude the C-string NUL
            char buffer[8192];
            struct buffer_stream buf_json(buffer, sizeof(buffer));
            struct json_object record(&buf_json);
            data_buffer<2048> buf;

            dictionary dict{request_data};
            dict.write_json(record);
            dict.write_raw_features(buf);

            if (record.b->length() != sizeof(expected_json) - 1
                || memcmp(expected_json, record.b->dstr, sizeof(expected_json) - 1)) {
                return false;
            }

            if (buf.readable_length() != sizeof(expected_raw_features) - 1
                || memcmp(expected_raw_features, buf.buffer, sizeof(expected_raw_features) - 1)) {
                return false;
            }

            // empty nested container must emit "[]" (no dangling comma)
            unsigned char nested[] = "d1:adee";
            unsigned char nested_expected[] = "[[\"61\",[]]]";
            struct datum nested_data{nested, nested + sizeof(nested) - 1};
            data_buffer<2048> nbuf;
            dictionary ndict{nested_data};
            ndict.write_raw_features(nbuf);
            if (nbuf.readable_length() != sizeof(nested_expected) - 1
                || memcmp(nested_expected, nbuf.buffer, sizeof(nested_expected) - 1)) {
                return false;
            }

            // a value that cannot be parsed must still emit one value (no dangling comma)
            unsigned char bad[] = "dxe";
            unsigned char bad_expected[] = "[[\"\",\"\"]]";
            struct datum bad_data{bad, bad + sizeof(bad) - 1};
            data_buffer<2048> bbuf;
            dictionary bdict{bad_data};
            bdict.write_raw_features(bbuf);
            if (bbuf.readable_length() != sizeof(bad_expected) - 1
                || memcmp(bad_expected, bbuf.buffer, sizeof(bad_expected) - 1)) {
                return false;
            }

            return true;
        }
        // LCOV_EXCL_STOP
#endif //NDEBUG
    };

    class bencoded_data {
        datum &body;
        uint8_t nesting_level;
        bool valid;

    public:
        bencoded_data(datum &d, uint8_t _nesting_level) :
            body{d},
            nesting_level(_nesting_level),
            valid{d.is_not_null()} { }

        bool is_not_empty() { return valid; }

        void write_raw_features(writeable &w);

        void write_json(struct json_object &o);


    };
};
#endif // BENCODE_H
