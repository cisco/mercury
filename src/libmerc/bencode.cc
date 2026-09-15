/*
 * bencode.cc
 *
 * Copyright (c) 2022 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include "bencode.h"

namespace bencoding {
    void blist::write_raw_features(writeable &w) {
        if (!valid) {
            return;
        }

        if (lookahead<list_or_dict_end> is_end{body}) {
            body = is_end.advance();
            w.copy('[');    // empty list -> "[]" (avoids a dangling comma in the parent)
            w.copy(']');
            tmp = body;     // propagate consumed position so siblings are not dropped
            return;
        }

        w.copy('[');

        bool first = true;
        while(body.is_not_empty()) {
            if (!first) {
                w.copy(',');
            } else {
                first = false;
            }

            // depth limit: emit remaining bytes as unparsed hex (like write_json), then
            // consume them so parents don't re-parse the leftovers
            if (nesting_level > MAX_DEPTH) {
                w.write_quote_enclosed_hex(body);
                body.skip(body.length());
                break;
            }

            bencoded_data value{body, static_cast<uint8_t>(nesting_level + 1)};
            value.write_raw_features(w);

            if (lookahead<list_or_dict_end> is_end{body}) {
                body = is_end.advance();
                break;
            }
        }
        w.copy(']');
        //Set the actual datum to the point till list is parsed
        tmp = body;
    }

    void blist::write_json(struct json_object &o) {
        if (!valid) {
            return;
        }

        if (lookahead<list_or_dict_end> is_end{tmp}) {
            tmp = is_end.advance();
            return;
        }

        struct json_array a{o, "attributes"};

        while(tmp.is_not_empty()) {
            struct json_object items(a);
            if (nesting_level > MAX_DEPTH) {
                items.print_key_hex("unparsed_value_hex", tmp);
                tmp.skip(tmp.length());   // consume tail so the parent does not re-hex it
                items.close();            // close the object so the JSON stays balanced
                break;
            }
            bencoded_data value{tmp, static_cast<uint8_t>(nesting_level + 1)};
            value.write_json(items);
            items.close();

            if (lookahead<list_or_dict_end> is_end{tmp}) {
                tmp = is_end.advance();
                break;
            }
        }
        a.close();
    }

    void dictionary::write_raw_features(writeable &w) {

        if (!valid) {
            return;
        }

        if (lookahead<list_or_dict_end> is_end{body}) {
            body = is_end.advance();
            w.copy('[');    // empty dict -> "[]" (avoids a dangling comma in the parent)
            w.copy(']');
            tmp = body;     // propagate consumed position so siblings are not dropped
            return;
        }

        w.copy('[');
        bool first = true;
        while(body.is_not_empty()) {
            if (!first) {
                w.copy(',');
            } else {
                first = false;
            }

            w.copy('[');
            byte_string key{body};
            key.write_raw_features(w);

            w.copy(',');

            // depth limit: emit remaining bytes as unparsed hex (like write_json), then
            // consume them so parents don't re-parse the leftovers
            if (nesting_level > MAX_DEPTH) {
                w.write_quote_enclosed_hex(body);
                body.skip(body.length());
                w.copy(']');
                break;
            }

            bencoded_data value{body, static_cast<uint8_t>(nesting_level + 1)};
            value.write_raw_features(w);

            w.copy(']');

            if (lookahead<list_or_dict_end> is_end{body}) {
                body = is_end.advance();
                break;
            }
        }
        w.copy(']');

        //Set the actual datum to the point till dictionary is parsed
        tmp = body;
    }

    void dictionary::write_json(struct json_object &o) {

        if (!valid) {
            return;
        }

        if (lookahead<list_or_dict_end> is_end{tmp}) {
            tmp = is_end.advance();
            return;
        }

        struct json_array a{o, "attributes"};

        while(tmp.is_not_empty()) {
            struct json_object items(a);

            byte_string key{tmp};
            items.print_key_json_string("key", key.value());
            if (nesting_level > MAX_DEPTH) {
                items.print_key_hex("unparsed_value_hex", tmp);
                tmp.skip(tmp.length());
                items.close();            // close the object so the JSON stays balanced
                break;
            }

            bencoded_data value{tmp, static_cast<uint8_t>(nesting_level + 1)};
            value.write_json(items);
            items.close();

            if (lookahead<list_or_dict_end> is_end{tmp}) {
                tmp = is_end.advance();
                break;
            }
        }
        a.close();
    }

    void bencoded_data::write_raw_features(writeable &w) {
        // this dispatcher always emits exactly one value so a parent's separator
        // never dangles, even on unparsable input
        if (!valid) {
            w.copy('"'); w.copy('"');
            return;
        }

        if (lookahead<encoded<uint8_t>> type{body}) {
            if (type.value == 'i') {
                bencoding::bint integer(body);
                integer.write_raw_features(w);
            } else if (type.value >= '0' and type.value <= '9') {
                bencoding::byte_string str(body);
                str.write_raw_features(w);
            } else if (type.value == 'd') {
                bencoding::dictionary dict(body, nesting_level);
                dict.write_raw_features(w);
            } else if (type.value == 'l') {
                bencoding::blist list(body, nesting_level);
                list.write_raw_features(w);
            } else {
                // Not a bencoded data
                w.copy('"'); w.copy('"');
                body.set_null();
            }
        } else {
            w.copy('"'); w.copy('"');
        }
    }

    void bencoded_data::write_json(struct json_object &o) {
        if (!valid) {
            return;
        }

        if (lookahead<encoded<uint8_t>> type{body}) {
            if (type.value == 'i') {
                bencoding::bint integer(body);
                integer.write_json(o);
            } else if (type.value >= '0' and type.value <= '9') {
                bencoding::byte_string str(body);
                str.write_json(o);
            } else if (type.value == 'd') {
                bencoding::dictionary dict(body, nesting_level);
                dict.write_json(o);
            } else if (type.value == 'l') {
                bencoding::blist list(body, nesting_level);
                list.write_json(o);
            } else {
                // Not a bencoded data
                body.set_null();
            }
        }
    }
}
