#include "bencode.h"

namespace bencoding {
    void blist::fingerprint(struct buffer_stream &b) const {
            b.write_char('[');
            while(body.is_not_empty()) {

                bencoded_data value{body};
                value.fingerprint(b);

                if (lookahead<dict_end> is_end{body}) {
                    body = is_end.advance();
                    break;
                }

                if (body.is_not_empty()) {
                    b.write_char(',');
                }
            }
            b.write_char(']');
    }

    void blist::write_json(struct json_object &o) {
            if (lookahead<dict_end> is_end{body}) {
                body = is_end.advance();
                return;
            }

            struct json_array a{o, "attributes"};

            while(body.is_not_empty()) {

                if (lookahead<dict_end> is_end{body}) {
                    body = is_end.advance();
                    break;
                }

                struct json_object items(a);
                bencoded_data value{body};
                value.write_json(items);
                items.close();
            }
            a.close();
    }

    void dictionary::fingerprint(struct buffer_stream &b) const {
            b.write_char('[');

            if (lookahead<dict_end> is_end{tmp}) {
                b.write_char(']');
                tmp = is_end.advance();
                return;
            }

            while(tmp.is_not_empty()) {
                b.write_char('{');

                byte_string key{tmp};
                key.fingerprint(b);

                b.write_char(':');

                bencoded_data value{tmp};
                value.fingerprint(b);

                b.write_char('}');

                if (lookahead<dict_end> is_end{tmp}) {
                    tmp = is_end.advance();
                    break;
                }

                if (tmp.is_not_empty()) {
                    b.write_char(',');
                }
            }
            b.write_char(']');
    }

    void dictionary::write_json(struct json_object &o) {
            
            if (lookahead<dict_end> is_end{tmp}) {
                tmp = is_end.advance();
                return;
            }
            
            struct json_array a{o, "attributes"};
            
            while(tmp.is_not_empty()) {
                
                if (lookahead<dict_end> is_end{tmp}) {
                    tmp = is_end.advance();
                    break;
                }
                
                struct json_object items(a);
                
                byte_string key{tmp};
                items.print_key_json_string("key", key.value());
                
                bencoded_data value{tmp};
                value.write_json(items);
                items.close();
            }
            a.close();
    }
}

void bencoded_data::fingerprint(struct buffer_stream &b) const {
        if (lookahead<encoded<uint8_t>> type{body}) {
            if (type.value == 'i') {
                bencoding::bint integer(body);
                integer.fingerprint(b);
            } else if (type.value >= '0' and type.value <= '9') {
                bencoding::byte_string str(body);
                str.fingerprint(b);
            } else if (type.value == 'd') {
                bencoding::dictionary dict(body);
                dict.fingerprint(b);
            } else if (type.value == 'l') {
                bencoding::blist list(body);
                list.fingerprint(b);  
            } else {
                fprintf(stderr, "Invalid bencoded value\n");
            }
        }
}

void bencoded_data::write_json(struct json_object &o) {
        if (lookahead<encoded<uint8_t>> type{body}) {
            if (type.value == 'i') {
                bencoding::bint integer(body);
                integer.write_json(o);
            } else if (type.value >= '0' and type.value <= '9') {
                bencoding::byte_string str(body);
                str.write_json(o);
            } else if (type.value == 'd') {
                bencoding::dictionary dict(body);
                dict.write_json(o);
            } else if (type.value == 'l') {
                bencoding::blist list(body);
                list.write_json(o);
            }
        }
}


