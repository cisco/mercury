/*
 * json_object.h
 *
 * Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */
 #ifndef JSON_BUFFER_H
 #define JSON_BUFFER_H
 
 #include "buffer_stream.h"
 #include "datum.h"
 #include "utf8.hpp"
 
 /*
  * json_object and json_array serialize JSON objects and arrays,
  * respectively, into a buffer
  */
 
 struct json_buffer {
     buffer_stream *b;
     bool comma = false;
     bool array = false;
     void write_comma(bool &c) {
         if (c) {
             b->write_char(',');
         } else {
             c = true;
         }
     }
     explicit json_buffer(struct buffer_stream *buf, bool _array=false) : b{buf}, array{_array} {
         if (array) {
            b->write_char('[');
         } else {
            b->write_char('{');
         }
     }

     explicit json_buffer(json_buffer &buf, bool _array=false) : b{buf.b}, array{_array} {
         if (array) {
            b->write_char('[');
         } else {
            b->write_char('{');
         }
     }

     explicit json_buffer(struct json_object &object) : 
        b{object.b},
        comma{object.comma} {}
     
     void close() {
        if (array) {
            b->write_char(']');
        } else {
            b->write_char('}');
        }
     }
  
     void print_key_string(const struct datum &d) {
         if (d.is_not_readable()) {
             return;
         }
         write_comma(comma);
         utf8_string s{d};
         b->write_char('\"');
         s.fingerprint(*b);
         b->write_char('\"');
         b->write_char(':');
     }

    void print_value_string(const struct 
        datum &d) {
        if (d.is_not_readable()) {
            return;
        }
        if (array) {
            write_comma(comma);
        }
        utf8_string s{d};
        b->write_char('\"');
        s.fingerprint(*b);
        b->write_char('\"');
    }
         
     void print_value_bool(bool x) {
        if (array) {
            write_comma(comma);
        }
         if (x) {
             b->puts("true");
         } else {
             b->puts("false");
         }
     }
     void print_value_null() {
        if (array) {
            write_comma(comma);
        }
         b->puts("\"null");
     }

     void print_value_uint64(uint64_t u) {
        if (array) {
            write_comma(comma);
        }
        b->snprintf("%lu", u);
     }
     void print_value_uint64_hex(uint64_t u) {
        if (array) {
            write_comma(comma);
        }
        b->write_char('"');
        b->write_hex_uint(u);
        b->write_char('"');
     }
    
     void print_value_hex(const struct datum &value) {
        if (array) {
            write_comma(comma);
        }
        b->write_char('\"');
         if (value.data && value.data_end && value.data_end > value.data) {
             b->raw_as_hex(value.data, value.data_end - value.data);
         }
        b->write_char('\"');
     }
     void print_value_base64(const struct datum &value) {
            if (array) {
            write_comma(comma);
        }
        b->write_char('\"');
         if (value.data && value.data_end && value.data_end > value.data) {
             b->raw_as_base64(value.data, value.data_end - value.data);
         }
        b->write_char('\"');
     }
 };
 #endif
 
 