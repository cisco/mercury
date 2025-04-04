/*
 * json_object.h
 *
 * Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */
#ifndef JSON_OBJECT_H
#define JSON_OBJECT_H

#include "buffer_stream.h"
#include "datum.h"
#include "utf8.hpp"

/*
 * json_object and json_array serialize JSON objects and arrays,
 * respectively, into a buffer
 */

struct json_object {
    buffer_stream *b;
    bool comma = false;
    void write_comma(bool &c) {
        if (c) {
            b->write_char(',');
        } else {
            c = true;
        }
    }
    explicit json_object(struct buffer_stream *buf) : b{buf} {
        b->write_char('{');
    }
    explicit json_object(struct buffer_stream *buf, const char *name) : b{buf} {
        b->write_char('\"');
        b->puts(name);
        b->puts("\":{");
    }
    json_object(struct json_object &object, const char *name) : b{object.b} {
        write_comma(object.comma);
        b->write_char('\"');
        b->puts(name);
        b->puts("\":{");
    }
    json_object(struct json_object &object) : b{object.b} {
        write_comma(object.comma);
        b->write_char('{');
    }
    explicit json_object(struct json_array &array);
    void reinit(struct json_array &array);
    void close() {
        b->write_char('}');
    }
    void print_key_json_string(const char *k, const uint8_t *v, size_t length) {
        if (v) {
            utf8_string s{v, v+length};
            print_key_value(k, s);
        }
    }
    void print_key_json_string(const char *k, const struct datum &d) {
        if (d.is_not_readable()) {
            return;
        }
        utf8_string s{d};
        print_key_value(k, s);
    }
    void print_key_string(const char *k, const char *v) {
        write_comma(comma);
        b->write_char('\"');
        b->puts(k);
        b->puts("\":\"");
        b->puts(v);
        b->write_char('\"');
    }
    void print_key_bool(const char *k, bool x) {
        write_comma(comma);
        b->write_char('\"');
        b->puts(k);
        b->puts("\":");
        if (x) {
            b->puts("true");
        } else {
            b->puts("false");
        }
    }
    void print_key_null(const char *k) {
        write_comma(comma);
        b->write_char('\"');
        b->puts(k);
        b->puts("\":null");
    }
    void print_key_uint8(const char *k, uint8_t u) {
        write_comma(comma);
        b->write_char('\"');
        b->puts(k);
        b->write_char('\"');
        b->write_char(':');
        b->write_uint8(u);
    }
    void print_key_uint8_hex(const char *k, uint8_t u) {
        write_comma(comma);
        b->snprintf("\"%s\":\"", k);
        b->write_hex_uint(u);
        b->write_char('\"');
    }
    void print_key_uint16(const char *k, uint16_t u) {
        write_comma(comma);
        b->write_char('\"');
        b->puts(k);
        b->write_char('\"');
        b->write_char(':');
        b->write_uint16(u);
    }
    void print_key_uint16_hex(const char *k, uint16_t u) {
        write_comma(comma);
        b->snprintf("\"%s\":\"", k);
        b->write_hex_uint(u);
        b->write_char('\"');
    }
    void print_key_uint(const char *k, unsigned long int u) { // note: JSON can't represent a uint64_t over 2^53
        write_comma(comma);
        b->snprintf("\"%s\":%lu", k, u);
    }
    void print_key_int(const char *k, long int i) {
        write_comma(comma);
        b->snprintf("\"%s\":%ld", k, i);
    }
    void print_key_float(const char *k, double d) {
        write_comma(comma);
        b->snprintf("\"%s\":%f", k, d);
    }
    void print_key_uint64_hex(const char *k, uint64_t  u) {
        write_comma(comma);
        b->snprintf("\"%s\":\"", k);
        b->write_hex_uint(u);
        b->write_char('\"');
    }
    template <typename U>
    void print_key_uint_hex(const char *k, U u) {
        // U must be an unsigned integer type, or an encoded<> type
        write_comma(comma);
        b->snprintf("\"%s\":\"", k);
        b->write_hex_uint(u);
        b->write_char('\"');
    }
    template <typename uint>
    void print_key_unknown_code(const char *k, uint u) {
        write_comma(comma);
        b->snprintf("\"%s\":\"UNKNOWN (", k);
        b->write_hex_uint(u);
        b->write_char(')');
        b->write_char('\"');
    }
    void print_key_hex(const char *k, const struct datum &value) {
        write_comma(comma);
        b->write_char('\"');
        b->puts(k);
        b->puts("\":\"");
        if (value.data && value.data_end && value.data_end > value.data) {
            b->raw_as_hex(value.data, value.data_end - value.data);
        }
        b->write_char('\"');
    }
    void print_key_hex(const char *k, const uint8_t *v, size_t length) {
        write_comma(comma);
        b->write_char('\"');
        b->puts(k);
        b->puts("\":\"");
        b->raw_as_hex(v, length);
        b->write_char('\"');
    }
    void print_key_base64(const char *k, const struct datum &value) {
        write_comma(comma);
        b->write_char('\"');
        b->puts(k);
        b->puts("\":");
        if (value.data && value.data_end) {
            b->raw_as_base64(value.data, value.data_end - value.data);
        } else {
            b->write_char('\"');
            b->write_char('\"');
        }
    }
    void print_key_timestamp(const char *k, struct timespec *ts) {
        write_comma(comma);
        b->write_char('\"');
        b->puts(k);
        b->puts("\":");
        b->write_timestamp(ts);
    }
    void print_key_timestamp_as_string(const char *k, struct timespec *ts) {
        write_comma(comma);
        b->write_char('\"');
        b->puts(k);
        b->puts("\":\"");
        b->write_timestamp_as_string(ts);
        b->write_char('\"');
    }
    template <typename T> void print_key_value(const char *k, T &w) {
        write_comma(comma);
        b->write_char('\"');
        b->puts(k);
        b->puts("\":\"");
        w.fingerprint(*b);
        b->write_char('\"');
     }
    void print_key_ipv4_addr(const char *k, const uint8_t *a) {
        write_comma(comma);
        b->write_char('\"');
        b->puts(k);
        b->puts("\":");
        b->write_char('\"');
        b->write_ipv4_addr(a);
        b->write_char('\"');
    }
    void print_key_ipv6_addr(const char *k, const uint8_t *a) {
        write_comma(comma);
        b->write_char('\"');
        b->puts(k);
        b->puts("\":");
        b->write_char('\"');
        b->write_ipv6_addr(a);
        b->write_char('\"');
    }
    void print_key_datum(const char *k, const struct datum &d) {
        write_comma(comma);
        b->write_char('\"');
        b->puts(k);
        b->puts("\":{");
        b->snprintf("\"data\":\"%p\",", d.data);
        b->snprintf("\"data_end\":\"%p\"", d.data_end);
        b->write_char('}');
    }
};

struct json_array {
    buffer_stream *b;
    bool comma = false;
    void write_comma(bool &c) {
        if (c) {
            b->write_char(',');
        } else {
            c = true;
        }
    }
    explicit json_array(struct buffer_stream *buf) : b{buf} {
        b->write_char('[');
    }
    explicit json_array(json_array &a) : b{a.b} {
        write_comma(a.comma);
        b->write_char('[');
    }
    json_array(struct json_object &object, const char *name) : b{object.b} {
        write_comma(object.comma);
        b->write_char('\"');
        b->puts(name);
        b->puts("\":[");
    }
    void close() {
        b->write_char(']');
    }
    void print_bool(bool x) {
        write_comma(comma);
        if (x) {
            b->puts("true");
        } else {
            b->puts("false");
        }
    }
    void print_null() {
        write_comma(comma);
        b->puts("null");
    }
    void print_uint16_hex(uint16_t u) {
        write_comma(comma);
        b->write_char('\"');
        b->write_hex_uint(u);
        b->write_char('\"');
    }
    void print_uint(unsigned long int u) {
        write_comma(comma);
        b->snprintf("%lu", u);
    }
    void print_int(long int i) {
        write_comma(comma);
        b->snprintf("%ld", i);
    }
    void print_float(double d) {
        write_comma(comma);
        b->snprintf("%f", d);
    }
    void print_string(const char *s) {
        write_comma(comma);
        b->write_char('\"');
        b->puts(s);
        b->write_char('\"');
    }
    void print_json_string(const struct datum &d) {
        if (d.is_not_readable()) {
            return;
        }
        utf8_string s{d};
        print_key(s);
    }
    void print_base64(const uint8_t *data, size_t length) {
        write_comma(comma);
        if (data) {
            b->raw_as_base64(data, length);
        } else {
            b->write_char('\"');
            b->write_char('\"');
        }
    }
    void print_hex(const struct datum &value) {
        write_comma(comma);
        b->write_char('\"');
        if (value.data && value.data_end) {
            b->raw_as_hex(value.data, value.data_end - value.data);
        }
        b->write_char('\"');
    }
    template <typename T> void print_key(T &w) {   // shouldn't this be named print_value()?
        write_comma(comma);
        b->write_char('\"');
        w.fingerprint(*b);
        b->write_char('\"');
    }

};

inline json_object::json_object(struct json_array &array) : b{array.b} {
    write_comma(array.comma);
    b->write_char('{');
}

inline void json_object::reinit(struct json_array &array) {
    b->write_char('}');
    b->write_char(',');
    b->write_char('{');
    comma = false;
    array.comma = true;
}

/// enable libfuzz to test a class T that parses a data buffer and
/// writes out JSON, by providing a template function that does most
/// of the work.
///
template <typename T, size_t N=8192>
int json_output_fuzzer(const uint8_t *data, size_t size) {
    struct datum data_to_be_parsed{data, data+size};
    T data_parser_object{data_to_be_parsed};
    if (data_to_be_parsed.is_not_null()) {
        char output_buffer[N];
        struct buffer_stream buf_json(output_buffer, sizeof(output_buffer));
        struct json_object record(&buf_json);
        data_parser_object.write_json(record, true);
    }
    return 0;
}


#ifdef USE_JSON_FILE_OBJECT
#include <stdio.h>
/*
 * json_file_object and json_file_array serialize JSON objects and
 * arrays, respectively, into a FILE.
 */

struct json_file_object {
    FILE *f;
    char comma = ' ';
    explicit json_file_object(FILE *file) : f{file} {
        fputc('{', f);
    }
    json_file_object(struct json_file_object &object, const char *name) : f{object.f} {
        fputc(object.comma, f);
        fputc('\"', f);
        fputs(name, f);
        fputs("\":{", f);
        object.comma = ',';
    }
    explicit json_file_object(struct json_file_array &array);
    void close() {
        fputc('}', f);
    }
    void print_key_string(const char *k, const char *v) {
        fputc(comma, f);
        fputc('\"', f);
        fputs(k, f);
        fputs("\":\"", f);
        fputs(v, f);
        fputc('\"', f);
        comma = ',';
    }
    void print_key_uint(const char *k, unsigned long int u) {
        fprintf(f, "%c\"%s\":%lu", comma, k, u);
        comma = ',';
    }
    void print_key_int(const char *k, long int i) {
        fprintf(f, "%c\"%s\":%ld", comma, k, i);
        comma = ',';
    }
    void print_key_float(const char *k, double d) {
        fprintf(f, "%c\"%s\":%f", comma, k, d);
        comma = ',';
    }
};

struct json_file_array {
    FILE *f;
    char comma = ' ';
    explicit json_file_array(FILE *file) : f{file} {
        fputc('[', f);
    }
    json_file_array(struct json_file_object &object, const char *name) : f{object.f} {
        fputc(object.comma, f);
        fputc('\"', f);
        fputs(name, f);
        fputs("\":[", f);
        object.comma = ',';
    }
    void close() {
        fputc(']', f);
    }
    void print_key_string(const char *k, const char *v) {
        fputc(comma, f);
        fputs("{\"", f);
        fputs(k, f);
        fputs("\":\"", f);
        fputs(v, f);
        fputs("\"}", f);
        comma = ',';
    }
    void print_int(long int i) {
        fprintf(f, "%c%ld", comma, i);
        comma = ',';
    }
};

json_file_object::json_file_object(struct json_file_array &array) : f{array.f} {
    fprintf(f, "%c{", array.comma);
    array.comma = ',';
}

#endif // USE_JSON_FILE_OBJECT

#endif // JSON_OBJECT_H
