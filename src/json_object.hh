#ifndef JSON_OBJECT_HH

#include <stdio.h>
#include "buffer_stream.h"

/*
 * json_object and json_array serialize JSON objects and arrays,
 * respectively, into a buffer
 */

struct json_object {
    buffer_stream *b;
    char comma = ' ';
    explicit json_object(struct buffer_stream *buf) : b{buf} {
        b->write_char('{');
    }
    explicit json_object(struct buffer_stream *buf, const char *name) : b{buf} {
        b->write_char('\"');
        b->puts(name);
        b->puts("\":{");
    }
    json_object(struct json_object &object, const char *name) : b{object.b} {
        //fprintf(stderr, "json_object constructor (name: %s, comma: %c)\n", name, comma);
        b->write_char(object.comma);
        b->write_char('\"');
        b->puts(name);
        b->puts("\":{");
        object.comma = ',';
    }
    json_object(struct json_object &object) : b{object.b} {
        //fprintf(stderr, "json_object constructor (comma: %c)\n", comma);
        b->write_char(object.comma);
        b->write_char('{');
        object.comma = ',';
    }
    explicit json_object(struct json_array &array);
    void reinit(struct json_array &array);
    void close() {
        b->write_char('}');
    }
    void print_key_string(const char *k, const char *v) {
        b->write_char(comma);
        b->write_char('\"');
        b->puts(k);
        b->puts("\":\"");
        b->puts(v);
        b->write_char('\"');
        comma = ',';
    }
    void print_key_bool(const char *k, bool x) {
        b->write_char(comma);
        b->write_char('\"');
        b->puts(k);
        b->puts("\":");
        if (x) {
            b->puts("true");
        } else {
            b->puts("false");
        }
        comma = ',';
    }
    void print_key_null(const char *k) {
        b->write_char(comma);
        b->write_char('\"');
        b->puts(k);
        b->puts("\":null");
        comma = ',';
    }
    void print_key_uint(const char *k, unsigned long int u) {
        b->snprintf("%c\"%s\":%lu", comma, k, u);
        comma = ',';
    }
    void print_key_int(const char *k, long int i) {
        b->snprintf("%c\"%s\":%ld", comma, k, i);
        comma = ',';
    }
    void print_key_float(const char *k, double d) {
        b->snprintf("%c\"%s\":%f", comma, k, d);
        comma = ',';
    }
    void print_key_hex(const char *k, const struct parser &value) {
        b->write_char(comma);
        b->write_char('\"');
        b->puts(k);
        b->puts("\":\"");
        if (value.data && value.data_end) {
            b->raw_as_hex(value.data, value.data_end - value.data);
        }
        b->write_char('\"');
        comma = ',';
    }
    void print_key_base64(const char *k, const struct parser &value) {
        b->write_char(comma);
        b->write_char('\"');
        b->puts(k);
        b->puts("\":");
        if (value.data && value.data_end) {
            b->raw_as_base64(value.data, value.data_end - value.data); 
        }
        comma = ',';
    }

};

struct json_array {
    buffer_stream *b;
    char comma = ' ';
    explicit json_array(struct buffer_stream *buf) : b{buf} {
        b->write_char('[');
    }
    json_array(struct json_object &object, const char *name) : b{object.b} {
        b->write_char(object.comma);
        b->write_char('\"');
        b->puts(name);
        b->puts("\":[");
        object.comma = ',';
    }
    void close() {
        b->write_char(']');
    }
    void print_bool(bool x) {
        b->write_char(comma);
        if (x) {
            b->puts("true");
        } else {
            b->puts("false");
        }
        comma = ',';
    }
    void print_null() {
        b->write_char(comma);
        b->puts("null");
        comma = ',';
    }
    void print_key_uint(unsigned long int u) {
        b->write_char(comma);
        b->snprintf("%lu", u);
        comma = ',';
    }
    void print_int(long int i) {
        b->write_char(comma);
        b->snprintf("%ld", i);
        comma = ',';
    }
    void print_float(double d) {
        b->write_char(comma);
        b->snprintf("%f", d);
        comma = ',';
    }
    void print_string(const char *s) {
        b->write_char(comma);
        b->write_char('\"');
        b->puts(s);
        b->write_char('\"');
        comma = ',';
    }
};

inline json_object::json_object(struct json_array &array) : b{array.b} {
    b->write_char(array.comma);
    b->write_char('{');
    array.comma = ',';
}

inline void json_object::reinit(struct json_array &array) {
    b->write_char('}');
    b->write_char(',');
    b->write_char('{');
    comma = ' ';
    array.comma = ',';
}

#ifdef USE_JSON_FILE_OBJECT
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

#endif // JSON_OBJECT_HH
