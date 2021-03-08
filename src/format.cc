// format.cc
//
// translates between and analyzes data formats
//
// g++ -Wall -O3 format.cc -o format
//
// Copyright (c) 2021 Cisco Systems, Inc.  All rights reserved.  License at
// https://github.com/cisco/mercury/blob/master/LICENSE

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>

#include "libmerc/json_object.h"

size_t hex_to_raw(const void *output,
                  size_t output_buf_len,
                  const char *null_terminated_hex_string) {
    const char *hex = null_terminated_hex_string;
    const unsigned char *out = (uint8_t *)output;
    size_t count = 0;

    while (output_buf_len-- > 0) {
        if (hex[0] == 0 || hex[0] == '\n') {
            break;
        }
        if (hex[1] == 0) {
            return count;   /* error */
        }
        sscanf(hex, "%2hhx", (unsigned char *)&out[count++]);
        hex += 2;
    }
    return count;
}

template <typename T> class average {
public:
    average<T>() : sum{0}, longest{0}, count{0} { }

    void update(T x) {
        count++;
        sum += x;
        if (x > longest) { longest = x; }
    }

    double value() {
        return (double)sum/count;
    }

    T get_longest() { return longest; }

private:
    T sum, longest;
    unsigned int count;
};

class data_format {
    size_t total;
    size_t printable;
    size_t ascii;
    size_t initial_graphical;
    size_t initial_caps;
    size_t graphical;
    size_t crlf_count;
    size_t asn1_count;
    size_t asn1_82_count;
    size_t zero_count;
    average<size_t> avg_ascii_run_length;
    average<size_t> avg_printable_run_length;

public:
    size_t get_total() { return total; }
    size_t get_printable_count() { return printable; }
    size_t get_ascii_count() { return ascii; }
    size_t get_initial_graphical_count() { return initial_graphical; }
    size_t get_initial_caps_count() { return initial_caps; }
    size_t get_graphical_count() { return graphical; }
    size_t get_crlf_count() { return crlf_count; }
    size_t get_asn1_count() { return asn1_count; }
    size_t get_asn1_82_count() { return asn1_82_count; }
    size_t get_zero_count() { return zero_count; }
    size_t get_avg_ascii_run_length() { return avg_ascii_run_length.value(); }
    size_t get_longest_ascii_run_length() { return avg_ascii_run_length.get_longest(); }
    size_t get_avg_printable_run_length() { return avg_printable_run_length.value(); }
    size_t get_longest_printable_run_length() { return avg_printable_run_length.get_longest(); }

    float as_fraction(size_t input) {
        return (float)input/total;
    }

    data_format(const uint8_t *data, size_t length) :
        total{length},
        printable{0},
        ascii{0},
        initial_graphical{0},
        initial_caps{0},
        graphical{0},
        crlf_count{0},
        asn1_count{0},
        asn1_82_count{0},
        zero_count{0},
        avg_ascii_run_length{},
        avg_printable_run_length{} {

            size_t ascii_run_length = 0;
            size_t printable_run_length = 0;

            for (size_t i=0; i < length; i++) {
                if (data[i] == 0) {
                    zero_count++;
                }
                if (isprint(data[i])) {
                    printable++;
                    printable_run_length++;
                } else {
                    if (printable_run_length > 0) {
                        avg_printable_run_length.update(printable_run_length);
                    }
                    printable_run_length = 0;
                }
                if (isascii(data[i])) {
                    ascii++;
                    ascii_run_length++;
                } else {
                    if (ascii_run_length > 0) {
                        avg_ascii_run_length.update(ascii_run_length);
                    }
                    ascii_run_length = 0;
                }
                if (initial_graphical == i && isgraph(data[i])) {
                    initial_graphical++;
                }
                if (initial_caps == i && isupper(data[i])) {
                    initial_caps++;
                }
                if (isgraph(data[i])) {
                    graphical++;
                }
                if (i > 0 && data[i-1] == '\r' && data[i] == '\n') {
                    crlf_count++;
                }
                if (i > 0 && data[i-1] == 0x30 && data[i] == 0x82) {
                    asn1_count++;
                }
                if (data[i] == 0x82) {
                    asn1_82_count++;
                }
            }
            if (ascii_run_length > 0) {
                avg_ascii_run_length.update(ascii_run_length);
            }
            if (printable_run_length > 0) {
                avg_printable_run_length.update(printable_run_length);
            }

        }

    void write_json(struct json_object &o) {
    }
};

ssize_t fprintf_hex_as_ascii(FILE *f, const char *line) {
    const char *hex = line;
    const char *init_hex = line;
    unsigned char outchar;

    while (*hex != 0) {
        if (hex[0] == '"') {
            putc('"', f);
            hex += 1;

        } else {
            if (hex[0] == 0) {
                break;
            }
            if (hex[1] == 0) {
                return hex - init_hex;   // error; incomplete hex character pair
            }
            int matched = sscanf(hex, "%2hhx", &outchar);
            if (matched == 1) {
                if (isprint(outchar)) {
                    if (outchar == '"' || outchar == '\\') {
                        putc('\\', f);  // escape special characters
                    }
                    putc(outchar, f);
                } else {
                    putc('.', f);
                }
                hex += 2;

            } else {
                break;
            }
        }
    }
    return hex - init_hex;
}

class ascii_printer {
public:
    ascii_printer(const uint8_t *d, size_t l) : data{d}, length{l} {}

    void operator()(struct buffer_stream &b) {

        b.write_char('"');
        for (size_t i=0; i<length; i++) {
            uint8_t outchar = data[i];
            if (isprint(outchar)) {
                if (outchar == '\n') {
                    b.write_char('\\');
                    b.write_char('n');
                } else if (outchar == '\t') {
                    b.write_char('\\');
                    b.write_char('t');
                }
                if (outchar == '"' || outchar == '\\') {
                    b.write_char('\\');  // escape special characters
                }
                b.write_char(outchar);
            } else {
                b.write_char('.');
            }
        }
        b.write_char('"');
    }

private:
    const uint8_t *data;
    size_t length;
};

int main(int argc, char *argv[]) {
    size_t len = 0;
    char *line = NULL;

    FILE *stream = stdin;

    while (1) {
        ssize_t nread = getline(&line, &len, stream);
        if (nread == -1) {
            free(line);
            return 0;
        }

        uint8_t buffer[8192];

        char output_buffer[8192 * 16];
        struct buffer_stream buf{output_buffer, sizeof(output_buffer)};

        size_t data_len = hex_to_raw(buffer, sizeof(buffer), line);
        if (data_len != 0) {
            struct json_object json{&buf};

            data_format format{buffer, data_len};

            json.print_key_uint("initial_graphical_count", format.get_initial_graphical_count());

            json.print_key_uint("initial_caps_count", format.get_initial_caps_count());

            json.print_key_uint("crlf_count", format.get_crlf_count());

            json.print_key_uint("asn1_count", format.get_asn1_count());

            json.print_key_uint("asn1_82_count", format.get_asn1_82_count());

            json.print_key_float("zero_fraction", format.as_fraction(format.get_zero_count()));

            json.print_key_float("graphical_fraction", format.as_fraction(format.get_graphical_count()));

            json.print_key_float("printable_fraction", format.as_fraction(format.get_printable_count()));

            json.print_key_float("ascii_fraction", format.as_fraction(format.get_ascii_count()));

            json.print_key_float("avg_ascii_run_length", format.get_avg_ascii_run_length());

            json.print_key_uint("longest_ascii_run_length", format.get_longest_ascii_run_length());

            json.print_key_float("avg_printable_run_length", format.get_avg_printable_run_length());

            json.print_key_uint("longest_printable_run_length", format.get_longest_printable_run_length());

            if (format.get_initial_graphical_count() > 2) {
                ascii_printer initial_graphical_printer{buffer, format.get_initial_graphical_count()};
                json.print_key_value("initial_graphical", initial_graphical_printer);
            }

            ascii_printer tmp_printer{buffer, data_len};
            json.print_key_value("ascii", tmp_printer);

            json.print_key_json_string("utf8", buffer, data_len);

            json.print_key_json_string("hex", (uint8_t *)line, 2*data_len);

            json.close();

            buf.write_line(stdout);
        }
    }

    return 0;
}
