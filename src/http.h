/*
 * http.h
 */


#ifndef HTTP_H
#define HTTP_H

#include "extractor.h"

struct http_headers : public parser {

    http_headers() : parser{} {}

    void parse(struct parser &p) {
        unsigned char crlf[2] = { '\r', '\n' };

        data = p.data;
        while (parser_get_data_length(&p) > 0) {
            if (parser_match(&p, crlf, sizeof(crlf), NULL) == status_ok) {
                break;  /* at end of headers */
            }
            if (parser_skip_upto_delim(&p, crlf, sizeof(crlf)) == status_err) {
                break;
            }
        }
        data_end = p.data;
    }

    void print_host(struct json_object &o, const char *key) const;
    void print_matching_name(struct json_object &o, const char *key, struct parser &name) const;
    void print_matching_names(struct json_object &o, const char *key, std::list<struct parser> &name) const;
    void print_matching_names(struct json_object &o, std::list<std::pair<struct parser, std::string>> &name_list) const;

    void fingerprint(struct buffer_stream &buf, std::unordered_map<std::basic_string<uint8_t>, bool> &name_dict) const;

};

struct http_request {
    struct parser method;
    struct parser uri;
    struct parser protocol;
    struct http_headers headers;

    http_request() : method{NULL, NULL}, uri{NULL, NULL}, protocol{NULL, NULL}, headers{} {}

    void parse(struct parser &p);

    static void write_json(struct parser data, struct json_object &record, bool output_metadata);

    void operator()(struct buffer_stream &b) const;

};

struct http_response {
    struct parser version;
    struct parser status_code;
    struct parser status_reason;
    struct http_headers headers;

    http_response() : version{NULL, NULL}, status_code{NULL, NULL}, status_reason{NULL, NULL}, headers{} {}

    void parse(struct parser &p);

    static void write_json(struct parser data, struct json_object &record);

    void operator()(struct buffer_stream &buf) const;

};

#endif /* HTTP_H */
