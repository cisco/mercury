/*
 * http.h
 */


#ifndef HTTP_H
#define HTTP_H

#include "extractor.h"

struct http_headers : public parser {

    http_headers() : parser{NULL, NULL} {}

    void print_host(struct json_object &o, const char *key) const;
    void print_matching_name(struct json_object &o, const char *key, struct parser &name) const;
    void print_matching_names(struct json_object &o, const char *key, std::list<struct parser> &name) const;
    void print_matching_names(struct json_object &o, std::list<std::pair<struct parser, std::string>> &name_list) const;
};

struct http_request {
    struct parser method;
    struct parser uri;
    struct parser protocol;
    struct http_headers headers;

    http_request() : method{NULL, NULL}, uri{NULL, NULL}, protocol{NULL, NULL} {}

    void parse(struct parser &p);

    static void write_json(struct parser data, struct json_object &record, bool output_metadata);

};

struct http_response {
    struct parser version;
    struct parser status_code;
    struct parser status_reason;
    struct http_headers headers;

    http_response() : version{NULL, NULL}, status_code{NULL, NULL}, status_reason{NULL, NULL}, headers{} {}

    void parse(struct parser &p);

    static void write_json(struct parser data, struct json_object &record);

};

#endif /* HTTP_H */
