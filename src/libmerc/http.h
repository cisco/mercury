/*
 * http.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */


#ifndef HTTP_H
#define HTTP_H

#include <list>
#include <unordered_map>

#include "tcp.h"
#include "match.h"
#include "analysis.h"
#include "fingerprint.h"

struct http_headers : public datum {
    bool complete;

    http_headers() : datum{}, complete{false} {}

    void parse(struct datum &p) {
        unsigned char crlf[2] = { '\r', '\n' };

        data = p.data;
        while (p.length() > 0) {
            if (p.compare(crlf, sizeof(crlf)) == 0) {
                complete = true;
                break;  /* at end of headers */
            }
            if (p.skip_up_to_delim(crlf, sizeof(crlf)) == false) {
                break;
            }
        }
        data_end = p.data;
    }

    void print_host(struct json_object &o, const char *key) const;
    void print_matching_name(struct json_object &o, const char *key, struct datum &name) const;
    void print_matching_names(struct json_object &o, const char *key, std::list<struct datum> &name) const;
    void print_matching_names(struct json_object &o, std::list<std::pair<struct datum, std::string>> &name_list) const;
    void print_matching_names(struct json_object &o, std::unordered_map<std::basic_string<uint8_t>, std::string> &name_dict) const;

    void fingerprint(struct buffer_stream &buf, std::unordered_map<std::basic_string<uint8_t>, bool> &name_dict) const;

    struct datum get_header(const std::basic_string<uint8_t> &header_name);
};

struct http_request : public tcp_base_protocol {
    struct datum method;
    struct datum uri;
    struct datum protocol;
    struct http_headers headers;

    http_request() : method{NULL, NULL}, uri{NULL, NULL}, protocol{NULL, NULL}, headers{} {}

    void parse(struct datum &p);

    bool is_not_empty() const { return protocol.is_not_empty(); }

    void write_json(struct json_object &record, bool output_metadata);

    void operator()(struct buffer_stream &b) const;

    void compute_fingerprint(struct fingerprint &fp) const;

    struct datum get_header(const std::basic_string<uint8_t> &header_name);

    bool do_analysis(const struct key &k_, struct analysis_context &analysis_, classifier *c);

    // weight 14 bitmask that matches all HTTP methods
    //
    static constexpr mask_and_value<8> matcher{
        { 0xe0, 0xe0, 0xe0, 0x80, 0x80, 0x80, 0x80, 0x80 },
        { 0x40, 0x40, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00 }
    };

    static constexpr mask_and_value<8> get_matcher{
        { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 },
        { 'G',  'E',  'T',  ' ',  0x00, 0x00, 0x00, 0x00 }
    };

    static constexpr mask_and_value<8> post_matcher{
        { 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 },
        { 'P',  'O',  'S',  'T',  ' ',  0x00, 0x00, 0x00 }
    };

    static constexpr mask_and_value<8> connect_matcher{
        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        { 'C',  'O',  'N',  'N',  'E',  'C',  'T',  ' ' }
    };

    static constexpr mask_and_value<8> put_matcher{
        { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 },
        { 'P',  'U',  'T',  ' ',  0x00, 0x00, 0x00, 0x00 }
    };

    static constexpr mask_and_value<8> head_matcher{
        { 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 },
        { 'H',  'E',  'A',  'D',  ' ',  0x00, 0x00, 0x00 }
    };

};

struct http_response : public tcp_base_protocol {
    struct datum version;
    struct datum status_code;
    struct datum status_reason;
    struct http_headers headers;

    http_response() : version{NULL, NULL}, status_code{NULL, NULL}, status_reason{NULL, NULL}, headers{} {}

    void parse(struct datum &p);

    bool is_not_empty() const { return status_code.is_not_empty(); }

    void write_json(struct json_object &record);

    void operator()(struct buffer_stream &buf) const;

    void compute_fingerprint(struct fingerprint &fp) const;

    struct datum get_header(const std::basic_string<uint8_t> &header_name);

    static constexpr mask_and_value<8> matcher{
        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00 },
        { 'H',  'T',  'T',  'P',  '/',  '1',  0x00, 0x00 }
    };

};

#endif /* HTTP_H */
