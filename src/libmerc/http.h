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

#include "protocol.h"
#include "match.h"
#include "analysis.h"
#include "fingerprint.h"
#include "perfect_hash.h"
#include "flow_key.h"
#include "cbor.hpp"
#include "cbor_object.hpp"

struct http_headers : public datum {
    bool complete;

    http_headers() : datum{}, complete{false} {}

    void parse(struct datum &p) {
        unsigned char crlf[2] = { '\r', '\n' };

        data = p.data;
        while (p.length() > 0) {
            if (p.compare(crlf, sizeof(crlf)) == 0) {
                p.skip(sizeof(crlf));
                complete = true;
                break;  /* at end of headers */
            }
            if (p.skip_up_to_delim(crlf, sizeof(crlf)) == false) {
                break;
            }
        }
        data_end = p.data;
    }

    // parses the headers for end of headers while ignoring missing CR '\r' in delimiter for header fields
    //
    void parse_ignore_cr(struct datum &p) {
        unsigned char lf[1] = { '\n' };
        unsigned char crlf[2] = { '\r', '\n'};

        data = p.data;
        while (p.length() > 0) {
            if (p.compare(lf, sizeof(lf)) == 0 || p.compare(crlf, sizeof(crlf)) == 0) {
                complete = true;
                break;  /* at end of headers */
            }
            if (p.skip_up_to_delim(lf, sizeof(lf)) == false) {
                break;
            }
        }
        data_end = p.data;
    }

    void print_host(struct json_object &o, const char *key) const;
    void print_matching_name(struct json_object &o, const char *key, struct datum &name) const;
    void print_matching_name(struct json_object &o, const char *key, const char* name) const;
    void print_matching_names(struct json_object &o, perfect_hash<const char*> &ph) const;
    void print_ssdp_names_and_feature_string(struct json_object &o, data_buffer<2048>& feature_buf, bool metadata) const;

    void fingerprint(struct buffer_stream &buf, perfect_hash<bool> &fp_data) const;

    struct datum get_header(const char *header_name);
};

class token : public datum {
public:
    token (struct datum& d) {
        datum::parse_up_to_delim(d, ':'); 
    }
};

class LWS {
public:

    LWS(struct datum &p) {
        while (p.is_readable() and (*p.data == '\t' or *p.data == ' ')) {
            p.data++;
        }
    }
};

class field_value : public datum {
public:
    field_value (struct datum& d) {
        datum::parse_up_to_delimiters(d, '\r', '\n');
    }
};

class delimiter {
    datum delimit;
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char lf[1] = { '\n' };

public:
    delimiter(struct datum &p) {
        delimit.data = p.data;
        while (p.data < p.data_end and !isalpha(*p.data)) {
            p.data++;
        }
        delimit.data_end = p.data;
    }

    delimiter(struct datum &p, const struct datum& del) : delimit{nullptr, nullptr} {
        if (p.compare_nbytes(del.data, del.length())) {
            delimit.parse(p, del.length());
        } else {
            check_standard_delim(p);
        }
    }
 
    void check_standard_delim(struct datum &p) {
        if (p.compare_nbytes(crlf, sizeof(crlf))) {
            delimit.parse(p, sizeof(crlf));
        } else if (p.compare_nbytes(lf, sizeof(lf))) {
            delimit.parse(p, sizeof(lf));
        }
    }

    const datum get_delimiter() const {
        return delimit;
    }

    void write_json(json_object &rec) const {
        rec.print_key_json_string("delimiter", delimit);
    }

    bool is_valid() const {
        return delimit.is_not_empty();
    }
 
};

struct httpheader {
    datum hdr_body;
    token name;
    literal_byte<':'> colon;
    LWS lws;
    field_value value;
    delimiter delim;
    bool valid;

    httpheader(datum &d, datum del) :
    hdr_body{d},
    name{d},
    colon{d},
    lws{d},
    value{d},
    delim{d, del} {
        hdr_body.data_end = value.data_end;
        valid = d.is_not_null();
    }

    httpheader(datum &d) :
    hdr_body{d},
    name{d},
    colon{d},
    lws{d},
    value{d},
    delim{d} {
        hdr_body.data_end = value.data_end;
        valid = d.is_not_null();
    }

    void fingerprint(struct buffer_stream &buf, perfect_hash<bool> &fp_data) const {
        if (!is_valid()) {
            return;
        }

        bool include_name = false;
        const bool include_value = *(fp_data.lookup(name.data, name.length(), include_name));
        if (include_name) {
            if (include_value) {
                buf.write_char('(');
                buf.raw_as_hex(hdr_body.data, hdr_body.length());         // write {name, value}
                buf.write_char(')');
            } else {
                buf.write_char('(');
                buf.raw_as_hex(name.data, name.length()); // write {name}
                buf.write_char(')');
            }
        }
    }

    bool is_valid () const {
        return valid;
    }

    void write_json(json_array &a) const {
        if (!is_valid()) {
            return;
        }

        json_object hdr{a};
        hdr.print_key_json_string("name", name);
        hdr.print_key_json_string("value", value);
        delim.write_json(hdr);
        hdr.close();
    }
};

template <size_t N>
class new_http_headers {
    datum header_body;
    datum delim;
    std::array<datum, N> headers;
    static constexpr size_t max_body_length = 512;  // limit on number of bytes reported

public:

    new_http_headers() :
    header_body{nullptr, nullptr},
    delim{nullptr, nullptr} {
    }

    httpheader get_next_header(struct datum& p) {
        return httpheader(p, delim);
    }

    datum get_header(size_t index) const {
        return headers[index];
    }

    void set_header_body(datum &d) {
        header_body = d;
    }

    void set_delimiter(datum _delim) {
        delim = _delim;
    }

    void write_json(struct json_object &record) {
        httpheader h = get_next_header(header_body);
        if (h.is_valid()) {
            json_array hdrs{record, "headers"};
            h.write_json(hdrs);
            while(1) { 
                delimiter d(header_body, delim);
                if (d.is_valid()) {
                    break;
                }
                httpheader h = get_next_header(header_body);
                if (!h.is_valid()) {
                    break;
                }
                h.write_json(hdrs);
            }
            hdrs.close();
        }
        if (header_body.is_readable()) {
            datum body = header_body;
            body.trim_to_length(max_body_length);
            record.print_key_hex("body", body);
        }
    }

    void write_l7_metadata(cbor_object &o) {
        httpheader h = get_next_header(header_body);
        if (h.is_valid()) {
            cbor_array hdrs{o, "headers"};
            hdrs.print_string(h.name);
            while(1) { 
                delimiter d(header_body, delim);
                if (d.is_valid()) {
                    break;
                }
                httpheader h = get_next_header(header_body);
                if (!h.is_valid()) {
                    break;
                }
                hdrs.print_string(h.name);
            }
            hdrs.close();
        }
    }


    /*
     * HTTP headers are parsed during fingerprinting. When there
     * are headers of interest, their values are stored in the
     * headers array.
     * The headers of interest are defined in the perfect hash table `ph`,
     * which stores the header name and the corresponding index.
     * If the parsed header is present in the hash table `ph`, the index
     * is retrieved and used to store the header value in the
     * headers array.
     *
     * Input Arguments:
     * b       - buffer stream to write the fingerprint.
     * fp_data - perfect hash table used to determine if the header or
     *           header-value pair should be part of the fingerprint.
     * ph      - perfect hash table used to determine if the header value
     *           needs to be stored and, if so, provides the index at
     *           which the value is stored.
     */
    void fingerprint(struct buffer_stream &b, perfect_hash<bool> &fp_data,
                     perfect_hash<uint8_t> &ph) {
        datum tmp = header_body;
        while(1) {
            delimiter d(tmp, delim);
            if (d.is_valid()) {
                break;
            }
            httpheader h = get_next_header(tmp);
            if (!h.is_valid()) {
                break;
            }
            h.fingerprint(b, fp_data);
            bool is_header_found = false;
            uint8_t header_idx = *ph.lookup(h.name.data, h.name.length(), is_header_found);
            if (is_header_found) {
                /* Incase of duplicate http headers, index of the first http header
                 * is stored.
                 */
                if (headers[header_idx].is_null()) {
                    headers[header_idx] = h.value;
                }
            }
        }
    }
};

struct http_request : public base_protocol {
    static constexpr uint8_t num_headers_to_report = 7;
    struct datum method;
    struct datum uri;
    struct datum protocol;
    new_http_headers<num_headers_to_report> headers;

    static constexpr static_dictionary<num_headers_to_report> req_hdrs {
        {
            "user-agent",
            "host",
            "x-forwarded-for",
            "via",
            "upgrade",
            "referer",
            "authorization"
        }
    };

    http_request(datum &p) :
    method{NULL, NULL},
    uri{NULL, NULL},
    protocol{NULL, NULL} {
        parse(p);
    }

    datum get_header(const char *name) const {
        return(headers.get_header(req_hdrs.index(name)));
    }
 
    void parse(struct datum &p);

    bool is_not_empty() const { return protocol.is_not_empty(); }

    void write_json(struct json_object &record, bool output_metadata);

    void write_l7_metadata(writeable &output, bool output_metadata);

    void fingerprint(struct buffer_stream &b);

    void compute_fingerprint(class fingerprint &fp);

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

struct http_response : public base_protocol {
    static constexpr uint8_t num_headers_to_report = 4;
    struct datum version;
    struct datum status_code;
    struct datum status_reason;
    new_http_headers<num_headers_to_report> headers;
    static constexpr static_dictionary<num_headers_to_report> resp_hdrs {
        {
            "content-type",
            "content-length",
            "server",
            "via"
        }
    };

    http_response(datum &p) : version{NULL, NULL}, status_code{NULL, NULL}, status_reason{NULL, NULL} { parse(p); }

    void parse(struct datum &p);

    bool is_not_empty() const { return status_code.is_not_empty(); }

    void write_json(struct json_object &record, bool metadata=false);

    void write_l7_metadata(writeable &output, bool output_metadata);

    void fingerprint(struct buffer_stream &buf);

    void compute_fingerprint(class fingerprint &fp);

    struct datum get_header(const char *header_name);

    static constexpr mask_and_value<8> matcher{
        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00 },
        { 'H',  'T',  'T',  'P',  '/',  '1',  0x00, 0x00 }
    };

};

namespace {

    [[maybe_unused]] int http_request_fuzz_test(const uint8_t *data, size_t size) {
        struct datum request_data{data, data+size};
        char buffer_1[8192];
        struct buffer_stream buf_json(buffer_1, sizeof(buffer_1));
        char buffer_2[8192];
        struct buffer_stream buf_fp(buffer_2, sizeof(buffer_2));
        struct json_object record(&buf_json);

        http_request request{request_data};
        if (request.is_not_empty()) {
            request.write_json(record, true);
            request.fingerprint(buf_fp);
        }

        return 0;
    }

    [[maybe_unused]] int http_response_fuzz_test(const uint8_t *data, size_t size) {
        struct datum response_data{data, data+size};
        char buffer_1[8192];
        struct buffer_stream buf_json(buffer_1, sizeof(buffer_1));
        char buffer_2[8192];
        struct buffer_stream buf_fp(buffer_2, sizeof(buffer_2));
        struct json_object record(&buf_json);

        http_response response{response_data};
        if (response.is_not_empty()) {
            response.write_json(record, true);
            response.fingerprint(buf_fp);
        }

        return 0;
    }

};

#endif /* HTTP_H */
