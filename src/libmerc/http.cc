/*
 * http.c
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <unordered_map>
#include <string>
#include "bytestring.h"
#include "http.h"
#include "json_object.h"
#include "match.h"

inline void to_lower(std::basic_string<uint8_t> &str, struct datum d) {
    if (d.is_not_readable()) {
        return;
    }
    while (d.data < d.data_end) {
        str.push_back(tolower(*d.data++));
    }
}

void http_request::parse(struct datum &p) {
    std::array<uint8_t, 6> proto_string{'H', 'T', 'T', 'P', '/', '1'};

    /* parse request line */
    method.parse_up_to_delim(p, ' ');
    if (method.length() < 3 || method.length() > 16 || !method.isupper()) {
        return;            // invalid format; not an HTTP method
    }
    p.skip(1);
    uri.parse_up_to_delim(p, ' ');
    p.skip(1);
    protocol.parse_up_to_delim(p, '\r');
    if (!protocol.matches(proto_string)) {
        protocol.set_null();
        return;            // invalid format; unrecognized protocol
    }
    p.skip(2);

    /* parse headers */
    headers.parse(p);

    return;
}

void http_headers::print_matching_name(struct json_object &o, const char *key, const char *name) const {
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };

    if (this->is_not_readable()) {
        return;
    }
    struct datum p{this->data, this->data_end};  // create copy, to leave object unmodified

    while (p.length() > 0) {
        if (p.compare(crlf, sizeof(crlf)) == 0) {
            break;  /* at end of headers */
        }

        struct datum keyword{p.data, NULL};
        if (p.skip_up_to_delim(csp, sizeof(csp)) == false) {
            return;
        }
        keyword.data_end = p.data;
        const char *header_name = NULL;

        std::basic_string<uint8_t> name_lowercase;
        to_lower(name_lowercase, keyword);
        
        if(strcmp(key, (const char*)name_lowercase.data()) == 0)
        {
            header_name = name;
        }
        
        const uint8_t *value_start = p.data;
        if (p.skip_up_to_delim(crlf, sizeof(crlf)) == false) {
            return;
        }
        const uint8_t *value_end = p.data - 2;
        if (header_name) {
            o.print_key_json_string(header_name, value_start, value_end - value_start);
        }
    }
}

void http_headers::print_matching_names(struct json_object &o, perfect_hash_visitor &name_dict, perfect_hash_table_type type) const {
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };

    if (this->is_not_readable()) {
        return;
    }
    struct datum p{this->data, this->data_end};  // create copy, to leave object unmodified

    while (p.length() > 0) {
        if (p.compare(crlf, sizeof(crlf)) == 0) {
            break;  /* at end of headers */
        }

        struct datum keyword{p.data, NULL};
        if (p.skip_up_to_delim(csp, sizeof(csp)) == false) {
            return;
        }
        keyword.data_end = p.data;
        const char *header_name = NULL;

        std::basic_string<uint8_t> name_lowercase;
        to_lower(name_lowercase, keyword);
        bool is_header_found = false;
        header_name = *name_dict.lookup_string(type, (const char*)name_lowercase.data(), is_header_found);
        if(!is_header_found)
            header_name = nullptr;
        
        const uint8_t *value_start = p.data;
        if (p.skip_up_to_delim(crlf, sizeof(crlf)) == false) {
            return;
        }
        const uint8_t *value_end = p.data - 2;
        if (header_name) {
            o.print_key_json_string(header_name, value_start, value_end - value_start);
        }
    }
}

void http_headers::fingerprint(struct buffer_stream &buf, perfect_hash_visitor& ph, const perfect_hash_table_type type) const {
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };

    struct datum p{this->data, this->data_end};  // create copy, to leave object unmodified

    while (p.length() > 0) {
        if (p.compare(crlf, sizeof(crlf)) == 0) {
            break;  /* at end of headers */
        }

        struct datum name{p.data, NULL};
        if (p.skip_up_to_delim(csp, sizeof(csp)) == false) {
            return;
        }
        name.data_end = p.data;
        bool include_name = false;

        std::basic_string<uint8_t> name_lowercase;
        to_lower(name_lowercase, name);
        const bool include_value = *(ph.lookup_bool(type, (const char*)name_lowercase.data(), include_name));

        if (p.skip_up_to_delim(crlf, sizeof(crlf)) == false) {
            return;
        }
        const uint8_t *name_end = p.data - 2;
        if (include_name) {
            if (include_value) {
                buf.write_char('(');
                buf.raw_as_hex(name.data, name_end - name.data);         // write {name, value}
                buf.write_char(')');
            } else {
                buf.write_char('(');
                buf.raw_as_hex(name.data, name.data_end - name.data - 2); // write {name}
                buf.write_char(')');
            }
        }
    }
}

void http_request::write_json(struct json_object &record, bool output_metadata) {

    if (this->is_not_empty()) {
        struct json_object http{record, "http"};
        struct json_object http_request{http, "request"};
        if (output_metadata) {
            http_request.print_key_json_string("method", method);
            http_request.print_key_json_string("uri", uri);
            http_request.print_key_json_string("protocol", protocol);
            // http.print_key_json_string("headers", headers.data, headers.length());
            // headers.print_host(http, "host");

            // run the list of http headers to be printed out against
            // all headers, and print the values corresponding to each
            // of the matching names
            //
            headers.print_matching_names(http_request, ph_visitor, perfect_hash_table_type::HTTP_REQEUST_HEADERS);
            //http_request.print_key_value("fingerprint", *this);

        } else {
            headers.print_matching_name(http_request, "user-agent: ", "user_agent" );
        }
        http_request.close();
        http.close();
    }

}

void http_response::parse(struct datum &p) {

    /* process request line */
    version.parse_up_to_delim(p, ' ');
    p.skip(1);
    status_code.parse_up_to_delim(p, ' ');
    p.skip(1);
    status_reason.parse_up_to_delim(p, '\r');
    p.skip(2);

    /* parse headers */
    headers.parse(p);

    return;
}

void http_response::write_json(struct json_object &record) {

    struct json_object http{record, "http"};
    struct json_object http_response{http, "response"};
    http_response.print_key_json_string("version", version.data, version.length());
    http_response.print_key_json_string("status_code", status_code.data, status_code.length());
    http_response.print_key_json_string("status_reason", status_reason.data, status_reason.length());
    //http.print_key_json_string("headers", response.headers.data, response.headers.length());

    // run the list of http headers to be printed out against
    // all headers, and print the values corresponding to each
    // of the matching names
    //
    headers.print_matching_names(http_response, ph_visitor, perfect_hash_table_type::HTTP_RESPONSE_HEADERS);
    //http_response.print_key_value("fingerprint", *this);

    http_response.close();
    http.close();

}

void http_request::fingerprint(struct buffer_stream &b) const {
    if (is_not_empty() == false) {
        return;
    }
    b.write_char('(');
    b.raw_as_hex(method.data, method.data_end - method.data);
    b.write_char(')');
    b.write_char('(');
    b.raw_as_hex(protocol.data, protocol.data_end - protocol.data);
    b.write_char(')');

    b.write_char('(');
    headers.fingerprint(b, ph_visitor, perfect_hash_table_type::HTTP_REQUEST_FP);
    b.write_char(')');
}

void http_response::fingerprint(struct buffer_stream &buf) const {
    if (is_not_empty() == false) {
        return;
    }
    buf.write_char('(');
    buf.raw_as_hex(version.data, version.data_end - version.data);
    buf.write_char(')');
    buf.write_char('(');
    buf.raw_as_hex(status_code.data, status_code.data_end - status_code.data);
    buf.write_char(')');
    buf.write_char('(');
    buf.raw_as_hex(status_reason.data, status_reason.data_end - status_reason.data);
    buf.write_char(')');

    buf.write_char('(');
    headers.fingerprint(buf, ph_visitor, perfect_hash_table_type::HTTP_RESPONSE_FP);
    buf.write_char(')');
}

void http_request::compute_fingerprint(struct fingerprint &fp) const {
    fp.set_type(fingerprint_type_http);
    fp.add(*this);
    fp.final();
}

struct datum http_headers::get_header(const std::basic_string<uint8_t> &location) {
    struct datum output{NULL, NULL};
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };

    if (this->is_not_readable()) {
        return output;
    }
    struct datum p{this->data, this->data_end};  // create copy, to leave object unmodified

    while (p.length() > 0) {
        if (p.compare(crlf, sizeof(crlf)) == 0) {
            break;  /* at end of headers */
        }

        struct datum keyword{p.data, NULL};
        if (p.skip_up_to_delim(csp, sizeof(csp)) == false) {
            return output;
        }
        keyword.data_end = p.data;
        const char *header_name = NULL;

        std::basic_string<uint8_t> name_lowercase;
        to_lower(name_lowercase, keyword);
        if (name_lowercase.compare(location) == 0) {
            header_name = "location";
        }
        const uint8_t *value_start = p.data;
        if (p.skip_up_to_delim(crlf, sizeof(crlf)) == false) {
            return output;
        }
        const uint8_t *value_end = p.data - 2;
        if (header_name) {
            output.data = value_start;
            output.data_end = value_end;
            break;
            //o.print_key_json_string(header_name, value_start, value_end - value_start);
        }
    }
    return output;
}

void http_response::compute_fingerprint(struct fingerprint &fp) const {
    fp.set_type(fingerprint_type_http_server);
    fp.add(*this);
    fp.final();
}

struct datum http_request::get_header(const std::basic_string<uint8_t> &header_name) {
    return headers.get_header(header_name);
}

struct datum http_response::get_header(const std::basic_string<uint8_t> &header_name) {
    return headers.get_header(header_name);
}

bool http_request::do_analysis(const struct key &k_, struct analysis_context &analysis_, classifier *c_) {
    std::basic_string<uint8_t> host_header = { 'h', 'o', 's', 't', ':', ' ' };
    struct datum host_data = get_header(host_header);
    std::basic_string<uint8_t> user_agent_header = { 'u', 's', 'e', 'r', '-', 'a', 'g', 'e', 'n', 't', ':', ' ' };
    struct datum user_agent_data = get_header(user_agent_header);

    analysis_.destination.init(host_data, user_agent_data, std::vector<std::string>(), k_);

    return c_->analyze_fingerprint_and_destination_context(analysis_.fp, analysis_.destination, analysis_.result);
}
