/*
 * http.c
 */

#include "http.h"
#include "json_object.h"

void http_request::parse(struct parser &p) {
    unsigned char crlf[2] = { '\r', '\n' };

    /* process request line */
    method.parse_up_to_delim(p, ' ');
    p.skip(1);
    uri.parse_up_to_delim(p, ' ');
    p.skip(1);
    protocol.parse_up_to_delim(p, '\r');
    p.skip(2);

    headers.data = p.data;
    while (parser_get_data_length(&p) > 0) {
        if (parser_match(&p, crlf, sizeof(crlf), NULL) == status_ok) {
            break;  /* at end of headers */
        }
        if (parser_skip_upto_delim(&p, crlf, sizeof(crlf)) == status_err) {
            break;
        }
    }
    headers.data_end = p.data;

    return;
}

void http_headers::print_host(struct json_object &o, const char *key) const {
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };

    struct parser p{this->data, this->data_end};

    while (parser_get_data_length(&p) > 0) {
        if (parser_match(&p, crlf, sizeof(crlf), NULL) == status_ok) {
            break;  /* at end of headers */
        }

        struct parser keyword{p.data, NULL};
        if (parser_skip_upto_delim(&p, csp, sizeof(csp)) == status_err) {
            return;
        }
        keyword.data_end = p.data;
        bool print_value = false;

        uint8_t h[] = { 'h', 'o', 's', 't', ':', ' ' };
        struct parser host{h, h+sizeof(h)};
        if (host.case_insensitive_match(keyword)) {
            print_value = true;
        }
        const uint8_t *value_start = p.data;
        if (parser_skip_upto_delim(&p, crlf, sizeof(crlf)) == status_err) {
            return;
        }
        const uint8_t *value_end = p.data - 2;
        if (print_value) {
            o.print_key_json_string(key, value_start, value_end - value_start);
            break;
        }
    }
}

void http_headers::print_matching_name(struct json_object &o, const char *key, struct parser &name) const {
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };

    struct parser p{this->data, this->data_end};

    while (parser_get_data_length(&p) > 0) {
        if (parser_match(&p, crlf, sizeof(crlf), NULL) == status_ok) {
            break;  /* at end of headers */
        }

        struct parser keyword{p.data, NULL};
        if (parser_skip_upto_delim(&p, csp, sizeof(csp)) == status_err) {
            return;
        }
        keyword.data_end = p.data;
        bool print_value = false;

        if (name.case_insensitive_match(keyword)) {
            print_value = true;
        }
        const uint8_t *value_start = p.data;
        if (parser_skip_upto_delim(&p, crlf, sizeof(crlf)) == status_err) {
            return;
        }
        const uint8_t *value_end = p.data - 2;
        if (print_value) {
            o.print_key_json_string(key, value_start, value_end - value_start);
            break;
        }
    }
}

void http_headers::print_matching_names(struct json_object &o, std::list<std::pair<struct parser, std::string>> &name_list) const {
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };

    struct parser p{this->data, this->data_end};

    while (parser_get_data_length(&p) > 0) {
        if (parser_match(&p, crlf, sizeof(crlf), NULL) == status_ok) {
            break;  /* at end of headers */
        }

        struct parser keyword{p.data, NULL};
        if (parser_skip_upto_delim(&p, csp, sizeof(csp)) == status_err) {
            return;
        }
        keyword.data_end = p.data;
        const char *header_name = NULL;

        for (const auto &name : name_list) {
            if (name.first.case_insensitive_match(keyword)) {
                header_name = (const char *)name.second.c_str();
            }
        }
        const uint8_t *value_start = p.data;
        if (parser_skip_upto_delim(&p, crlf, sizeof(crlf)) == status_err) {
            return;
        }
        const uint8_t *value_end = p.data - 2;
        if (header_name) {
            o.print_key_json_string(header_name, value_start, value_end - value_start);
        }
    }
}

// write_json is a static http_request member function
//
void http_request::write_json(struct parser data, struct json_object &record) {

    // construct a list of http header names to be printed out
    //
    uint8_t ua[] = { 'u', 's', 'e', 'r', '-', 'a', 'g', 'e', 'n', 't', ':', ' ' };
    struct parser user_agent{ua, ua+sizeof(ua)};
    std::pair<struct parser, std::string> user_agent_name{user_agent, "user_agent"};

    uint8_t h[] = { 'h', 'o', 's', 't', ':', ' ' };
    struct parser host{h, h+sizeof(h)};
    std::pair<struct parser, std::string> host_name{host, "host"};

    uint8_t xff[] = { 'x', '-', 'f', 'o', 'r', 'w', 'a', 'r', 'd', 'e', 'd', '-', 'f', 'o', 'r', ':', ' ' };
    struct parser xff_parser{xff, xff+sizeof(xff)};
    std::pair<struct parser, std::string> x_forwarded_for{xff_parser, "x_forwarded_for"};

    uint8_t v[] = { 'v', 'i', 'a', ':', ' ' };
    struct parser v_parser{v, v+sizeof(v)};
    std::pair<struct parser, std::string> via{v_parser, "via"};

    std::list<std::pair<struct parser, std::string>> names_to_print{user_agent_name, host_name, x_forwarded_for, via};

    struct json_object http{record, "http"};
    struct json_object http_request{http, "request"};
    struct http_request request;
    request.parse(data);
    http_request.print_key_json_string("method", request.method.data, request.method.length());
    http_request.print_key_json_string("uri", request.uri.data, request.uri.length());
    http_request.print_key_json_string("protocol", request.protocol.data, request.protocol.length());
    // http.print_key_json_string("headers", request.headers.data, request.headers.length());
    // request.headers.print_host(http, "host");

    // run the list of http headers to be printed out against
    // all headers, and print the values corresponding to each
    // of the matching names
    //
    request.headers.print_matching_names(http_request, names_to_print);

    http_request.close();
    http.close();

}

void http_response::parse(struct parser &p) {
    unsigned char crlf[2] = { '\r', '\n' };

    /* process request line */
    version.parse_up_to_delim(p, ' ');
    p.skip(1);
    status_code.parse_up_to_delim(p, ' ');
    p.skip(1);
    status_reason.parse_up_to_delim(p, '\r');
    p.skip(2);

    headers.data = p.data;
    while (parser_get_data_length(&p) > 0) {
        if (parser_match(&p, crlf, sizeof(crlf), NULL) == status_ok) {
            break;  /* at end of headers */
        }
        if (parser_skip_upto_delim(&p, crlf, sizeof(crlf)) == status_err) {
            break;
        }
    }
    headers.data_end = p.data;

    return;
}

void http_response::write_json(struct parser data, struct json_object &record) {

    // construct a list of http header names to be printed out
    //
    uint8_t ct[] = { 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 't', 'y', 'p', 'e', ':', ' ' };
    struct parser content_type{ct, ct+sizeof(ct)};
    std::pair<struct parser, std::string> content_type_pair{content_type, "content_type"};

    uint8_t cl[] = { 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 'l', 'e', 'n', 'g', 't', 'h', ':', ' ' };
    struct parser content_length{cl, cl+sizeof(cl)};
    std::pair<struct parser, std::string> content_length_pair{content_length, "content_length"};

    uint8_t srv[] = { 's', 'e', 'r', 'v', 'e', 'r', ':', ' ' };
    struct parser server{srv, srv+sizeof(srv)};
    std::pair<struct parser, std::string> server_pair{server, "server"};

    uint8_t v[] = { 'v', 'i', 'a', ':', ' ' };
    struct parser v_parser{v, v+sizeof(v)};
    std::pair<struct parser, std::string> via_pair{v_parser, "via"};

    std::list<std::pair<struct parser, std::string>> names_to_print{server_pair, content_type_pair, content_length_pair, via_pair};

    struct json_object http{record, "http"};
    struct json_object http_response{http, "response"};
    struct http_response response;
    response.parse(data);
    http_response.print_key_json_string("version", response.version.data, response.version.length());
    http_response.print_key_json_string("status_code", response.status_code.data, response.status_code.length());
    http_response.print_key_json_string("status_reason", response.status_reason.data, response.status_reason.length());
    //http.print_key_json_string("headers", response.headers.data, response.headers.length());

    // run the list of http headers to be printed out against
    // all headers, and print the values corresponding to each
    // of the matching names
    //
    response.headers.print_matching_names(http_response, names_to_print);

    http_response.close();
    http.close();

}
