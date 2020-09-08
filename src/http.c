/*
 * http.c
 */

#include <unordered_map>
#include "asn1/bytestring.h"
#include "http.h"
#include "json_object.h"
#include "match.h"

void http_request::parse(struct parser &p) {

    /* parse request line */
    method.parse_up_to_delim(p, ' ');
    p.skip(1);
    uri.parse_up_to_delim(p, ' ');
    p.skip(1);
    protocol.parse_up_to_delim(p, '\r');
    p.skip(2);

    /* parse headers */
    headers.parse(p);

    return;
}

void http_headers::print_host(struct json_object &o, const char *key) const {
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };

    struct parser p{this->data, this->data_end};  // create copy, to leave object unmodified

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

    if (this->is_not_readable()) {
        return;
    }
    struct parser p{this->data, this->data_end};  // create copy, to leave object unmodified

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

    if (this->is_not_readable()) {
        return;
    }
    struct parser p{this->data, this->data_end};  // create copy, to leave object unmodified

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

inline void to_lower(std::basic_string<uint8_t> &str, struct parser d) {
    if (d.is_not_readable()) {
        return;
    }
    while (d.data < d.data_end) {
        str.push_back(tolower(*d.data++));
    }
}

void http_headers::fingerprint(struct buffer_stream &buf, std::unordered_map<std::basic_string<uint8_t>, bool> &name_dict) const {
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };

    struct parser p{this->data, this->data_end};  // create copy, to leave object unmodified

    while (parser_get_data_length(&p) > 0) {
        if (parser_match(&p, crlf, sizeof(crlf), NULL) == status_ok) {
            break;  /* at end of headers */
        }

        struct parser name{p.data, NULL};
        if (parser_skip_upto_delim(&p, csp, sizeof(csp)) == status_err) {
            return;
        }
        name.data_end = p.data;
        bool include_name = false;
        bool include_value = false;

        std::basic_string<uint8_t> name_lowercase;
        to_lower(name_lowercase, name);
        auto pair = name_dict.find(name_lowercase);
        if (pair != name_dict.end()) {
            include_name = true;
            include_value = pair->second;
        }

        if (parser_skip_upto_delim(&p, crlf, sizeof(crlf)) == status_err) {
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

// write_json is a static http_request member function
//
void http_request::write_json(struct parser data, struct json_object &record, bool output_metadata) {

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

    uint8_t u[] = { 'u', 'p', 'g', 'r', 'a', 'd', 'e', ':', ' ' };
    struct parser u_parser{u, u+sizeof(u)};
    std::pair<struct parser, std::string> upgrade_pair{u_parser, "upgrade"};

    std::list<std::pair<struct parser, std::string>> names_to_print{user_agent_name, host_name, x_forwarded_for, via, upgrade_pair};

    struct http_request request;
    request.parse(data);
    if (request.method.is_not_empty()) {
        struct json_object http{record, "http"};
        struct json_object http_request{http, "request"};
        if (output_metadata) {
            http_request.print_key_json_string("method", request.method);
            http_request.print_key_json_string("uri", request.uri);
            http_request.print_key_json_string("protocol", request.protocol);
            // http.print_key_json_string("headers", request.headers.data, request.headers.length());
            // request.headers.print_host(http, "host");

            // run the list of http headers to be printed out against
            // all headers, and print the values corresponding to each
            // of the matching names
            //
            request.headers.print_matching_names(http_request, names_to_print);
            http_request.print_key_value("fingerprint", request);

        } else {

            // output only the user-agent
            std::list<std::pair<struct parser, std::string>> ua_only{user_agent_name};
            request.headers.print_matching_names(http_request, ua_only);
        }
        http_request.close();
        http.close();
    }

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
    http_response.print_key_value("fingerprint", response);

    http_response.close();
    http.close();

}

void http_request::operator()(struct buffer_stream &b) const {
    if (method.is_not_readable()) {
        return;
    }
    b.write_char('\"');
    b.write_char('(');
    b.raw_as_hex(method.data, method.data_end - method.data);
    b.write_char(')');
    b.write_char('(');
    b.raw_as_hex(protocol.data, protocol.data_end - protocol.data);
    b.write_char(')');

    std::unordered_map<std::basic_string<uint8_t>, bool> http_static_keywords = {
        { { 'a', 'c', 'c', 'e', 'p', 't', ':', ' ' }, true },
        { { 'a', 'c', 'c', 'e', 'p', 't', '-', 'e', 'n', 'c', 'o', 'd', 'i', 'n', 'g', ':', ' '}, true },
        { { 'c', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n', ':', ' ' }, true },
        { { 'd', 'n', 't', ':', ' ' }, true },
        { { 'd', 'p', 'r', ':', ' ' }, true },
        { { 'u', 'p', 'g', 'r', 'a', 'd', 'e', '-', 'i', 'n', 's', 'e', 'c', 'u', 'r', 'e', '-', 'r', 'e', 'q', 'u', 'e', 's', 't', 's', ':', ' ' }, true },
        { { 'x', '-', 'r', 'e', 'q', 'u', 'e', 's', 't', 'e', 'd', '-', 'w', 'i', 't', 'h', ':', ' ' }, true },
        { { 'a', 'c', 'c', 'e', 'p', 't', '-', 'c', 'h', 'a', 'r', 's', 'e', 't', ':', ' ' }, false },
        { { 'a', 'c', 'c', 'e', 'p', 't', '-', 'l', 'a', 'n', 'g', 'u', 'a', 'g', 'e', ':', ' ' }, false },
        { { 'a', 'u', 't', 'h', 'o', 'r', 'i', 'z', 'a', 't', 'i', 'o', 'n', ':', ' ' }, false },
        { { 'c', 'a', 'c', 'h', 'e', '-', 'c', 'o', 'n', 't', 'r', 'o', 'l', ':', ' ' }, false },
        { { 'h', 'o', 's', 't', ':', ' ' }, false },
        { { 'i', 'f', '-', 'm', 'o', 'd', 'i', 'f', 'i', 'e', 'd', '-', 's', 'i', 'n', 'c', 'e', ':', ' ' }, false },
        { { 'k', 'e', 'e', 'p', '-', 'a', 'l', 'i', 'v', 'e', ':', ' ' }, false },
        { { 'u', 's', 'e', 'r', '-', 'a', 'g', 'e', 'n', 't', ':', ' ' }, false },
        { { 'x', '-', 'f', 'l', 'a', 's', 'h', '-', 'v', 'e', 'r', 's', 'i', 'o', 'n', ':', ' ' }, false },
        { { 'x', '-', 'p', '2', 'p', '-', 'p', 'e', 'e', 'r', 'd', 'i', 's', 't', ':', ' ' }, false } 
    };
    headers.fingerprint(b, http_static_keywords);
    b.write_char('\"');
}

void http_response::operator()(struct buffer_stream &buf) const {
    if (status_reason.is_not_readable()) {
        return;
    }
    buf.write_char('\"');
    buf.write_char('(');
    buf.raw_as_hex(version.data, version.data_end - version.data);
    buf.write_char(')');
    buf.write_char('(');
    buf.raw_as_hex(status_code.data, status_code.data_end - status_code.data);
    buf.write_char(')');
    buf.write_char('(');
    buf.raw_as_hex(status_reason.data, status_reason.data_end - status_reason.data);
    buf.write_char(')');

    std::unordered_map<std::basic_string<uint8_t>, bool> http_static_keywords = {
        { (uint8_t *)"access-control-allow-credentials: ", true },
        { (uint8_t *)"access-control-allow-headers: ", true },
        { (uint8_t *)"access-control-allow-methods: ", true },
        { (uint8_t *)"access-control-expose-headers: ", true },
        { (uint8_t *)"cache-control: ", true },
        { (uint8_t *)"code: ", true },
        { (uint8_t *)"connection: ", true },
        { (uint8_t *)"content-language: ", true },
        { (uint8_t *)"content-transfer-encoding: ", true },
        { (uint8_t *)"p3p: ", true },
        { (uint8_t *)"pragma: ", true },
        { (uint8_t *)"reason: ", true },
        { (uint8_t *)"server: ", true },
        { (uint8_t *)"strict-transport-security: ", true },
        { (uint8_t *)"version: ", true },
        { (uint8_t *)"x-aspnetmvc-version: ", true },
        { (uint8_t *)"x-aspnet-version: ", true },
        { (uint8_t *)"x-cid: ", true },
        { (uint8_t *)"x-ms-version: ", true },
        { (uint8_t *)"x-xss-protection: ", true },
        { (uint8_t *)"appex-activity-id: ", false },
        { (uint8_t *)"cdnuuid: ", false },
        { (uint8_t *)"cf-ray: ", false },
        { (uint8_t *)"content-range: ", false },
        { (uint8_t *)"content-type: ", false },
        { (uint8_t *)"date: ", false },
        { (uint8_t *)"etag: ", false },
        { (uint8_t *)"expires: ", false },
        { (uint8_t *)"flow_context: ", false },
        { (uint8_t *)"ms-cv: ", false },
        { (uint8_t *)"msregion: ", false },
        { (uint8_t *)"ms-requestid: ", false },
        { (uint8_t *)"request-id: ", false },
        { (uint8_t *)"vary: ", false },
        { (uint8_t *)"x-amz-cf-pop: ", false },
        { (uint8_t *)"x-amz-request-id: ", false },
        { (uint8_t *)"x-azure-ref-originshield: ", false },
        { (uint8_t *)"x-cache: ", false },
        { (uint8_t *)"x-cache-hits: ", false },
        { (uint8_t *)"x-ccc: ", false },
        { (uint8_t *)"x-diagnostic-s: ", false },
        { (uint8_t *)"x-feserver: ", false },
        { (uint8_t *)"x-hw: ", false },
        { (uint8_t *)"x-msedge-ref: ", false },
        { (uint8_t *)"x-ocsp-responder-id: ", false },
        { (uint8_t *)"x-requestid: ", false },
        { (uint8_t *)"x-served-by: ", false },
        { (uint8_t *)"x-timer: ", false },
        { (uint8_t *)"x-trace-context: ", false }

    };
    headers.fingerprint(buf, http_static_keywords);
    buf.write_char('\"');
}
