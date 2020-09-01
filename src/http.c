/*
 * http.c
 */

#include "http.h"
#include "json_object.h"
#include "match.h"

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

void http_headers::fingerprint(struct buffer_stream &buf, std::list<std::pair<struct parser, bool>> &name_list) const {
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };

    struct parser p{this->data, this->data_end};

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

        for (const auto &n : name_list) {
            if (n.first.case_insensitive_match(name)) {
                include_name = true;
                include_value = n.second;
            }
        }
        const uint8_t *value_start = p.data;
        if (parser_skip_upto_delim(&p, crlf, sizeof(crlf)) == status_err) {
            return;
        }
        const uint8_t *value_end = p.data - 2;
        if (include_name) {
            if (include_value) {
                buf.write_char('(');
                buf.raw_as_hex(name.data, value_end - name.data);         // write {name, value}
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
            request.fingerprint(http_request, "fingerprint");

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

    http_response.close();
    http.close();

}

#define define_pair_parser_bool(x, v) uint8_t x[]

uint8_t a[] = { 'a', 'c', 'c', 'e', 'p', 't', ':', ' ' };
struct parser a_parser{a, a+sizeof(a)};
std::pair<struct parser, bool> accept_pair{a_parser, true};

void http_request::fingerprint(json_object &o, const char *key) const {
    if (method.is_not_readable()) {
        return;
    }
    char fp_buffer[2048];
    struct buffer_stream buf(fp_buffer, sizeof(fp_buffer));
    buf.write_char('(');
    buf.raw_as_hex(method.data, method.data_end - method.data);
    buf.write_char(')');
    buf.write_char('(');
    buf.raw_as_hex(protocol.data, protocol.data_end - protocol.data);
    buf.write_char(')');

    keyword_t http_static_name_and_value[] = {
        keyword_init("accept"),
        keyword_init("accept-encoding"),
        keyword_init("connection"),
        keyword_init("dnt"),
        keyword_init("dpr"),
        keyword_init("upgrade-insecure-requests"),
        keyword_init("x-requested-with"),
        keyword_init("")
    };
    keyword_t http_static_name[] = {
        keyword_init("accept-charset"),
        keyword_init("accept-language"),
        keyword_init("authorization"),
        keyword_init("cache-control"),
        keyword_init("host"),
        keyword_init("if-modified-since"),
        keyword_init("keep-alive"),
        keyword_init("user-agent"),
        keyword_init("x-flash-version"),
        keyword_init("x-p2p-peerdist"),
        keyword_init("")
    };
    keyword_matcher_t matcher_http_static_name_and_value = {
        http_static_name_and_value, /* case insensitive */
        NULL                        /* case sensitive   */
    };
    keyword_matcher_t matcher_http_static_name = {
        http_static_name,           /* case insensitive */
        NULL                        /* case sensitive   */
    };

    uint8_t a[]   = { 'a', 'c', 'c', 'e', 'p', 't', ':', ' ' };
    struct parser a_parser{a, a+sizeof(a)};
    std::pair<struct parser, bool> a_pair{a_parser, true};

    uint8_t ae[]  = {'a', 'c', 'c', 'e', 'p', 't', '-', 'e', 'n', 'c', 'o', 'd', 'i', 'n', 'g', ':', ' '};
    struct parser ae_parser{ae, ae+sizeof(ae)};
    std::pair<struct parser, bool> ae_pair{ae_parser, true};

    uint8_t c[]   = { 'c', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n', ':', ' ' };
    struct parser c_parser{c, c+sizeof(c)};
    std::pair<struct parser, bool> c_pair{c_parser, true};

    uint8_t dnt[] = { 'd', 'n', 't', ':', ' ' };
    struct parser dnt_parser{dnt, dnt+sizeof(dnt)};
    std::pair<struct parser, bool> dnt_pair{dnt_parser, true};

    uint8_t dpr[] = { 'd', 'p', 'r', ':', ' ' };
    struct parser dpr_parser{dpr, dpr+sizeof(dpr)};
    std::pair<struct parser, bool> dpr_pair{dpr_parser, true};

    uint8_t u[]   = { 'u', 'p', 'g', 'r', 'a', 'd', 'e', '-', 'i', 'n', 's', 'e', 'c', 'u', 'r', 'e', '-', 'r', 'e', 'q', 'u', 'e', 's', 't', 's', ':', ' ' };
    struct parser u_parser{u, u+sizeof(u)};
    std::pair<struct parser, bool> u_pair{u_parser, true};

    uint8_t x[]   = { 'x', '-', 'r', 'e', 'q', 'u', 'e', 's', 't', 'e', 'd', '-', 'w', 'i', 't', 'h', ':', ' ' };
    struct parser x_parser{x, x+sizeof(x)};
    std::pair<struct parser, bool> x_pair{x_parser, true};

    uint8_t ac[]  = {'a', 'c', 'c', 'e', 'p', 't', '-', 'c', 'h', 'a', 'r', 's', 'e', 't', ':', ' ' };
    struct parser ac_parser{ac, ac+sizeof(ac)};
    std::pair<struct parser, bool> ac_pair{ac_parser, false};

    uint8_t al[]  = {'a', 'c', 'c', 'e', 'p', 't', '-', 'l', 'a', 'n', 'g', 'u', 'a', 'g', 'e', ':', ' ' };
    struct parser al_parser{al, al+sizeof(al)};
    std::pair<struct parser, bool> al_pair{al_parser, false};

    uint8_t az[]  = {'a', 'u', 't', 'h', 'o', 'r', 'i', 'z', 'a', 't', 'i', 'o', 'n', ':', ' ' };
    struct parser az_parser{az, az+sizeof(az)};
    std::pair<struct parser, bool> az_pair{az_parser, false};

    uint8_t cc[]  = {'c', 'a', 'c', 'h', 'e', '-', 'c', 'o', 'n', 't', 'r', 'o', 'l', ':', ' ' };
    struct parser cc_parser{cc, cc+sizeof(cc)};
    std::pair<struct parser, bool> cc_pair{cc_parser, false};

    uint8_t h[]   = {'h', 'o', 's', 't', ':', ' ' };
    struct parser h_parser{h, h+sizeof(h)};
    std::pair<struct parser, bool> h_pair{h_parser, false};

    uint8_t ims[] = {'i', 'f', '-', 'm', 'o', 'd', 'i', 'f', 'i', 'e', 'd', '-', 's', 'i', 'n', 'c', 'e', ':', ' ' };
    struct parser ims_parser{ims, ims+sizeof(ims)};
    std::pair<struct parser, bool> ims_pair{ims_parser, false};

    uint8_t ka[]  = {'k', 'e', 'e', 'p', '-', 'a', 'l', 'i', 'v', 'e', ':', ' ' };
    struct parser ka_parser{ka, ka+sizeof(ka)};
    std::pair<struct parser, bool> ka_pair{ka_parser, false};

    uint8_t ua[]  = {'u', 's', 'e', 'r', '-', 'a', 'g', 'e', 'n', 't', ':', ' ' };
    struct parser ua_parser{ua, ua+sizeof(ua)};
    std::pair<struct parser, bool> ua_pair{ua_parser, false};

    uint8_t xfv[] = {'x', '-', 'f', 'l', 'a', 's', 'h', '-', 'v', 'e', 'r', 's', 'i', 'o', 'n', ':', ' ' };
    struct parser xfv_parser{xfv, xfv+sizeof(xfv)};
    std::pair<struct parser, bool> xfv_pair{xfv_parser, false};

    uint8_t xpp[] = {'x', '-', 'p', '2', 'p', '-', 'p', 'e', 'e', 'r', 'd', 'i', 's', 't', ':', ' ' };
    struct parser xpp_parser{xpp, xpp+sizeof(xpp)};
    std::pair<struct parser, bool> xpp_pair{xpp_parser, false};

    std::list<std::pair<struct parser, bool>> static_names{
        a_pair, ae_pair, c_pair, dnt_pair, dpr_pair, u_pair, x_pair,
        ac_pair, al_pair, az_pair, cc_pair, h_pair, ims_pair, ka_pair, ua_pair, xfv_pair, xpp_pair
    };

    headers.fingerprint(buf, static_names);

    buf.write_char('\0'); // null-terminate the JSON string in the buffer
    o.print_key_string(key, fp_buffer);
}
