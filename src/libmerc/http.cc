/*
 * http.c
 */

#include <unordered_map>
#include "asn1/bytestring.h"
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

void http_headers::print_matching_names(struct json_object &o, std::unordered_map<std::basic_string<uint8_t>, std::string> &name_dict) const {
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };

    if (this->is_not_readable()) {
        return;
    }
    struct datum p{this->data, this->data_end};  // create copy, to leave object unmodified

    while (datum_get_data_length(&p) > 0) {
        if (datum_match(&p, crlf, sizeof(crlf), NULL) == status_ok) {
            break;  /* at end of headers */
        }

        struct datum keyword{p.data, NULL};
        if (datum_skip_upto_delim(&p, csp, sizeof(csp)) == status_err) {
            return;
        }
        keyword.data_end = p.data;
        const char *header_name = NULL;

        std::basic_string<uint8_t> name_lowercase;
        to_lower(name_lowercase, keyword);
        auto pair = name_dict.find(name_lowercase);
        if (pair != name_dict.end()) {
            header_name = (const char *)pair->second.c_str();
        }
        const uint8_t *value_start = p.data;
        if (datum_skip_upto_delim(&p, crlf, sizeof(crlf)) == status_err) {
            return;
        }
        const uint8_t *value_end = p.data - 2;
        if (header_name) {
            o.print_key_json_string(header_name, value_start, value_end - value_start);
        }
    }
}

void http_headers::fingerprint(struct buffer_stream &buf, std::unordered_map<std::basic_string<uint8_t>, bool> &name_dict) const {
    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char csp[2] = { ':', ' ' };

    struct datum p{this->data, this->data_end};  // create copy, to leave object unmodified

    while (datum_get_data_length(&p) > 0) {
        if (datum_match(&p, crlf, sizeof(crlf), NULL) == status_ok) {
            break;  /* at end of headers */
        }

        struct datum name{p.data, NULL};
        if (datum_skip_upto_delim(&p, csp, sizeof(csp)) == status_err) {
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

        if (datum_skip_upto_delim(&p, crlf, sizeof(crlf)) == status_err) {
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

    // list of http header names to be printed out
    //
    std::unordered_map<std::basic_string<uint8_t>, std::string> header_names_to_print = {
        { { 'u', 's', 'e', 'r', '-', 'a', 'g', 'e', 'n', 't', ':', ' ' }, "user_agent" },
        { { 'h', 'o', 's', 't', ':', ' ' }, "host"},
        { { 'x', '-', 'f', 'o', 'r', 'w', 'a', 'r', 'd', 'e', 'd', '-', 'f', 'o', 'r', ':', ' ' }, "x_forwarded_for"},
        { { 'v', 'i', 'a', ':', ' ' }, "via"},
        { { 'u', 'p', 'g', 'r', 'a', 'd', 'e', ':', ' ' }, "upgrade"}
    };

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
            headers.print_matching_names(http_request, header_names_to_print);
            //http_request.print_key_value("fingerprint", *this);

        } else {

            // output only the user-agent
            std::unordered_map<std::basic_string<uint8_t>, std::string> ua_only = {
                { { 'u', 's', 'e', 'r', '-', 'a', 'g', 'e', 'n', 't', ':', ' ' }, "user_agent" }
            };
            headers.print_matching_names(http_request, ua_only);
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

    // list of http header names to be printed out
    //
    std::unordered_map<std::basic_string<uint8_t>, std::string> header_names_to_print = {
        { { 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 't', 'y', 'p', 'e', ':', ' ' }, "content_type"},
        { { 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 'l', 'e', 'n', 'g', 't', 'h', ':', ' ' }, "content_length"},
        { { 's', 'e', 'r', 'v', 'e', 'r', ':', ' ' }, "server"},
        { { 'v', 'i', 'a', ':', ' ' }, "via"}
    };

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
    headers.print_matching_names(http_response, header_names_to_print);
    //http_response.print_key_value("fingerprint", *this);

    http_response.close();
    http.close();

}

void http_request::operator()(struct buffer_stream &b) const {
    if (is_not_empty() == false) {
        b.write_char('\"');
        b.write_char('\"');
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
    if (is_not_empty() == false) {
        buf.write_char('\"');
        buf.write_char('\"');
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
