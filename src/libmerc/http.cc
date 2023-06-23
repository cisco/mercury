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

        if (keyword.case_insensitive_match(key)) {
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

void http_headers::print_matching_names(struct json_object &o, perfect_hash<const char*> &ph) const {
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

        bool is_header_found = false;
        header_name = *ph.lookup(keyword.data, keyword.length(), is_header_found);
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

// Parses http formatted ssdp msg for http header in lenient way (ignores whitespaces around header - value pair and ignores absence of '\r' in delimiter)
// and prints to json record, based on bool metadata
//
void http_headers::print_ssdp_names_and_feature_string(struct json_object &o, data_buffer<2048>& feature_buf, bool metadata) const {

    // header_ssdp contains the keywords to be printed out; the
    // boolean sets output verbosity in absense of metadata option
    //
    static std::vector<perfect_hash_entry<std::pair<const char*, bool>>> header_ssdp = {
        { "host", {"host",true} },
        { "cache-control", {"cache_control",false} },
        { "location", {"location",true} },
        { "nt", {"notify_type",true} },
        { "nts", {"notify_subtype", false} },
        { "server", {"server",true} },
        { "usn", {"usn",false} },
        { "mx", {"delay",false} },
        { "st", {"target",true} },
        { "user-agent", {"user_agent",true} },
        { "date", {"date",false} },
        { "ext", {"ext",false} },
        { "bootid.upnp.org", {"bootid",false} },
        { "configid.upnp.org", {"conf_id",false} },
        { "searchport.upnp.org", {"searchport",false} },
        { "opt", {"opt",false} },
        { "01-nls", {"nls",false} },
        { "man", {"man",false} }
    };
    static perfect_hash<std::pair<const char*, bool>> ph{header_ssdp};

    unsigned char crlf[2] = { '\r', '\n' };
    unsigned char lf[1] = { '\n' };
    unsigned char col[1] = { ':' };
    unsigned char ws = ' ';
    unsigned char cr = '\r';

    if (this->is_not_readable()) {
        return;
    }
    struct datum p{this->data, this->data_end};  // create copy, to leave object unmodified

    bool first_header=true;
    while (p.length() > 0) {
        if (p.compare(lf, sizeof(lf)) == 0 || p.compare(crlf, sizeof(crlf)) == 0) {
            break;  /* at end of headers */
        }

        struct datum keyword{p.data, NULL};
        if (p.skip_up_to_delim(col, sizeof(col)) == false) {
            return;
        }
        keyword.data_end = p.data;
        //keyword.trim_trail(ws);   // trim trailing whitespace after colon
        keyword.trim(1);    // ommit colon
        keyword.trim_trail(ws);   // trim trailing whitespace before colon

        bool is_header_found = false;
        const std::pair<const char *, bool> *header_name = ph.lookup(keyword.data, keyword.length(), is_header_found);
        if (!is_header_found) {
            header_name = nullptr;
        }
        const uint8_t *value_start = p.data;
        if (p.skip_up_to_delim(lf, sizeof(lf)) == false) {
            return;
        }
        // check type of delimiter '\r\n' or '\n'
        const uint8_t *value_end = *(p.data-2) == cr ? p.data-2 : p.data-1;
        if (header_name && (header_name->second || metadata)) {
            o.print_key_json_string(header_name->first, value_start, value_end - value_start);
            if(!first_header){
                feature_buf.copy(',');
            }
            feature_buf.copy('[');
            feature_buf.write_quote_enclosed_hex((uint8_t*)header_name->first, strlen(header_name->first));
            feature_buf.copy(',');
            feature_buf.write_quote_enclosed_hex(value_start, value_end - value_start);
            feature_buf.copy(']');
        }
        first_header=false;
    }
}

void http_headers::fingerprint(struct buffer_stream &buf, perfect_hash<bool> &fp_data) const {
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

        const bool include_value = *(fp_data.lookup(name.data, name.length(), include_name));

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
    static std::vector<perfect_hash_entry<const char*>> header_data_request = {
        { "user-agent: ", "user_agent" },
        { "host: ", "host"},
        { "x-forwarded-for: ", "x_forwarded_for"},
        { "via: ", "via"},
        { "upgrade: ", "upgrade"},
        { "referer: ", "referer"}
    };
    static perfect_hash<const char*> ph{header_data_request};

    if (this->is_not_empty()) {
        struct json_object http{record, "http"};
        struct json_object http_request{http, "request"};
        if (output_metadata) {
            http_request.print_key_json_string("method", method);
            http_request.print_key_json_string("uri", uri);
            http_request.print_key_json_string("protocol", protocol);
            // http.print_key_json_string("headers", headers.data, headers.length());

            // run the list of http headers to be printed out against
            // all headers, and print the values corresponding to each
            // of the matching names
            //
            headers.print_matching_names(http_request, ph);

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

void http_response::write_json(struct json_object &record, bool metadata) {
    if (!metadata) {
        return;  // TODO: remove this to un-supress output
    }

    static std::vector<perfect_hash_entry<const char*>> header_data_response = {
        { "content-type: ", "content_type"},
        { "content-length: ", "content_length"},
        { "server: ", "server"},
        { "via: ", "via"}
    };
    static perfect_hash<const char*> ph{header_data_response};

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
    headers.print_matching_names(http_response, ph);

    http_response.close();
    http.close();

}

void http_request::fingerprint(struct buffer_stream &b) const {
    static std::vector<perfect_hash_entry<bool>> fp_data_request = {
        { "accept: ", true },
        { "accept-encoding: ", true },
        { "connection: ", true },
        { "dnt: ", true },
        { "dpr: ", true },
        { "upgrade-insecure-requests: ", true },
        { "x-requested-with: ", true },
        { "accept-charset: ", false },
        { "accept-language: ", false },
        { "authorization: ", false },
        { "cache-control: ", false },
        { "host: ", false },
        { "if-modified-since: ", false },
        { "keep-alive: ", false },
        { "user-agent: ", false },
        { "x-flash-version: ", false },
        { "x-p2p-peerdist: ", false }
    };
    static perfect_hash<bool> ph{fp_data_request};
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
    headers.fingerprint(b, ph);
    b.write_char(')');
}

void http_response::fingerprint(struct buffer_stream &buf) const {
    static std::vector<perfect_hash_entry<bool>> fp_data_response = {
        { "access-control-allow-credentials: ", true },
        { "access-control-allow-headers: ", true },
        { "access-control-allow-methods: ", true },
        { "access-control-expose-headers: ", true },
        { "cache-control: ", true },
        { "code: ", true },
        { "connection: ", true },
        { "content-language: ", true },
        { "content-transfer-encoding: ", true },
        { "p3p: ", true },
        { "pragma: ", true },
        { "reason: ", true },
        { "server: ", true },
        { "strict-transport-security: ", true },
        { "version: ", true },
        { "x-aspnetmvc-version: ", true },
        { "x-aspnet-version: ", true },
        { "x-cid: ", true },
        { "x-ms-version: ", true },
        { "x-xss-protection: ", true },
        { "appex-activity-id: ", false },
        { "cdnuuid: ", false },
        { "cf-ray: ", false },
        { "content-range: ", false },
        { "content-type: ", false },
        { "date: ", false },
        { "etag: ", false },
        { "expires: ", false },
        { "flow_context: ", false },
        { "ms-cv: ", false },
        { "msregion: ", false },
        { "ms-requestid: ", false },
        { "request-id: ", false },
        { "vary: ", false },
        { "x-amz-cf-pop: ", false },
        { "x-amz-request-id: ", false },
        { "x-azure-ref-originshield: ", false },
        { "x-cache: ", false },
        { "x-cache-hits: ", false },
        { "x-ccc: ", false },
        { "x-diagnostic-s: ", false },
        { "x-feserver: ", false },
        { "x-hw: ", false },
        { "x-msedge-ref: ", false },
        { "x-ocsp-responder-id: ", false },
        { "x-requestid: ", false },
        { "x-served-by: ", false },
        { "x-timer: ", false },
        { "x-trace-context: ", false }
    };
    static perfect_hash<bool> ph{fp_data_response};
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
    headers.fingerprint(buf, ph);
    buf.write_char(')');
}

void http_request::compute_fingerprint(class fingerprint &fp) const {
    fp.set_type(fingerprint_type_http);
    fp.add(*this);
    fp.final();
}

struct datum http_headers::get_header(const char *location) {
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

        if (keyword.case_insensitive_match(location)) {
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

void http_response::compute_fingerprint(class fingerprint &fp) const {
    fp.set_type(fingerprint_type_http_server);
    fp.add(*this);
    fp.final();
}

struct datum http_request::get_header(const char *header_name) {
    return headers.get_header(header_name);
}

struct datum http_response::get_header(const char *header_name) {
    return headers.get_header(header_name);
}

bool http_request::do_analysis(const struct key &k_, struct analysis_context &analysis_, classifier *c_) {
    struct datum host_data = get_header("host: ");
    struct datum user_agent_data = get_header("user-agent: ");

    analysis_.destination.init(host_data, user_agent_data, {nullptr, nullptr}, k_);

    return c_->analyze_fingerprint_and_destination_context(analysis_.fp, analysis_.destination, analysis_.result);
}
