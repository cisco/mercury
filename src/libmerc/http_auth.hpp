// http_auth.hpp
//
// HTTP Authorization/Authentication

#ifndef HTTP_AUTH_HPP
#define HTTP_AUTH_HPP

#include "datum.h"
#include "base64.h"
#include "json_object.h"

class scheme : public datum {
public:
    scheme(struct datum& d) {
        datum::parse_up_to_delim(d, ' ');
    }

    /// the enumeration `type` identifies Authorization scheme types;
    /// only Bearer, Basic, and Digest are currently supported
    ///
    /// The full set of schemes is laid out at
    /// https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml
    ///
    enum type {
        unknown,
        basic,
        digest,
        bearer,
    };

    static const char *type_get_name(enum type t) {
        switch(t) {
        case basic: return "basic";
        case digest: return "digest";
        case bearer: return "bearer";
        case unknown:
        default:
            ;
        }
        return "unknown";
    }

    scheme::type get_type() const {
        //
        // TODO: technically, this function should use
        // case-insensitive comparisons
        //
        if (this->equals(std::array<uint8_t,5>{'B', 'a', 's', 'i', 'c'})) {
            return type::basic;
        }
        if (this->equals(std::array<uint8_t,6>{'B', 'e', 'a', 'r', 'e', 'r'})) {
            return type::bearer;
        }
        if (this->equals(std::array<uint8_t,6>{'D', 'i', 'g', 'e', 's', 't'})) {
            return type::digest;
        }
        return unknown;
    }

};

class bearer_token {
    datum complete_value;
    datum header;
    datum payload;
    datum signature;

public:

    // constructs a bearer_token object from a \ref datum (not a
    // reference to a `datum)
    //
    bearer_token(datum d) {
        complete_value = d,
        header.parse_up_to_delim(d, '.');
        d.accept('.');
        payload.parse_up_to_delim(d, '.');
        d.accept('.');
        signature = d;
    }

    bool is_valid() const { return signature.is_not_null(); }

    void write_json(json_object &o) const {
        if (!is_valid()) { return; }

        uint8_t header_buf[1024];
        int header_len = base64::decode(header_buf, sizeof(header_buf), header.data, header.length());
        uint8_t payload_buf[1024];
        int payload_len = base64::decode(payload_buf, sizeof(payload_buf), payload.data, payload.length());

        // if base64 decoding was successful, we print out the decoded
        // payload and header, along with the undecoded signature;
        // otherwise, we write out the complete value of the token, to
        // handle cases in which the client doesn't want to conform to
        // RFC 6750 Section 2.1
        //
        if (header_len > 0 and payload_len > 0) {
            o.print_key_json_string("header", header_buf, header_len);
            o.print_key_json_string("payload", payload_buf, payload_len);
            o.print_key_json_string("signature", signature.data, signature.length());
        } else {
            o.print_key_json_string("token", complete_value.data, complete_value.length());
        }

    }

};

class authorization {
    scheme auth_scheme;
    literal_byte<' '> space;
    datum auth_param;

public:

    /// construct an `authorization` object from a \ref datum (not a `datum` reference)
    ///
    authorization(datum d) :
        auth_scheme{d},
        space{d},
        auth_param{d}
    { }

    bool is_valid() const { return auth_param.is_not_null(); }

    void write_json(json_object &o, bool metadata=false) const {
        (void)metadata;
        if (!is_valid()) { return; }
        json_object auth_json{o, "authorization"};
        scheme::type schemetype = auth_scheme.get_type();
        json_object scheme_json{auth_json, auth_scheme.type_get_name(schemetype)};
        if (schemetype == scheme::type::basic) {
            uint8_t outbuf[2048];
            int outlen = base64::decode(outbuf, sizeof(outbuf), auth_param.data, auth_param.length());
            outlen = outlen > 0 ? outlen : 0;        // if base64 decoding fails, print nothing
            scheme_json.print_key_json_string("param", outbuf, outlen);

        } else if (schemetype == scheme::type::bearer) {

            bearer_token{auth_param}.write_json(scheme_json);

        } else {
            scheme_json.print_key_json_string("param", auth_param.data, auth_param.length());
        }
        scheme_json.close();
        auth_json.close();
    }

};

[[maybe_unused]] inline int http_authorization_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<authorization>(data, size);
}

#endif
