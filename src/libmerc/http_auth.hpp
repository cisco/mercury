// http_auth.hpp
//
// HTTP Authorization/Authentication

#ifndef HTTP_AUTH_HPP
#define HTTP_AUTH_HPP

#include "datum.h"
#include "base64.h"

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
        if (this->cmp(std::array<uint8_t,5>{'B', 'a', 's', 'i', 'c'})) {
            return type::basic;
        }
        if (this->cmp(std::array<uint8_t,6>{'B', 'e', 'a', 'r', 'e', 'r'})) {
            return type::bearer;
        }
        if (this->cmp(std::array<uint8_t,6>{'D', 'i', 'g', 'e', 's', 't'})) {
            return type::digest;
        }
        return unknown;
    }

};

class bearer_token {
    datum header;
    datum payload;
    datum signature;

public:

    // constructs a bearer_token object from a \ref datum (not a
    // reference to a `datum)
    //
    bearer_token(datum d) {
        header.parse_up_to_delim(d, '.');
        d.accept('.');
        payload.parse_up_to_delim(d, '.');
        d.accept('.');
        signature = d;
    }

    bool is_valid() const { return signature.is_not_null(); }

    void write_json(json_object &o) const {
        if (!is_valid()) { return; }

        uint8_t outbuf[1024];
        int outlen = base64::decode(outbuf, sizeof(outbuf), header.data, header.length());
        outlen = outlen > 0 ? outlen : 0;
        o.print_key_json_string("header", outbuf, outlen);
        outlen = base64::decode(outbuf, sizeof(outbuf), payload.data, payload.length());
        outlen = outlen > 0 ? outlen : 0;
        o.print_key_json_string("payload", outbuf, outlen);
        o.print_key_json_string("signature", signature.data, signature.length());

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

    void write_json(json_object &o) const {
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
            scheme_json.print_key_json_string("param", auth_param);
        }
        scheme_json.close();
        auth_json.close();
    }

};

#endif
