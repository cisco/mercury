// newhttp.h

#ifndef NEWHTTP_H
#define NEWHTTP_H

#include "datum.h"
#include "json_object.h"

namespace newhttp {

    class uri_chars : public one_or_more<uri_chars> {
    public:
        inline static bool in_class(uint8_t x) {
            // return x != ' ';
            return x > ' ' && x <= '~';
        }
    };

    class uppercase : public one_or_more<uppercase> {
    public:
        inline static bool in_class(uint8_t x) {
            return x >= 'A' && x <= 'Z';
        }
    };

    class method : public one_or_more<method> {
    public:
        inline static bool in_class(uint8_t x) {
            return (x >= 'A' && x <= 'Z') || x == '-';
        }
    };

    //    token          = 1*<any CHAR except CTLs or separators>
    //    separators     = "(" | ")" | "<" | ">" | "@"
    //                   | "," | ";" | ":" | "\" | <">
    //                   | "/" | "[" | "]" | "?" | "="
    //                   | "{" | "}" | SP | HT

    // Following RFC 2616 (HTTP/1.1)
    //
    //        OCTET          = <any 8-bit sequence of data>
    //        CHAR           = <any US-ASCII character (octets 0 - 127)>
    //        UPALPHA        = <any US-ASCII uppercase letter "A".."Z">
    //        LOALPHA        = <any US-ASCII lowercase letter "a".."z">
    //        ALPHA          = UPALPHA | LOALPHA
    //        DIGIT          = <any US-ASCII digit "0".."9">
    //        CTL            = <any US-ASCII control character
    //                         (octets 0 - 31) and DEL (127)>
    //        CR             = <US-ASCII CR, carriage return (13)>
    //        LF             = <US-ASCII LF, linefeed (10)>
    //        SP             = <US-ASCII SP, space (32)>
    //        HT             = <US-ASCII HT, horizontal-tab (9)>
    //        <">            = <US-ASCII double-quote mark (34)>

    //  HTTP-Version   = "HTTP" "/" 1*DIGIT "." 1*DIGIT
    //
    class version : public datum {
        literal<5> proto;
        digit maj_digit;
        literal<1> dot;
        digit min_digit;
        bool valid;
    public:
        version(datum &d) :
            datum{d},
            proto(d, { 'H', 'T', 'T', 'P', '/' }),
            maj_digit{d},
            dot{d, { '.' }},
            min_digit{d},
            valid{d.is_not_null()}
        {
            if (valid) {
                data_end = d.data;
            } else {
                set_null();
            }
        }
    };

    class crlf {
        literal<2> delim;
    public:
        crlf(datum &d) : delim{d, { '\r', '\n' } } { }
    };

    class request_line {
        newhttp::method method;
        space sp1;
        one_or_more<uri_chars> uri;
        space sp2;
        newhttp::version version;
        crlf delim;
        bool valid;

    public:

        request_line(datum &d) :
            method{d},
            sp1{d},
            uri{d},
            sp2{d},
            version{d},
            delim{d},
            valid{d.is_not_null()}
        { }

        void write_json(json_object &o) const {
            if (!valid) {
                return;
            }
            o.print_key_json_string("method", method);
            o.print_key_json_string("uri", uri);
            o.print_key_json_string("version", version);
        }

        bool is_valid() const { return valid; }
    };


    //    token          = 1*<any CHAR except CTLs or separators>
    //
    //    separators     = "(" | ")" | "<" | ">" | "@"
    //                   | "," | ";" | ":" | "\" | <">
    //                   | "/" | "[" | "]" | "?" | "="
    //                   | "{" | "}" | SP | HT
    //
    //    message-header = field-name ":" [ field-value ]
    //    field-name     = token
    //    field-value    = *( field-content | LWS )
    //    field-content  = <the OCTETs making up the field-value
    //                     and consisting of either *TEXT or combinations
    //                     of token, separators, and quoted-string>

    class token : public one_or_more<token> {
    public:
        inline static bool in_class(uint8_t c) {
            if (c > ' ' && c <= '~') {
                switch (c) {
                case '(':
                case ')':
                case '<':
                case '>':
                case '@':
                case ',':
                case ';':
                    // case ':': // compatibility hack
                case '\\':
                case '"':
                case '/':
                case '[':
                case ']':
                case '?':
                case '=':
                case '{':
                case '}':
                case '\t':
                    return false;
                default:
                    return true;
                }
            }
            return false;
        }
    };

    //  TEXT = <any OCTET except CTLs, but including LWS>
    //
    class text : public one_or_more<text> {
    public:
        inline static bool in_class(uint8_t x) {
            return (x >= ' ' && x <= '~') || (x == '\t');
        }
    };

    class http_header {
        token name;
        //    accept_byte<':'> colon;
        space sp;
        text value;

    public:

        http_header(datum &d) :
            name{d},
            // colon{d},
            sp{d},
            value{d}
        { }

        void write_json(json_array &a) {
            if (is_not_empty()) {
                json_object hdr{a};
                hdr.print_key_json_string("name", name);
                hdr.print_key_json_string("value", value);
                hdr.close();
            }
        }

        bool is_not_empty() const { return value.is_not_empty(); }
    };

    class headers : public datum {
    public:

        headers(datum &d) : datum{d} { }

        void write_json(json_object &o) const {
            json_array hdrs{o, "headers"};
            datum tmp{*this};
            while (tmp.is_not_empty()) {
                if (lookahead<crlf> at_end{tmp}) {
                    break;
                }
                http_header h{tmp};
                if (!h.is_not_empty()) {
                    break;
                }
                h.write_json(hdrs);
                crlf ignore{tmp};
            }
            hdrs.close();
            crlf ignore{tmp};
            o.print_key_json_string("body", tmp);
        }

    };

    class request {
        newhttp::request_line request_line;
        newhttp::headers headers;

    public:

        request(datum &d) :
            request_line{d},
            headers{d}
        { }

        bool is_valid() const {
            return request_line.is_valid();
        }

        void write_json(json_object &o) const {
            json_object http{o, "newhttp"};
            request_line.write_json(http);
            headers.write_json(http);
            http.close();
        }

    };

};

#endif // NEWHTTP_H
