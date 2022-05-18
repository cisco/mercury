// bittorrent.h
//

#include <stdint.h>
#include "datum.h"
#include "json_object.h"

#ifndef BITTORRENT_H
#define BITTORRENT_H


// class acceptor accepts and ignores a single character specified via
// the template parameter C, setting d to null if the expected
// character is not found
//
template <uint8_t C>
class acceptor {
public:
    acceptor(datum &d) {
        d.accept(C);
    }
};

// class literal is a literal std::array of characters
//
template <size_t N>
class literal {
public:
    literal(datum &d, const std::array<uint8_t, N> &a) {
        for (const auto &c : a) {
            d.accept(c);
        }
    }
};


// class ignore_char_class accepts and ignores a single character,
// defined by the function static bool D::in_class(uint8_t), defined
// in the class D.  This implementation uses the Curiously Recurring
// Template Pattern (CRTP).
//
template <class D>
class ignore_char_class {
public:
    ignore_char_class(datum &d) {
        if (d.is_null()) {
            return;
        }
        uint8_t tmp;
        d.lookahead_uint8(&tmp);   // TODO: 0 == error
        if (!D::in_class(tmp)) {   // character not in class
            d.set_null();
        }
        d.skip(1);
    }
};

class digit : public ignore_char_class<digit> {
public:
    inline static bool in_class(uint8_t x) {
        return x >= '0' && x <= '9';
    }
};

// class space implements HTTP 'linear white space' (LWS)
//
class space : public ignore_char_class<space> {
public:
    inline static bool in_class(uint8_t x) {
        return x == ' ' || x == '\t';
    }
};

// class one_or_more<char_class> parses a datum that holds one or more
// uint8_ts in the character class char_class.  It is implemented
// using the CRTP (Curiously Recurring Template Pattern).
//
template <class D>
class one_or_more : public datum {
public:
    one_or_more(datum &d) {
        if (d.is_null()) {
            return;
        }
        this->data = d.data;
        uint8_t tmp;
        d.lookahead_uint8(&tmp);   // TODO: 0 == error
        //fprintf(stderr, "one_or_more: %c\n", tmp);
        if (!D::in_class(tmp)) {      // first character not in class
            this->data = nullptr;
            this->data_end = nullptr;
        }
        while (d.is_not_empty()) {
            d.lookahead_uint8(&tmp); // TODO: 0 == error
            //fprintf(stderr, "one_or_more: %c\n", tmp);
            if (D::in_class(tmp)) {
                d.skip(1);
            } else {
                break;
            }
        }
        this->data_end = d.data;
    }
};

//
// start of new http_request implementation
//

namespace http {

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
    public:
        version(datum &d) :
            proto(d, { 'H', 'T', 'T', 'P', '/' }),
            maj_digit{d},
            dot{d, { '.' }},
            min_digit{d}
        { }
    };

    class request_line {
        http::method method;
        space sp1;
        one_or_more<uri_chars> uri;
        space sp2;
        http::version version;
        literal<2> crlf;
        bool valid;

    public:

        request_line(datum &d) :
            method{d},
            sp1{d},
            uri{d},
            sp2{d},
            version{d},
            crlf{d, { '\r', '\n' }},
            valid{d.is_not_null()}
        { }

        void print(FILE *f) const {
            if (!valid) {
                //            return;
            }
            fprintf(f, "method:  ");  method.fprint(f); fputc('\n', f);
            fprintf(f, "uri:     ");     uri.fprint(f); fputc('\n', f);
            fprintf(f, "version: "); version.fprint(f); fputc('\n', f);
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
        //    acceptor<':'> colon;
        space sp;
        text value;

    public:

        http_header(datum &d) :
            name{d},
            // colon{d},
            sp{d},
            value{d}
        { }

        void fprint(FILE *f) {
            if (is_not_empty()) {
                fprintf(f, "name:   ");  name.fprint(f); fputc('\n', f);
                fprintf(f, "value:  "); value.fprint(f); fputc('\n', f);
            }
        }

        bool is_not_empty() const { return value.is_not_empty(); }
    };

    class headers : public datum {
    public:

        headers(datum &d) : datum{d} { }

        void print(FILE *f) const {
            datum tmp{*this};
            while (tmp.is_not_empty()) {
                http_header h{tmp};
                if (!h.is_not_empty()) {
                    break;
                }
                h.fprint(f);
                literal<2> crlf{tmp, { '\r', '\n' }};
            }
        }
    };

    class request {
        http::request_line request_line;
        http::headers headers;

    public:

        request(datum &d) :
            request_line{d},
            headers{d}
        { }

        void print(FILE *f) const {
            request_line.print(f);
            headers.print(f);
        }

        bool is_valid() const {
            return request_line.is_valid();
        }

    };

};

//
// end of http_request implementation
//

namespace bencoding {

    // Bencoding, following "BitTorrentSpecification - TheoryOrg.html"
    //
    // Bencoding is a way to specify and organize data in a terse
    // format. It supports the following types: byte strings, integers,
    // lists, and dictionaries.
    //

    // Byte strings are encoded as follows:
    // <string length encoded in base ten ASCII>:<string data>
    //
    //
    class byte_string {
        uint64_t len = 0;
        datum val;

    public:

        byte_string(datum &d) {
            // loop over digits and compute value
            //
            uint8_t c;
            while (d.is_not_empty()) {
                d.read_uint8(&c);
                if (c == ':') {
                    break;          // at end; not an error
                }
                if (c < '0' || c > '9') {
                    d.set_null();   // error; input is not a bint
                    break;
                }
                len *= 10;
                len += c - '0';
            }
            val.parse(d, len);
        }

        template <size_t N>
        byte_string(datum &d, std::array<uint8_t, N> k) {
            // loop over digits and compute value
            //
            uint8_t c;
            while (d.is_not_empty()) {
                d.read_uint8(&c);
                if (c == ':') {
                    break;          // at end; not an error
                }
                if (c < '0' || c > '9') {
                    d.set_null();   // error; input is not a bint
                    break;
                }
                len *= 10;
                len += c - '0';
            }
            val.parse(d, len);
            if (!val.matches(k)) {
                d.set_null();
            }
        }

        datum value() const { return val; }

    };


    // Lists are encoded as follows:
    // l<bencoded values>e
    //
    // Lists may contain any bencoded type, including integers, strings,
    // dictionaries, and even lists within other lists.

    // Integers are encoded as follows:
    // i<integer encoded in base ten ASCII>e
    //
    //  A signed 64bit integer is mandatory
    //
    class bint {
        int64_t val = 0;
    public:
        bint(datum &d) {
            d.accept('i');

            // TODO: check for minus

            // loop over digits and compute value
            //
            uint8_t c;
            while (d.is_not_empty()) {
                d.read_uint8(&c);
                if (c == 'e') {
                    break;          // at end; not an error
                }
                if (c < '0' || c > '9') {
                    d.set_null();   // error; input is not a bint
                    break;
                }
                val *= 10;
                val += c - '0';
            }
        }
        int64_t value() const { return val; }
    };

    // class key_and_value represents the key/value pair used in
    // dictionaries
    //
    // TODO: accept only strings that match a statically-defined array
    // of characters
    //
    template <typename T, size_t N=0>
    class key_and_value {
        byte_string key;
        T val;

    public:

        key_and_value(datum &d, std::array<uint8_t, N> k={}) : key{d, k}, val{d} { }

        datum value() const { return val.value(); }
    };

    // Dictionaries are encoded as follows:
    //     d<bencoded string><bencoded element>e
    //
    // The initial d and trailing e are the beginning and ending
    // delimiters. Note that the keys must be bencoded strings. The
    // values may be any bencoded type, including integers, strings,
    // lists, and other dictionaries. Keys must be strings and appear
    // in sorted order (sorted as raw strings, not alphanumerics). The
    // strings should be compared using a binary comparison, not a
    // culture-specific "natural" comparison.
    //
    template <typename... Ts>
    class dictionary {
        // ???
    public:

        dictionary(datum &d) {  }
    };
};

// class literal accepts and ignores an input, setting d to null if
// the expected input is not found
//
template <uint8_t literal_char>
class literal_ {
public:

    literal_(datum &d) {
        d.accept(literal_char);
    }
};


// Local Service Discovery (LSD) uses the following multicast groups:
// A) 239.192.152.143:6771 (org-local) and B) [ff15::efc0:988f]:6771
// (site-local)
//
// Implementation note: Since the multicast groups have a broader
// scope than lan-local implementations may want to set the
// IP_MULTICAST_TTL socket option to a value above 1
//
//   An LSD announce is formatted as follows:
//
//   BT-SEARCH * HTTP/1.1\r\n
//   Host: <host>\r\n
//   Port: <port>\r\n
//   Infohash: <ihash>\r\n
//   cookie: <cookie (optional)>\r\n
//   \r\n
//   \r\n
//
// host: RFC 2616 section 14.23 and RFC 2732 compliant Host header
// specifying the multicast group to which the announce is sent. In
// other words, strings A) or B), as appropriate.
//
// port: port on which the bittorrent client is listening in base-10,
// ascii
//
class digits : public one_or_more<digits> {
public:
    inline static bool in_class(uint8_t x) {
        return x >= '0' && x <= '9';
    }
};

// ihash: hex-encoded (40 character) infohash.  An announce may
// contain multiple, consecutive Infohash headers to announce the
// participation in more than one torrent. This may not be supported
// by older implementations. When sending multiple infohashes the
// packet length should not exceed 1400 bytes to avoid
// MTU/fragmentation problems.
//
// cookie: opaque value, allowing the sending client to filter out its
// own announces if it receives them via multicast loopback

class bt_search {
    literal<11> proto;
    datum headers;

public:

    bt_search(datum &d) :
        proto{d, {'B', 'T', '-', 'S', 'E', 'A', 'R', 'C', 'H', '\r', '\n' } },
        headers{d}
    { }

};





class bittorrent_handshake {
    encoded<uint8_t> protocol_name_length;
    datum protocol_name;
    datum extension_bytes;
    datum hash_of_info_dict;
    datum peer_id;

public:
    bittorrent_handshake(datum &d) :
        protocol_name_length{d},
        protocol_name{d, protocol_name_length},
        extension_bytes{d, 8},
        hash_of_info_dict{d, 20},
        peer_id{d, 20}
    { }

    bool is_valid() const { return peer_id.is_not_empty(); }

    void fprint(FILE *f) const {
        fprintf(f, "protocol_name:     ");  protocol_name.fprint(f);         fputc('\n', f);
        fprintf(f, "extension_bytes:   ");  extension_bytes.fprint_hex(f);   fputc('\n', f);
        fprintf(f, "hash_of_info_dict: ");  hash_of_info_dict.fprint_hex(f); fputc('\n', f);
        fprintf(f, "peer_id:           ");  peer_id.fprint_hex(f);           fputc('\n', f);
    }
};

// not sure we need to parse peer messages
//
class bittorrent_peer_message {
    encoded<uint32_t> message_length;
    encoded<uint8_t> message_type;

public:

    bittorrent_peer_message(datum &d) :
        message_length{d},
        message_type{d}
    {
    }
};

#endif // BITTORRENT_H
