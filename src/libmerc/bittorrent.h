// bittorrent.h
//

#include <stdint.h>
#include "datum.h"
#include "json_object.h"

#ifndef BITTORRENT_H
#define BITTORRENT_H

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
// ihash: hex-encoded (40 character) infohash.  An announce may
// contain multiple, consecutive Infohash headers to announce the
// participation in more than one torrent. This may not be supported
// by older implementations. When sending multiple infohashes the
// packet length should not exceed 1400 bytes to avoid
// MTU/fragmentation problems.
//
// cookie: opaque value, allowing the sending client to filter out its
// own announces if it receives them via multicast loopback

class bittorrent {

public:

    bittorrent(datum &) { }

};


#endif // BITTORRENT_H
