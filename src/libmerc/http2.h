// http2.h
//
// HTTP version two header processing

#ifndef HTTP2_H
#define HTTP2_H

#include "datum.h"
#include "json_object.h"

// HPACK - HTTP2 Header [De]Compression
//

/* From RFC 7541

          | 1     | :authority                  |               |
          | 2     | :method                     | GET           |
          | 3     | :method                     | POST          |
          | 4     | :path                       | /             |
          | 5     | :path                       | /index.html   |
          | 6     | :scheme                     | http          |
          | 7     | :scheme                     | https         |
          | 8     | :status                     | 200           |
          | 9     | :status                     | 204           |
          | 10    | :status                     | 206           |
          | 11    | :status                     | 304           |
          | 12    | :status                     | 400           |
          | 13    | :status                     | 404           |
          | 14    | :status                     | 500           |
          | 15    | accept-charset              |               |
          | 16    | accept-encoding             | gzip, deflate |
          | 17    | accept-language             |               |
          | 18    | accept-ranges               |               |
          | 19    | accept                      |               |
          | 20    | access-control-allow-origin |               |
          | 21    | age                         |               |
          | 22    | allow                       |               |
          | 23    | authorization               |               |
          | 24    | cache-control               |               |
          | 25    | content-disposition         |               |
          | 26    | content-encoding            |               |
          | 27    | content-language            |               |
          | 28    | content-length              |               |
          | 29    | content-location            |               |
          | 30    | content-range               |               |
          | 31    | content-type                |               |
          | 32    | cookie                      |               |
          | 33    | date                        |               |
          | 34    | etag                        |               |
          | 35    | expect                      |               |
          | 36    | expires                     |               |
          | 37    | from                        |               |
          | 38    | host                        |               |
          | 39    | if-match                    |               |
          | 40    | if-modified-since           |               |
          | 41    | if-none-match               |               |
          | 42    | if-range                    |               |
          | 43    | if-unmodified-since         |               |
          | 44    | last-modified               |               |
          | 45    | link                        |               |
          | 46    | location                    |               |
          | 47    | max-forwards                |               |
          | 48    | proxy-authenticate          |               |
          | 49    | proxy-authorization         |               |
          | 50    | range                       |               |
          | 51    | referer                     |               |
          | 52    | refresh                     |               |
          | 53    | retry-after                 |               |
          | 54    | server                      |               |
          | 55    | set-cookie                  |               |
          | 56    | strict-transport-security   |               |
          | 57    | transfer-encoding           |               |
          | 58    | user-agent                  |               |
          | 59    | vary                        |               |
          | 60    | via                         |               |
          | 61    | www-authenticate            |               |
*/

class hpack_decoder {

public:
    datum input;

    hpack_decoder(datum &in) : input{in} {}

    void get_next(FILE *f) {
        fprintf(f, "\n%s:\t", __func__);

        uint8_t first;
        input.read_uint8(&first);

        fprintf(f, "first: %02x\t", first);

        if (first & 0x80) { // 1***: indexed header field
            // parse integer

            ssize_t value = decode(first, 7);
            fprintf(f, "indexed header field\tvalue: %zd\t", value);

        } else {  // literal header field

            if (first & 0x40) { // 01**: literal header field with incremental indexing
                //
                fprintf(f, "literal header field\t");
            }
            else if ((first & 0xf0) == 0) {  // 0000: literal header field without indexing
                //
                fprintf(f, "literal header field without indexing\t");

                ssize_t value = decode(first, 4);
                fprintf(f, "value: %zd\t", value);
                if (value > 0) {
                    // LOOK UP value IN TABLE
                } else {
                    // READ VALUE FROM INPUT
                }

            }
            else if ((first & 0xf0) == 1) {  // 0001: literal header field never indexed
                //
                fprintf(f, "literal header field never indexed\t");
           }
        }

        fprintf(f, "\n");
    }

    ssize_t decode(uint8_t first_byte, unsigned int N) {
        uint8_t mask;
        if (N==7) { mask = 0x7f; }
        if (N==6) { mask = 0x3f; }
        if (N==5) { mask = 0x1f; }
        if (N==4) { mask = 0x0f; }
        if (N==3) { mask = 0x07; }
        if (N==2) { mask = 0x03; }
        if (N==1) { mask = 0x01; }

        if ((first_byte & mask) < mask) {
            return first_byte & mask;   // value occupies single byte
        }

        // recover value from remaining bytes
        //
        int multiplier = 128;
        ssize_t tmp = 0;
        uint8_t next_byte;
        do {
            input.read_uint8(&next_byte);
            tmp += (next_byte & 0x7f) * multiplier;
            multiplier *= 128;
        } while(next_byte & 0x80 && input.is_not_empty());

        return tmp + mask;
    }
};

// Headers Frame (following RFC7540)
//
//    +---------------+
//    |Pad Length? (8)|
//    +-+-------------+-----------------------------------------------+
//    |E|                 Stream Dependency? (31)                     |
//    +-+-------------+-----------------------------------------------+
//    |  Weight? (8)  |
//    +-+-------------+-----------------------------------------------+
//    |                   Header Block Fragment (*)                 ...
//    +---------------------------------------------------------------+
//    |                           Padding (*)                       ...
//    +---------------------------------------------------------------+

class http2_headers {
    uint8_t pad_length;
    uint32_t e_stream_dependency;
    uint8_t weight;
    datum header_block_fragment;

public:
    http2_headers() : pad_length{0}, e_stream_dependency{0}, weight{0}, header_block_fragment{NULL, NULL} { }

    void parse(datum &d, bool padded=false, bool priority=false) {
        if (padded) {
            d.read_uint8(&pad_length);
        }
        if (priority) {
            d.read_uint32(&e_stream_dependency);
            d.read_uint8(&weight);
        }
        header_block_fragment = d;
    }

    void write_json(json_object &o) {
        json_object json_frame(o, "headers");
        json_frame.print_key_uint("pad_length", pad_length);
        // json_frame.print_key_uint("e", e_stream_dependency);  // TODO: need bit accessor function
        json_frame.print_key_uint("stream_dependency", e_stream_dependency);
        json_frame.print_key_hex("header_block_fragment", header_block_fragment);
        hpack_decoder headers{header_block_fragment};

        while(headers.input.is_not_empty()) {
            datum tmp = headers.input;
            headers.get_next(stderr);
            if (headers.input == tmp) {
                // we are not advancing, so abandon this loop
                fprintf(stderr, "break\n");
                break;
            }
        }
        json_frame.close();
    }
};


//  Frame Format (following RFC 7540)
//
//    +-----------------------------------------------+
//    |                 Length (24)                   |
//    +---------------+---------------+---------------+
//    |   Type (8)    |   Flags (8)   |
//    +-+-------------+---------------+-------------------------------+
//    |R|                 Stream Identifier (31)                      |
//    +=+=============================================================+
//    |                   Frame Payload (0...)                      ...
//    +---------------------------------------------------------------+
//

class http2_frame {
    uint64_t length;
    uint8_t type;
    uint8_t flags;
    uint32_t stream_id;
    datum payload;

public:

    enum type : uint8_t {
        DATA          = 0x0,
        HEADERS       = 0x1,
        PRIORITY      = 0x2,
        RST_STREAM    = 0x3,
        SETTINGS      = 0x4,
        PUSH_PROMISE  = 0x5,
        PING          = 0x6,
        GOAWAY        = 0x7,
        WINDOW_UPDATE = 0x8,
        CONTINUATION  = 0x9
    };

    http2_frame() : length{0}, type{0}, flags{0}, stream_id{0}, payload{NULL, NULL} {}

    void parse(struct datum &d) {
        d.read_uint(&length, 3);
        d.read_uint8(&type);
        d.read_uint8(&flags);
        d.read_uint32(&stream_id);
        payload = d;
    }

    const char *type_string(uint8_t t) {
        switch(t) {
        case DATA:           return "DATA";
        case HEADERS:        return "HEADERS";
        case PRIORITY:       return "PRIORITY";
        case RST_STREAM:     return "RST_STREAM";
        case SETTINGS:       return "SETTINGS";
        case PUSH_PROMISE:   return "PUSH_PROMISE";
        case PING:           return "PING";
        case GOAWAY:         return "GOAWAY";
        case WINDOW_UPDATE:  return "WINDOW_UPDATE";
        case CONTINUATION:   return "CONTINUATION";
        default:
            return "unknown";
        };
    }

    void write_json(struct json_object &o) {
        json_object json_frame(o, "frame");
        json_frame.print_key_uint("length", length);
        json_frame.print_key_string("type", type_string(type));
        json_frame.print_key_uint("flags", flags);
        json_frame.print_key_uint("stream_id", stream_id);
        json_frame.print_key_hex("payload", payload);

        if (type == HEADERS) {
            http2_headers h;
            h.parse(payload);
            h.write_json(o);
        }

        json_frame.close();
    }
};

namespace {
    
    [[maybe_unused]] int http2_frame_fuzz_test(const uint8_t *data, size_t size) {
        datum d{data, data+size};
        http2_frame pkt_data;
        pkt_data.parse(d);
        if (d.is_not_null()) {
            char output_buffer[8192];
            struct buffer_stream buf_json(output_buffer, sizeof(output_buffer));
            struct json_object record(&buf_json);
            pkt_data.write_json(record);
        }
        return 0;
    }

    [[maybe_unused]] int http2_header_fuzz_test(const uint8_t *data, size_t size) {
        datum d{data, data+size};
        http2_headers pkt_data;
        pkt_data.parse(d);
        if (d.is_not_null()) {
            char output_buffer[8192];
            struct buffer_stream buf_json(output_buffer, sizeof(output_buffer));
            struct json_object record(&buf_json);
            pkt_data.write_json(record);
        }
        return 0;
    }

};

#endif // HTTP2_H
