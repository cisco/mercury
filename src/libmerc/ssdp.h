/*
 * ssdp.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */


#ifndef SSDP_H
#define SSDP_H

#include "json_object.h"
#include "match.h"
#include "http.h"

/*
 * ssdp
 *
 * Reference : RFC https://datatracker.ietf.org/doc/html/draft-cai-ssdp-v1-01 (outdated)
 *           : UPnP Device Architecture Spec http://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf
 *           : UpnP Device Architecture Spec (updated) https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf
 */

class ssdp : public base_protocol {

    enum msg_type {
        notify          = 0,
        m_search        = 1,
        response        = 2,
        max_msg_type    = 3
    };

    static constexpr const char* msg_str[max_msg_type] = {"notify", "m_search", "response"};

    struct datum method;
    struct http_headers headers;
    enum msg_type type;

    void set_msg_type (datum &p) {
        uint8_t msg;
        p.lookahead_uint8(&msg);

        switch (msg)
        {
        case 'N':
            type = notify;
            break;
        case 'M':
            type = m_search;
            break;
        case 'H':
            type = response;
            break;
        default:
            type = max_msg_type;
            break;
        }

        return;
    }

public:

    ssdp(datum &p) : method{NULL, NULL}, headers{}, type{max_msg_type} { parse(p); }

    void parse(datum &p) {
        set_msg_type(p);

        method.parse_up_to_delim(p, '\n');
        method.trim_trail('\r');
        p.skip(1);

        /* parse the headers */
        headers.parse_ignore_cr(p);

        return;
    }

    bool is_not_empty() const { return (type != max_msg_type); }

    //sample feature string format
    //"features":"[method,[[attribute_1_key, attribute_1_value],[attribute_2_key, attribute_2_value],...]]"

    void write_raw_features(struct json_object &o, data_buffer<2048>& feature_buf){
        if (feature_buf.readable_length() == 0) {
            o.print_key_string("features", "[]");
        } else {
            o.print_key_json_string("features", feature_buf.contents());
        }
    }

    void write_json(struct json_object &record, bool output_metadata) {
        if (this->is_not_empty()) {
            struct json_object ssdp{record, "ssdp"};
            struct json_object msg{ssdp, msg_str[type]};

            // run the list of http headers to be printed out against
            // all headers, and print the values corresponding to each
            // of the matching names
            //
            if (output_metadata) {
                msg.print_key_json_string("method", method);
            }

            data_buffer<2048> feature_buf;
            feature_buf.copy('[');
            feature_buf.write_quote_enclosed_hex(method.data, method.length());
            feature_buf.copy(',');
            feature_buf.copy('[');
            headers.print_ssdp_names_and_feature_string(msg, feature_buf, output_metadata);
            feature_buf.copy(']');
            feature_buf.copy(']');
            write_raw_features(msg, feature_buf);

            msg.close();
            ssdp.close();
        }

        return;
    }

    /*
     *    Matchers for ssdp msg types
     *    static constexpr mask_and_value<8> matcher_notify{
     *        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00 },
     *        { 'N',  'O',  'T',  'I',  'F', 'Y', 0x00, 0x00 }
     *   };
     *
     *    static constexpr mask_and_value<8> matcher_search{
     *        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
     *        { 'M',  '-',  'S',  'E',  'A', 'R', 'C', 'H' }
     *    };
     *
     *    static constexpr mask_and_value<8> matcher_response{
     *        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
     *        { 'H',  'T',  'T',  'P',  '/', '1', '.', '1' }
     *    };
    */

    // common matcher for all three ssdp msg types
    //
    static constexpr mask_and_value<8> matcher{
        { 0xe8, 0x84, 0xf0, 0xe0, 0x00, 0x90, 0x00, 0x00 },
        { 0x48, 0x04, 0x50, 0x40, 0x00, 0x10, 0x00, 0x00 }
    };

};

namespace {

    [[maybe_unused]] int ssdp_fuzz_test(const uint8_t *data, size_t size) {
        datum pkt_data{data, data+size};
        ssdp ssdp_record{pkt_data};
        return 0;
    }

}; // end of namespace


#endif /* SSDP_H */
