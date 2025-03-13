// rfb.hpp

#ifndef RFB_HPP
#define RFB_HPP

#include "datum.h"
#include "protocol.h"
#include "json_object.h"
#include "match.h"
//#include "fingerprint.h"

namespace rfb {

    //  RFB 003.008\n (hex 52 46 42 20 30 30 33 2e 30 30 38 0a)
    //
    class protocol_version_handshake : public base_protocol {
        literal_byte<'R','F','B',' '> preamble; // ,'0','0','3','.'
        datum version;
        bool valid = false;

    public:

        protocol_version_handshake(datum &d) : preamble{d} {
            fprintf(stderr, "%s\n", __func__);
            version.parse_up_to_delim(d, '\n');
            if (d.is_not_null()) {
                valid = true;
            }
        }

        void write_json(json_object &o, bool) {
            fprintf(stderr, "%s\n", __func__);
            if (valid) {
                json_object rfb_json{o, "rfb"};
                rfb_json.print_key_json_string("version", version);
                rfb_json.close();
            }
        }

        static constexpr mask_and_value<8> matcher{
            { 'R','F','B',' ','0','0','3','.', },
            { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
        };


    };

};

#endif // RFB_HPP
