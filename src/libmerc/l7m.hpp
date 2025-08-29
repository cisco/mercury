// l7.hpp
//
// layer seven metadata

#ifndef L7M_HPP
#define L7M_HPP

#include "datum.h"
#include "cbor.hpp"
#include "cbor_object.hpp"

[[maybe_unused]] inline std::string translate_l7_metadata_to_json_string(datum d) {
    char buffer[8192];
    struct buffer_stream buf_json(buffer, sizeof(buffer));

    // determine the L7 metadata version by peeking at the first two
    // bytes of d, then invoke the appropriate decoding function
    //
    // note: the first byte must be 0xbf, the initial byte of a cbor
    // indefinite length map
    //
    if (lookahead<literal_byte<0xbf, 0x01>> tmp{d}) {
        struct json_object record(&buf_json);
        fdc::decode_version_one(d, record);
        record.close();

    } else {
        if (decode_cbor_map_to_json(d, buf_json, nullptr) == false) {
            return "";
        }
    }
    buf_json.write_char('\0');
    return buf_json.get_string();
}

[[maybe_unused]] inline std::string get_json_decoded_fdc(const char *fdc_blob, ssize_t blob_len) {
    datum fdc_data = datum{(uint8_t*)fdc_blob,(uint8_t*)(fdc_blob+blob_len)};
    return translate_l7_metadata_to_json_string(fdc_data);
}

#endif // L7M_HPP
