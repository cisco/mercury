// ntp.h
//
// network time protocol

#ifndef NTP_H
#define NTP_H

#include "datum.h"
#include "protocol.h"

// NTP Packet Header Format (following RFC 5905, Figure 8)
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |LI | VN  |Mode |    Stratum    |     Poll      |   Precision   |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                         Root Delay                            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                         Root Dispersion                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                          Reference ID                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                     Reference Timestamp (64)                  +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                      Origin Timestamp (64)                    +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                      Receive Timestamp (64)                   +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                      Transmit Timestamp (64)                  +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   .                                                               .
//   .                    Extension Field 1 (variable)               .
//   .                                                               .
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   .                                                               .
//   .                    Extension Field 2 (variable)               .
//   .                                                               .
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                          Key Identifier                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   |                            dgst (128)                         |
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//

class ntp : public base_protocol {
    encoded<uint8_t> flags;
    encoded<uint8_t> stratum;
    encoded<uint8_t> poll;
    encoded<uint8_t> precision;
    encoded<uint32_t> root_delay;
    encoded<uint32_t> root_dispersion;
    encoded<uint32_t> reference_id;
    encoded<uint64_t> reference_timestamp;
    encoded<uint64_t> origin_timestamp;
    encoded<uint64_t> recieve_timestamp;
    encoded<uint64_t> transmit_timestamp;
    bool valid;

    uint8_t LI()   const { return flags.slice<0,2>(); }
    uint8_t VN()   const { return flags.slice<2,5>(); }
    uint8_t Mode() const { return flags.slice<5,8>(); }

public:

    ntp(datum &d) :
        flags{d},
        stratum{d},
        poll{d},
        precision{d},
        root_delay{d},
        root_dispersion{d},
        reference_id{d},
        reference_timestamp{d},
        origin_timestamp{d},
        recieve_timestamp{d},
        transmit_timestamp{d},
        valid{d.is_not_null()}
    { }

    bool is_not_empty() const { return valid; }

    void write_json(json_object &o, bool metadata=false) {
        (void)metadata;
        if (!valid) {
            return;
        }
        json_object ntp_json(o, "ntp");
        ntp_json.print_key_uint("li",   LI());
        ntp_json.print_key_uint("vn",   VN());
        ntp_json.print_key_uint("mode", Mode());
        ntp_json.print_key_uint("stratum", stratum);
        ntp_json.print_key_uint("poll", poll);
        ntp_json.print_key_uint("precision", precision);
        ntp_json.print_key_uint("root_delay", root_delay);
        ntp_json.print_key_uint("root_dispersion", root_dispersion);
        ntp_json.print_key_uint("reference_id", reference_id);
        ntp_json.print_key_uint("reference_timestamp", reference_timestamp);
        ntp_json.print_key_uint("origin_timestamp", origin_timestamp);
        ntp_json.print_key_uint("receive_timestamp", recieve_timestamp);
        ntp_json.print_key_uint("transmit_timestamp", transmit_timestamp);
        ntp_json.close();
    }

    void write_l7_metadata(cbor_object &o, bool) {
        cbor_array protocols{o, "protocols"};
        protocols.print_string("ntp");
        protocols.close();
    }
};

[[maybe_unused]] inline int ntp_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<ntp>(data, size);
}

namespace ntp_test {
#ifndef NDEBUG
    inline bool unit_test() {
        char buffer[2048];

        uint8_t ntp_request[] = {
            0x1b, 0x00, 0x00, 0xe9,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xe6, 0x30, 0xf6, 0xc5, 0x98, 0xeb, 0xca, 0xbe
        };
        datum d1{ntp_request, ntp_request + sizeof(ntp_request)};
        ntp pkt1{d1};
        if (!pkt1.is_not_empty()) return false;
        {
            buffer_stream buf{buffer, sizeof(buffer)};
            json_object json{&buf};
            pkt1.write_json(json);
            json.close();
            buf.write_char('\0');
            if (!strstr(buffer, "\"mode\":3")) return false;
        }

        uint8_t ntp_response[] = {
            0x24, 0x01, 0x06, 0xec,
            0x00, 0x00, 0x00, 0x6a, 0x00, 0x00, 0x06, 0xd8, 0x19, 0x42, 0xe6, 0x01,
            0xe6, 0x30, 0xf6, 0xc5, 0x98, 0xeb, 0xca, 0xbe,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xe6, 0x30, 0xf6, 0xc9, 0x38, 0xeb, 0xb3, 0x41,
            0xe6, 0x30, 0xf6, 0xc9, 0x38, 0xeb, 0xd6, 0x7d
        };
        datum d2{ntp_response, ntp_response + sizeof(ntp_response)};
        ntp pkt2{d2};
        if (!pkt2.is_not_empty()) return false;

        uint8_t too_short[] = { 0x1b, 0x00, 0x00, 0xe9 };
        datum d3{too_short, too_short + sizeof(too_short)};
        ntp pkt3{d3};
        if (pkt3.is_not_empty()) return false;

        return true;
    }
#endif
} // namespace ntp_test

// NTP udp.data examples:
//
// "1c0300e90000006a000006d81942e601e630f6c598ebcabe0000000000000000e630f6c938ebb341e630f6c938ebd67d"
// "1c0300e90000006a000006d81942e601e630f6c5989e419f0000000000000000e630f6c9b48591a4e630f6c9b485bb96"
// "1c0300e90000006a000006e01942e601e630f7759757a3550000000000000000e630f783f75786cfe630f783f757ad65"
// "1c0300e90000006a000006e01942e601e630f77598c9264f0000000000000000e630f78450d97628e630f78450d9945b"

#endif // NTP_H
