// ospf.h
//
// Open Shortest Path First (OSPF) routing protocol


#ifndef OSPF_H
#define OSPF_H

#include "datum.h"

//  OSPF packet header (following RFC 2328, A.3.1)
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   Version #   |     Type      |         Packet length         |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                          Router ID                            |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                           Area ID                             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Checksum            |             AuType            |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                       Authentication                          |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                       Authentication                          |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class ospf : public base_protocol {
    uint8_t version;
    uint8_t type;
    uint16_t length;
    uint32_t router_id;
    uint32_t area_id;
    uint16_t au_type;
    datum authentication;
    datum body;

    enum type_code : uint8_t {
        hello                       = 1,
        database_description        = 2,
        link_state_request          = 3,
        link_state_update           = 4,
        link_state_acknowledgment   = 5,
    };

    static const char *type_string(ospf::type_code t) {
        switch(t) {
        case hello: return "hello";
        case database_description: return "database_description";
        case link_state_request: return "link_state_request";
        case link_state_update: return "link_state_update";
        case link_state_acknowledgment: return "link_state_acknowledgement";
        default:
            ;
        }
        return "unknown";
    };

    enum au_type_code : uint16_t {
        no_authentication                                           = 0,
        simple_password_authentication                              = 1,
        cryptographic_authentication                                = 2,
        cryptographic_authentication_with_extended_sequence_numbers = 3,
    };

    static const char *au_type_string(ospf::au_type_code t) {
        switch(t) {
        case no_authentication: return "no_authentication";
        case simple_password_authentication: return "simple_password_authentication";
        case cryptographic_authentication: return "cryptographic_authentication";
        case cryptographic_authentication_with_extended_sequence_numbers: return "cryptographic_authentication_with_extended_sequence_numbers";
        default:
            ;
        }
        if (t < 256) {
            return "unassigned";
        }
        return "deprecated/unknown";
    }

public:

    ospf(datum &d) {
        d.read_uint8(&version);
        d.read_uint8(&type);
        d.read_uint16(&length);
        d.read_uint32(&router_id);
        d.read_uint32(&area_id);
        d.skip(2); // checksum
        d.read_uint16(&au_type);
        authentication.parse(d, 8);
        body.parse(d, length - header_length);
    }

    static constexpr size_t header_length = 24;

    bool is_valid() const { return body.is_not_empty(); }
    bool is_not_empty() const { return
            body.is_not_empty(); }

    void write_json(json_object &o, bool metadata=false) const {
        (void)metadata;  // ignore parameter

        if (is_valid()) {
            json_object json{o, "ospf"};
            json.print_key_uint("vesion", version);
            json.print_key_string("type", type_string(static_cast<type_code>(type)));
            json.print_key_uint("router_id", router_id);
            json.print_key_uint("area_id", area_id);
            json.print_key_string("au_type", au_type_string(static_cast<au_type_code>(au_type)));
            json.print_key_hex("authentication", authentication);
            json.print_key_hex("body", body);
            json.close();
        }
    }

};

#endif // OSPF_H
