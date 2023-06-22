/*
 * netbios.h
 *
 * Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

/**
 * \file netbios.h
 *
 * \brief interface file for NETBIOS sessions service and datagram service code
 */
#ifndef NETBIOS_H
#define NETBIOS_H

#include "dns.h"
#include "json_object.h"
#include "util_obj.h"
#include "match.h"

/**
 * \file netbios.h
 *
 * \brief Netbios session service and Netbios Datagram Service protocol support
 *
 * \remarks
 * \verbatim
 *
 * Netbios session servicei(NBSS) and Netbios Datagram Service packet(NBDS) formats (from RFC 1002)
 *
 * NBSS packet format:
 *
 *
 *                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |      TYPE     |     FLAGS     |            LENGTH             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  /               TRAILER (Packet Type Dependent)                 /
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+a
 *
 */

class nbss_packet : public base_protocol {
    encoded<uint8_t> type;
    encoded<uint8_t> flags;
    encoded<uint16_t> length;
    datum &body;
    bool valid;

public:
    nbss_packet(datum &d) :
        type(d),
        flags(d),
        length(d),
        body(d),
        valid(d.is_not_null()) { }

    bool is_not_empty() {
        return valid;
    }

    uint8_t get_code() const {  return type.value(); }

    const char * get_code_str() const {
        switch(type) {
        case 0x00:      return "session_message";
        case 0x81:      return "session_request";
        case 0x82:      return "positive_session_response";
        case 0x83:      return "negative_session_response";
        case 0x84:      return "retarget_session_response";
        case 0x85:      return "session_keep_alive";
        default:        return nullptr;
        }
    }

    static constexpr mask_and_value<4> matcher {
        {0x7c, 0x7f, 0x00, 0x00},
        {0x00, 0x00, 0x00, 0x00}
    };

    static ssize_t get_payload_length(datum pkt) {
        encoded<uint32_t> len(pkt);
        return(len.slice<15, 32>() + 4);
    }

    void write_json(struct json_object &o, bool) {
        if (this->is_not_empty()) {
            struct json_object nbss{o, "nbss"};
            type_codes<nbss_packet> type_code{*this};
            nbss.print_key_value("type", type_code);
            nbss.print_key_uint16("length", length.value());
            nbss.print_key_hex("data", body);
            nbss.close();
        }
    }
};

/*
 * Netbios Datagram Service(NBDS) packet format:
 *
 * DIRECT_UNIQUE, DIRECT_GROUP, & BROADCAST DATAGRAM
 *
 *                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   MSG_TYPE    |     FLAGS     |           DGM_ID              |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                           SOURCE_IP                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          SOURCE_PORT          |          DGM_LENGTH           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         PACKET_OFFSET         |                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
 *  |                                                               |
 *  /                          SOURCE_NAME                          /
 *  /                                                               /
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  /                       DESTINATION_NAME                        /
 *  /                                                               /
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  /                           USER_DATA                           /
 *  /                                                               /
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

class direct_or_bcast_dgm {
    encoded<uint16_t> dgm_length;
    encoded<uint16_t> packet_offset;
    datum tmp_body;
    dns_name source_name;
    dns_name destination_name;
    datum &body;
    bool valid;

public:
    direct_or_bcast_dgm(datum &d) :
        dgm_length(d),
        packet_offset(d),
        tmp_body(d),
        source_name(tmp_body, d),
        destination_name(tmp_body, d),
        body(d),
        valid(d.is_not_null()) { }

    bool is_not_empty() {
        return valid;
    }

    void write_json(struct json_object &o) {
        if(!valid) {
            return;
        }

        o.print_key_uint16("datagram_length", dgm_length.value());
        o.print_key_uint16("packet_offset", packet_offset.value());
        data_buffer<MAX_NETBIOS_NAME> netbios_name;
        if (source_name.is_netbios()) {
            source_name.get_netbios_name(netbios_name);
            o.print_key_json_string("source_name", netbios_name.buffer, netbios_name.readable_length());
        }
        if (destination_name.is_netbios()) {
            netbios_name.reset();
            destination_name.get_netbios_name(netbios_name);
            o.print_key_json_string("destination_name", netbios_name.buffer, netbios_name.readable_length());
        }
        o.print_key_hex("data", body);
    }
};

class dgm_error {
    encoded<uint8_t> error_code;
    bool valid;

public:
    dgm_error(datum &d) :
        error_code(d),
        valid(d.is_not_null()) { }

    bool is_not_empty() {
        return valid;
    }

    void write_json(struct json_object &o) {
        if(!valid) {
            return;
        }

        o.print_key_uint8("error_code", error_code.value());
    }
};

class dgm_query {
    datum tmp_body;
    dns_name destination_name;
    bool valid;

public:
    dgm_query(datum &d) :
        tmp_body(d),
        destination_name(tmp_body, d),
        valid(d.is_not_null()) { }

    bool is_not_empty() {
        return valid;
    }

    void write_json(struct json_object &o) {
        if(!valid) {
            return;
        }
        if (destination_name.is_netbios()) {
            data_buffer<MAX_NETBIOS_NAME> netbios_name;
            destination_name.get_netbios_name(netbios_name);
            o.print_key_json_string("destination_name", netbios_name.buffer, netbios_name.readable_length());
        }
    }
};

class nbds_packet : public base_protocol {
    encoded<uint8_t> msg_type;
    encoded<uint8_t> flags;
    encoded<uint16_t> datagram_id;
    ipv4_addr source_ip;
    encoded<uint16_t> source_port;
    datum &body;
    bool valid;

public:
    nbds_packet (datum &d) :
        msg_type(d),
        flags(d),
        datagram_id(d),
        source_ip(d),
        source_port(d),
        body(d),
        valid(d.is_not_null()) { }

    bool is_not_empty() {
        return valid;
    }

    uint8_t get_code() const {  return msg_type.value(); }

    const char * get_code_str() const {
        switch(msg_type) {
        case 0x10:      return "direct_unique_datagram";
        case 0x11:      return "direct_group_datagram";
        case 0x12:      return "broadcast_datagram";
        case 0x13:      return "datagram_error";
        case 0x14:      return "datagram_query_request";
        case 0x15:      return "datagram_positive_query_response";
        case 0x16:      return "datagram_negative_query_response";
        default:        return nullptr;
        }
    }

    static constexpr mask_and_value<4> matcher {
        {0xec, 0x0f, 0x00, 0x00},
        {0x00, 0x00, 0x00, 0x00}
    };

    void write_json(struct json_object &o, bool) {
        if (this->is_not_empty()) {
            struct json_object nbds{o, "nbds"};
            type_codes<nbds_packet> type_code{*this}; 
            nbds.print_key_value("msg_type", type_code);
            nbds.print_key_uint8_hex("flags", flags.value());
            nbds.print_key_uint16("datagram_id",  datagram_id);
            nbds.print_key_value("source_ip", source_ip);
            nbds.print_key_uint16("source_port", source_port);
            switch(msg_type) {
            case 0x10:
            case 0x11:
            case 0x12:
            {
                direct_or_bcast_dgm pkt(body);
                pkt.write_json(nbds);
                break;
            }
            case 0x13:
            {
                dgm_error pkt(body);
                pkt.write_json(nbds);
                break;
            }
            case 0x14:
            case 0x15:
            case 0x16:
            {
                dgm_query pkt(body);
                pkt.write_json(nbds);
                break;
            }
            default:
            nbds.print_key_hex("data", body);
            }
            nbds.close();
        }
    }
};

namespace {

    [[maybe_unused]] int nbss_packet_fuzz_test(const uint8_t *data, size_t size) {
        struct datum nbss_data{data, data+size};
        char buffer[8192];
        struct buffer_stream buf_json(buffer, sizeof(buffer));
        struct json_object record(&buf_json);


        nbss_packet pkt{nbss_data};
        if (pkt.is_not_empty()) {
            pkt.write_json(record, true);
        }

        return 0;
    }

    [[maybe_unused]] int nbds_packet_fuzz_test(const uint8_t *data, size_t size) {
        struct datum nbds_data{data, data+size};
        char buffer[8192];
        struct buffer_stream buf_json(buffer, sizeof(buffer));
        struct json_object record(&buf_json);


        nbds_packet pkt{nbds_data};
        if (pkt.is_not_empty()) {
            pkt.write_json(record, true);
        }

        return 0;
    }
}; // end of namespace


#endif
