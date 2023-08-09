/*
 * openvpn.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

/*
 * \file openvpn.h
 *
 * \brief interface file for OpenVPN code
 */
#ifndef OPENVPN_H
#define OPENVPN_H

#include <vector>

#include "datum.h"
#include "protocol.h"
#include "json_object.h"
#include "tls.h"


// openvpn tcp ack packet
// note: fields with '*' are optional fields
// note: more than one openvpn pkt may be present in a single TCP packet
//
//   0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |              len              | op_code |key_.|               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
//  |                           session_id                          |
//  +                                               +-+-+-+-+-+-+-+-+
//  |                                               |               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
//  |                                                               |
//  +                                                               +
//  |                                                               |
//  +                                                               +
//  |                                                               |
//  +                                                               +
//  |                                                               |
//  +                                                               +
//  |                                                               |
//  +                                                               +
//  |                                                               |
//  +                                                               +
//  |                        HMAC*(16/20/32/64)                     |
//  +                                               +-+-+-+-+-+-+-+-+
//  |                                               |               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                 replay_pkt_id                 |               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                   net_time*                   |pkt_id_array_l.|
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |            pkt_id_array_element[0](if array_len>0)            |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                              ...                              |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                pkt_id_array_element[array_len-1]              |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                remote_session_id (if array_len>0)             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// openvpn tcp ctrl packet
//
//   0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |              len              | op_code |key_.|               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
//  |                           session_id                          |
//  +                                               +-+-+-+-+-+-+-+-+
//  |                                               |               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
//  |                                                               |
//  +                                                               +
//  |                                                               |
//  +                                                               +
//  |                                                               |
//  +                                                               +
//  |                                                               |
//  +                                                               +
//  |                                                               |
//  +                                                               +
//  |                                                               |
//  +                                                               +
//  |                        HMAC*(16/20/32/64)                     |
//  +                                               +-+-+-+-+-+-+-+-+
//  |                                               |               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                 replay_pkt_id                 |               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                   net_time*                   |pkt_id_array_l.|
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |            pkt_id_array_element[0](if array_len>0)            |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                              ...                              |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                pkt_id_array_element[array_len-1]              |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                remote_session_id (if array_len>0)             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                           msg_pkt_id                          |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  +                                                               +
//  |                                                               |
//  +                  data* .... (len - header_len)                 +
//  |                                                               |
//  +                                                               +
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

struct openvpn_payload {
    encoded<uint64_t> session_id{0};
    datum HMAC;
    uint8_t HMAC_len = 0;
    encoded<uint32_t> replay_pkt_id{0};
    encoded<uint32_t> net_time{0};
    encoded<uint8_t> pkt_id_array_len{0};
    datum pkt_id_array{nullptr,nullptr};
    encoded<uint64_t> remote_session_id{0};
    encoded<uint32_t> msg_pkt_id{0};
    datum data{nullptr,nullptr};
    uint16_t hdr_len = 0;       // total length of openvpn pkt except control data and length field
    uint16_t data_len = 0;
    uint16_t orignal_pkt_len;  // pkt len from openvpn header
    // booleans for various combinations of optional fields
    //
    bool ctrl_payload;      // if false, only ack payload
    bool have_data;
    bool tls_auth;          // if false, no HMAC
    bool if_net_time;       // if false, no net_time field
    bool if_pkt_id_array;   // if false, no pkt_id_array and remote_session_id
    bool valid = false;
    bool last_pkt = false;      // last openvpn record in tcp pkt

    openvpn_payload(datum &d, uint16_t len, bool is_ctrl, bool data) : orignal_pkt_len{len}, ctrl_payload{is_ctrl}, have_data{data}, tls_auth{false}, if_net_time{false}, if_pkt_id_array{false} {parse(d);}

    bool is_valid() {return valid;}

    bool valid_HMAC (uint32_t hmac) {
        // entropy must be > .75 for valid HMAC
        uint8_t count = 0;
        if ((hmac & 0x000000FF) == 0x00000000) {
            count++;
        }
        if ((hmac & 0x0000FF00) == 0x00000000) {
            count++;
        }
        if ((hmac & 0x00FF0000) == 0x00000000) {
            count++;
        }
        if ((hmac & 0xFF000000) == 0x00000000) {
            count++;
        }
        if (count > 1) {
            return false;
        } else {
            return true;
        }
    }

    void parse(datum &d) {
        // parse payload by trying to test presense of optional fields by specific logic
        //

        session_id = encoded<uint64_t>{d};

        // entropy check for HMAC detection
        //
        uint32_t temp_HMAC = lookahead< encoded<uint32_t> >{d}.value.value();
        if (valid_HMAC(temp_HMAC)) {
            // check if HMAC of 16 bytes - 64 bytes
            if (d.length() < 16) {
                return;
            }
            // try to find the HMAC len, as the next field "replay pkt id" will start with 0x00,0x00 for initial pkts
            const unsigned char delim[2] = {0x00,0x00};
            uint8_t len = d.find_delim(delim,2) - 2;
            if (len < 16 || len >= d.length()) {
                return;
            }
            HMAC = datum{d.data,d.data+len};
            HMAC_len = len;
            d.skip(len);
            tls_auth = true;
        }

        replay_pkt_id = encoded<uint32_t>{d};

        // check for optional timestamp
        // if timestamp is present, byte1 and byte2 are part of timestamp, else byte1 is pkt_id_array len and byte2 is array 1st element pkt id.
        // each array element is 4 bytes and elements' 1st byte is zero, check for timestamp accordingly
        datum data_copy = d;
        encoded<uint8_t> byte1{data_copy};
        encoded<uint8_t> byte2{data_copy};
        if (byte1*4 > data_copy.length() || byte2) {
            if_net_time = true;
            net_time = encoded<uint32_t>{d};
        }
        else {
            if_net_time = false;
        }

        // parse pkt msg-id array
        //
        pkt_id_array_len = encoded<uint8_t>{d};
        if (d.length()< (4*pkt_id_array_len)) {
            return;
        }
        if (pkt_id_array_len) {
            pkt_id_array = datum{d.data, d.data+(4*pkt_id_array_len)};
            d.skip(4*pkt_id_array_len);
            remote_session_id = encoded<uint64_t>{d};
            if_pkt_id_array = true;
        }

        if (ctrl_payload) {
            msg_pkt_id = encoded<uint32_t>{d};
        }
 
        // calculate data len
        //        opcode  session id      HMAC            replay pkt-id
        hdr_len = 1 +      8 +          (tls_auth?HMAC_len:0) +     4 +     
        //         timestamp          pkt-id array len       pkt-id array                               remote session id      msg pkt id
                (if_net_time?4:0) +    1 +                (pkt_id_array_len?4*pkt_id_array_len:0) + (pkt_id_array_len?8:0)+ (ctrl_payload?4:0);
        
        if (have_data) {
            if (hdr_len >= orignal_pkt_len){
                return;
            }
            data_len = orignal_pkt_len - hdr_len;
            if (d.length()<data_len){
                return;
            }
            data = datum{d.data,d.data+data_len};
            d.skip(data_len);
        }

        valid = true;
        return;

    }

    void write_json(struct json_object &record, bool output_metadata) {
        if (output_metadata) {
            record.print_key_uint_hex("session_id",session_id);
            record.print_key_bool("hmac",tls_auth);
            if (if_net_time){
                record.print_key_int("net_time",net_time);
            }
        }
        record.print_key_int("replay_pkt_id",replay_pkt_id);
        record.print_key_int("id_array_len",pkt_id_array_len);
        if (ctrl_payload) {
            record.print_key_int("msg_pkt_id",msg_pkt_id);
        }
    }

};

enum class openvpn_type : uint8_t {
    ack     = 0,
    ctrl    = 1,
    data    = 2,
    unknown = 3
};

class openvpn_tcp_record {
    encoded<uint16_t> len;
    encoded<uint8_t> code;
    uint8_t pkt_opcode;
    uint8_t key_id;
    openvpn_type type = openvpn_type::ack;
    openvpn_payload payload;
    bool valid;

public:

    openvpn_tcp_record(datum &d) :
        len{d},
        code{d},
        pkt_opcode{code.slice<0,5>()},
        key_id{code.slice<5,8>()},
        type{get_type(pkt_opcode)},
        payload{d,len.value(),(get_type()==openvpn_type::ctrl),(pkt_opcode==0x04)},
        valid{payload.is_valid() && (type!=openvpn_type::unknown)} {}

    openvpn_type get_type(uint8_t opcode) {
        switch (opcode) {
            case 0x01 :
            case 0x02 :
            case 0x03 :
            case 0x04 :
            case 0x07 :
            case 0x08 :
            case 0x0A :
            case 0x0B : return openvpn_type::ctrl;
            case 0x05 : return openvpn_type::ack;
            case 0x06 :
            case 0x09 : return openvpn_type::data;
            default   : return openvpn_type::unknown;
        }
    }

    const char* get_opcode_str() const {
        switch (pkt_opcode) {
            case 0x01 : return "P_CONTROL_HARD_RESET_CLIENT_V1";
            case 0x02 : return "P_CONTROL_HARD_RESET_SERVER_V1";
            case 0x03 : return "P_CONTROL_SOFT_RESET_V1";
            case 0x04 : return "P_CONTROL_V1";
            case 0x05 : return "P_ACK_V1";
            case 0x06 : return "P_DATA_V1";
            case 0x07 : return "P_CONTROL_HARD_RESET_CLIENT_V2";
            case 0x08 : return "P_CONTROL_HARD_RESET_SERVER_V2";
            case 0x09 : return "P_DATA_V2";
            case 0x0A : return "P_CONTROL_HARD_RESET_CLIENT_V3";
            case 0x0B : return "P_CONTROL_WKC_V1";
            default   : return nullptr;
        }
    }

    openvpn_type get_type() {return type;}

    uint8_t get_code() const {return pkt_opcode;}

    const char* get_code_str() const {
        return get_opcode_str();
    }

    bool is_valid() {return valid;}

    void write_json(struct json_object &record, bool output_metadata) {
        type_codes<openvpn_tcp_record> opcode{*this};
        record.print_key_value("opcode", opcode);
        payload.write_json(record,output_metadata);
    }

    bool have_data() { return payload.have_data; }

    datum &get_data() { return payload.data; }

    uint8_t get_HMAC_len() const { return payload.HMAC_len; }

    uint8_t get_opcode() const { return pkt_opcode; }

    bool get_keyid() const { return !key_id;  } // return true for zeroed key_id
};

class openvpn_tcp : public base_protocol {
    std::vector<openvpn_tcp_record> ctrl_records;
    std::vector<openvpn_tcp_record> ack_records;
    uint8_t num_records = 0;
    data_buffer<800> reassembly_buff;
    bool valid = false;
    tls_handshake handshake;
    tls_client_hello hello;
    uint64_t total_data = 0;
    bool fp_true = false;

public:
    openvpn_tcp(datum& d) {
        while (d.is_not_empty()) {
            openvpn_tcp_record record{d};
            // TODO: set d null for non valid
            if (d.is_null() || !record.is_valid()) {
                return;
            }
            if (record.get_type() == openvpn_type::ack) {
                ack_records.push_back(record);
            }
            else if (record.get_type() == openvpn_type::ctrl) {
                ctrl_records.push_back(record);
            }
            num_records++;
        }
        valid = true;

        //  TODO: sort the records wrt pkt_msg_id before reassembling
        //  reassemble data if ctrl frames
        if (!ctrl_records.size()) {
            return;
        }

        for (auto it : ctrl_records) {
            if (it.have_data()) {
                if (!reassembly_buff.is_null()) {
                    reassembly_buff.parse(it.get_data());
                }
                total_data += it.get_data().length();
            }
        }

        datum reassembly_data = reassembly_buff.contents();
        if (!reassembly_data.is_not_empty()) {
            return;
        }
        tls_record rec{reassembly_data};
        handshake = tls_handshake{rec.fragment};
        hello.parse(handshake.body);
        if (hello.is_not_empty()) {
            fp_true = true;
        }
    }

    bool is_not_empty() {return valid && num_records;}

    void write_json(struct json_object &record, bool output_metadata) {
        if (this->is_not_empty()) {
            struct json_object openvpn_tcp_json(record,"openvpn");
            openvpn_tcp_json.print_key_int("num_records",num_records);
            // loop over the openvpn records and print
            json_array record_array(openvpn_tcp_json,"records");
            for (auto it : ctrl_records) {
                json_object rec(record_array);
                it.write_json(rec,output_metadata);
                rec.close();
            }
            for (auto it : ack_records) {
                json_object rec(record_array);
                it.write_json(rec,output_metadata);
                rec.close();
            }
            record_array.close();

            if (total_data) {
                openvpn_tcp_json.print_key_int("data_len",total_data);
            }
            if (fp_true) {
                openvpn_tcp_json.print_key_bool("has_tls",true);
            }

            openvpn_tcp_json.close();

            if (fp_true) {
                hello.write_json(record, output_metadata);
            }
        }
    }

    void fingerprint(struct buffer_stream &buf) const {
        if (!fp_true) {
            return;
        }
        // Add openvpn related stuff
        //buf.write_char('(');

        // add protocol type for tcp/udp
        buf.write_char('(');
        uint8_t proto = 6;
        buf.write_hex_uint(proto);
        buf.write_char(')');

        // add ctrl record counts
        buf.write_char('(');
        uint8_t num_rec = ctrl_records.size();
        buf.write_hex_uint(num_rec);
        buf.write_char(')');

        // add op_code and normalized key id
        buf.write_char('(');
        buf.write_hex_uint(ctrl_records[0].get_opcode());
        uint8_t key_id;
        if (ctrl_records[0].get_keyid()) {
            key_id = 0;
        }
        else {
            key_id = 1;
        }
        buf.write_hex_uint(key_id);
        buf.write_char(')'); 

        // add HMAC len if TLS-auth true or else 0 from 1st ctrl record
        buf.write_char('(');
        buf.write_hex_uint(ctrl_records[0].get_HMAC_len());
        buf.write_char(')');

        //buf.write_char(')');
    }

    void compute_fingerprint(class fingerprint &fp) const {
        if (!fp_true) {
            return;
        }
        fp.set_type(fingerprint_type_openvpn);
        fp.add(*this);
        fp.add(hello);
        fp.final();
    }

};

namespace {

    [[maybe_unused]] int openvpn_tcp_fuzz_test(const uint8_t *data, size_t size) {
        struct datum pkt_data{data, data+size};
        char buffer_1[8192];
        struct buffer_stream buf_json(buffer_1, sizeof(buffer_1));
        char buffer_2[8192];
        struct buffer_stream buf_fp(buffer_2, sizeof(buffer_2));
        struct json_object record(&buf_json);
        

        openvpn_tcp pkt_openvpn{pkt_data};
        if (pkt_openvpn.is_not_empty()) {
            pkt_openvpn.write_json(record, true);
            pkt_openvpn.fingerprint(buf_fp);
        }

        return 0;
    }

};


#endif  // OPENVPN_H 
