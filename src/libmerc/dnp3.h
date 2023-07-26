/*
 * dnp3.h
 *
 * Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

/*
 * \file dnp3.h
 *
 * \brief interface file for DNP3 code
 */
#ifndef DNP3_H
#define DNP3_H

#include "datum.h"
#include "json_object.h"
#include "match.h"
#include "protocol.h"

// DNP3 App Response Header
//
//    0                   1          
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |    App Ctrl   |   Func Code   |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |      Internal Indications     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//
// DNP3 App Request Header
//
//    0                   1          
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |    App Ctrl   |   Func Code   |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//
//
// DNP3 App Control Byte
//
//    0              
//    0   1   2    3   4 5 6 7
//    +---+---+----+---+-+-+-+-+
//    |Fin|Fir|Cons|UNS|  SEQ  |
//    +---+---+----+---+-+-+-+-+    
//
//
// DNP3 Transport
//
//    0              
//    0   1   2 3 4 5 6 7
//    +---+---+-+-+-+-+-+-+
//    |Fin|Fir|    SEQ    |
//    +---+---+-+-+-+-+-+-+
//
//
// DNP3 Link Control Byte
//
//     0              
//     0   1   2   3       4  5 6 7
//     +---+---+---+-------+--+-+-+--+
//     |Dir|Pri|FCB|FCV/DFC|Func Code|
//     +---+---+---+-------+--+-+-+--+
//
//
// DNP3 Link layer
//
//     0                   1                   2                   3  
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |      0x05     |      0x64     |      len      |   ctrl byte   |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |           dest addr           |            src addr           |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |            hdr crc            |                               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
//     |                                                               |
//     +                                                               +
//     |                                                               |
//     +                                                               +
//     |                     data blck-1 (16 bytes)                    |
//     +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                               |           blck crc-1          |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//                                   ...
//                                   ...
//                                   ...
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                                                               |
//     +                                                               +
//     |                                                               |
//     +                     data blck-n (16 bytes)                    +
//     |                                                               |
//     +                                                               +
//     |                                                               |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |           blck crc-n          |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//





struct dnp3_app_hdr {
    encoded<uint8_t> app_ctrl;
    bool fin;
    bool fir;
    bool con;
    bool uns;
    uint8_t seq;
    encoded<uint8_t> func_code;
    bool is_resp;
    encoded<uint16_t> internal_indications;
    std::string indications_str;

public:
    dnp3_app_hdr(datum &data):
    app_ctrl{data},
    fin{app_ctrl.bit<0>()},
    fir{app_ctrl.bit<1>()},
    con{app_ctrl.bit<2>()},
    uns{app_ctrl.bit<3>()},
    seq{app_ctrl.slice<4,8>()},
    func_code{data},
    is_resp{false},
    internal_indications{0},
    indications_str{""} {
        uint8_t code = func_code.value();
        if (code == 0x81 || code == 0x82 || code == 0x83) {
            is_resp = true;
        }

        if (is_resp) {
            internal_indications = encoded<uint16_t>{data};
        }
    }

    const char *get_func_code_str_req() const {
        switch (func_code) {
            case 0x00 : return "confirm";
            case 0x01 : return "read";
            case 0x02 : return "write";
            case 0x03 : return "select";
            case 0x04 : return "operate";
            case 0x05 : return "dir_operate";
            case 0x06 : return "dir_operate_no_resp";
            case 0x07 : return "freeze";
            case 0x08 : return "freeze_no_resp";
            case 0x09 : return "freeze_clear";
            case 0x0A : return "freeze_clear_no_resp";
            case 0x0B : return "freeze_at_time";
            case 0x0C : return "freeze_at_time_no_resp";
            case 0x0D : return "cold_restart";
            case 0x0E : return "warm_restart";
            case 0x0F : return "init_data";
            case 0x10 : return "init_app";
            case 0x11 : return "start_app";
            case 0x12 : return "stop_app";
            case 0x13 : return "save_config";
            case 0x14 : return "enable_solicited";
            case 0x15 : return "disable_solicited";
            case 0x16 : return "assign_class";
            case 0x17 : return "delay_measurement";
            case 0x18 : return "record_curr_time";
            case 0x19 : return "open_file";
            case 0x1A : return "close_file";
            case 0x1B : return "delete_file";
            case 0x1C : return "get_file_info";
            case 0x1D : return "authenticate_file";
            case 0x1E : return "abort_file";
            case 0x1F : return "activate_config";
            case 0x20 : return "authenticate_req";
            case 0x21 : return "authenticate_req_no_ack";
            //default   : return "no_matching_code";
            default   : return nullptr;
        }
    }

    const char *get_func_code_str_resp() const {
        switch (func_code) {
            case 0x81 : return "response";
            case 0x82 : return "unsolicited_response";
            case 0x83 : return "authentication_response";
            //default   : return "no_matching_code";
            default   : return nullptr;
        }
    }

    const char *get_func_code_str() const {
        if (is_resp) {
            return get_func_code_str_resp();
        }
        else {
            return get_func_code_str_req();
        }
    }

    const char* get_code_str() const {
        return get_func_code_str();
    }

    const char* get_indications_str() {
        if (internal_indications.bit<7>()) {
            indications_str += "broadcast,";
        }
        if (internal_indications.bit<6>()) {
            indications_str += "class_1_events,";
        }
        if (internal_indications.bit<5>()) {
            indications_str += "class_2_events,";
        }
        if (internal_indications.bit<4>()) {
            indications_str += "class_3_events,";
        }
        if (internal_indications.bit<3>()) {
            indications_str += "need_time,";
        }
        if (internal_indications.bit<2>()) {
            indications_str += "local_control,";
        }
        if (internal_indications.bit<1>()) {
            indications_str += "device_trobule,";
        }
        if (internal_indications.bit<0>()) {
            indications_str += "device_restart,";
        }
        if (internal_indications.bit<15>()) {
            indications_str += "func_code_unsupported,";
        }
        if (internal_indications.bit<14>()) {
            indications_str += "obj_unknown,";
        }
        if (internal_indications.bit<13>()) {
            indications_str += "parameter_error,";
        }
        if (internal_indications.bit<12>()) {
            indications_str += "event_buffer_overflow,";
        }
        if (internal_indications.bit<11>()) {
            indications_str += "already_executing,";
        }
        if (internal_indications.bit<10>()) {
            indications_str += "config_corrupt,";
        }
        if (internal_indications.bit<9>()) {
            indications_str += "reserved_1,";
        }
        if (internal_indications.bit<8>()) {
            indications_str += "reserved_2,";
        }

        return indications_str.c_str();
    }

    uint8_t get_code() const {return func_code.value();}

    void write_json(struct json_object &record, bool output_metadata) {
        json_object app_hdr(record, "app_hdr");
        app_hdr.print_key_bool("fin",fin);
        app_hdr.print_key_bool("fir",fir);
        app_hdr.print_key_bool("con",con);
        app_hdr.print_key_bool("uns",uns);
        app_hdr.print_key_int("seq",seq);
        app_hdr.print_key_bool("resp", is_resp);
        //app_hdr.print_key_int("func_code",func_code.value());
        type_codes<dnp3_app_hdr> code{*this};
        app_hdr.print_key_value("func_str", code);
        if (is_resp) {
            app_hdr.print_key_string("internal_indications", get_indications_str());
        }
        if (output_metadata) {
            //FIXIT: add additional info
        }
        app_hdr.close();
    }
};

class dnp3_app {
    bool is_resp;
    bool outstation_resp;
    datum data;
    dnp3_app_hdr app_hdr;
    bool valid;

public:
    dnp3_app(datum seg_data):
    data{seg_data},
    app_hdr{data},
    valid{data.is_not_empty()}
    {}

    bool is_not_empty() { return (valid); }

    void write_json(struct json_object &record, bool output_metadata) {
        json_object app(record, "app");
        app_hdr.write_json(app, output_metadata);
        app.print_key_int("left_obj_data", data.length());
        app.close();
    }
};

class dnp3_transport {
    encoded<uint8_t> first_byte;
    bool fin;
    bool fir;
    uint8_t seq_num;
    datum segment;
    bool valid;

public:
    dnp3_transport(datum seg):
        first_byte{seg},
        fin{first_byte.bit<0>()},
        fir{first_byte.bit<1>()},
        seq_num{first_byte.slice<2,8>()},
        segment{seg},
        valid{seg.is_not_null()} {}

    bool is_not_empty() const { return (valid); }

    void write_json(struct json_object &record, bool output_metadata) {
        json_object transport(record, "transport");
        transport.print_key_bool("fin", fin);
        transport.print_key_bool("fir",fir);
        transport.print_key_int("seq",seq_num);
        if (output_metadata) {
            // FIXIT: add more info
        }
        transport.close();
        return;
    }

    datum get_app_data() {return segment;}
};

struct dnp3_link_control {
    bool dir;
    bool primary;
    bool fcb;
    bool fcv;
    bool dfc;
    uint8_t function_code;

    const std::pair< const char *, bool> get_primary_func_code_str() const{
        switch (function_code) {
            case 0 : return {"RESET_LINK_STATES", !fcv};
            case 2 : return {"TEST_LINK_STATES", fcv};
            case 3 : return {"CONFIRMED_USER_DATA", fcv};
            case 4 : return {"UNCONFIRMED_USER_DATA", !fcv};
            case 9 : return {"REQUEST_LINK_STATES", !fcv};
            //default : return {"no_matching_code", true};
            default : return {nullptr, true};
        }
    }

    const char *get_secondary_func_code_str() const{
        switch (function_code) {
            case 0 : return "ACK";
            case 1 : return "NACK";
            case 0x0B : return "LINK_STATUS";
            case 0x0F : return "NOT_SUPPORTED";
            //default : return "no_matching_code";
            default : return nullptr;
        }
    }

public:
    dnp3_link_control(): dir{false}, primary{false}, fcb{false}, fcv{false}, dfc{false}, function_code{0} {}
    dnp3_link_control(encoded<uint8_t>ctrl_byte):
        dir{ctrl_byte.bit<0>()},
        primary{ctrl_byte.bit<1>()},
        fcb{ctrl_byte.bit<2>()},
        fcv{ctrl_byte.bit<3>()},
        dfc{fcv},
        function_code{ctrl_byte.slice<4,8>()} {}

    uint8_t get_code() const {return function_code;}

    const char* get_code_str() const {
        if (primary) {
            return get_primary_func_code_str().first;
        }
        else {
            return get_secondary_func_code_str();
        }
    }

    void write_json(struct json_object &record, bool output_metadata) {
        json_object control(record, "control");
        control.print_key_bool("dir", dir);
        control.print_key_bool("prim", primary);
        if (primary){
            control.print_key_bool("fcb",fcb);
            control.print_key_bool("fcv",fcv);
            //control.print_key_string("func_code",get_primary_func_code_str().first);
            type_codes<dnp3_link_control> code{*this};
            control.print_key_value("func_str", code);
            // add extra info based on bool metadata
            if (output_metadata) {
                if (!get_primary_func_code_str().second) {
                    control.print_key_bool("func_fcv_mismatch", true);
                }
            }
        }
        else {
            control.print_key_bool("fcb",fcb);
            control.print_key_bool("dfc",dfc);
            //control.print_key_string("func_code",get_secondary_func_code_str());
            type_codes<dnp3_link_control> code{*this};
            control.print_key_value("func_str", code);
            // add extra info based on bool metadata
            if (output_metadata) {
                if (fcb) {
                    control.print_key_bool("prim_fcb_mismatch", true);
                }
                if (dfc) {
                    control.print_key_bool("sec_buffer_exceed", true);
                }
            } 
        }
        control.close();
        return;
    }
};

class dnp3_link {
    encoded<uint16_t> start_bytes;
    encoded<uint8_t> len;
    dnp3_link_control ctrl_byte;
    encoded<uint16_t> dest_addr;
    encoded<uint16_t> src_addr;
    encoded<uint16_t> hdr_crc;
    bool valid;

public:
    //userdata
    uint8_t data_len;
    uint8_t block_count;
    unsigned char data[256];
    uint16_t block_crc[16];

    dnp3_link (datum &frame) :
        start_bytes{frame},
        len{frame},
        ctrl_byte{encoded<uint8_t>{frame}},
        dest_addr{frame, true},
        src_addr{frame, true},
        hdr_crc{frame},
        valid{true},
        data_len{len - 5},
        block_count((data_len%16 ? (data_len/16 + 1) : data_len/16)),
        data{},
        block_crc{}
        {
            if (!frame.is_not_null()) {
                valid = false;
                return;
            }

            for (uint8_t i = 0; i < block_count; i++) {
                frame.copy(data+i*18,16);
                block_crc[i] = encoded<uint16_t>{frame}.value();
            }
        }

        bool is_not_empty() const { return (valid); }

        void write_json(struct json_object &record, bool output_metadata) {
            struct json_object link(record, "link");
            link.print_key_int("data_len", data_len);
            ctrl_byte.write_json(link, output_metadata);
            link.print_key_int("dest_addr", dest_addr);
            link.print_key_int("src_addr", src_addr);
            if (output_metadata) {
                link.print_key_int("block_count", block_count);
                // FIXIT: add print for crc checks, both header and blocks
                // FIXIT: add checks for reserved addresses
            }

            link.close();
            return;
        }
};

class dnp3 : public base_protocol {
    dnp3_link link;
    dnp3_transport transport;
    dnp3_app app;
    bool valid;

public:
    dnp3(datum &pkt) :
        link{pkt},
        transport{datum(link.data,link.data+link.data_len+1)},
        app{transport.get_app_data()},
        valid{link.is_not_empty() && transport.is_not_empty()} {}

    static constexpr mask_and_value<4> matcher{
        { 0xff, 0xff, 0x00, 0x00 },
        { 0x05, 0x64, 0x00, 0x00 }
    };

    // For DNP3, complete length is 2start bytes + 1byte len field + 2 bytes for hdr CRC + 2 bytes CRC for every 16byte data block
    //
    static ssize_t get_payload_length(datum pkt) {
        pkt.skip(2);
        encoded<uint8_t> len(pkt);
        return (3 + len + 2 + (len % 16 ? (len/16 + 1) : len/16 )*2);
    }

    bool is_not_empty() const { return (valid); }

    void write_json(struct json_object &record, bool output_metadata) {
        if (this->is_not_empty()) {
            struct json_object dnp3(record,"dnp3");
            link.write_json(dnp3, output_metadata);
            transport.write_json(dnp3, output_metadata);
            app.write_json(dnp3, output_metadata);
            dnp3.close();
        }

        return;
    }

};

namespace {

    [[maybe_unused]] int dnp3_fuzz_test(const uint8_t *data, size_t size) {
        datum pkt_data{data, data+size};
        dnp3 dnp3_record{pkt_data};

        char buffer[8192];
        struct buffer_stream buf_json(buffer, sizeof(buffer));
        struct json_object record(&buf_json);

        if (dnp3_record.is_not_empty()) {
            dnp3_record.write_json(record, true);
        }

        return 0;
    }

}; // end of namespace


#endif      // DNP3_H
