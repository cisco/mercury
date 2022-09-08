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

class dnp3_app {

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

    void write_json(struct json_object &record, bool output_metadata) { }
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
            default : return {"no matching code", true};
        }
    }

    const char *get_secondary_func_code_str() const{
        switch (function_code) {
            case 0 : return {"ACK"};
            case 1 : return {"NACK"};
            case 0x0B : return {"LINK_STATUS"};
            case 0x0F : return {"NOT_SUPPORTED"};
            default : return {"no matching code"};
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

    bool is_not_empty() const { return (valid); }

    void write_json(struct json_object &record, bool output_metadata) {
        json_object control(record, "control");
        control.print_key_bool("dir", dir);
        control.print_key_bool("prim", primary);
        if (primary){
            control.print_key_bool("fcb",fcb);
            control.print_key_bool("fcv",fcv);
            control.print_key_string("func_code",get_primary_func_code_str().first);
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
            control.print_key_string("func_code",get_secondary_func_code_str());
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
        dest_addr{frame},
        src_addr{frame},
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

class dnp3 {
    dnp3_link link;
    dnp3_transport transport;
    //dnp3_app app;
    bool valid;

public:
    dnp3(datum &pkt) :
        link{pkt},
        transport{datum(link.data,link.data+link.data_len+1)},
        valid{link.is_not_empty() && transport.is_not_empty()}


        {

        }

    static constexpr mask_and_value<8> matcher{
        { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0x05, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
    };

    bool is_not_empty() const { return (valid); }

    void write_json(struct json_object &record, bool output_metadata) {
        if (this->is_not_empty()) {
            struct json_object dnp3(record,"dnp3");
            link.write_json(dnp3, output_metadata);
            transport.write_json(dnp3, output_metadata);
            dnp3.close();
        }

        return;
    }

};






#endif      // DNP3_H