/*
 * smb1.h
 *
 * Copyright (c) 2022 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

/**
 * \file smb1.h
 *
 * \brief interface file for SMB code
 */
#ifndef SMB1_H
#define SMB1_H

#include "protocol.h"
#include "json_object.h"
#include "util_obj.h"
#include "match.h"

/*
 * SMB1 code is written based on the details from the below
 * microsoft document.
 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f
 */
class smb1_command {
public:
    encoded<uint8_t> cmd;

    smb1_command (datum &d, bool byte_swap = true) : cmd(d, byte_swap) { }

    const char * get_command_string() const {
        switch (cmd.value()) {
        case 0x00:      return "smb_com_create_directory";
        case 0x01:      return "smb_com_delete_directory";
        case 0x02:      return "smb_com_open";
        case 0x03:      return "smb_com_create";
        case 0x04:      return "smb_com_close";
        case 0x05:      return "smb_com_flush";
        case 0x06:      return "smb_com_delete";
        case 0x07:      return "smb_com_rename";
        case 0x08:      return "smb_com_query_information";
        case 0x09:      return "smb_com_set_information";
        case 0x0a:      return "smb_com_read";
        case 0x0b:      return "smb_com_write";
        case 0x0c:      return "smb_com_lock_byte_range";
        case 0x0d:      return "smb_com_unlock_byte_range";
        case 0x0e:      return "smb_com_create_temporary";
        case 0x0f:      return "smb_com_create_new";
        case 0x10:      return "smb_com_check_directory";
        case 0x11:      return "smb_com_process_exit";
        case 0x12:      return "smb_com_seek";
        case 0x13:      return "smb_com_lock_and_read";
        case 0x14:      return "smb_com_write_and_unlock";
        case 0x1a:      return "smb_com_read_raw";
        case 0x1b:      return "smb_com_read_mpx";
        case 0x1c:      return "smb_com_read_mpx_secondary";
        case 0x1d:      return "smb_com_write_raw";
        case 0x1e:      return "smb_com_write_mpx";
        case 0x1f:      return "smb_com_write_mpx_secondary";
        case 0x20:      return "smb_com_write_complete";
        case 0x21:      return "smb_com_query_server";
        case 0x22:      return "smb_com_set_information2";
        case 0x23:      return "smb_com_query_information2";
        case 0x24:      return "smb_com_locking_andx";
        case 0x25:      return "smb_com_transaction";
        case 0x26:      return "smb_com_transaction_secondary";
        case 0x27:      return "smb_com_ioctl";
        case 0x28:      return "smb_com_ioctl_secondary";
        case 0x29:      return "smb_com_copy";
        case 0x2a:      return "smb_com_move";
        case 0x2b:      return "smb_com_echo";
        case 0x2c:      return "smb_com_write_and_close";
        case 0x2d:      return "smb_com_open_andx";
        case 0x2e:      return "smb_com_read_andx";
        case 0x2f:      return "smb_com_write_andx";
        case 0x30:      return "smb_com_new_file_size";
        case 0x31:      return "smb_com_close_and_tree_disc";
        case 0x32:      return "smb_com_transaction2";
        case 0x33:      return "smb_com_transaction2_secondary";
        case 0x34:      return "smb_com_find_close2";
        case 0x35:      return "smb_com_find_notify_close";
        case 0x70:      return "smb_com_tree_connect";
        case 0x71:      return "smb_com_tree_disconnect";
        case 0x72:      return "smb_com_negotiate";
        case 0x73:      return "smb_com_session_setup_andx";
        case 0x74:      return "smb_com_logoff_andx";
        case 0x75:      return "smb_com_tree_connect_andx";
        case 0x7e:      return "smb_com_security_package_andx";
        case 0x80:      return "smb_com_query_information_disk";
        case 0x81:      return "smb_com_search";
        case 0x82:      return "smb_com_find";
        case 0x83:      return "smb_com_find_unique";
        case 0x84:      return "smb_com_find_close";
        case 0xa0:      return "smb_com_nt_transact";
        case 0xa1:      return "smb_com_nt_transact_secondary";
        case 0xa2:      return "smb_com-nt_create_andx";
        case 0xa4:      return "smb_com_nt_cancel";
        case 0xa5:      return "smb_com_nt_rename";
        case 0xc0:      return "smb_com_open_print_file";
        case 0xc1:      return "smb_com_write_print_file";
        case 0xc2:      return "smb_com_close_print_file";
        case 0xc3:      return "smb_com_get_print_queue";
        case 0xd8:      return "smb_com_read_bulk";
        case 0xd9:      return "smb_com_write_bulk";
        case 0xda:      return "smb_com_write_bulk_data";
        case 0xfe:      return "smb_com_invalid";
        case 0xff:      return "smb_com_no_andx_command";
        default:        break;
        }
        return "unknown";
    }
};

/*
 * SMB_Dialect
 * {
 *  UCHAR      BufferFormat;
 *  OEM_STRING DialectString;
 * }
 * BufferFormat (1 byte): This field MUST be 0x02. This is a buffer format indicator
 * that identifies the next field as a null-terminated array of characters.
 * DialectString (variable): A null-terminated string identifying an SMB dialect.
 */
class smb1_dialects {
    datum dialect_body;

public:
    smb1_dialects(datum &d) : dialect_body(d) { }

    void write_json(struct json_object &o) {
        struct json_array a{o, "dialects"};
        while(dialect_body.is_not_empty()) {
            literal<1> buffer_format{dialect_body, {0x02}};
            if (dialect_body.is_not_empty()) {
                datum dialect;
                dialect.parse_up_to_delim(dialect_body, '\0');
                a.print_json_string(dialect);
                dialect_body.skip(1); //skip the null byte
            }
        }
        a.close();
    }
};

/* 
 * Negotiate protocol request structure:
 * SMB_Parameters
 * {
 *  UCHAR  WordCount;
 * }
 * SMB_Data
 * {
 *  USHORT ByteCount;
 *  Bytes
 *  {
 *    UCHAR Dialects[];
 *  }
 * }
 */
class smb1_negotiate_request {
    encoded<uint8_t> word_count;
    encoded<uint16_t> byte_count;
    smb1_dialects dialect_list;
    bool valid;

public:
    smb1_negotiate_request(datum &d, bool byte_swap = true) :
        word_count(d, byte_swap),
        byte_count(d, byte_swap),
        dialect_list(d),
        valid(d.is_not_null()) { }

    void write_json(struct json_object &o) {
        if (!valid) {
            return;
        }
        json_object neg_req{o, "negotiate_request"};
        dialect_list.write_json(neg_req);
        neg_req.close();
    }
};

class smb1_header {
    literal<4> proto;
    smb1_command command;
    encoded<uint32_t> status;
    encoded<uint8_t> flag;
    encoded<uint16_t> flags2;
    encoded<uint16_t> pid_high;
    encoded<uint64_t> signature;
    skip_bytes<2> reserved;
    encoded<uint16_t> tid;
    encoded<uint16_t> pid_low;
    encoded<uint16_t> uid;
    encoded<uint16_t> mid;
    bool valid;

    static constexpr uint32_t resp_mask = 0x80;
    static constexpr bool byte_swap = true;

public:
    enum packet_type {
        NEGOTIATE_REQUEST,

        LAST_TYPE           //Should be the last field in enum
    };

    smb1_header(datum &d) :
        proto{d, {0xff, 'S', 'M', 'B'}},
    command(d, byte_swap),
    status(d, byte_swap),
    flag(d, byte_swap),
    flags2(d, byte_swap),
    pid_high(d, byte_swap),
    signature(d, byte_swap),
    reserved(d),
    tid(d, byte_swap),
    pid_low(d, byte_swap),
    uid(d, byte_swap),
    mid(d, byte_swap),
    valid{d.is_not_null()} {}

    bool is_valid() const { return valid; }

    bool is_response() {
        return (flag & resp_mask);
    }

    packet_type get_packet_type() {
        switch(command.cmd) {
        case 0x72:  //Negotiate
            if (!is_response()) {
                return packet_type::NEGOTIATE_REQUEST;
            }
            break;
        default:
            break;
        }
        return packet_type::LAST_TYPE;
    }

    void write_json(struct json_object &o) {
        o.print_key_string("command", command.get_command_string());
        o.print_key_uint_hex("status", status.value());
        o.print_key_bool("response", flag.bit<0>());
        o.print_key_bool("batch_oplock", flag.bit<1>());
        o.print_key_bool("oplock", flag.bit<2>());
        o.print_key_bool("canonicalized_path", flag.bit<3>());
        o.print_key_bool("case_insensitive", flag.bit<4>());
        o.print_key_bool("receive_buffer_available", flag.bit<6>());
        o.print_key_bool("lock_and_read", flag.bit<7>());
        o.print_key_bool("unicode_string", flags2.bit<0>());
        o.print_key_bool("NT_error_codes", flags2.bit<1>());
        o.print_key_bool("read_if_execute", flags2.bit<2>());
        o.print_key_bool("DFS", flags2.bit<3>());
        o.print_key_bool("extended_security", flags2.bit<4>());
        o.print_key_bool("reparse_path", flags2.bit<5>());
        o.print_key_bool("long_name", flags2.bit<9>());
        o.print_key_bool("security_signatures_required", flags2.bit<11>());
        o.print_key_bool("compressed", flags2.bit<12>()); 
        o.print_key_bool("security_signatures_allowed", flags2.bit<13>());
        o.print_key_bool("extended_attributes", flags2.bit<14>());
        o.print_key_bool("long_names_allowed", flags2.bit<15>());
        o.print_key_uint16("process_id_high", pid_high.value());
        o.print_key_uint64_hex("signature", signature.value());
        o.print_key_uint16("tree_id", tid.value());
        o.print_key_uint16("process_id_low", pid_low.value());
        o.print_key_uint16("user_id", uid.value());
        o.print_key_uint16("multiplex_id", mid.value());
    }
};

class smb1_packet : public base_protocol {
    encoded<uint32_t> nbss_layer;
    smb1_header hdr;
    datum& body;

public:
    smb1_packet(datum &d) :
        nbss_layer(d),
        hdr(d),
        body(d) { }

    bool is_not_empty() const { return hdr.is_valid(); }

    void write_json(struct json_object &o, bool) {
        if (this->is_not_empty()) {
            struct json_object smb1{o, "smb1"};
            hdr.write_json(smb1);

            switch (hdr.get_packet_type()) {
                case smb1_header::packet_type::NEGOTIATE_REQUEST:
                {
                    smb1_negotiate_request neg_req(body);
                    neg_req.write_json(smb1);
                    break;
                }
                default:
                    break;
            }
            smb1.close();
        }
    }

    static constexpr mask_and_value<8> matcher {
        { 0x00, //Message type
          0x00, 0x00, 0x00 , //Length
          0xff, 0xff, 0xff, 0xff // 
        },
        { 0x00, 0x00, 0x00, 0x00, 0xff, 0x53, 0x4d, 0x42}
    };
};

namespace {

    [[maybe_unused]] int smb1_fuzz_test(const uint8_t *data, size_t size) {
        struct datum request_data{data, data+size};
        char buffer[8192];
        struct buffer_stream buf_json(buffer, sizeof(buffer));
        struct json_object record(&buf_json);
        

        smb1_packet request{request_data};
        if (request.is_not_empty()) {
            request.write_json(record, true);
        }

        return 0;
    }

};

#endif /* SMB1_H */
