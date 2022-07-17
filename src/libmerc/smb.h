/*
 * smb.h
 *
 * Copyright (c) 2022 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

/**
 * \file smb.h
 *
 * \brief interface file for SMB code
 */
#ifndef SMB_H
#define SMB_H

#include "json_object.h"
#include "util_obj.h"
#include "match.h"

class smb1_command {
public:
    encoded<uint8_t> cmd;

    smb1_command (datum &d, bool byte_swap = true) : cmd(d, byte_swap) { }

    const char * get_command_string() {
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

/* class skip_bytes skips N number of bytes in the given datum*/
template <size_t N>
class skip_bytes {
public:
    skip_bytes (datum &d) {
        d.skip(N);
    }
};

class smb1_dialects {
    std::vector<datum> dialects;

public:
    smb1_dialects(datum &d) {
        while(d.is_not_empty()) {
            encoded<uint8_t> buffer_format(d);
            datum dialect;
            dialect.parse_up_to_delim(d, '\0');
            dialects.push_back(dialect);
            d.skip(1); //skip the null byte
        }
    }

    bool is_not_empty() const {
        return (dialects.size());
    }

    void write_json(struct json_object &o) {
        struct json_array a{o, "dialects"};
        for (auto& dialect : dialects) {
            a.print_json_string(dialect);
        }
        a.close();
    }
};

class smb1_negotiate_request {
    encoded<uint8_t> word_count;
    encoded<uint16_t> byte_count;
    smb1_dialects dialect_list;

public:
    smb1_negotiate_request(datum &d, bool byte_swap = true) :
        word_count(d, byte_swap),
        byte_count(d, byte_swap),
        dialect_list(d) { }

    void write_json(struct json_object &o) {
        if (dialect_list.is_not_empty()) {
            json_object neg_req{o, "negotiate_request"};
            dialect_list.write_json(neg_req);
            neg_req.close();
        }
    }
};

enum packet_type {
    NEGOTIATE_REQUEST,
    NEGOTIATE_RESPONSE,

    LAST_TYPE           //Should be the last field in enum
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
            return packet_type::NEGOTIATE_RESPONSE;
        default:
            break;
        }
        return packet_type::LAST_TYPE;
    }

    void write_json(struct json_object &o) {
        o.print_key_string("command", command.get_command_string());
        o.print_key_uint_hex("status", status.value());
        o.print_key_uint8_hex("flag", flag.value());
        o.print_key_uint16_hex("flags2", flags2.value());
        o.print_key_uint16("process_id_high", pid_high.value());
        o.print_key_uint64_hex("signature", signature.value());
        o.print_key_uint16("tree_id", tid.value());
        o.print_key_uint16("process_id_low", pid_low.value());
        o.print_key_uint16("user_id", uid.value());
        o.print_key_uint16("multiplex_id", mid.value());

    }
};

class smb1_packet {
    encoded<uint32_t> nbss_layer;
    smb1_header hdr;
    datum& body;

public:
    smb1_packet(datum &d) :
        nbss_layer(d),
        hdr(d),
        body(d) { }

    bool is_not_empty() const { return hdr.is_valid(); }

    void write_json(struct json_object &o) {
        hdr.write_json(o);
        
         switch(hdr.get_packet_type()) {
            case packet_type::NEGOTIATE_REQUEST:
            {
                smb1_negotiate_request neg_req(body);
                neg_req.write_json(o);
                break;
            }
            default:
                break;
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

/*
 * The valid format for a GUID is {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
 * X is a hex digit (0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F)
 */
class guid {
    encoded<uint32_t> a;
    encoded<uint16_t> b;
    encoded<uint16_t> c;
    datum d;
    bool valid;

public:
    guid(datum &data, bool byte_swap = true) :
        a(data, byte_swap),
        b(data, byte_swap),
        c(data, byte_swap),
        d(data, 8),
        valid{data.is_not_null()} { }

   void fingerprint(struct buffer_stream &b) {
        if(!valid) {
            return;
        }
        b.write_hex_uint32(a);
        b.write_char('-');
        b.write_hex_uint16(this->b);
        b.write_char('-');
        b.write_hex_uint16(c);
        b.write_char('-');
        b.raw_as_hex(d.data, 2);
        b.write_char('-');
        b.raw_as_hex(d.data + 2, 6);
    }
};

class dialect {
    encoded<uint16_t> val;
    bool valid;

public:
    dialect (datum &d, bool byte_swap = true) : val(d, byte_swap), valid(d.is_not_null()) { }

    const char * get_dialect_string() {
        switch (val) {         
        case 0x0202:         return "SMB 2.0.2";
        case 0x0210:         return "SMB 2.1";
        case 0x0300:         return "SMB 3.0";
        case 0x0302:         return "SMB 3.0.2";
        case 0x0311:         return "SMB 3.1.1";
        default:             break;
        }
        return "unknown";
    }

    bool is_smb_dialect_311() const {
        return (val == 0x0311);
    }
};    
         
class dialects {
    std::vector<dialect> dialects_list;
    bool valid;

public:
    dialects (datum &d, uint16_t cnt, bool byte_swap = true) {
        for (auto i = 0; i < cnt; i++) {
            dialect id(d, byte_swap);
            dialects_list.push_back(id);
        }
        valid = d.is_not_null();
    }

    void write_json(struct json_object &o) {
        if(!valid) {
            return;
        }
        struct json_array a{o, "dialects"};
        for(auto& i : dialects_list) {
            a.print_string(i.get_dialect_string());
        }
        a.close();
    }
};

class win_epoch_time {
    encoded<uint64_t> value;
    bool valid;
    static constexpr uint64_t unixTimeBaseAsWin = 11644473600000000000ull; // The unix base time (January 1, 1970 UTC) as ns since Win32 epoch (1601-01-01)
    static constexpr uint64_t nsToSecFactor = 1000000000;
public:
    win_epoch_time (datum &d, bool byte_swap = true) : value(d, byte_swap), valid(d.is_not_null()) { }

    void fingerprint(struct buffer_stream &b) { 
        if(!valid) {
            return;
        }

        if(value) {
            struct timespec ts;
            ts.tv_sec = (value * 100 - unixTimeBaseAsWin) / nsToSecFactor;
            ts.tv_nsec = value % nsToSecFactor;
            b.write_timestamp_as_string(&ts);
        } else {
            b.puts("No time specified");
        }
    }
};
                 
class smb2_negotiate_request {
    encoded<uint16_t> structure_size;
    encoded<uint16_t> dialect_count;
    encoded<uint16_t> sec_mode;
    skip_bytes<2> reserved1;
    encoded<uint32_t> cap;
    guid id;
    encoded<uint32_t> neg_context_offset;
    encoded<uint16_t> neg_context_count;
    skip_bytes<2> reserved2;
    dialects dialect_list;
    bool valid;

    static constexpr bool byte_swap = true;
public:
    smb2_negotiate_request (datum &d) : 
        structure_size(d, byte_swap),
        dialect_count(d, byte_swap),
        sec_mode(d, byte_swap),
        reserved1(d),
        cap(d, byte_swap),
        id(d, byte_swap),
        neg_context_offset(d, byte_swap),
        neg_context_count(d, byte_swap),
        reserved2(d),
        dialect_list(d, dialect_count.value()) {
            valid = d.is_not_null();
    }

    void write_json(struct json_object &o) {
        if(!valid) {
            return;
        }
        json_object neg_req{o, "negotiate_request"};
        neg_req.print_key_uint16("structure_size", structure_size);
        neg_req.print_key_uint16("dialect_count", dialect_count);
        neg_req.print_key_uint16_hex("security_mode", sec_mode);
        neg_req.print_key_uint_hex("capabilities", cap);
        neg_req.print_key_value("guid", id);
        neg_req.print_key_uint_hex("negotiate_context_offset", neg_context_offset);
        neg_req.print_key_uint16("negotiate_context_count", neg_context_count);
        dialect_list.write_json(o);
        neg_req.close();
    }
};

class smb2_negotiate_response {
    encoded<uint16_t> structure_size;
    encoded<uint16_t> sec_mode;
    dialect dialect_num;
    encoded<uint16_t> neg_context_cnt;
    guid id;
    encoded<uint32_t> capabilities;
    encoded<uint32_t> max_transact_size;
    encoded<uint32_t> max_read_size;
    encoded<uint32_t> max_write_size;
    win_epoch_time system_time;
    win_epoch_time server_start_time;
    encoded<uint32_t> neg_context_offset;
    bool valid;

    static constexpr bool byte_swap = true;
public:
    smb2_negotiate_response (datum &d) :
        structure_size(d, byte_swap),
        sec_mode(d, byte_swap),
        dialect_num(d, byte_swap),
        neg_context_cnt(d, byte_swap),
        id(d, byte_swap),
        capabilities(d, byte_swap),
        max_transact_size(d, byte_swap),
        max_read_size(d, byte_swap),
        max_write_size(d, byte_swap),
        system_time(d, byte_swap),
        server_start_time(d, byte_swap),
        neg_context_offset(d, byte_swap),
        valid(d.is_not_null()) { }

    void write_json (struct json_object &o) {
        if(!valid) {
            return;
        }

        json_object neg_resp{o, "negotiate_response"};
        neg_resp.print_key_uint16("structure_size", structure_size);
        neg_resp.print_key_uint16_hex("security_mode", sec_mode);
        neg_resp.print_key_string("dialect", dialect_num.get_dialect_string());
        neg_resp.print_key_uint16("negotiate_context_count", neg_context_cnt);
        neg_resp.print_key_value("guid", id);
        neg_resp.print_key_uint_hex("capabilities", capabilities);
        neg_resp.print_key_uint("max_transact_size", max_transact_size);
        neg_resp.print_key_uint("max_read_size", max_read_size);
        neg_resp.print_key_uint("max_write_size", max_write_size);
        neg_resp.print_key_value("system_time", system_time);
        neg_resp.print_key_value("server_start_time", server_start_time);
        neg_resp.close();
    }
};
 
class smb2_command {
public:
    encoded<uint16_t> command;

    enum command_type : uint16_t {
        SMB2_NEGOTIATE = 0x0000,
        SMB2_SESSION_SETUP = 0x0001,
        SMB2_LOGOFF = 0x0002,
        SMB2_TREE_CONNECT = 0x0003,
        SMB2_TREE_DISCONNECT = 0x0004,
        SMB2_CREATE = 0x0005,
        SMB2_CLOSE = 0x0006,
        SMB2_FLUSH = 0x0007,
        SMB2_READ = 0x0008,
        SMB2_WRITE = 0x0009,
        SMB2_LOCK = 0x000a,
        SMB2_IOCTL = 0x000b,
        SMB2_CANCEL = 0x000c,
        SMB2_ECHO = 0x000d,
        SMB2_QUERY_DIRECTORY = 0x000e,
        SMB2_CHANGE_NOTIFY = 0x000f,
        SMB2_QUERY_INFO = 0x0010,
        SMB2_SET_INFO = 0x0011,
        SMB2_OPLOCK_BREAK = 0x0012
    };

    smb2_command(datum &d, bool byte_swap = true) : command(d, byte_swap) { }

    const char * get_string() const {
        switch (command) {
            case SMB2_NEGOTIATE:        return "smb2_negotiate";
            case SMB2_SESSION_SETUP:    return "smb2_session_setup";
            case SMB2_LOGOFF:           return "smb2_logoff";
            case SMB2_TREE_CONNECT:     return "smb2_tree_connect";
            case SMB2_TREE_DISCONNECT:  return "smb2_tree_disconnect";
            case SMB2_CREATE:           return "smb2_create";
            case SMB2_CLOSE:            return "smb2_close";
            case SMB2_FLUSH:            return "smb2_flush";
            case SMB2_READ:             return "smb2_read";
            case SMB2_WRITE:            return "smb2_write";
            case SMB2_LOCK:             return "smb2_lock";
            case SMB2_IOCTL:            return "smb2_ioctl";
            case SMB2_CANCEL:           return "smb2_cancel";
            case SMB2_ECHO:             return "smb2_echo";
            case SMB2_QUERY_DIRECTORY:  return "smb2_query_directory";
            case SMB2_CHANGE_NOTIFY:    return "smb2_change_notify";
            case SMB2_QUERY_INFO:       return "smb2_query_info";
            case SMB2_SET_INFO:         return "smb2_set_info";
            case SMB2_OPLOCK_BREAK:     return "smb2_oplock_break";
            default:                    break;
        }
        return "unknown";
    }
};

class smb2_header {
    literal<4> proto;
    encoded<uint16_t> structure_size;
    encoded<uint16_t> credit_charge;
    encoded<uint32_t> status; /* In a request, this field is interpreted in different ways depending on the SMB2 dialect.
                               * In the SMB 3.x dialect family, this field is interpreted as the ChannelSequence field
                               * followed by the Reserved field in a request. */
    smb2_command cmd;
    encoded<uint16_t> credit_req_resp;
    encoded<uint32_t> flags;
    encoded<uint32_t> next_cmd;
    encoded<uint64_t> msg_id;
    encoded<uint32_t> process_id;
    encoded<uint32_t> tree_id;
    encoded<uint64_t> ssn_id;
    datum signature;
    bool valid;

    static constexpr uint32_t req_mask = 0x00000001;
    static constexpr bool byte_swap = true;
public:
    smb2_header(datum &d) :
        proto{d, {0xFE, 'S', 'M', 'B'}},
        structure_size{d, byte_swap},
        credit_charge{d, byte_swap},
        status{d, byte_swap},
        cmd{d},
        credit_req_resp{d, byte_swap},
        flags{d, byte_swap},
        next_cmd{d, byte_swap},
        msg_id{d, byte_swap},
        process_id{d, byte_swap},
        tree_id{d, byte_swap},
        ssn_id{d, byte_swap},
        signature{d, 16},
        valid{d.is_not_null()} { }

    bool is_response() {
        return flags & req_mask;
    }

    packet_type get_packet_type() {
        switch(cmd.command) {
            case smb2_command::command_type::SMB2_NEGOTIATE:
                if (!is_response()) {
                    return packet_type::NEGOTIATE_REQUEST;
                }
                return packet_type::NEGOTIATE_RESPONSE;
            default:
                break;
        }
        return packet_type::LAST_TYPE;
    }

    bool is_valid() const { return valid; }

    void write_json(struct json_object &o) {
        o.print_key_uint16("structure_size", structure_size.value());
        o.print_key_uint16("credit_charge", credit_charge.value());
        o.print_key_uint_hex("status", status.value());
        o.print_key_string("command", cmd.get_string());
        if (is_response()) {
            o.print_key_uint("credits_granted", credit_req_resp.value());
        } else {
            o.print_key_uint("credits_requested", credit_req_resp.value());
        }
        o.print_key_uint_hex("flags", flags.value());
        o.print_key_uint_hex("next_command", next_cmd.value());
        o.print_key_uint64_hex("message_id", msg_id.value());
        o.print_key_uint_hex("process_id", process_id.value());
        o.print_key_uint_hex("tree_id", tree_id.value());
        o.print_key_uint64_hex("session_id", ssn_id.value());
        o.print_key_hex("signature", signature);
    }
};

class smb2_packet {
    encoded<uint32_t> nbss_layer;
    smb2_header hdr;
    datum& body;

public:
    smb2_packet(datum &d) :
        nbss_layer(d),
        hdr(d),
        body(d) { }

    bool is_not_empty() const { return hdr.is_valid(); }

    void write_json(struct json_object &o) {
        hdr.write_json(o);

        switch(hdr.get_packet_type()) {
            case packet_type::NEGOTIATE_REQUEST:
            {
                smb2_negotiate_request neg_req(body);
                neg_req.write_json(o);
            }
                break;
            case packet_type::NEGOTIATE_RESPONSE:
            {
                smb2_negotiate_response neg_resp(body);
                neg_resp.write_json(o);
            }
                break;
            case packet_type::LAST_TYPE:

            default:
                break;
        }
    }

    static constexpr mask_and_value<8> matcher {
        { 0x00, //Message type
          0x00, 0x00, 0x00 , //Length
          0xff, 0xff, 0xff, 0xff // 
        },
        { 0x00, 0x00, 0x00, 0x00, 0xfe, 0x53, 0x4d, 0x42}
    };
};
 
#endif /* SMB_H */
