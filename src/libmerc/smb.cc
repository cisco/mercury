/*
 * smb.cc
 *
 * Copyright (c) 2022 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include "smb.h"

const char * smb1_command::get_command_string() const {
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

void smb1_header::write_json(struct json_object &o) {
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

const char * dialect::get_dialect_string() const {
    switch (val) {         
        case 0x0202:         return "SMB 2.0.2";
        case 0x0210:         return "SMB 2.1";
        case 0x0222:         return "SMB 2.2.2";
        case 0x0224:         return "SMB 2.2.4";
        case 0x02ff:         return "SMB2 wildcard";
        case 0x0300:         return "SMB 3.0";
        case 0x0302:         return "SMB 3.0.2";
        case 0x0310:         return "SMB 3.1.0";
        case 0x0311:         return "SMB 3.1.1";
        default:             break;
    }
    return "unknown";
}

void negotiate_context::write_json(struct json_object &o) {
    if(!valid) {
        return;
    }

    struct json_array neg_contexts{o, "negotiate_contexts"};

    while(body.is_not_null() && body.is_not_empty()) {
        struct json_object a{neg_contexts};

        encoded<uint16_t> context_type(body, byte_swap);
        a.print_key_string("context_type", get_context_type_string(context_type));

        encoded<uint16_t> data_length(body, byte_swap);
        a.print_key_uint16("data_length", data_length.value());

        body.skip(4); //skip the 4 byte reserved field

        switch(context_type) {
        case SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
        {
            smb2_preauth_integrity_capa x(body, byte_swap);
            x.write_json(a);
            break;
        }
        case SMB2_ENCRYPTION_CAPABILITIES:
        {
            smb2_encryption_capa x(body, byte_swap);
            x.write_json(a);
            break;
        }
        case SMB2_COMPRESSION_CAPABILITIES:
        {
            smb2_compression_capa x(body, byte_swap);
            x.write_json(a);
            break;
        }
        case SMB2_NETNAME_NEGOTIATE_CONTEXT_ID:
        {
            datum netname;
            netname.parse(body, data_length.value());
            a.print_key_json_string("netname", netname);
            break;
        }
        case SMB2_TRANSPORT_CAPABILITIES:
        {
            encoded<uint32_t> flags(body, byte_swap);
            a.print_key_uint_hex("flags", flags);
            break;
        }
        case SMB2_RDMA_TRANSFORM_CAPABILITIES:
        {
            smb2_rdma_transform_capa x(body, byte_swap);
            x.write_json(a);
            break;
        }
        case SMB2_SIGNING_CAPABILITIES:
        {
            smb2_signing_capa x(body, byte_swap);
            x.write_json(a);
            break;
        }
        default:
            body.skip(data_length);
            break;
        }   
        /*
         * Each Negotiate contexts are 8 byte aligned.
         * Hence there will be padding bytes after each
         * negotiate context to make the next one 8 byte aligned.
         */
        body.skip(8 - data_length % 8);
        a.close();
    }   
    neg_contexts.close();
}

void smb2_negotiate_request::write_json(struct json_object &o) {
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
    neg_context.write_json(o);
    neg_req.close();
}

void smb2_negotiate_response::write_json (struct json_object &o) {
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
    neg_resp.print_key_uint16("security_buffer_offset", security_buffer_offset);
    neg_resp.print_key_uint16("security_buffer_length", security_buffer_length);
    neg_context.write_json(neg_resp);
    neg_resp.close();
}

const char * smb2_command::get_string() const {
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

packet_type smb2_header::get_packet_type() {
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

void smb2_header::write_json(struct json_object &o) {
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
