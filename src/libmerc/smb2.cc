/*
 * smb2.cc
 *
 * Copyright (c) 2022 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include "smb2.h"

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
        default:             return nullptr;
    }
}

/*
 * This function checks if the netname has printable ascii
 * characters. 
 * If yes - it writes the ascii characters to the string
 * name and returns true.

 * If No - returns false
 */
bool negotiate_context::get_netname(datum netname, std::string& name) {
    while(netname.is_readable()) {
        encoded<uint16_t> c(netname, true);
        if (!c) {
            return false;
        }
        if (c >= 0x20 and c <= 0x7f) {
            name.push_back(char(c));
        } else {
            return false;
        }
    }
    return true;
}

void negotiate_context::write_json(struct json_array &o) {
    if(!valid) {
        return;
    }

    struct json_object a{o};
    type_codes<negotiate_context> code{*this};
    a.print_key_value("context_type", code);

    a.print_key_uint16("data_length", data_length.value());

    datum tmp = body;

    switch(context_type) {
    case SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
    {
        smb2_preauth_integrity_capa x(tmp, byte_swap);
        x.write_json(a);
        break;
    }
    case SMB2_ENCRYPTION_CAPABILITIES:
    {
        smb2_encryption_capa x(tmp, byte_swap);
        x.write_json(a);
        break;
    }
    case SMB2_COMPRESSION_CAPABILITIES:
    {
        smb2_compression_capa x(tmp, byte_swap);
        x.write_json(a);
        break;
    }
    case SMB2_NETNAME_NEGOTIATE_CONTEXT_ID:
    /*
     * Netname: A Unicode UTF-16 fully qualified domain name, a NetBIOS name
     * or an IP address of the server machine.
     */
    {
        datum netname;
        netname.parse(tmp, data_length.value());
        /*
         * If the netname has all characters as printable ascii, then print
         * it as a string, otherwise print is as hex characters.
         */
        std::string name;
        name.reserve(data_length.value()/2);
        if (get_netname(netname, name)) {
            a.print_key_string("netname", name.c_str());
        } else {
            a.print_key_hex("netname", netname);
        }
        break;
    }
    case SMB2_TRANSPORT_CAPABILITIES:
    {
        encoded<uint32_t> flags(tmp, byte_swap);
        a.print_key_uint_hex("flags", flags);
        break;
    }
    case SMB2_RDMA_TRANSFORM_CAPABILITIES:
    {
        smb2_rdma_transform_capa x(tmp, byte_swap);
        x.write_json(a);
        break;
    }
    case SMB2_SIGNING_CAPABILITIES:
    {
        smb2_signing_capa x(tmp, byte_swap);
        x.write_json(a);
        break;
    }
    default:
        a.print_key_hex("value", tmp);
        break;
    }   
    a.close();
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
    neg_contexts.write_json(o);
    neg_req.close();
}

void smb2_negotiate_response::write_json (struct json_object &o) {
    if(!valid) {
        return;
    }

    json_object neg_resp{o, "negotiate_response"};
    neg_resp.print_key_uint16("structure_size", structure_size);
    neg_resp.print_key_uint16_hex("security_mode", sec_mode);
   
    type_codes<smb2_negotiate_response> code{*this};
    neg_resp.print_key_value("dialect", code);

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
    neg_contexts.write_json(neg_resp);
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
        default:                    return nullptr;
    }
}

void smb2_header::write_json(struct json_object &o) {
    o.print_key_uint16("structure_size", structure_size.value());
    o.print_key_uint16("credit_charge", credit_charge.value());
    o.print_key_uint_hex("status", status.value());
    
    type_codes<smb2_header> code{*this};
    o.print_key_value("command", code);

    if (is_response()) {
        o.print_key_uint("credits_granted", credit_req_resp.value());
    } else {
        o.print_key_uint("credits_requested", credit_req_resp.value());
    }
    o.print_key_bool("response", flags.bit<31>());
    o.print_key_bool("async_command", flags.bit<30>());
    o.print_key_bool("chained_request", flags.bit<29>());
    o.print_key_bool("signed", flags.bit<28>());
    o.print_key_uint8_hex("priority", flags.slice<25, 28>());
    o.print_key_bool("dfs_operation", flags.bit<3>());
    o.print_key_bool("replay_operation", flags.bit<2>());
    o.print_key_uint_hex("next_command", next_cmd.value());
    o.print_key_uint64_hex("message_id", msg_id.value());
    o.print_key_uint_hex("process_id", process_id.value());
    o.print_key_uint_hex("tree_id", tree_id.value());
    o.print_key_uint64_hex("session_id", ssn_id.value());
    o.print_key_hex("signature", signature);
}