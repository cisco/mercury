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