/*
 * smb2.h
 *
 * Copyright (c) 2022 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

/**
 * \file smb.h
 *
 * \brief interface file for SMB code
 */
#ifndef SMB2_H
#define SMB2_H

#include "protocol.h"
#include "json_object.h"
#include "util_obj.h"
#include "match.h"

#include <vector>
#include "datum.h"

/*
 * SMB2 and 3 is implemented based on the reference from
 * the below microsoft document.
 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962
 */

/*
 * GUID--Packet Representation
 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/001eec5a-7f8b-4293-9e21-ca349392db40
 *
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
        b.write_hex_uint(a);
        b.write_char('-');
        b.write_hex_uint(this->b);
        b.write_char('-');
        b.write_hex_uint(c);
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

    const char * get_dialect_string() const;

    void write_raw_features(writeable &buf) const {
        buf.write_quote_enclosed_hex(val);
    }

    void write_json(json_array &o) const {
        o.print_uint16_hex(val.value());
    }

    uint16_t get_code() const {return val.value();}

    const char* get_code_str() const{
        return get_dialect_string();
    };
};    
         
class dialects {
public:
    std::vector<dialect> dialects_list;
    bool valid;

    dialects (datum &d, uint16_t cnt, bool byte_swap = true) {
        for (auto i = 0; i < cnt; i++) {
            dialect id(d, byte_swap);
            dialects_list.push_back(id);
        }
        valid = d.is_not_null();
    }

    void write_raw_features(writeable &buf) const {
        if(!valid) {
            return;
        }

        bool first = true;
        buf.copy('[');
        for(auto& i : dialects_list) {
            if (!first) {
                buf.copy(',');
            } else {
                first = false;
            }
            i.write_raw_features(buf);
        }
        buf.copy(']');
    }

    void write_json(struct json_object &o) {
        if(!valid) {
            return;
        }
        struct json_array a{o, "dialects"};
        for(auto& i : dialects_list) {
            i.write_json(a);
        }
        a.close();
    }
};

/*
 * Windows epoch time:
 * Time in the form of 100-nanosecond intervals since January 1, 1601.
 */
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

/*
 * SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a07bd66-4734-4af8-abcf-5a44ff7ee0e5
 */
class smb2_preauth_integrity_capa {
    encoded<uint16_t> hash_algo_count;
    encoded<uint16_t> salt_length;
    std::vector<uint16_t> hash_algo;
    datum salt;

public:
    smb2_preauth_integrity_capa(datum &d, bool byte_swap) :
        hash_algo_count(d, byte_swap),
        salt_length(d, byte_swap) {
        uint16_t count = 0;
        hash_algo.reserve(hash_algo_count.value());
        while (count < hash_algo_count and d.is_not_empty()) {
            encoded<uint16_t> algo(d, byte_swap);
            hash_algo.push_back(algo.value());
            count++;
        }
        salt.parse(d, salt_length);
    }

    void write_json(struct json_object &o) {
        o.print_key_uint16("hash_algorithm_count", hash_algo_count.value());
        struct json_array algo{o, "hash_algorithms"};
        for (const auto& val : hash_algo) {
            algo.print_uint16_hex(val);
        }
        algo.close();
        o.print_key_hex("salt", salt);
    }
};

/*
 * SMB2_ENCRYPTION_CAPABILITIES:
 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/16693be7-2b27-4d3b-804b-f605bde5bcdd
 */
struct cipher{
    encoded<uint16_t> val;

    const char * get_cipher_string() const {
        switch(val) {
        case 0x0001 : return "AES-128-CCM";
        case 0x0002 : return "AES-128-GCM";
        case 0x0003 : return "AES-256-CCM";
        case 0x0004 : return "AES-256-GCM";
        default     : return nullptr;
        }
    }
};

class smb2_encryption_capa {
public:
    encoded<uint16_t> cipher_count;
    std::vector<cipher> ciphers;

    smb2_encryption_capa (datum &d, bool byte_swap) :
        cipher_count(d, byte_swap) {
        uint16_t count = 0;
        ciphers.reserve(cipher_count.value());
        while(count < cipher_count and d.is_not_empty()) {
            encoded<uint16_t> temp_cipher(d, byte_swap);
            ciphers[count].val=temp_cipher.value();
            count++;
        }
    }
    
    uint16_t count = 0;
    void write_json(struct json_object &o) {
        o.print_key_uint16("cipher_count", cipher_count.value());
        struct json_array ids{o, "ciphers"};
        while(count < cipher_count) {
            type_codes<smb2_encryption_capa> code{*this};
            ids.print_key(code);
            count++;
        }
        ids.close();
    }

    uint16_t get_code() const {return ciphers[count].val.value();}

    const char* get_code_str() const {
        return ciphers[count].get_cipher_string();
    }

};

/*
 * SMB2_COMPRESSION_CAPABILITIES:
 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/78e0c942-ab41-472b-b117-4a95ebe88271
 */
class smb2_compression_capa {
    encoded<uint16_t> compression_algo_count;
    skip_bytes<2> padding;
    encoded<uint32_t> flags;
    std::vector<uint16_t> compression_algos;

    const char * get_comp_algo_string(const uint16_t& val) const {
        switch(val) {
        case 0x0000:        return "none";
        case 0x0001:        return "LZNT1";
        case 0x0002:        return "LZ77";
        case 0x0003:        return "LZ77+Huffman";
        case 0x0004:        return "Pattern_V1";
        default:            break;
        }
        return "unknown";
    }

public:
    smb2_compression_capa(datum &d, bool byte_swap) :
        compression_algo_count(d, byte_swap),
        padding(d),
        flags(d, byte_swap) {
        compression_algos.reserve(compression_algo_count.value());
        uint16_t count = 0;
        while(count < compression_algo_count and d.is_not_empty()) {
            encoded<uint16_t> compression_algo(d, byte_swap);
            compression_algos.push_back(compression_algo.value());
            count++;
        }
    }

    void write_json(struct json_object &o) {
        o.print_key_uint16("compression_algorithm_count", compression_algo_count.value());
        o.print_key_uint_hex("flags", flags.value());
        struct json_array comp_algos{o, "compression_algorithms"};
        for (const auto& val : compression_algos) {
            comp_algos.print_string(get_comp_algo_string(val));    
        }
        comp_algos.close();
    }
};

/*
 * SMB2_RDMA_TRANSFORM_CAPABILITIES:
 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/52b74a74-9838-4f51-b2b0-efeb23bd79d6
 */
class smb2_rdma_transform_capa {
    encoded<uint16_t> transform_count;
    skip_bytes<2> reserved1;
    skip_bytes<4> reserved2;
    std::vector<uint16_t> rdma_transforms_ids;

    const char * get_id_string(const uint16_t& val) const {
        switch(val) {
        case 0x0000:        return "smb2_rdma_transform_none";
        case 0x0001:        return "smb2_rdma_transform_encryption";
        case 0x0002:        return "smb2_rdma_transform_signing";
        default:            break;
        }
        return "unknown";
    }
public:
    smb2_rdma_transform_capa (datum &d, bool byte_swap) :
        transform_count(d, byte_swap),
        reserved1(d),
        reserved2(d) {
        rdma_transforms_ids.reserve(transform_count.value());
        uint16_t count = 0;
        while(count < transform_count and d.is_not_empty()) {
            encoded<uint16_t> id(d, byte_swap);
            rdma_transforms_ids.push_back(id);
            count++;
        }
    }

    void write_json(struct json_object &o) {
        o.print_key_uint16("transform_count", transform_count.value());
        struct json_array ids{o, "rdma_transform_ids"};
        for (const auto& val : rdma_transforms_ids) {
            ids.print_string(get_id_string(val));
        }
        ids.close();
    }
};

/*
 * SMB2_SIGNING_CAPABILITIES:
 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/cb9b5d66-b6be-4d18-aa66-8784a871cc10
 */
class smb2_signing_capa {
    encoded<uint16_t> signing_algo_count;
    std::vector<uint16_t> signing_algos;
 
    const char * get_id_string(const uint16_t& val) const {
        switch(val) {
        case 0x0000:        return "HMAC-SHA256";
        case 0x0001:        return "AES-CMAC";
        case 0x0002:        return "AES-GMAC";
        default:            break;
        }
        return "unknown";
    }
public:
    smb2_signing_capa (datum &d, bool byte_swap) :
        signing_algo_count(d, byte_swap) {
        signing_algos.reserve(signing_algo_count.value());
        uint16_t count = 0;
        while(count < signing_algo_count and d.is_not_empty()) {       
            encoded<uint16_t> id(d, byte_swap);
            signing_algos.push_back(id);
            count++;
        }
    }

    void write_json(struct json_object &o) {
        o.print_key_uint16("signing_algorithm_count", signing_algo_count.value());
        struct json_array ids{o, "signing_algorithms"};
        for (const auto& val : signing_algos) {
            ids.print_string(get_id_string(val));
        }
        ids.close();
    }
};


/*
 * SMB2 NEGOTIATE_CONTEXT:
 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/15332256-522e-4a53-8cd7-0bd17678a2f7
 */
class negotiate_context {
    encoded<uint16_t> context_type;
    encoded<uint16_t> data_length;
    skip_bytes<4> reserved;
    datum body;    
    bool byte_swap;
    bool valid;

    enum context_type {
        SMB2_PREAUTH_INTEGRITY_CAPABILITIES = 0x1,
        SMB2_ENCRYPTION_CAPABILITIES = 0x2,
        SMB2_COMPRESSION_CAPABILITIES = 0x3,
        SMB2_NETNAME_NEGOTIATE_CONTEXT_ID = 0x5,
        SMB2_TRANSPORT_CAPABILITIES = 0x6,
        SMB2_RDMA_TRANSFORM_CAPABILITIES = 0x7,
        SMB2_SIGNING_CAPABILITIES = 0x8
    };

    bool get_netname(datum netname, std::string& name);

public:
    negotiate_context (datum &d, bool _byte_swap) :
        context_type(d, _byte_swap),
        data_length(d, _byte_swap),
        reserved(d),
        body(d, data_length.value()),
        byte_swap(_byte_swap),
        valid(d.is_not_null()) {
        d.skip(8 - data_length % 8);    // Skip the 8 byte aligned padding bytes
        }

    const char * get_context_type_string() const {
        switch(context_type) {
        case SMB2_PREAUTH_INTEGRITY_CAPABILITIES:        return "smb2_preauth_integrity_capabilities";
        case SMB2_ENCRYPTION_CAPABILITIES:               return "smb2_encryption_capabilties";
        case SMB2_COMPRESSION_CAPABILITIES:              return "smb2_compression_capabilities";
        case SMB2_NETNAME_NEGOTIATE_CONTEXT_ID:          return "smb2_netname_negotiate_context_id";
        case SMB2_TRANSPORT_CAPABILITIES:                return "smb2_transport_capabilities";
        case SMB2_RDMA_TRANSFORM_CAPABILITIES:           return "smb2_rdma_transform_capabilites";
        case SMB2_SIGNING_CAPABILITIES:                  return "SMB2_SIGNING_CAPABILITIES";
        default:                                         return nullptr;
        }
    } 

    uint16_t get_code() const {return context_type.value();}

    const char* get_code_str() const{
        return get_context_type_string();
    };

    void write_json(struct json_array &o);

    void write_raw_features(writeable &buf) const {
        buf.copy('[');
        buf.write_quote_enclosed_hex(context_type);
        buf.copy(',');
        buf.write_quote_enclosed_hex(body.data, body.length());
        buf.copy(']');
    }
};

class negotiate_context_list {
    std::vector<negotiate_context> context_list;

public:
    negotiate_context_list (struct datum &d, bool byte_swap) {
        while(d.is_not_empty()) {
            context_list.emplace_back(negotiate_context(d, byte_swap));
        }
    }

    void write_raw_features(writeable &buf) const {
        buf.copy('[');
        bool first = true;
        for (const auto &i : context_list) {
            if (!first) {
                buf.copy(',');
            } else {
                first = false;
            }
            i.write_raw_features(buf);
        }
        buf.copy(']');
    }

    void write_json(struct json_object &o) {
        if (context_list.empty()) {
            return;
        }

        struct json_array neg_contexts{o, "negotiate_contexts"};
        for (auto &i : context_list) {
            i.write_json(neg_contexts);
        }
        neg_contexts.close();
    }
};


/*
 * There is padding between the end of the Dialects array and the
 * first negotiate context in NegotiateContextList so that the first
 * negotiate context is 8-byte aligned.
 *
 * NegotiateContextOffset - specifies the offset, in bytes, from the
 * beginning of the SMB2 header to the first NegotiateContextList.
 * 
 * SMB2 header - 64 bytes in length
 * Number of bytes till reserved2 member of smb2_negotiate_request is 100
 * Then follows the variable length dialect lists which contains dialects
 * of length 2 bytes.
 *
 * Padding bytes = negotiate_context_offset - 100 - (2 * number of dialects)
 */
class neg_req_padding {
    size_t padding_bytes;

public:
    neg_req_padding(datum &d, uint32_t neg_context_offset, uint16_t dialect_count) {
        padding_bytes = neg_context_offset - 100 - dialect_count * 2;
        d.skip(padding_bytes);
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
    neg_req_padding padding;
    negotiate_context_list neg_contexts;
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
        dialect_list(d, dialect_count.value()),
        padding(d, neg_context_offset.value(), dialect_count.value()),
        neg_contexts(d, byte_swap),
        valid(d.is_not_null()) { }

    void write_raw_features(writeable &buf) const {
        if(!valid) {
            return;
        }

        buf.copy(',');
        buf.copy('[');
        buf.write_quote_enclosed_hex(dialect_count);
        buf.copy(',');
        buf.write_quote_enclosed_hex(sec_mode);
        buf.copy(',');
        buf.write_quote_enclosed_hex(cap);
        buf.copy(']');
        buf.copy(',');
        dialect_list.write_raw_features(buf);
        buf.copy(',');
        neg_contexts.write_raw_features(buf);
    }

    void write_json(struct json_object &o);
};

/*
 * There is padding between the end of the  Buffer field and the first negotiate context
 * in the NegotiateContextList so that the first negotiate context is 8-byte aligned.
 *
 * NegotiateContextOffset - specifies the offset, in bytes, from the
 * beginning of the SMB2 header to the first NegotiateContextList.
 *
 * SMB2 header = 64 byes in length
 * Number of bytes till negotiate_context_offset field of
 * smb2_negotiate_response structure is 128, which is 8 byte aligned.
 *
 * Then follows buffer field which is of varaible length defined by the
 * field security_buffer_length.
 * Hence padding bytes = 8 - (security_buffer_length % 8)
 */
class neg_resp_padding {
    size_t padding_bytes;

public:
    neg_resp_padding(datum &d, uint16_t security_buffer_length) {
        padding_bytes = 8 - (security_buffer_length % 8);
        d.skip(padding_bytes);
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
    encoded<uint16_t> security_buffer_offset;
    encoded<uint16_t> security_buffer_length;
    encoded<uint32_t> negotiate_context_offset;
    datum buffer;
    neg_resp_padding padding;
    negotiate_context_list neg_contexts;
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
        security_buffer_offset(d, byte_swap),
        security_buffer_length(d, byte_swap),
        negotiate_context_offset(d, byte_swap),
        buffer(d, security_buffer_length.value()),
        padding(d, security_buffer_length.value()),
        neg_contexts(d, byte_swap),
        valid(d.is_not_null()) { }

    void write_raw_features(writeable &buf) const {
        if(!valid) {
            return;
        }

        buf.copy(',');
        buf.copy('[');
        buf.write_quote_enclosed_hex(sec_mode);
        buf.copy(',');
        dialect_num.write_raw_features(buf);
        buf.copy(',');
        buf.write_quote_enclosed_hex(capabilities);
        buf.copy(']');
        buf.copy(',');
        neg_contexts.write_raw_features(buf);
    }
    void write_json (struct json_object &o);

    uint16_t get_code() const {return dialect_num.get_code();}

    const char* get_code_str() const {
        return dialect_num.get_code_str();
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

    const char * get_string() const;
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
    enum packet_type {
        NEGOTIATE_REQUEST,
        NEGOTIATE_RESPONSE,

        LAST_TYPE           //Should be the last field in enum
    };

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

    void write_raw_features(writeable &buf) const {
        if (!valid) {
            return;
        }

        buf.copy('[');
        buf.write_quote_enclosed_hex(cmd.command);
        buf.copy(',');
        buf.write_quote_enclosed_hex(flags);
        buf.copy(',');
        buf.write_quote_enclosed_hex(next_cmd);
        buf.copy(']');
    }
        
    void write_json(struct json_object &o);

    uint16_t get_code() const {return cmd.command.value();}

    const char* get_code_str() const {
        return cmd.get_string();
    }
    
};

class smb2_packet : public base_protocol {
    encoded<uint32_t> nbss_layer;
    smb2_header hdr;
    datum& body;

public:
    smb2_packet(datum &d) :
        nbss_layer(d),
        hdr(d),
        body(d) { }

    bool is_not_empty() const { return hdr.is_valid(); }

    void write_json(struct json_object &o, bool) {
        if (this->is_not_empty()) {
            struct json_object smb2{o, "smb2"};
            hdr.write_json(smb2);

            switch (hdr.get_packet_type()) {
                case smb2_header::packet_type::NEGOTIATE_REQUEST:
                {
                    smb2_negotiate_request neg_req(body);
                    neg_req.write_json(smb2);
                    data_buffer<2048> buf;
                    buf.copy('[');
                    hdr.write_raw_features(buf);
                    neg_req.write_raw_features(buf);
                    buf.copy(']');
                    smb2.print_key_json_string("features", buf.contents());
                }
                    break;
                case smb2_header::packet_type::NEGOTIATE_RESPONSE:
                {
                    smb2_negotiate_response neg_resp(body);
                    neg_resp.write_json(smb2);
                    data_buffer<2048> buf;
                    buf.copy('[');
                    hdr.write_raw_features(buf);
                    neg_resp.write_raw_features(buf);
                    buf.copy(']');
                    smb2.print_key_json_string("features", buf.contents());
                }
                    break;
                case smb2_header::packet_type::LAST_TYPE:

                default:
                    break;
            }
            smb2.close();
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

namespace {

    [[maybe_unused]] int smb2_fuzz_test(const uint8_t *data, size_t size) {
        struct datum request_data{data, data+size};
        char buffer[8192];
        struct buffer_stream buf_json(buffer, sizeof(buffer));
        struct json_object record(&buf_json);
        

        smb2_packet request{request_data};
        if (request.is_not_empty()) {
            request.write_json(record, true);
        }

        return 0;
    }

};

#endif /* SMB2_H */
