/*
 * socks.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

/*
 * \file socks.h
 *
 * \brief interface file for SOCKS4, SOCKS5, and sub-auth code
 */
#ifndef SOCKS_H
#define SOCKS_H

#include "json_object.h"
#include "match.h"

//  SOCKS4_a and SOCKS4_c(SOCKS4_a with domain name)
//
class socks4_req {
    encoded<uint8_t> version;
    encoded<uint8_t> cmd;
    encoded<uint16_t> port;
    encoded<uint32_t> ip;
    datum id;
    datum domain;
    bool socks4a;   // true if extended ver of SOCKS4_c, called SOCKS4_a, with domain name
    bool is_valid;

    void parse(datum &pkt) {
        id.parse_up_to_delim(pkt, 0x00);
        if (id.data_end == pkt.data_end) {
            // delim not found
            return;
        }
        if (id.data_end == (pkt.data_end-1)) {
            // no domain name
            is_valid = true;
            return;
        }
        pkt.skip(1);    // skip 0x00
        domain.parse_up_to_delim(pkt, 0x00);
        if (domain.data_end == pkt.data_end) {
            // delim not found
            return;
        }
        if (domain.data_end == (pkt.data_end-1)) {
            is_valid = true;
            socks4a = true;
            return;
        }
        // did not reach pkt end
        is_valid = false;
        return;
    }

public:
    socks4_req(datum &pkt) :
        version{pkt},
        cmd{pkt},
        port{pkt},
        ip{pkt},
        id{nullptr,nullptr},
        domain{nullptr,nullptr},
        socks4a{false},
        is_valid{false} { parse(pkt); }

    static constexpr mask_and_value<4> matcher{
        { 0xff, 0xfc, 0x00, 0x00 },
        { 0x04, 0x00, 0x00, 0x00 }
    };

    // For SOCKS4, skipping the ver, cmd, port, ip, user-id follows (printable ASCII) and null byte
    // followed by optional domain name and null byte
    // check first and last byte of id for ascii printable and null termination
    static ssize_t get_payload_length(datum pkt) {
        ssize_t len = pkt.length();
        pkt.skip(8);
        if (!pkt.is_not_empty()) {
            return 0;
        }
        if ((pkt.length() == 1 && *pkt.data == 0x00)
            || ((*pkt.data>=32 || *pkt.data==0x00) && *(pkt.data_end-2)>=32 && *(pkt.data_end-1)==0x00)) {
                return len; 
        }
        else {
            return 0;
        }
    }

    uint8_t get_code() const {return cmd;}

    const char* get_code_str() const {
        switch (cmd) {
            case 0x01 : return "CONNECT";
            case 0x02 : return "BIND";
            default : return nullptr;
        }
    }

    void write_json(struct json_object &record, bool output_metadata) {
        if (!is_valid) {
            return;
        }
        json_object socks4_pkt(record, "socks4");
        type_codes<socks4_req> code(*this);
        socks4_pkt.print_key_value("cmd", code);
        socks4_pkt.print_key_int("port",port);
        if (output_metadata) {
            uint32_t ip_val = htonl(ip.value());
            socks4_pkt.print_key_ipv4_addr("ip",(uint8_t*)&ip_val);
        }
        socks4_pkt.print_key_json_string("id",id);
        if (socks4a) {
            if (output_metadata) {
                socks4_pkt.print_key_bool("socks4a", true);
            }
            socks4_pkt.print_key_json_string("domain",domain);
        }
    }

    bool is_not_empty() const { return (is_valid); }
};



//  SOCKS5
//
struct socks5_auth_code {
    encoded<uint8_t> code;

    socks5_auth_code(datum &code_list) : code{code_list} {}

    uint8_t get_code() const { return code.value(); }

    const char* get_code_str() const {
        switch (code) {
            case 0x00 : return "NO_AUTH";
            case 0x01 : return "GSSAPI";
            case 0x02 : return "USER_PASS";
            case 0x03 : return "CHALLENGE_HANDSHAKE_AUTH";
            case 0x04 : return "UNASSIGNED";
            case 0x05 : return "CHALLENGE_RESPONSE_AUTH";
            case 0x06 : return "SSL";
            case 0x07 : return "NDS";
            case 0x08 : return "MULTI_AUTH_FRAMEWORK";
            case 0x09 : return "JSON_FRAMEWORK_BLOCK";
            case 0x86 : return "SSL";
            default :
                if (code < 0x7F) {
                    return "UNASSIGNED";
                }
                else if (code < 0xFE) {
                    return "PRIVATE";
                }
                else return "NO_MATCH";
        }
    }

    void write_json(struct json_array &record) {
        record.print_string(get_code_str());
    }
};

class socks5_hello {
    encoded<uint8_t> version;
    encoded<uint8_t> nauth;
    datum auths;
    bool valid;

public:
    socks5_hello(datum &pkt) :
    version{pkt},
    nauth{pkt},
    auths{pkt,nauth},
    valid{true} {}

    static constexpr mask_and_value<4> matcher{
        { 0xff, 0xf0, 0x00, 0x00 },
        { 0x05, 0x00, 0x00, 0x00 }
    };

    bool is_not_empty() const { return (valid); }

    static ssize_t get_payload_length(datum pkt) {
        pkt.skip(1);
        return 1 + 1 + encoded<uint8_t>{pkt}.value();
    }

    void write_json(json_object &record, bool metadata) {
        if (!valid) {
            return;
        }
        json_object socks_pkt(record, "socks5");
        if (metadata) {
            socks_pkt.print_key_int("nauth", nauth);
        }
        json_array auth_list(socks_pkt,"auth_list");
        while (auths.is_not_empty()) {
            socks5_auth_code code(auths);
            code.write_json(auth_list);
        }
        auth_list.close();
    }
};

class socks5_usr_pass {
    encoded<uint8_t> version;
    encoded<uint8_t> id_len;
    datum id;
    encoded<uint8_t> pw_len;
    datum pw;
    bool valid;

public:
    socks5_usr_pass(datum &pkt) :
        version{pkt},
        id_len{pkt},
        id{pkt,id_len},
        pw_len{pkt},
        pw{pkt,pw_len},
        valid{true} {}

    static constexpr mask_and_value<4> matcher{
        { 0xff, 0x00, 0x00, 0x00 },
        { 0x01, 0x00, 0x00, 0x00 }
    };

    static ssize_t get_payload_length(datum pkt) {
        ssize_t len = 3;
        pkt.skip(1);
        len += encoded<uint8_t>{pkt}.value();
        pkt.skip(len-3);
        len += encoded<uint8_t>{pkt}.value();
        return len;
    }

    bool is_not_empty() { return valid; }

    void write_json(json_object &record, bool metadata) {
        if (!valid) {
            return;
        }
        json_object auth_pkt{record,"socks5_usrpass"};
        if (metadata) {
            auth_pkt.print_key_int("id_len",id_len);
        }
        auth_pkt.print_key_json_string("id",id);
        if (metadata) {
            auth_pkt.print_key_int("pw_len",pw_len);
        }
        auth_pkt.print_key_json_string("pw",pw);
    }
};

class socks5_gss {
    encoded<uint8_t> ver;
    encoded<uint8_t> mtype;
    encoded<uint16_t> tok_len;
    datum tok;
    bool valid;

public:
    socks5_gss(datum &pkt):
        ver{pkt},
        mtype{pkt},
        tok_len{pkt},
        tok{pkt,tok_len.value()},
        valid{true} {}

    static constexpr mask_and_value<4> matcher{
        { 0xff, 0xfc, 0x00, 0x00 },
        { 0x01, 0x00, 0x00, 0x00 }
    };

    static ssize_t get_payload_length(datum pkt) {
        pkt.skip(2);
        return 2 + 2 + encoded<uint16_t>{pkt}.value();
    }

    bool is_not_empty() { return valid; }

    const char* get_code_str() const {
        switch (mtype) {
            case 0x00 : return "null";
            case 0x01 : return "auth";
            case 0x02 : return "security_level";
            case 0x03 : return "enc_msg";
            default : return "null";
        }
    }

    void write_json(json_object &record, bool metadata) {
        if (!valid) {
            return;
        }
        json_object auth_pkt{record,"socks5_gss"};
        auth_pkt.print_key_string("mtype",get_code_str());
        if (metadata) {
            auth_pkt.print_key_int("msg_len",tok_len);
        }
    }
};

struct socks5_domain {
    encoded<uint8_t> len;
    datum domain;

    socks5_domain(datum &pkt) : len{pkt}, domain{pkt,len.value()} {}

    void write_json(json_object &record) {
        record.print_key_json_string("domain",domain);
    }
};

struct socks5_addr {
    using var_addr = std::variant<std::monostate, encoded<uint32_t>, datum, socks5_domain>;
    encoded<uint8_t> type;
    var_addr addr;

    void write_json_addr(socks5_domain &domain, json_object &o) { domain.write_json(o); }
    
    void write_json_addr(encoded<uint32_t> &ip, json_object &o) {
        uint32_t ip_val = htonl(ip.value());
        o.print_key_ipv4_addr("ip",(uint8_t*)&ip_val);
    }

    void write_json_addr(std::monostate &, json_object& o) {}    
    
    template <typename T> void write_json_addr(T &,json_object &o ) {}

    socks5_addr (datum &pkt) : type{pkt} {
        switch (type) {
            case 0x01 : addr.emplace<encoded<uint32_t> >(pkt);
            case 0x03 : addr.emplace<socks5_domain>(pkt);
            case 0x04 : addr.emplace<datum>(pkt,16);
            default : addr.emplace<std::monostate>();
        }
    }

    void write_json(json_object &record, bool metadata) {
        if (metadata) {
            record.print_key_int("addr_type",type);
        }
        std::visit(overloaded{
            [&](auto &address) {
                write_json_addr(address,record);
            },
        }, addr);
    }

};

#endif  // SOCKS_H 