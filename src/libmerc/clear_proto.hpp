/*
 * clear_text_proto.hpp
 *
 * Copyright (c) 2025 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef CLEAR_PROTO_H
#define CLEAR_PROTO_H

#include <vector>
#include <unordered_map>
#include <string_view>

enum tcp_msg_type {
    tcp_msg_type_unknown = 0,
    tcp_msg_type_http_request,
    tcp_msg_type_http_response,
    tcp_msg_type_tls_client_hello,
    tcp_msg_type_tls_server_hello,
    tcp_msg_type_tls_certificate,
    tcp_msg_type_ssh,
    tcp_msg_type_ssh_kex,
    tcp_msg_type_smtp_client,
    tcp_msg_type_smtp_server,
    tcp_msg_type_dns,
    tcp_msg_type_smb1,
    tcp_msg_type_smb2,
    tcp_msg_type_iec,
    tcp_msg_type_dnp3,
    tcp_msg_type_nbss,
    tcp_msg_type_openvpn,
    tcp_msg_type_bittorrent,
    tcp_msg_type_mysql_server,
    tcp_msg_type_mysql_login_request,
    tcp_msg_type_tofsee_initial_message,
    tcp_msg_type_socks4,
    tcp_msg_type_socks5_hello,
    tcp_msg_type_socks5_req_resp,
    tcp_msg_type_ldap,
    tcp_msg_type_rfb,
    tcp_msg_type_tacacs,
    tcp_msg_type_ftp_request,
    tcp_msg_type_ftp_response,
    tcp_msg_type_rdp,
};

class clear_text_protos {
    inline static std::unordered_map<std::string_view, std::vector<tcp_msg_type>> protos = {
//HTTP methods taken from https://www.iana.org/assignments/http-methods/http-methods.xhtm
		{"ACL",              {tcp_msg_type_http_request}},
		{"BASELINE",         {tcp_msg_type_http_request}},
		{"BIND",             {tcp_msg_type_http_request}},
		{"CHECKIN",          {tcp_msg_type_http_request}},
		{"CHECKOUT",         {tcp_msg_type_http_request}},
		{"CONNECT",          {tcp_msg_type_http_request}},
		{"COPY",             {tcp_msg_type_http_request}},
		{"DELETE",           {tcp_msg_type_http_request}},
		{"GET",              {tcp_msg_type_http_request}},
		{"HEAD",             {tcp_msg_type_http_request}},
		{"LABEL",            {tcp_msg_type_http_request}},
		{"LINK",             {tcp_msg_type_http_request}},
		{"LOCK",             {tcp_msg_type_http_request}},
		{"MERGE",            {tcp_msg_type_http_request}},
		{"MKACTIVITY",       {tcp_msg_type_http_request}},
		{"MKCALENDAR",       {tcp_msg_type_http_request}},
		{"MKCOL",            {tcp_msg_type_http_request}},
		{"MKREDIRECTREF",    {tcp_msg_type_http_request}},
		{"MKWORKSPACE",      {tcp_msg_type_http_request}},
		{"MOVE",             {tcp_msg_type_http_request}},
		{"OPTIONS",          {tcp_msg_type_http_request}},
		{"ORDERPATCH",       {tcp_msg_type_http_request}},
		{"PATCH",            {tcp_msg_type_http_request}},
		{"POST",             {tcp_msg_type_http_request}},
		{"PRI",              {tcp_msg_type_http_request}},
		{"PROPFIND",         {tcp_msg_type_http_request}},
		{"PROPPATCH",        {tcp_msg_type_http_request}},
		{"PUT",              {tcp_msg_type_http_request}},
		{"REBIND",           {tcp_msg_type_http_request}},
		{"REPORT",           {tcp_msg_type_http_request}},
		{"SEARCH",           {tcp_msg_type_http_request}},
		{"TRACE",            {tcp_msg_type_http_request}},
		{"UNBIND",           {tcp_msg_type_http_request}},
		{"UNCHECKOUT",       {tcp_msg_type_http_request}},
		{"UNLINK",           {tcp_msg_type_http_request}},
		{"UNLOCK",           {tcp_msg_type_http_request}},
		{"UPDATE",           {tcp_msg_type_http_request}},
		{"UPDATEREDIRECTREF",{tcp_msg_type_http_request}},
		{"VERSION",          {tcp_msg_type_http_request}},
//Extensions taken from https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions.xhtml
		{"ABOR",             {tcp_msg_type_ftp_request}},
		{"ACCT",             {tcp_msg_type_ftp_request}},
		{"ADAT",             {tcp_msg_type_ftp_request}},
		{"ALGS",             {tcp_msg_type_ftp_request}},
		{"ALLO",             {tcp_msg_type_ftp_request}},
		{"APPE",             {tcp_msg_type_ftp_request}},
		{"AUTH",             {tcp_msg_type_ftp_request, tcp_msg_type_smtp_client}},
		{"CCC",              {tcp_msg_type_ftp_request}},
		{"CDUP",             {tcp_msg_type_ftp_request}},
		{"CONF",             {tcp_msg_type_ftp_request}},
		{"CWD",              {tcp_msg_type_ftp_request}},
		{"DELE",             {tcp_msg_type_ftp_request}},
		{"ENC",              {tcp_msg_type_ftp_request}},
		{"EPRT",             {tcp_msg_type_ftp_request}},
		{"EPSV",             {tcp_msg_type_ftp_request}},
		{"FEAT",             {tcp_msg_type_ftp_request}},
		{"HELP",             {tcp_msg_type_ftp_request, tcp_msg_type_smtp_client}},
		{"HOST",             {tcp_msg_type_ftp_request}},
		{"LANG",             {tcp_msg_type_ftp_request}},
		{"LIST",             {tcp_msg_type_ftp_request}},
		{"LPRT",             {tcp_msg_type_ftp_request}},
		{"LPSV",             {tcp_msg_type_ftp_request}},
		{"MDTM",             {tcp_msg_type_ftp_request}},
		{"MIC",              {tcp_msg_type_ftp_request}},
		{"MKD",              {tcp_msg_type_ftp_request}},
		{"MLSD",             {tcp_msg_type_ftp_request}},
		{"MLST",             {tcp_msg_type_ftp_request}},
		{"MODE",             {tcp_msg_type_ftp_request}},
		{"NLST",             {tcp_msg_type_ftp_request}},
		{"NOOP",             {tcp_msg_type_ftp_request, tcp_msg_type_smtp_client}},
		{"OPTS",             {tcp_msg_type_ftp_request}},
		{"PASS",             {tcp_msg_type_ftp_request}},
		{"PASV",             {tcp_msg_type_ftp_request}},
		{"PBSZ",             {tcp_msg_type_ftp_request}},
		{"PORT",             {tcp_msg_type_ftp_request}},
		{"PROT",             {tcp_msg_type_ftp_request}},
		{"PWD",              {tcp_msg_type_ftp_request}},
		{"QUIT",             {tcp_msg_type_ftp_request, tcp_msg_type_smtp_client}},
		{"REIN",             {tcp_msg_type_ftp_request}},
		{"REST",             {tcp_msg_type_ftp_request}},
		{"RETR",             {tcp_msg_type_ftp_request}},
		{"RMD",              {tcp_msg_type_ftp_request}},
		{"RNFR",             {tcp_msg_type_ftp_request}},
		{"RNTO",             {tcp_msg_type_ftp_request}},
		{"SITE",             {tcp_msg_type_ftp_request}},
		{"SIZE",             {tcp_msg_type_ftp_request}},
		{"SMNT",             {tcp_msg_type_ftp_request}},
		{"STAT",             {tcp_msg_type_ftp_request}},
		{"STOR",             {tcp_msg_type_ftp_request}},
		{"STOU",             {tcp_msg_type_ftp_request}},
		{"STRU",             {tcp_msg_type_ftp_request}},
		{"SYST",             {tcp_msg_type_ftp_request}},
		{"TYPE",             {tcp_msg_type_ftp_request}},
		{"USER",             {tcp_msg_type_ftp_request}},
		{"XCUP",             {tcp_msg_type_ftp_request}},
		{"XCWD",             {tcp_msg_type_ftp_request}},
		{"XMKD",             {tcp_msg_type_ftp_request}},
		{"XPWD",             {tcp_msg_type_ftp_request}},
		{"XRMD",             {tcp_msg_type_ftp_request}},
//Extensions not yet present in IANA
        {"CLNT",             {tcp_msg_type_ftp_request}},
//SMTP commands collated from https://mailtrap.io/blog/smtp-commands-and-responses
		{"ATRN",             {tcp_msg_type_smtp_client}},
		{"BDAT",             {tcp_msg_type_smtp_client}},
		{"DATA",             {tcp_msg_type_smtp_client}},
		{"EHLO",             {tcp_msg_type_smtp_client}},
		{"ETRN",             {tcp_msg_type_smtp_client}},
		{"EXPN",             {tcp_msg_type_smtp_client}},
		{"HELO",             {tcp_msg_type_smtp_client}},
		{"MAIL",             {tcp_msg_type_smtp_client}},
		{"RCPT",             {tcp_msg_type_smtp_client}},
		{"STARTTLS",         {tcp_msg_type_smtp_client}},
		{"VRFY",             {tcp_msg_type_smtp_client}},
//HTTP response
		{"HTTP",             {tcp_msg_type_http_response}},
//RFB
		{"RFB",              {tcp_msg_type_rfb}}
    };

public:
    
   static const std::vector<tcp_msg_type>* find_proto(const char* data, size_t length) {
        std::string_view keyword(data, length);
        auto it = protos.find(keyword);
        if (it != protos.end()) {
            return &it->second;
        }
        return nullptr;
    }
 
   static const std::vector<tcp_msg_type>* find_proto(const datum &d) {
        std::string_view keyword(reinterpret_cast<const char*>(d.data), d.length());
        auto it = protos.find(keyword);
        if (it != protos.end()) {
            return &it->second;
        }
        return nullptr;
    }

};
#endif

