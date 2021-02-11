// libmerc.cc
//
// interface to the mercury network metadata capture and analysis
// library

#include <map>
#include <algorithm>

#include "libmerc.h"
#include "version.h"
#include "analysis.h"
#include "extractor.h"  // for proto_ident_config()
#include "pkt_proc.h"

#ifndef  MERCURY_SEMANTIC_VERSION
#warning MERCURY_SEMANTIC_VERSION is not defined
#define  MERCURY_SEMANTIC_VERSION 0,0,0
#endif


void mercury_print_version_string(FILE *f) {
    struct semantic_version mercury_version(MERCURY_SEMANTIC_VERSION);
    mercury_version.print(f);
}

struct libmerc_config global_vars;

int mercury_init(const struct libmerc_config *vars, int verbosity) {

    // sanity check, to help with shared object library development
    fprintf(stderr, "libmerc build time: %s %s\n", __DATE__, __TIME__);

    try {
        global_vars = *vars;
        global_vars.resources = vars->resources;
        global_vars.packet_filter_cfg = vars->packet_filter_cfg;
        enum status status = proto_ident_config(vars->packet_filter_cfg);
        if (status) {
            return status;
        }
        if (global_vars.do_analysis) {
            if (analysis_init(verbosity, global_vars.resources, global_vars.fp_proc_threshold,
                              global_vars.proc_dst_threshold, global_vars.report_os) != 0) {
                return -1; // failure
            }
        }
        return 0; // success
    }
    catch (char const *s) {
        fprintf(stderr, "%s\n", s);
    }
    catch (...) {
        ;
    }
    return -1; // failure
}

int mercury_finalize() {
    if (global_vars.do_analysis) {
        analysis_finalize();
    }
    return 0; // success
}

size_t mercury_packet_processor_write_json(mercury_packet_processor processor, void *buffer, size_t buffer_size, uint8_t *packet, size_t length, struct timespec* ts)
{
    try {
        return processor->write_json(buffer, buffer_size, packet, length, ts, NULL);
    }
    catch (char const *s) {
        fprintf(stderr, "%s\n", s);
    }
    catch (...) {
        ;
    }
    return 0;
}

size_t mercury_packet_processor_ip_write_json(mercury_packet_processor processor, void *buffer, size_t buffer_size, uint8_t *packet, size_t length, struct timespec* ts)
{
    try {
        return processor->ip_write_json(buffer, buffer_size, packet, length, ts, NULL);
    }
    catch (char const *s) {
        fprintf(stderr, "%s\n", s);
    }
    catch (...) {
        ;
    }
    return 0;
}

const struct analysis_context *mercury_packet_processor_ip_get_analysis_context(mercury_packet_processor processor, uint8_t *packet, size_t length, struct timespec* ts)
{
    try {
        uint8_t buffer[4096]; // buffer for (ignored) json output

        if (processor->ip_write_json(buffer, sizeof(buffer), packet, length, ts, NULL) > 0) {
            return &processor->analysis;
        }
    }
    catch (char const *s) {
        fprintf(stderr, "%s\n", s);
    }
    catch (...) {
        ;
    }
    return 0;
}

enum fingerprint_status analysis_context_get_fingerprint_status(const struct analysis_context *ac) {

    if (ac) {
        if (ac->result.valid) {
            return fingerprint_status_labeled;
        } else if (ac->result.randomized) {
            return fingerprint_status_randomized;
        } else {
            return fingerprint_status_unlabled;
        }
    }
    return fingerprint_status_no_info_available;
}

enum fingerprint_type analysis_context_get_fingerprint_type(const struct analysis_context *ac) {

    if (ac) {
        return ac->fp.type;
    }
    return fingerprint_type_unknown;
}

const char *analysis_context_get_fingerprint_string(const struct analysis_context *ac) {
    if (ac) {
        return ac->fp.fp_str;
    }
    return NULL;
}

const char *analysis_context_get_server_name(const struct analysis_context *ac) {
    if (ac) {
        return ac->destination.sn_str;
    }
    return NULL;
}

bool analysis_context_get_process_info(const struct analysis_context *ac, // input
                                       const char **probable_process,     // output
                                       double *probability_score          // output
                                       ) {

    if (ac && ac->result.valid) {
        *probable_process = ac->result.max_proc;
        *probability_score = ac->result.max_score;
        return true;
    }
    return false;
}

bool analysis_context_get_malware_info(const struct analysis_context *ac, // input
                                       bool *probable_process_is_malware, // output
                                       double *probability_malware        // output
                                       ) {

    if (ac && ac->result.valid && ac->result.classify_malware) {
        *probable_process_is_malware = ac->result.max_mal;
        *probability_malware = ac->result.malware_prob;
        return true;
    }
    return false;
}

bool analysis_context_get_os_info(const struct analysis_context *ac, // input
                                  const struct os_information **os_info,   // output
                                  size_t *os_info_len                // output
                                  ) {

    if (ac && ac->result.valid && ac->result.os_info != NULL) {
        *os_info = ac->result.os_info;
        *os_info_len = ac->result.os_info_len;
        return true;
    }
    return false;
}


/*
 * struct packet_filter implements a packet metadata filter
 */

unsigned int tcp_message_filter_cutoff;  /* init tcp msg   */

/*
 * select_tcp_syn selects TCP SYNs for extraction
 */
bool select_tcp_syn = 1;

/*
 * select_tcp_syn selects MDNS (port 5353)
 */
bool select_mdns = true;

/*
 * configuration for protocol identification
 */

extern unsigned char tls_client_hello_mask[8];
extern unsigned char tls_server_cert_embedded_mask[12];
extern unsigned char http_client_mask[8];
extern unsigned char http_client_post_mask[8];
extern unsigned char http_client_connect_mask[8];
extern unsigned char http_client_put_mask[8];
extern unsigned char http_client_head_mask[8];
extern unsigned char http_server_mask[8];
extern unsigned char ssh_mask[8];
extern unsigned char ssh_kex_mask[8];

extern unsigned char dhcp_client_mask[8];  /* udp.c */
extern unsigned char dns_server_mask[8];   /* udp.c */
extern unsigned char dns_client_mask[8];   /* udp.c */
extern unsigned char wireguard_mask[8];    /* udp.c */
extern unsigned char quic_mask[8];         /* udp.c */
extern unsigned char dtls_client_hello_mask[8]; /* udp.c */
extern unsigned char dtls_server_hello_mask[8]; /* udp.c */

enum status proto_ident_config(const char *config_string) {
    if (config_string == NULL) {
        return status_ok;    /* use the default configuration */
    }

    std::map<std::string, bool> protocols{
        { "all",         false },
        { "none",        false },
        { "dhcp",        false },
        { "dns",         false },
        { "dtls",        false },
        { "http",        false },
        { "ssh",         false },
        { "tcp",         false },
        { "tcp.message", false },
        { "tls",         false },
        { "wireguard",   false },
        { "quic",        false },
    };

    std::string s{config_string};
    std::string delim{","};
    size_t pos = 0;
    std::string token;
    while ((pos = s.find(delim)) != std::string::npos) {
        token = s.substr(0, pos);
        token.erase(std::remove_if(token.begin(), token.end(), isspace), token.end());
        s.erase(0, pos + delim.length());

        auto pair = protocols.find(token);
        if (pair != protocols.end()) {
            pair->second = true;
        } else {
            fprintf(stderr, "error: unrecognized filter command \"%s\"\n", token.c_str());
            return status_err;
        }
    }
    token = s.substr(0, pos);
    s.erase(std::remove_if(s.begin(), s.end(), isspace), s.end());
    auto pair = protocols.find(token);
    if (pair != protocols.end()) {
        pair->second = true;
    } else {
        fprintf(stderr, "error: unrecognized filter command \"%s\"\n", token.c_str());
        return status_err;
    }

    if (protocols["all"] == true) {
        return status_ok;
    }
    if (protocols["none"] == true) {
        for (auto &pair : protocols) {
            pair.second = false;
        }
    }
    if (protocols["dhcp"] == false) {
        bzero(dhcp_client_mask, sizeof(dhcp_client_mask));
    }
    if (protocols["dns"] == false) {
        bzero(dns_server_mask, sizeof(dns_server_mask));
        bzero(dns_client_mask, sizeof(dns_client_mask));
        select_mdns = false;
    }
    if (protocols["http"] == false) {
        bzero(http_client_mask, sizeof(http_client_mask));
        bzero(http_client_post_mask, sizeof(http_client_post_mask));
        bzero(http_client_connect_mask, sizeof(http_client_connect_mask));
        bzero(http_client_put_mask, sizeof(http_client_put_mask));
        bzero(http_client_head_mask, sizeof(http_client_head_mask));
        bzero(http_server_mask, sizeof(http_server_mask));
    }
    if (protocols["ssh"] == false) {
        bzero(ssh_kex_mask, sizeof(ssh_kex_mask));
        bzero(ssh_mask, sizeof(ssh_mask));
    }
    if (protocols["tcp"] == false) {
        select_tcp_syn = 0;
    }
    if (protocols["tcp.message"] == true) {
        select_tcp_syn = 0;
        tcp_message_filter_cutoff = 1;
    }
    if (protocols["tls"] == false) {
        bzero(tls_client_hello_mask, sizeof(tls_client_hello_mask));
        bzero(tls_server_cert_embedded_mask, sizeof(tls_server_cert_embedded_mask));
    }
    if (protocols["dtls"] == false) {
        bzero(dtls_client_hello_mask, sizeof(dtls_client_hello_mask));
        bzero(dtls_server_hello_mask, sizeof(dtls_server_hello_mask));
    }
    if (protocols["wireguard"] == false) {
        bzero(wireguard_mask, sizeof(wireguard_mask));
    }
    if (protocols["quic"] == false) {
        bzero(quic_mask, sizeof(quic_mask));
    }
    return status_ok;
}

mercury_packet_processor mercury_packet_processor_construct() {
    try {
        stateful_pkt_proc *tmp = new stateful_pkt_proc;
        return tmp;
    }
    catch (...) {
        ; // error, return NULL
    }
    return NULL;
}

void mercury_packet_processor_destruct(mercury_packet_processor mpp) {
    try {
        if (mpp) {
            mpp->finalize();
            delete mpp;
        }
    }
    catch (...) {
    }
}


const char license_string[] =
    "Copyright (c) 2019-2020 Cisco Systems, Inc.\n"
    "All rights reserved.\n"
    "\n"
    "  Redistribution and use in source and binary forms, with or without\n"
    "  modification, are permitted provided that the following conditions\n"
    "  are met:\n"
    "\n"
    "    Redistributions of source code must retain the above copyright\n"
    "    notice, this list of conditions and the following disclaimer.\n"
    "\n"
    "    Redistributions in binary form must reproduce the above\n"
    "    copyright notice, this list of conditions and the following\n"
    "    disclaimer in the documentation and/or other materials provided\n"
    "    with the distribution.\n"
    "\n"
    "    Neither the name of the Cisco Systems, Inc. nor the names of its\n"
    "    contributors may be used to endorse or promote products derived\n"
    "    from this software without specific prior written permission.\n"
    "\n"
    "  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n"
    "  \"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT\n"
    "  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS\n"
    "  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE\n"
    "  COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,\n"
    "  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES\n"
    "  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR\n"
    "  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)\n"
    "  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,\n"
    "  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)\n"
    "  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED\n"
    "  OF THE POSSIBILITY OF SUCH DAMAGE.\n"
    "\n"
    "For current and comprehensive license information, please see:\n"
    "\n"
    " * https://github.com/cisco/mercury/LICENSE for the main license\n"
    " * https://github.com/cisco/mercury/src/lctrie for the lctrie license;\n"
    "   this package is copyright 2016-2017 Charles Stewart\n"
    "   <chuckination_at_gmail_dot_com>\n"
    " * https://github.com/cisco/mercury/src/rapidjson for the rapidjson license;\n"
    "   this package is copyright 2015 THL A29 Limited, a Tencent company, and\n"
    "   Milo Yip.";

const char *mercury_get_license_string() {
    return license_string;
}


