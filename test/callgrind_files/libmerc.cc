// libmerc.cc
//
// interface to the mercury network metadata capture and analysis
// library

#include <map>
#include <algorithm>
#include <stdexcept>

#include "libmerc.h"
#include "version.h"
#include "analysis.h"
#include "extractor.h"  // for proto_ident_config()
#include "pkt_proc.h"

#ifndef  MERCURY_SEMANTIC_VERSION
#warning MERCURY_SEMANTIC_VERSION is not defined
#define  MERCURY_SEMANTIC_VERSION 0,0,0
#endif

#ifndef  GIT_COMMIT_ID
#warning GIT_COMMIT_ID is not defined
#define  GIT_COMMIT_ID "commit unknown"
#endif

#ifndef  GIT_COUNT
#warning GIT_COUNT is not defined
#define  GIT_COUNT 0
#endif

const char *git_commit_id = GIT_COMMIT_ID;

const uint32_t git_count = GIT_COUNT;

void mercury_print_version_string(FILE *f) {
    struct semantic_version mercury_version(MERCURY_SEMANTIC_VERSION);
    mercury_version.print(f);
}

uint32_t mercury_get_version_number() {
    struct semantic_version mercury_version(MERCURY_SEMANTIC_VERSION);
    return mercury_version.get_version_as_uint32();
}

const char *mercury_get_resource_version(struct mercury *mc) {
    if (mc && mc->c) {
        return mc->c->get_resource_version();
    }
    return nullptr;
}

mercury_context mercury_init(const struct libmerc_config *vars, int verbosity) {

    mercury *m = nullptr;

    if (verbosity > 0) {
        // bulid information, to help with shared object library development and use
        //
        printf_err(log_none, "libmerc build time: %s %s\n", __DATE__, __TIME__);
        struct semantic_version v(MERCURY_SEMANTIC_VERSION);
        printf_err(log_info, "libmerc version: %u.%u.%u\n", v.major, v.minor, v.patchlevel);
        printf_err(log_info, "libmerc build count: %u\n", git_count);
        printf_err(log_info, "libmerc git commit id: %s\n", git_commit_id);
    }

    try {
        m = new mercury{vars, verbosity};
        return m;  // success
    }
    catch (std::exception &e) {
        printf_err(log_err, "%s\n", e.what());
    }
    if (m) {
        delete m;
    }
    return nullptr; // failure
}

int mercury_finalize(mercury_context mc) {
    if (mc) {
        delete mc;
        return 0; // success
    }
    return -1;    // error
}
#include <valgrind/callgrind.h>
size_t mercury_packet_processor_write_json(mercury_packet_processor processor, void *buffer, size_t buffer_size, uint8_t *packet, size_t length, struct timespec* ts)
{
    try {
        CALLGRIND_TOGGLE_COLLECT;
        auto z = processor->write_json(buffer, buffer_size, packet, length, ts, NULL);
        CALLGRIND_TOGGLE_COLLECT;
        return z;
    }
    catch (std::exception &e) {
        printf_err(log_err, "%s\n", e.what());
    }
    return 0;
}

size_t mercury_packet_processor_ip_write_json(mercury_packet_processor processor, void *buffer, size_t buffer_size, uint8_t *packet, size_t length, struct timespec* ts)
{
    try {
        return processor->ip_write_json(buffer, buffer_size, packet, length, ts, NULL);
    }
    catch (std::exception &e) {
        printf_err(log_err, "%s\n", e.what());
    }
    return 0;
}

const struct analysis_context *mercury_packet_processor_ip_get_analysis_context(mercury_packet_processor processor, uint8_t *packet, size_t length, struct timespec* ts)
{
    try {
        // TODO: eliminate ignored JSON output
        //
        uint8_t buffer[4096]; // buffer for (ignored) json output

        processor->analysis.result.status = fingerprint_status_no_info_available;
        if (processor->ip_write_json(buffer, sizeof(buffer), packet, length, ts, NULL) > 0) {
            return &processor->analysis;
        }
    }
    catch (std::exception &e) {
        printf_err(log_err, "%s\n", e.what());
    }
    return NULL;
}

const struct analysis_context *mercury_packet_processor_get_analysis_context(mercury_packet_processor processor, uint8_t *packet, size_t length, struct timespec* ts)
{
    try {
        uint8_t buffer[4096]; // buffer for (ignored) json output

        processor->analysis.result.status = fingerprint_status_no_info_available;
        if (processor->write_json(buffer, sizeof(buffer), packet, length, ts, NULL) > 0) {  // TODO: replace with get_context!
            if (processor->analysis.result.is_valid()) {
                return &processor->analysis;
            }
        }
    }
    catch (std::exception &e) {
        printf_err(log_err, "%s\n", e.what());
    }
    return NULL;
}

enum fingerprint_status analysis_context_get_fingerprint_status(const struct analysis_context *ac) {

    if (ac) {
        return ac->result.status;
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
        if (ac->destination.sn_str[0] != '\0') {
            return ac->destination.sn_str;
        }
    }
    return NULL;
}

bool analysis_context_get_alpns(const struct analysis_context *ac, // input
                                const char **alpns,                // output
                                uint8_t *alpn_count,               // output
                                uint8_t *max_len                   // output
                                ) {
    if (ac) {
         return ac->get_alpns(alpns, alpn_count, max_len);
    }
    return false;
}

const char *analysis_context_get_user_agent(const struct analysis_context *ac) {
    if (ac) {
        if (ac->destination.ua_str[0] != '\0') {
            return ac->destination.ua_str;
        }
    }
}

bool analysis_context_get_process_info(const struct analysis_context *ac, // input
                                       const char **probable_process,     // output
                                       double *probability_score          // output
                                       ) {

    if (ac && ac->result.is_valid() && ac->result.status != fingerprint_status_unlabled) {
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

    if (ac && ac->result.is_valid() && ac->result.classify_malware) {
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

    if (ac && ac->result.is_valid() && ac->result.os_info != NULL) {
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
extern unsigned char http_client_mask[8];
extern unsigned char http_client_post_mask[8];
extern unsigned char http_client_connect_mask[8];
extern unsigned char http_client_put_mask[8];
extern unsigned char http_client_head_mask[8];
extern unsigned char http_server_mask[8];
extern unsigned char ssh_mask[8];
extern unsigned char ssh_kex_mask[8];
extern unsigned char smtp_client_mask[8];
extern unsigned char smtp_server_mask[8];

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
        { "smtp",        false },
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
            printf_err(log_err, "unrecognized filter command \"%s\"\n", token.c_str());
            return status_err;
        }
    }
    token = s.substr(0, pos);
    s.erase(std::remove_if(s.begin(), s.end(), isspace), s.end());
    auto pair = protocols.find(token);
    if (pair != protocols.end()) {
        pair->second = true;
    } else {
        printf_err(log_err, "unrecognized filter command \"%s\"\n", token.c_str());
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
    if (protocols["smtp"] == false) {
        bzero(smtp_client_mask, sizeof(smtp_client_mask));
        bzero(smtp_server_mask, sizeof(smtp_server_mask));
    }
    return status_ok;
}

mercury_packet_processor mercury_packet_processor_construct(mercury_context mc) {
    try {
        stateful_pkt_proc *tmp = new stateful_pkt_proc{mc, 0};
        return tmp;
    }
    catch (std::exception &e) {
        printf_err(log_err, "%s\n", e.what());
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
    catch (std::exception &e) {
        printf_err(log_err, "%s\n", e.what());
    }
}

bool mercury_write_stats_data(mercury_context mc, const char *stats_data_file_path) {

    if (mc == NULL || stats_data_file_path == NULL) {
        return false;
    }

    gzFile stats_data_file = gzopen(stats_data_file_path, "w");
    if (stats_data_file == nullptr) {
        printf_err(log_err, "could not open file '%s' for writing mercury stats data\n", stats_data_file_path);
        return false;
    }
    mc->aggregator->gzprint(stats_data_file);
    gzclose(stats_data_file);

    return true;
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

//
// start of libmerc version 2 API
//

// flexible error reporting, using a printf-style interface and
// syslog-style severity levels

// printf_err_func() takes a severity level, a printf-style format
// string, and the arguments assocaited with the format string, and
// prints out a message on stderr.  On success, the number of
// characters written is returned; if a failure occurs, a negative
// number is returned.
//
// This function is suitable for use with
// register_printf_err_callback().
//
int printf_err_func(log_level level, const char *format, ...) {

    // output error level message
    //
    const char *msg = "";
    switch(level) {
    case log_emerg:   msg = "emergency: ";     break;
    case log_alert:   msg = "alert: ";         break;
    case log_crit:    msg = "critical: ";      break;
    case log_err:     msg = "error: ";         break;
    case log_warning: msg = "warning: ";       break;
    case log_notice:  msg = "notice: ";        break;
    case log_info:    msg = "informational: "; break;
    case log_debug:   msg = "debug: ";         break;
    case log_none:  break;  // leave msg empty
    }
    int retval = fprintf(stderr, "%s", msg);
    if (retval < 0) {
        return retval;
    }
    int sum = retval;

    // output formatted argument list
    //
    va_list args;
    va_start(args, format);
    retval = vfprintf(stderr, format, args);
    va_end(args);
    if (retval < 0) {
        return retval;
    }
    sum += retval;

    return sum;
}

int silent_err_func(log_level, const char *, ...) {
    return 0;
}

printf_err_ptr printf_err = printf_err_func;

void register_printf_err_callback(printf_err_ptr callback) {

    if (callback == nullptr) {
        printf_err = silent_err_func;
    } else {
        printf_err = callback;
    }
}
