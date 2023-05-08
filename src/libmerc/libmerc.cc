// libmerc.cc
//
// interface to the mercury network metadata capture and analysis
// library

#include <map>
#include <algorithm>
#include <stdexcept>
#include <ctime>

#include "libmerc.h"
#include "version.h"
#include "analysis.h"
#include "pkt_proc.h"
#include "config_generator.h"
#include "global_config.h"

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

// the variables git_commit_id and git_count represent the source code
// used to build the library, and init_time holds its most recent
// initialization time; they are declared static to maintain the ODR,
// and are passed to some output routines below
//
static const char *git_commit_id = GIT_COMMIT_ID;

static const uint32_t git_count = GIT_COUNT;

static char init_time[128] = { '\0' };


void mercury_print_version_string(FILE *f) {
    struct semantic_version mercury_version(MERCURY_SEMANTIC_VERSION);
    mercury_version.print(f);
}

void mercury_get_version_string(char *buf, size_t size) {
    struct semantic_version mercury_version(MERCURY_SEMANTIC_VERSION);
    mercury_version.print_version_string(buf, size);
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
    std::time_t timenow = time(NULL);
    strftime(init_time, sizeof(init_time) - 1, "%Y-%m-%dT%H:%M:%SZ", gmtime(&timenow));

    if (verbosity > 0) {
        // bulid information, to help with shared object library development and use
        //
        printf_err(log_none, "libmerc init time: %s\n", init_time);
        struct semantic_version v(MERCURY_SEMANTIC_VERSION);
        printf_err(log_info, "libmerc version: %u.%u.%u\n", v.major, v.minor, v.patchlevel);
        printf_err(log_info, "libmerc build count: %u\n", git_count);
        printf_err(log_info, "libmerc git commit id: %s\n", git_commit_id);
    }

    // if NDEBUG is not defined, the assert() macro will be used;
    // report that fact through printf_err() to confirm that tests are
    // taking place
    //
    assert(printf_err(log_info, "libmerc is running assert() tests\n") != 0);

    try {
        m = new mercury{vars, verbosity};
        return m;
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

size_t mercury_packet_processor_write_json(mercury_packet_processor processor, void *buffer, size_t buffer_size, uint8_t *packet, size_t length, struct timespec* ts)
{
    try {
        return processor->write_json(buffer, buffer_size, packet, length, ts, processor->reassembler_ptr);
    }
    catch (std::exception &e) {
        printf_err(log_err, "%s\n", e.what());
    }
    return 0;
}

size_t mercury_packet_processor_write_json_linktype(mercury_packet_processor processor, void *buffer, size_t buffer_size, uint8_t *packet, size_t length, struct timespec* ts, uint16_t linktype)
{
    try {
        return processor->write_json(buffer, buffer_size, packet, length, ts, processor->reassembler_ptr, linktype);
    }
    catch (std::exception &e) {
        printf_err(log_err, "%s\n", e.what());
    }
    return 0;
}

const struct analysis_context *mercury_packet_processor_ip_get_analysis_context(mercury_packet_processor processor, uint8_t *packet, size_t length, struct timespec* ts)
{
    try {
        if (processor->analyze_ip_packet(packet, length, ts, processor->reassembler_ptr)) {
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

const struct analysis_context *mercury_packet_processor_get_analysis_context(mercury_packet_processor processor, uint8_t *packet, size_t length, struct timespec* ts)
{
    try {
        if (processor->analyze_eth_packet(packet, length, ts, processor->reassembler_ptr)) {
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

const struct analysis_context *mercury_packet_processor_get_analysis_context_linktype(mercury_packet_processor processor, uint8_t *packet, size_t length, struct timespec* ts, uint16_t linktype)
{
    try
    {
        if (processor->analyze_packet(packet, length, ts, processor->reassembler_ptr, linktype)) {
            if (processor->analysis.result.is_valid()) {
                return &processor->analysis;
            }
        }
    }
    catch (std::exception &e)
    {
        printf_err(log_err, "%s\n", e.what());
    }
    return NULL;
}

bool mercury_packet_processor_more_pkts_needed(mercury_packet_processor processor) {
try {
        return processor->analysis.flow_state_pkts_needed;
    }
    catch (std::exception &e) {
        printf_err(log_err, "%s\n", e.what());
    }
    return false;
}

enum fingerprint_status analysis_context_get_fingerprint_status(const struct analysis_context *ac) {
    if (ac) {
        return ac->result.status;
    }
    return fingerprint_status_no_info_available;
}

enum fingerprint_type analysis_context_get_fingerprint_type(const struct analysis_context *ac) {
    if (ac) {
        return ac->fp.get_type();
    }
    return fingerprint_type_unknown;
}

const char *analysis_context_get_fingerprint_string(const struct analysis_context *ac) {
    if (ac) {
        return ac->fp.string();
    }
    return NULL;
}

const char *analysis_context_get_server_name(const struct analysis_context *ac) {
    if (ac) {
        return ac->get_server_name();
    }
    return NULL;
}

const char *analysis_context_get_user_agent(const struct analysis_context *ac) {
    if (ac) {
        return ac->get_user_agent();
    }
    return NULL;
}

bool analysis_context_get_alpns(const struct analysis_context *ac, // input
                                const uint8_t **alpn,              // output
                                size_t *alpn_length                // output
                                ) {
    if (ac) {
        return ac->get_alpns(alpn, alpn_length);
    }

    return false;
}

bool analysis_context_get_process_info(const struct analysis_context *ac, // input
                                       const char **probable_process,     // output
                                       double *probability_score          // output
                                       ) {
    if (ac) {
        return ac->result.get_process_info(probable_process, probability_score);
    }
    return false;
}

bool analysis_context_get_malware_info(const struct analysis_context *ac, // input
                                       bool *probable_process_is_malware, // output
                                       double *probability_malware        // output
                                       ) {

    if (ac) {
        return ac->result.get_malware_info(probable_process_is_malware, probability_malware);
    }
    return false;
}

bool analysis_context_get_os_info(const struct analysis_context *ac, // input
                                  const struct os_information **os_info,   // output
                                  size_t *os_info_len                // output
                                  ) {

    if (ac) {
        return ac->result.get_os_info(os_info, os_info_len);
    }
    return false;
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
    mc->aggregator->gzprint(stats_data_file,
                           git_commit_id,
                           git_count,
                           init_time);
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
int printf_err_func(enum log_level level, const char *format, va_list args) {

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
    retval = vfprintf(stderr, format, args);
    if (retval < 0) {
        return retval;
    }
    sum += retval;

    return sum;
}

int silent_err_func(log_level, const char *, va_list) {
    return 0;
}

static printf_err_ptr printf_err_static = printf_err_func;

#ifdef DONT_USE_STDERR

int printf_err(enum log_level level, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int retval = printf_err_static(level, format, args);
    va_end(args);
    return retval;
}

#endif

void register_printf_err_callback(printf_err_ptr callback) {

    if (callback == nullptr) {
        printf_err_static = silent_err_func;
    } else {
        printf_err_static = callback;
    }
}

size_t get_stats_aggregator_num_entries(mercury_context mc)
{
    if (mc == NULL) {
       return 0;
    }

    return mc->aggregator->get_num_entries();
}
