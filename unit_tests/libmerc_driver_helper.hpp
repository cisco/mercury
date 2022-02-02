/*
 * libmerc_helper_functions.h
 *
 * functions for using in unit tests
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include "libmerc_api.hpp"

#ifndef LIBMERC_SO_PATH
#define LIBMERC_SO_PATH "./../src/libmerc/libmerc.so"
#endif

/*variables*/
extern unsigned char client_hello_eth[];
extern size_t client_hello_eth_len;
extern unsigned char tcp_syn[];
extern size_t tcp_syn_len;
extern unsigned char unlabeled_data[];
extern unsigned char client_hello_no_server_name_eth[];
extern unsigned char firefox_client_hello_eth[];
extern int verbosity;
extern char * default_resources_path;
extern char * resources_lite_path;
extern char * resources_mp_path;
extern const char * path_to_libmerc_library;
extern const char * path_to_libmerc_alt_library;
/*variables end*/

/*functions*/
void fprint_analysis_context(FILE *f,
                             const struct libmerc_api *merc,
                             const struct analysis_context *ctx);

mercury_context initialize_mercury(libmerc_config& config);

libmerc_config create_config(bool dns_json_output = false,
                             bool certs_json_output = false,
                             bool metadata_output = false,
                             bool do_analysis = true,
                             bool do_stats = true,
                             bool report_os = false,
                             bool output_tcp_initial_data = false,
                             bool output_udp_initial_data = false,
                             char *resources = default_resources_path,
                             const uint8_t * enc_key = NULL,
                             enc_key_type key_type = enc_key_type_none,
                             char *packet_filter_cfg = NULL,
                             float fp_proc_threshold = 0.0,
                             float proc_dst_threshold = 0.0,
                             size_t max_stats_entries = 0);

void check_global_configuraton(mercury_context &mc, libmerc_config &config);

void *packet_processor(void *arg);

/*function end*/
