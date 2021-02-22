/*
 * @file libmerc.h
 *
 * @brief interface to mercury packet metadata capture and analysis library
 */

#ifndef LIBMERC_H
#define LIBMERC_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

/*
 * struct libmerc_config represents the complete configuration of
 * the libmerc library
 */
struct libmerc_config {

#ifdef __cplusplus
    // constructor, for c++ only
    libmerc_config() :
        dns_json_output{false},
        certs_json_output{false},
        metadata_output{false},
        do_analysis{false},
        report_os{false},
        output_tcp_initial_data{false},
        output_udp_initial_data{false},
        resources{NULL},
        packet_filter_cfg{NULL},
        fp_proc_threshold{0.0},
        proc_dst_threshold{0.0}
    {}
#endif

    bool dns_json_output;         /* output DNS as JSON           */
    bool certs_json_output;       /* output certificates as JSON  */
    bool metadata_output;         /* output lots of metadata      */
    bool do_analysis;             /* write analysys{} JSON object */
    bool report_os;               /* report oses in analysis JSON */
    bool output_tcp_initial_data; /* write initial data field     */
    bool output_udp_initial_data; /* write initial data field     */

    char *resources;         /* directory containing (analysis) resource files */
    char *packet_filter_cfg; /* packet filter configuration string             */

    float fp_proc_threshold;   /* remove processes with less than <var> weight    */
    float proc_dst_threshold;  /* remove destinations with less than <var> weight */
};


#ifndef __cplusplus
#define libmerc_config_init() {false,false,false,false,false,false,false,NULL,NULL,0.0,0.0}
#endif

/**
 * @brief initializes libmerc
 *
 * Initializes libmerc to use the configuration as specified with the
 * input parameters.  Returns zero on success.
 *
 * @param vars          libmerc_config
 * @param verbosity     higher values increase verbosity sent to stderr
 * @param resource_dir  directory of resource files to use in analysis
 *
 */
#ifdef __cplusplus
extern "C"
#endif
int mercury_init(const struct libmerc_config *vars, int verbosity);

/**
 * @brief finalizes libmerc
 *
 * Finalizes the libmerc library, and frees up resources allocated by
 * mercury_init().   Returns zero on success.
 *
 */
#ifdef __cplusplus
extern "C"
#endif
int mercury_finalize();

/*
 * mercury_packet_processor is an opaque pointer to a threadsafe
 * packet processor
 */
//#ifdef __cplusplus
typedef struct stateful_pkt_proc *mercury_packet_processor;
//#endif

/*
 * mercury_packet_processor_construct() allocates and initializes a
 * new mercury_packet_processor.  Returns a valid pointer on success,
 * and NULL otherwise.
 */
#ifdef __cplusplus
extern "C"
#endif
mercury_packet_processor mercury_packet_processor_construct();

/*
 * mercury_packet_processor_destruct() deallocates all resources
 * associated with a mercury_packet_processor.
 */
#ifdef __cplusplus
extern "C"
#endif
void mercury_packet_processor_destruct(mercury_packet_processor mpp);

/*
 * mercury_packet_processor_write_json() processes a packet and timestamp and
 * writes the resulting JSON into a buffer.
 *
 * processor (input) - packet processor context to be used
 * buffer (output) - location to which JSON will be written
 * buffer_size (input) - length of buffer in bytes
 * packet (input) - location of packet, starting with ethernet header
 * ts (input) - pointer to timestamp associated with packet
 */
#ifdef __cplusplus
extern "C"
#endif
size_t mercury_packet_processor_write_json(mercury_packet_processor processor,
                                           void *buffer,
                                           size_t buffer_size,
                                           uint8_t *packet,
                                           size_t length,
                                           struct timespec* ts);

/*
 * same as above, but packet points to an IP header (v4 or v6)
 */
#ifdef __cplusplus
extern "C"
#endif
size_t mercury_packet_processor_ip_write_json(mercury_packet_processor processor,
                                              void *buffer,
                                              size_t buffer_size,
                                              uint8_t *packet,
                                              size_t length,
                                              struct timespec* ts);

enum fingerprint_status {
    fingerprint_status_no_info_available = 0,  // fingerprint status is unknown
    fingerprint_status_labeled           = 1,  // fingerprint is in FPDB
    fingerprint_status_randomized        = 2,  // fingerprint is in randomized FP set
    fingerprint_status_unlabled          = 3   // fingerprint is not in FPDB or randomized set
};

#ifdef __cplusplus
extern "C"
#endif
const struct analysis_context *mercury_packet_processor_ip_get_analysis_context(mercury_packet_processor processor,
                                                                                uint8_t *packet,
                                                                                size_t length,
                                                                                struct timespec* ts);

#ifdef __cplusplus
extern "C"
#endif
enum fingerprint_status analysis_context_get_fingerprint_status(const struct analysis_context *ac);

// enum fingerprint_type identifies the type of fingerprint
// for the struct fingerprint; we use an regular enum in
// order to be C-compatible
//
enum fingerprint_type {
     fingerprint_type_unknown = 0,
     fingerprint_type_tls = 1
};

#ifdef __cplusplus
extern "C"
#endif
enum fingerprint_type analysis_context_get_fingerprint_type(const struct analysis_context *ac);

#ifdef __cplusplus
extern "C"
#endif
const char *analysis_context_get_fingerprint_string(const struct analysis_context *ac);

#ifdef __cplusplus
extern "C"
#endif
const char *analysis_context_get_server_name(const struct analysis_context *ac);


#ifdef __cplusplus
extern "C"
#endif
bool analysis_context_get_process_info(const struct analysis_context *ac, // input
                                       const char **probable_process,     // output
                                       double *probability_score          // output
                                       );

#ifdef __cplusplus
extern "C"
#endif
bool analysis_context_get_malware_info(const struct analysis_context *ac, // input
                                       bool *probable_process_is_malware, // output
                                       double *probability_malware        // output
                                       );


struct os_information {
    char *os_name;
    uint64_t os_prevalence;
};

#ifdef __cplusplus
extern "C"
#endif
bool analysis_context_get_os_info(const struct analysis_context *ac, // input
                                  const struct os_information **os_info,   // output
                                  size_t *os_info_len                // output
                                  );


enum status {
    status_ok = 0,
    status_err = 1,
    status_err_no_more_data = 2
};
// enum status : bool { ok = 0, err = 1 };

/**
 * @brief returns the mercury license string
 *
 * Returns a printable string containing the license for mercury and
 * libmerc.
 *
 */
#ifdef __cplusplus
extern "C"
#endif
const char *mercury_get_license_string();

/**
 * @brief prints the mercury semantic version
 *
 * Prints the semantic version of mercury/libmerc to the FILE provided
 * as input.
 *
 * @param [in] file to print semantic version on.
 *
 */
#ifdef __cplusplus
extern "C"
#endif
void mercury_print_version_string(FILE *f);

// OTHER FUNCTIONS
//
enum status proto_ident_config(const char *config_string);

enum status static_data_config(const char *config_string);

#endif /* LIBMERC_H */
