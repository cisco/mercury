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
#include <stdarg.h>
#include <time.h>

// defaults (if not set via ./configure)
//
#ifndef DEFAULT_RESOURCE_DIR
#define DEFAULT_RESOURCE_DIR "/usr/local/share/mercury"
#endif


// The LIBMERC_DLL_EXPORTED attribute can be applied to a function or
// variable to indicate that it should be exported from a shared
// object library even if the -fvisibility=hidden option is passed to
// the compiler; for background, see
// https://www.gnu.org/software/gnulib/manual/html_node/Exported-Symbols-of-Shared-Libraries.html
//
#define LIBMERC_DLL_EXPORTED __attribute__((__visibility__("default")))

//
// start of libmerc version 2 API
//

// flexible error reporting, using a printf-style interface and
// syslog-style severity levels
//
// enum log_level indicates the importance of a message passed to
// the error-printing callback function.  The levels are modeled after
// those of the SYSLOG facility.
//
enum log_level {
    log_emerg   = 0,  // system is unusable
    log_alert   = 1,  // action must be taken immediately
    log_crit    = 2,  // critical conditions
    log_err     = 3,  // error conditions
    log_warning = 4,  // warning conditions
    log_notice  = 5,  // normal but significant condition
    log_info    = 6,  // informational
    log_debug   = 7,  // debug-level messages
    log_none    = 8   // not a log message
};

// printf_err_ptr is a typedef of a function pointer for a
// printf-style function that handles error output.  It can be used to
// register an error-handling function that performs specialized
// output of a formatted error message.
//
#ifdef __cplusplus
extern "C"
#endif
typedef int (*printf_err_ptr)(enum log_level level, const char *format, va_list args);

#ifdef DONT_USE_STDERR
int printf_err(enum log_level level, const char *format, ...);
#else
#define printf_err(level, ...) fprintf(stderr, __VA_ARGS__)
#endif

// register_printf_err_callback() registers a callback function for
// printing error messages with a printf-style function.  The function
// int printf_err_func() in err.cc provides an example of how to
// construct such a function using a standard C va_list.
//
// If the callback argument passed to this function is null, then no
// error messages will be output.  (That is, the callback is set to a
// function that ignores its arguments and generates no output.)
//
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
void register_printf_err_callback(printf_err_ptr callback);

// printf_err() should be called to invoke the callback function
//
//extern printf_err_ptr printf_err;  // defined in libmerc.cc

//
// start of libmerc version 1 API
//

enum enc_key_type {
    enc_key_type_none = 0,
    enc_key_type_aes_128,
    enc_key_type_aes_256
};

/**
 * @brief struct libmerc_config represents the complete configuration
 * of the libmerc library.
 *
 * To initialize libmerc, create a libmerc_config structure and pass
 * it to the mercury_init() function.  To create a libmerc_config
 * structure, you can use the #define libmerc_config_init(), which
 * represents a minimal, default configuration.
 */
struct libmerc_config {

#ifdef __cplusplus
    // default values, for c++ only
    bool dns_json_output = false;         /* output DNS as JSON           */
    bool certs_json_output = false;       /* output certificates as JSON  */
    bool metadata_output = false;         /* output lots of metadata      */
    bool do_analysis = false;             /* write analysys{} JSON object */
    bool do_stats = false;                /* gather src/fp/dst statistics */
    bool report_os = false;               /* report oses in analysis JSON */
    bool output_tcp_initial_data = false; /* write initial data field     */
    bool output_udp_initial_data = false; /* write initial data field     */
    //bool tcp_reassembly = false;          /* reassemble tcp segments      */

    char *resources = NULL;             /* archive containing resource files       */
    const uint8_t *enc_key = NULL;      /* (optional) decryption key for archive   */
    enum enc_key_type key_type = enc_key_type_none;  /* key type (none=0 if key not present)    */

    char *packet_filter_cfg = nullptr; /* packet filter configuration string             */

    float fp_proc_threshold = 0.0;   /* remove processes with less than <var> weight    */
    float proc_dst_threshold = 0.0;  /* remove destinations with less than <var> weight */
    size_t max_stats_entries = 0;  /* max num entries in stats tables                 */

#else

    bool dns_json_output;         /* output DNS as JSON           */
    bool certs_json_output;       /* output certificates as JSON  */
    bool metadata_output;         /* output lots of metadata      */
    bool do_analysis;             /* write analysys{} JSON object */
    bool do_stats;                /* gather src/fp/dst statistics */
    bool report_os;               /* report oses in analysis JSON */
    bool output_tcp_initial_data; /* write initial data field     */
    bool output_udp_initial_data; /* write initial data field     */

    char *resources;             /* archive containing resource files       */
    const uint8_t *enc_key;      /* (optional) decryption key for archive   */
    enum enc_key_type key_type;  /* key type (none=0 if key not present)    */

    char *packet_filter_cfg; /* packet filter configuration string             */

    float fp_proc_threshold;   /* remove processes with less than <var> weight    */
    float proc_dst_threshold;  /* remove destinations with less than <var> weight */
    size_t max_stats_entries;  /* max num entries in stats tables                 */
#endif
};

/**
 * libmerc_config_init() initializes a libmerc_config structure to a
 * minimal, default configuration.
 */
#ifndef __cplusplus
#define libmerc_config_init() {false,false,false,false,false,false,false,false,NULL,NULL,enc_key_type_none,NULL,0.0,0.0,0}
#endif


/**
 * mercury_context is an opaque pointer to an object that holds the
 * mercury state associated with a running instance
 */
typedef struct mercury *mercury_context;

/**
 * @brief initializes libmerc
 *
 * Initializes libmerc to use the configuration as specified with the
 * input parameters.  Returns a valid mercury_context handle on
 * success, and NULL otherwise.
 *
 * @param vars          libmerc_config
 * @param verbosity     higher values increase verbosity
 * @param resource_dir  directory of resource files to use in analysis
 *
 * @return a valid mercury_context handle on success, NULL on failure
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
mercury_context mercury_init(const struct libmerc_config *vars, int verbosity);

/**
 * @brief finalizes libmerc
 *
 * Finalizes the libmerc context associated with the handle, and frees
 * up resources allocated by mercury_init().  Returns zero on success.
 *
 * @return 0 on success, -1 on failure
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
int mercury_finalize(mercury_context mc);

/**
 * mercury_packet_processor is an opaque pointer to a threadsafe
 * packet processor.
 */
//#ifdef __cplusplus
typedef struct stateful_pkt_proc *mercury_packet_processor;
//#endif

/**
 * mercury_packet_processor_construct() allocates and initializes a
 * new mercury_packet_processor associated with the mercury_context
 * passed as input.
 *
 * @return a valid pointer on success, NULL otherwise.
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
mercury_packet_processor mercury_packet_processor_construct(mercury_context mc);

/**
 * mercury_packet_processor_destruct() deallocates all resources
 * associated with a mercury_packet_processor.
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
void mercury_packet_processor_destruct(mercury_packet_processor mpp);

/**
 * mercury_packet_processor_write_json() processes a packet and timestamp and
 * writes the resulting JSON into a buffer.
 *
 * @param processor (input) is a packet processor context to be used
 * @param buffer (output) - location to which JSON will be written
 * @param buffer_size (input) - length of buffer in bytes
 * @param packet (input) - location of packet, starting with ethernet header
 * @param ts (input) - pointer to timestamp associated with packet
 *
 * @return the number of bytes of JSON output written.
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
size_t mercury_packet_processor_write_json(mercury_packet_processor processor,
                                           void *buffer,
                                           size_t buffer_size,
                                           uint8_t *packet,
                                           size_t length,
                                           struct timespec* ts);

/**
 * mercury_packet_processor_write_json_linktype() processes a packet and timestamp and linktype
 * writes the resulting JSON into a buffer.
 *
 * @param processor (input) is a packet processor context to be used
 * @param buffer (output) - location to which JSON will be written
 * @param buffer_size (input) - length of buffer in bytes
 * @param packet (input) - location of packet, starting with ethernet header
 * @param ts (input) - pointer to timestamp associated with packet
 * @param linktype (input) - linktype used in packet
 *
 * @return the number of bytes of JSON output written.
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
size_t mercury_packet_processor_write_json_linktype(mercury_packet_processor processor,
                                           void *buffer,
                                           size_t buffer_size,
                                           uint8_t *packet,
                                           size_t length,
                                           struct timespec* ts,
                                           uint16_t linktype);

/**
 * enum fingerprint_status represents the status of a fingerprint
 * relative to the library's knowledge about fingerprints, based on
 * the data in its resources and the other fingerprints that it has
 * observed.
 */
enum fingerprint_status {
    fingerprint_status_no_info_available = 0,  /**< fingerprint status is unknown                       */
    fingerprint_status_labeled           = 1,  /**< fingerprint is in FPDB                              */
    fingerprint_status_randomized        = 2,  /**< fingerprint is not in FPDB or unlabeled set         */
    fingerprint_status_unlabled          = 3,  /**< fingerprint is not in FPDB, but is in unlabeled set */
    fingerprint_status_unanalyzed        = 4,  /**< fingerprint unanalyzed (no FPDB for this fp type)   */
};

/**
 * mercury_packet_processor_ip_get_analysis_context() processes an IP
 * packet and timestamp and returns a pointer to an analysis context
 * if a fingerprint was found in the packet, and returns nothing
 * otherwise.
 *
 * @param processor (input) is a packet processor context to be used
 * @param buffer_size (input) - length of buffer in bytes
 * @param packet (input) - location of packet, starting with IPv4 or IPv6 header
 * @param ts (input) - pointer to timestamp associated with packet
 *
 * @return a pointer to an analysis_context, if a fingerprint was
 * found, otherwise NULL.
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
const struct analysis_context *mercury_packet_processor_ip_get_analysis_context(mercury_packet_processor processor,
                                                                                uint8_t *packet,
                                                                                size_t length,
                                                                                struct timespec* ts);

/**
 * analysis_context_get_fingerprint_status() returns the fingerprint_status
 * associated with an analysis_context.
 *
 * @param ac (input) is an analysis_context pointer.
 *
 * @return a fingerprint_status enumeration.
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
enum fingerprint_status analysis_context_get_fingerprint_status(const struct analysis_context *ac);

/**
 * enum fingerprint_type identifies a type of fingerprint for the
 * struct fingerprint.
 *
 *    note: these enumeration values correspond to the array name[] in
 *    fingerprint::write() in fingerprint.h; if you change one, you
 *    *must* change the other, to keep them in sync
 *
 */
enum fingerprint_type {
     fingerprint_type_unknown = 0,     /**< The fingerprint type is not known. */
     fingerprint_type_tls = 1,         /**< TLS client fingerprint             */
     fingerprint_type_tls_server = 2,  /**< TLS server fingerprint             */
     fingerprint_type_http = 3,        /**< HTTP client fingerprint            */
     fingerprint_type_http_server = 4, /**< HTTP server fingerprint            */
     fingerprint_type_ssh = 5,         /**< SSH init fingerprint               */
     fingerprint_type_ssh_kex = 6,     /**< SSH kex fingerprint                */
     fingerprint_type_tcp = 7,         /**< TCP SYN fingerprint                */
     fingerprint_type_dhcp = 8,        /**< DHCP client fingerprint            */
     fingerprint_type_smtp_server = 9, /**< SMTP server fingerprint            */
     fingerprint_type_dtls = 10,       /**< DTLS client fingerprint            */
     fingerprint_type_dtls_server = 11, /**< DTLS server fingerprint           */
     fingerprint_type_quic = 12,       /**< IETF QUIC                          */
     fingerprint_type_tcp_server = 13, /**< TCP SYN ACK fingerprint            */
     fingerprint_type_openvpn = 14, /**< OpenVPN TCP fingerprint           */
};

/**
 * analysis_context_get_fingerprint_type() returns the fingerprint_status
 * associated with an analysis_context.
 *
 * @param ac (input) is an analysis_context pointer.
 *
 * @return a fingerprint_type enumeration.
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
enum fingerprint_type analysis_context_get_fingerprint_type(const struct analysis_context *ac);

/**
 * analysis_context_get_fingerprint_string() returns the printable,
 * null-terminated string for the fingerprint associated with an
 * analysis_context, if there is one.
 *
 * @param ac (input) is an analysis_context pointer.
 *
 * @return a null-terminated, printable character string, if a
 * fingerprint was found by the library; otherwise, NULL.
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
const char *analysis_context_get_fingerprint_string(const struct analysis_context *ac);

/**
 * analysis_context_get_server_name() returns the printable,
 * null-terminated string for the TLS client hello server name
 * associated with an analysis_context, if there is one.
 *
 * @param ac (input) is an analysis_context pointer.
 *
 * @return a null-terminated, printable character string, if a TLS
 * client hello server name was found by the library; otherwise, NULL.
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
const char *analysis_context_get_server_name(const struct analysis_context *ac);

/**
 * analysis_context_get_process_info() writes the probable process and
 * its corresdponing probability score into the locations provided,
 * given an analysis_context.
 *
 * @param ac (input) is an analysis_context pointer.
 *
 * @param probable_process (output) is the location to write the
 * probable_process string.
 *
 * @param probability_score (output) is the location to write the
 * probability score.
 *
 * @return true if the probable_process and probabiltiy_score are
 * valid after the function returns, and false otherwise.
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
bool analysis_context_get_process_info(const struct analysis_context *ac, // input
                                       const char **probable_process,     // output
                                       double *probability_score          // output
                                       );

/**
 * analysis_context_get_malware_info() writes the
 * probable_process_is_malware boolean and the probability_malware
 * value into the locations provided, for a given analysis_context.
 *
 * @param ac (input) is an analysis_context pointer.
 *
 * @param probable_process_is_malware (output) is the location to write the
 * boolean.
 *
 * @param probability_malware (output) is the location to write the
 * probability that the process is malware.
 *
 * @return true if the probable_process_is_malware and
 * probabiltiy_malware values are valid after the function returns,
 * and false otherwise.
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
bool analysis_context_get_malware_info(const struct analysis_context *ac, // input
                                       bool *probable_process_is_malware, // output
                                       double *probability_malware        // output
                                       );

/**
 * os_information holds the name of an operating system and the
 * prevalence with which it has been observed with a particular
 * fingerprint.
 */
struct os_information {
    char *os_name;           /**< printable, null-termated string holding OS name */
    uint64_t os_prevalence;  /**< prevalence with which this OS is associated with fingerprint */
};

/**
 * analysis_context_get_os_info() sets a pointer to an array of
 * os_information structures and the length of that array, for a given
 * analysis_context.
 *
 * @param ac (input) is an analysis_context pointer.
 *
 * @param os_info (output) is the location to which the os_information
 * array pointer will be written.
 *
 * @param os_info_len (output) is the location to write the
 * length of the os_info array.
 *
 * @return true if the os_info and os_info_len locations point to
 * valid data after the function returns, and false otherwise.
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
bool analysis_context_get_os_info(const struct analysis_context *ac,     // input
                                  const struct os_information **os_info, // output
                                  size_t *os_info_len                    // output
                                  );

/**
 * mercury_write_stats_data()
 *
 * @param mercury_context is the context associated with the stats
 * data to be written out.
 *
 * @param stats_data_file_path (input) is a pointer to an ASCII
 * character string holding the path to the file to which stats data
 * is to be written.
 *
 * This function may process a lot of data, and it may take a very
 * long time to return, so the caller MUST be prepared to wait for
 * seconds or minutes.
 *
 * This function SHOULD be called periodically, e.g. every hour or
 * every day.  Mercury's stats engine accumulates data between calls
 * to this function, and each call flushes all of the data maintained
 * by that engine.  The stats engine uses a large but fixed amount of
 * RAM for data storage; if it runs out of storage, it will stop
 * accumulating data.
 *
 * @return true on success, false otherwise.
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
bool mercury_write_stats_data(mercury_context mc, const char *stats_data_file_path);


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
extern "C" LIBMERC_DLL_EXPORTED
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
extern "C" LIBMERC_DLL_EXPORTED
#endif
void mercury_print_version_string(FILE *f);

/**
 * @brief returns the mercury semantic version
 *
 * Returns the semantic version of mercury/libmerc as a uint32_t, in
 * which the major version is the most significant byte, the minor
 * version is the second most significant byte, the patchlevel is the
 * third most significant byte, and the least significant byte may be
 * zero.  That is, the format looks like
 *
 *    major | minor | patchlevel | 0
 *
 * @return an unsigned integer that encodes the semantic version
 *
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
uint32_t mercury_get_version_number();

/**
 * @brief prints the mercury semantic version
 *
 * Prints the semantic version of mercury/libmerc to the buffer provided
 * as input.
 *
 * @param [in] buffer to print semantic version on.
 *
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
void mercury_get_version_string(char *buf, size_t size);

/**
 * @brief returns the resource archive VERSION
 *
 * Returns a pointer to a NULL-terminated string containing the
 * entirety of the VERSION file in the resource archive provided to
 * the mercury library.  If there was no VERSION file in the archive,
 * then a zero-length string will be returned.
 *
 * @warning this function should only be called after libmerc is
 * initialized, and it should not be called after it is
 * de-initialized.
 *
 * @return a pointer to a null-terminated string containing the
 * resource archive VERSION file
 *
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
const char *mercury_get_resource_version(mercury_context mc);

//
// start of libmerc version 3 API
//

/**
 * mercury_packet_processor_get_analysis_context() processes an
 * ethernet packet and timestamp and returns a pointer to an analysis
 * context if a fingerprint was found in the packet, and returns
 * nothing otherwise.
 *
 * @param processor (input) is a packet processor context to be used
 * @param buffer_size (input) - length of buffer in bytes
 * @param packet (input) - location of packet, starting with the ethernet header
 * @param ts (input) - pointer to timestamp associated with packet
 *
 * @return a pointer to an analysis_context, if a fingerprint was
 * found, otherwise NULL.
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
const struct analysis_context *mercury_packet_processor_get_analysis_context(mercury_packet_processor processor,
                                                                             uint8_t *packet,
                                                                             size_t length,
                                                                             struct timespec* ts);

/**
 * mercury_packet_processor_get_analysis_context_linktype() processes a
 * packet of specified link type and timestamp and returns a pointer to
 * an analysis context if a fingerprint was found in the packet, and
 * returns nothing otherwise.
 *
 * @param processor (input) is a packet processor context to be used
 * @param buffer_size (input) - length of buffer in bytes
 * @param packet (input) - location of packet, starting with the ethernet header
 * @param ts (input) - pointer to timestamp associated with packet
 * @param linktype (input) - linktype used in the packet
 *
 * @return a pointer to an analysis_context, if a fingerprint was
 * found, otherwise NULL.
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
const struct analysis_context *mercury_packet_processor_get_analysis_context_linktype(mercury_packet_processor processor,
                                                                             uint8_t *packet,
                                                                             size_t length,
                                                                             struct timespec* ts,
                                                                             uint16_t linktype);
/**
 * analysis_context_get_user_agent() returns the printable,
 * null-terminated string for the HTTP/QUIC user agent
 * associated with an analysis_context, if there is one.
 *
 * @param ac (input) is an analysis_context pointer.
 *
 * @return a null-terminated, printable character string, if a HTTP/QUIC
 * user agent was found by the library; otherwise, NULL.
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
const char *analysis_context_get_user_agent(const struct analysis_context *ac);

/**
 * analysis_context_get_alpns() sets a pointer to a buffer containing
 * zero or more protocol names from the application layer protocol
 * negotiation (ALPN) extension, for a given analysis_context.
 *
 * @param ac (input) is an analysis_context pointer.
 *
 * @param alpn_data (output) is the location to which the alpns array
 * pointer will be written.
 *
 * @param alpn_length (output) is the location to which the length of the
 * alpn_data will be written.
 *
 * @return true if the alpn_data and alpn_length point to valid data
 * after the function returns, and false otherwise.
 *
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
bool analysis_context_get_alpns(const struct analysis_context *ac, // input
                                const uint8_t **alpn_data,         // output
                                size_t *alpn_length                // output
                                );

//
// start of libmerc version 4 API
//

/**
 * mercury_packet_processor_more_pkts_needed() return a boolean true, given a nullptr
 * analysis_context from get_analysis_context call, if more packets are required for the current flow to get a valid
 * analysis_context
 *
 * @param processor (input) is a packet processor context to be used
 *
 * @return a boolean true if more packets are required, otherwise false
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
bool mercury_packet_processor_more_pkts_needed(mercury_packet_processor processor);

//
// start of libmerc version 5 API
//

/**
 * get_stats_aggregator_num_entries() returns current number of entries in stats_aggregator,
 * given a nullptr analysis_context returns 0
 *
 * @param mercury_context is the context associated
 *
 * @return current number of entries in stats_aggregator or 0. Will return 0 if libmerc is not configured to report stats.
 */
#ifdef __cplusplus
extern "C" LIBMERC_DLL_EXPORTED
#endif
size_t get_stats_aggregator_num_entries(mercury_context mc);

#endif /* LIBMERC_H */
