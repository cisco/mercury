/*
 * @file libmerc.h
 *
 * @brief interface to mercury packet metadata capture and analysis library
 */

#ifndef LIBMERC_H
#define LIBMERC_H

#include "version.h"

/*
 * class libmerc_config represents the complete configuration of
 * the libmerc library
 */
class libmerc_config {
public:
    libmerc_config() :
        dns_json_output{false},
        certs_json_output{false},
        metadata_output{false},
        do_analysis{false},
        output_tcp_initial_data{false},
        output_udp_initial_data{false},
        resources{NULL},
        packet_filter_cfg{NULL}
    {}

    bool dns_json_output;   /* output DNS as JSON              */
    bool certs_json_output; /* output certificates as JSON     */
    bool metadata_output;   /* output lots of metadata         */
    bool do_analysis;       /* write analysys{} JSON object    */
    bool output_tcp_initial_data; /* write initial data field  */
    bool output_udp_initial_data; /* write initial data field  */

    char *resources;        /* directory containing (analysis) resource files */
    char *packet_filter_cfg; /* packet filter configuration string             */
};

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
int mercury_init(const class libmerc_config &vars, int verbosity);

/**
 * @brief finalizes libmerc
 *
 * Finalizes the libmerc library, and frees up resources allocated by
 * mercury_init().   Returns zero on success.
 *
 */
int mercury_finalize();

enum status {
    status_ok = 0,
    status_err = 1,
    status_err_no_more_data = 2
};
// enum status : bool { ok = 0, err = 1 };

enum status static_data_config(const char *config_string);

/**
 * @brief returns the mercury license string
 *
 * Returns a printable string containing the license for mercury and
 * libmerc.
 *
 */
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
void mercury_print_version_string(FILE *f);


enum status proto_ident_config(const char *config_string);


#define MAX_FILENAME 256

#endif /* LIBMERC_H */
