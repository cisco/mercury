/*
 * @file libmerc.h
 *
 * @brief interface to mercury packet metadata capture and analysis library
 */

#ifndef LIBMERC_H
#define LIBMERC_H

#include "version.h"

#define MAX_FILENAME 256

/*
 * struct global_variables holds all of mercury's global variables.
 * This set is currently limited to booleans that control the
 * processing and output.  It would be nice avoid global state by
 * passing these values into the packet processor (struct pkt_proc),
 * but for now we are using this global struct to keep track of the
 * global state, and put them all on the same cache line.
 */
class global_variables {
public:
    global_variables() :
        dns_json_output{false},
        certs_json_output{false},
        metadata_output{false},
        do_analysis{false},
        output_tcp_initial_data{false},
        output_udp_initial_data{false} {}

    bool dns_json_output;   /* output DNS as JSON              */
    bool certs_json_output; /* output certificates as JSON     */
    bool metadata_output;   /* output lots of metadata         */
    bool do_analysis;       /* write analysys{} JSON object    */
    bool output_tcp_initial_data; /* write initial data field  */
    bool output_udp_initial_data; /* write initial data field  */
};

int mercury_set_global_variables(const class global_variables &vars);

int analysis_init(int verbosity, const char *resource_dir);

int analysis_finalize();

enum status {
    status_ok = 0,
    status_err = 1,
    status_err_no_more_data = 2
};
// enum status : bool { ok = 0, err = 1 };

/**
 * @brief extracts a TLS client fingerprint from a packet
 *
 * Extracts a TLS clientHello fingerprint from the TCP data field
 * (which starts at @em data and contains @em data_len bytes) and
 * writes it into the output buffer (which starts at @em outbuf and
 * contains @em outbuf_len bytes) in bracket notation (human readable)
 * form, if there is enough room for it.
 *
 * @param [in] data the start of the TCP data field
 * @param [in] data_len the number of bytes in the TCP data field
 * @param [out] outbuf the output buffer
 * @param [in] outbuf_len the number of bytes in the output buffer
 *
 */
size_t extract_fp_from_tls_client_hello(uint8_t *data,
                                        size_t data_len,
                                        uint8_t *outbuf,
                                        size_t outbuf_len);


enum status proto_ident_config(const char *config_string);

enum status static_data_config(const char *config_string);

const char *mercury_get_license_string();

void mercury_print_version_string(FILE *f);

#endif /* LIBMERC_H */
