/*
 * config.c
 *
 * mercury configuration structures and functions
 *
 * Copyright (c) 2021 Cisco Systems, Inc.  All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <thread>
#include "config.h"
#include "libmerc/libmerc.h"

char *command_get_argument(const char *command, char *line) {
    if (strncmp(command, line, strlen(command)-1) == 0) {
        char *arg = line + strlen(command);
        size_t arg_len = strlen(arg) - 1;
        if (arg[arg_len] == '\n')  {
            arg[arg_len] = 0;  /* null terminate arg string */
        }
        return arg;
    }
    return NULL;
}

enum status argument_parse_as_boolean(const char *arg, bool *variable_to_set) {
    if (arg[0] == '1') {
        *variable_to_set = 1;
        return status_ok;
    } else if (arg[0] == '0') {
        *variable_to_set = 0;
        return status_ok;
    }
    return status_err;
}

enum status argument_parse_as_int(const char *arg, int *variable_to_set) {
    char *endptr = NULL;
    int tmp = strtol(arg, &endptr, 10);
    if (*endptr == 0) {
        *variable_to_set = tmp;
        return status_ok;
    }
    return status_err;
}

enum status argument_parse_as_uint64(const char *arg, uint64_t *variable_to_set) {
    char *endptr = NULL;
    uint64_t tmp = strtoul(arg, &endptr, 10);
    if (*endptr == 0) {
        *variable_to_set = tmp;
        return status_ok;
    }
    return status_err;
}

enum status argument_parse_as_float(const char *arg, float *variable_to_set) {
    char *endptr = NULL;
    float tmp = strtof(arg, &endptr);
    if (*endptr == 0) {
        *variable_to_set = tmp;
        return status_ok;
    }
    return status_err;
}

char *str_append(char *s1, const char *s2) {
    if (s2 == nullptr) {
        return s1;     // nothing to append
    }
    size_t newlen = strlen(s2) + 1; // for terminating null character
    if (s1) {
        newlen += strlen(s1);
    }
    char *newstr = (char *)realloc(s1, newlen);
    if (newstr == nullptr) {
        return nullptr;  // error; realloc failed
    }
    if (s1 == nullptr) {
        strcpy(newstr, s2);
    } else {
        strcat(newstr, s2);
    }
    return newstr;
}

static char *select_arg = nullptr;
static char *additional_args = nullptr;

static enum status mercury_config_parse_line(struct mercury_config *cfg,
                                             struct libmerc_config &global_vars,
                                             char *line) {
    char *arg = NULL;

    if ((arg = command_get_argument("read=", line)) != NULL) {
        cfg->read_filename = strdup(arg);
        // use blocking output, so that no packets are lost in copying
        cfg->output_block = true;
        // use blocking stats to avoid losing stats events
        additional_args = str_append(additional_args, "stats-blocking;");
        return status_ok;

    } else if ((arg = command_get_argument("write=", line)) != NULL) {
        cfg->write_filename = strdup(arg);
        return status_ok;

    } else if ((arg = command_get_argument("fingerprint=", line)) != NULL) {
        cfg->fingerprint_filename = strdup(arg);
        return status_ok;

    } else if ((arg = command_get_argument("capture=", line)) != NULL) {
        cfg->capture_interface = strdup(arg);
        return status_ok;

    } else if ((arg = command_get_argument("resources=", line)) != NULL) {
        global_vars.resources = strdup(arg);
        return status_ok;

    } else if ((arg = command_get_argument("directory=", line)) != NULL) {
        cfg->working_dir = strdup(arg);
        return status_ok;

    } else if ((arg = command_get_argument("analysis=", line)) != NULL) {
        return argument_parse_as_boolean(arg, &global_vars.do_analysis);

    } else if ((arg = command_get_argument("buffer=", line)) != NULL) {
        return argument_parse_as_float(arg, &cfg->buffer_fraction);

    } else if ((arg = command_get_argument("threads=", line)) != NULL) {
        if (strcmp("cpu", arg) == 0) {
            cfg->num_threads = std::thread::hardware_concurrency();
        } else {
            cfg->num_threads = strtoul(arg, NULL, 10);
        }
        return status_ok;

    } else if ((arg = command_get_argument("limit=", line)) != NULL) {
        return argument_parse_as_uint64(arg, &cfg->rotate);

    } else if ((arg = command_get_argument("output-time=", line)) != NULL) {
        return argument_parse_as_uint64(arg, &cfg->out_rotation_duration);

    } else if ((arg = command_get_argument("user=", line)) != NULL) {
        cfg->user = strdup(arg);
        return status_ok;

    } else if ((arg = command_get_argument("loop=", line)) != NULL) {
        return argument_parse_as_int(arg, &cfg->loop_count);

    } else if ((arg = command_get_argument("verbosity=", line)) != NULL) {
        return argument_parse_as_int(arg, &cfg->verbosity);

    } else if ((arg = command_get_argument("select=", line)) != NULL) {
        if (select_arg != nullptr) {
            return status_err;  // select command previously detected
        }
        select_arg = str_append(select_arg, "select=");
        select_arg = str_append(select_arg, arg);
        select_arg = str_append(select_arg, ";");
        return status_ok;

    } else if ((arg = command_get_argument("dns-json", line)) != NULL) {
        global_vars.dns_json_output = true;
        return status_ok;

    } else if ((arg = command_get_argument("certs-json", line)) != NULL) {
        global_vars.certs_json_output = true;
        return status_ok;

    } else if ((arg = command_get_argument("metadata", line)) != NULL) {
        global_vars.metadata_output = true;
        return status_ok;

    } else if ((arg = command_get_argument("nonselected-tcp-data", line)) != NULL) {
        global_vars.output_tcp_initial_data = true;
        return status_ok;

    } else if ((arg = command_get_argument("nonselected-udp-data", line)) != NULL) {
        global_vars.output_udp_initial_data = true;
        return status_ok;

    } else if ((arg = command_get_argument("tcp-reassembly", line)) != NULL) {
        additional_args = str_append(additional_args, "tcp-reassembly;");
        return status_ok;

    } else if ((arg = command_get_argument("quic-reassembly", line)) != NULL) {
        additional_args = str_append(additional_args, "quic-reassembly;");
        return status_ok;

    } else if ((arg = command_get_argument("format=", line)) != NULL) {
        additional_args = str_append(additional_args, "format=");
        additional_args = str_append(additional_args, arg);
        additional_args = str_append(additional_args, ";");
        return status_ok;

    } else {
        if (line[0] == '#') { /* comment line */
            return status_ok;
        }
        return status_err;    /* warning: neither a command nor a comment */
    }

    return status_ok;
}

void string_remove_whitespace(char* s) {
    const char* d = s;
    do {
        while (isspace(*d)) {
            ++d;
        }
        *s++ = *d++;
    } while (*s);
}

enum status mercury_config_read_from_file(struct mercury_config &cfg,
                                          struct libmerc_config &global_vars,
                                          const char *filename) {
    if (cfg.verbosity) {
        fprintf(stderr, "reading config file %s\n", filename);
    }

    FILE *cfg_file = fopen(filename, "r");
    if (cfg_file == NULL) {
        fprintf(stderr, "%s: could not open file %s\n", strerror(errno), filename);
        return status_err;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    while ((nread = getline(&line, &len, cfg_file)) != -1) {
        if (nread > 1) {
            line[nread-1] = 0; /* replace CR with null terminator */
            string_remove_whitespace(line);
            if (mercury_config_parse_line(&cfg, global_vars, line)) {
                fprintf(stderr, "warning: ignoring unparseable command line '%s'\n", line);
            }
        }
    }
    free(line);
    fclose(cfg_file);

    // apply additional args
    //
    if (select_arg == nullptr) {
        select_arg = str_append(select_arg, "select=all;");
    }
    global_vars.packet_filter_cfg = str_append(select_arg, additional_args);

    return status_ok;
}
