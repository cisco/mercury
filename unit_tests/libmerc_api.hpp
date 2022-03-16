/*
 * libmerc_api.h
 *
 * libmerc api structure and variables needed for unit tests
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <array>
#include <stdexcept>

#include "libmerc.h"
#include "pkt_proc.h"
#include "catch.hpp"

namespace snort {
#define SO_PUBLIC

    SO_PUBLIC void LogMessage(const char*, ...) __attribute__((format (printf, 1, 2)));
    SO_PUBLIC void LogMessage(FILE*, const char*, ...) __attribute__((format (printf, 2, 3)));
    SO_PUBLIC void WarningMessage(const char*, ...) __attribute__((format (printf, 1, 2)));
    SO_PUBLIC void ErrorMessage(const char*, ...) __attribute__((format (printf, 1, 2)));

    [[noreturn]] SO_PUBLIC void FatalError(const char*, ...) __attribute__((format (printf, 1, 2)));
}

typedef void (*dummy_func)();

struct libmerc_api {

    libmerc_api(const char *lib_path) {
        if (bind(lib_path) != 0) {
            std::string err = "error: could not initialize libmerc_api on lib_path ";
            err.append(lib_path);
            throw std::runtime_error(err.c_str());
        }
    }

    ~libmerc_api() {
        mercury_unbind(*this);
    }

    decltype(mercury_init)                                           *init = nullptr;
    decltype(mercury_finalize)                                       *finalize = nullptr;
    decltype(mercury_packet_processor_construct)                     *packet_processor_construct = nullptr;
    decltype(mercury_packet_processor_destruct)                      *packet_processor_destruct = nullptr;
    decltype(mercury_packet_processor_get_analysis_context)          *get_analysis_context = nullptr;
    decltype(mercury_packet_processor_get_analysis_context_linktype) *get_analysis_context_linktype = nullptr;
    decltype(analysis_context_get_fingerprint_type)                  *get_fingerprint_type = nullptr;
    decltype(analysis_context_get_fingerprint_status)                *get_fingerprint_status = nullptr;
    decltype(analysis_context_get_process_info)                      *get_process_info = nullptr;
    decltype(analysis_context_get_malware_info)                      *get_malware_info = nullptr;
    decltype(mercury_write_stats_data)                               *write_stats_data = nullptr;

    void *dl_handle = nullptr;

    int bind(const char *lib_path) {

        if ((dl_handle = dlopen(lib_path, RTLD_LAZY|RTLD_LOCAL)) == nullptr) {
            const char *dlerr = dlerror();
            fprintf(stderr, "mercury: failed to load %s: %s\n", lib_path, dlerr ? dlerr : "unknown error");
            return -1; // error
        } else {
            fprintf(stderr, "mercury: loading %s\n", lib_path);
        }

        init =                          (decltype(init))                          dlsym(dl_handle, "mercury_init");
        finalize =                      (decltype(finalize))                      dlsym(dl_handle, "mercury_finalize");
        packet_processor_construct =    (decltype(packet_processor_construct))    dlsym(dl_handle, "mercury_packet_processor_construct");
        packet_processor_destruct =     (decltype(packet_processor_destruct))     dlsym(dl_handle, "mercury_packet_processor_destruct");
        get_analysis_context =          (decltype(get_analysis_context))          dlsym(dl_handle, "mercury_packet_processor_get_analysis_context");
        get_analysis_context_linktype = (decltype(get_analysis_context_linktype)) dlsym(dl_handle, "mercury_packet_processor_get_analysis_context_linktype"); 
        get_fingerprint_type =          (decltype(get_fingerprint_type))          dlsym(dl_handle, "analysis_context_get_fingerprint_type");
        get_fingerprint_status =        (decltype(get_fingerprint_status))        dlsym(dl_handle, "analysis_context_get_fingerprint_status");
        get_process_info =              (decltype(get_process_info))              dlsym(dl_handle, "analysis_context_get_process_info");
        get_malware_info =              (decltype(get_malware_info))              dlsym(dl_handle, "analysis_context_get_malware_info");
        write_stats_data =              (decltype(write_stats_data))              dlsym(dl_handle, "mercury_write_stats_data");

        if (init                          == nullptr ||
            finalize                      == nullptr ||
            packet_processor_construct    == nullptr ||
            packet_processor_destruct     == nullptr ||
            get_analysis_context          == nullptr ||
            get_analysis_context_linktype == nullptr ||
            get_fingerprint_type          == nullptr ||
            get_fingerprint_status        == nullptr ||
            get_process_info              == nullptr ||
            get_malware_info              == nullptr ||
            write_stats_data              == nullptr) {
            fprintf(stderr, "error: could not initialize one or more libmerc function pointers\n");
            return -1;
        }
        return 0;

        fprintf(stderr, "mercury_bind() succeeded with handle %p\n", dl_handle);

        return 0; // success
    }

    void mercury_unbind(struct libmerc_api &libmerc_api) {
        dlclose(libmerc_api.dl_handle);
        libmerc_api.dl_handle = nullptr;
    }

};

struct packet_processor_state {
    unsigned int thread_number;
    struct libmerc_api *mercury;
    mercury_context mc;

    packet_processor_state(unsigned int tn, struct libmerc_api *m, mercury_context c) : thread_number{tn}, mercury{m}, mc{c} {}

};
