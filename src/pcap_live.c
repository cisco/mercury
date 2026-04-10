/*
 * pcap_live.c
 *
 * libpcap-based live capture backend for platforms such as macOS
 *
 * Copyright (c) 2026 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <pcap/pcap.h>

#include "libmerc/utils.h"
#include "output.h"
#include "signal_handling.h"

constexpr static size_t PCAP_LIVE_SNAPLEN = 65536;

enum mercury_linktype : uint16_t {
    mercury_linktype_null = 0,
    mercury_linktype_ethernet = 1,
    mercury_linktype_ppp = 9,
    mercury_linktype_raw = 101,
};

struct packet_info {
    struct timespec ts;
    uint32_t caplen;
    uint32_t len;
    uint16_t linktype = mercury_linktype_ethernet;
};

struct pkt_proc {
    virtual void apply(struct packet_info *pi, uint8_t *eth) = 0;
    virtual void flush() = 0;
    virtual void finalize() = 0;
    virtual ~pkt_proc() {};
    size_t bytes_written = 0;
    size_t packets_written = 0;
};

struct pkt_proc *pkt_proc_new_from_config(struct mercury_config *cfg,
                                          mercury_context mc,
                                          int tnum,
                                          struct ll_queue *llq);


struct pcap_live_context {
    pcap_t *pcap_handle = nullptr;
    struct pkt_proc *pkt_processor = nullptr;
    uint16_t linktype = mercury_linktype_ethernet;
    uint64_t packets = 0;
    uint64_t bytes = 0;
};


/* Maps libpcap DLT values for live interfaces onto the Mercury
 * linktype values expected by packet processing.
 */
static uint16_t pcap_datalink_to_mercury_linktype(int datalink) {
    switch (datalink) {
    case DLT_NULL:
        return mercury_linktype_null;
    case DLT_EN10MB:
        return mercury_linktype_ethernet;
    case DLT_PPP:
        return mercury_linktype_ppp;
    case DLT_RAW:
        return mercury_linktype_raw;
#ifdef DLT_LOOP
    case DLT_LOOP:
        return mercury_linktype_null;
#endif
    default:
        return 0xffff;
    }
}


/* Creates and activates a libpcap handle for live capture, applying
 * the backend's snaplen, timeout, and buffer-size policy.
 */
static enum status pcap_live_open(struct mercury_config *cfg,
                                  struct pcap_live_context *ctx) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = pcap_create(cfg->capture_interface, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "error: could not create libpcap handle for interface %s: %s\n",
                cfg->capture_interface,
                errbuf[0] ? errbuf : "unknown error");
        return status_err;
    }

    int rc = pcap_set_snaplen(handle, PCAP_LIVE_SNAPLEN);
    if (rc != 0) {
        fprintf(stderr, "error: could not set snaplen on interface %s: %s\n",
                cfg->capture_interface,
                pcap_statustostr(rc));
        pcap_close(handle);
        return status_err;
    }

    rc = pcap_set_promisc(handle, 1);
    if (rc != 0) {
        fprintf(stderr, "error: could not enable promiscuous mode on interface %s: %s\n",
                cfg->capture_interface,
                pcap_statustostr(rc));
        pcap_close(handle);
        return status_err;
    }

    rc = pcap_set_timeout(handle, 1000);
    if (rc != 0) {
        fprintf(stderr, "error: could not set capture timeout on interface %s: %s\n",
                cfg->capture_interface,
                pcap_statustostr(rc));
        pcap_close(handle);
        return status_err;
    }

    uint64_t desired_memory = (uint64_t)sysconf(_SC_PHYS_PAGES) *
                              (uint64_t)sysconf(_SC_PAGESIZE) *
                              cfg->buffer_fraction *
                              cfg->io_balance_frac;
    if (desired_memory > 0 && desired_memory <= INT32_MAX) {
        rc = pcap_set_buffer_size(handle, (int)desired_memory);
        if (rc != 0 && cfg->verbosity) {
            fprintf(stderr,
                    "warning: could not set libpcap buffer size to %" PRIu64 ": %s\n",
                    desired_memory,
                    pcap_statustostr(rc));
        }
    }

    rc = pcap_set_immediate_mode(handle, 1);
    if (rc != 0 && cfg->verbosity) {
        fprintf(stderr, "warning: could not enable immediate mode on interface %s: %s\n",
                cfg->capture_interface,
                pcap_statustostr(rc));
    }

    rc = pcap_activate(handle);
    if (rc < 0) {
        fprintf(stderr, "error: could not activate capture on interface %s: %s\n",
                cfg->capture_interface,
                pcap_geterr(handle));
        pcap_close(handle);
        return status_err;
    }
    if (rc > 0 && cfg->verbosity) {
        fprintf(stderr, "warning: interface %s activated with warning: %s\n",
                cfg->capture_interface,
                pcap_statustostr(rc));
    }

    int datalink = pcap_datalink(handle);
    ctx->linktype = pcap_datalink_to_mercury_linktype(datalink);
    if (ctx->linktype == 0xffff) {
        fprintf(stderr, "error: unsupported datalink type %d (%s) on interface %s\n",
                datalink,
                pcap_datalink_val_to_name(datalink) ? pcap_datalink_val_to_name(datalink) : "unknown",
                cfg->capture_interface);
        pcap_close(handle);
        return status_err;
    }

    ctx->pcap_handle = handle;
    return status_ok;
}


/* Releases the libpcap handle and packet processor owned by the live
 * capture backend.
 */
static void pcap_live_close(struct pcap_live_context *ctx) {
    if (ctx->pkt_processor != nullptr) {
        ctx->pkt_processor->finalize();
        delete ctx->pkt_processor;
        ctx->pkt_processor = nullptr;
    }

    if (ctx->pcap_handle != nullptr) {
        pcap_close(ctx->pcap_handle);
        ctx->pcap_handle = nullptr;
    }
}


/* Runs the libpcap packet loop and forwards each captured packet into
 * Mercury's existing packet-processing pipeline.
 */
static void *pcap_live_thread_func(void *arg) {
    struct pcap_live_context *ctx = (struct pcap_live_context *)arg;
    struct pcap_pkthdr *pkthdr = nullptr;
    const u_char *packet = nullptr;

    while (sig_close_flag == 0) {
        int rc = pcap_next_ex(ctx->pcap_handle, &pkthdr, &packet);
        if (rc == 1) {
            struct packet_info pi;
            pi.len = pkthdr->len;
            pi.caplen = pkthdr->caplen;
            pi.ts.tv_sec = pkthdr->ts.tv_sec;
            pi.ts.tv_nsec = pkthdr->ts.tv_usec * 1000;
            pi.linktype = ctx->linktype;

            ctx->pkt_processor->apply(&pi, (uint8_t *)packet);
            ctx->packets++;
            ctx->bytes += pkthdr->caplen;
            continue;
        }

        if (rc == 0) {
            continue;
        }

        if (rc == PCAP_ERROR_BREAK) {
            break;
        }

        fprintf(stderr, "error: libpcap capture failed: %s\n", pcap_geterr(ctx->pcap_handle));
        break;
    }

    return nullptr;
}


/* Implements live interface capture on macOS using a single libpcap
 * worker and the shared Mercury output and processing path.
 */
enum status bind_and_dispatch(struct mercury_config *cfg,
                              mercury_context mc,
                              struct output_file *out_ctx,
                              struct cap_stats *cstats) {
    if (cfg->num_threads != 1) {
        fprintf(stderr, "error: macOS live capture supports exactly one thread (requested %d)\n",
                cfg->num_threads);
        return status_err;
    }

    struct pcap_live_context ctx;
    enum status status = pcap_live_open(cfg, &ctx);
    if (status != status_ok) {
        return status;
    }

    if (drop_root_privileges(cfg->user, cfg->working_dir) != status_ok) {
        pcap_live_close(&ctx);
        return status_err;
    }
    if (cfg->user) {
        fprintf(stderr, "running as user %s\n", cfg->user);
    } else {
        fprintf(stderr, "dropped root privileges\n");
    }

    ctx.pkt_processor = pkt_proc_new_from_config(cfg, mc, 0, &out_ctx->qs.queue[0]);
    if (ctx.pkt_processor == nullptr) {
        fprintf(stderr, "error: could not initialize frame handler\n");
        pcap_live_close(&ctx);
        return status_err;
    }

    int err = pthread_mutex_lock(&(out_ctx->t_output_m));
    if (err != 0) {
        fprintf(stderr, "%s: error locking output start mutex\n", strerror(err));
        pcap_live_close(&ctx);
        return status_err;
    }
    out_ctx->t_output_p = 1;
    err = pthread_cond_broadcast(&(out_ctx->t_output_c));
    if (err != 0) {
        fprintf(stderr, "%s: error broadcasting output start condition\n", strerror(err));
        pthread_mutex_unlock(&(out_ctx->t_output_m));
        pcap_live_close(&ctx);
        return status_err;
    }
    err = pthread_mutex_unlock(&(out_ctx->t_output_m));
    if (err != 0) {
        fprintf(stderr, "%s: error unlocking output start mutex\n", strerror(err));
        pcap_live_close(&ctx);
        return status_err;
    }

    pthread_attr_t pt_stack_size;
    err = pthread_attr_init(&pt_stack_size);
    if (err != 0) {
        fprintf(stderr, "Unable to init stack size attribute for libpcap worker pthread: %s\n", strerror(err));
        pcap_live_close(&ctx);
        return status_err;
    }

    err = pthread_attr_setstacksize(&pt_stack_size, 16 * 1024 * 1024);
    if (err != 0) {
        fprintf(stderr, "Unable to set stack size attribute for libpcap worker pthread: %s\n", strerror(err));
        pcap_live_close(&ctx);
        return status_err;
    }

    pthread_t tid;
    err = pthread_create(&tid, &pt_stack_size, pcap_live_thread_func, &ctx);
    if (err != 0) {
        fprintf(stderr, "%s: error creating libpcap capture thread\n", strerror(err));
        pcap_live_close(&ctx);
        return status_err;
    }

    pthread_join(tid, nullptr);

    struct pcap_stat ps;
    memset(&ps, 0, sizeof(ps));
    if (pcap_stats(ctx.pcap_handle, &ps) == 0) {
        cstats->sock_packets = ps.ps_recv;
        cstats->drops = ps.ps_drop;
#ifdef __APPLE__
        cstats->drops += ps.ps_ifdrop;
#endif
    } else {
        cstats->sock_packets = ctx.packets;
        cstats->drops = 0;
    }

    cstats->packets = ctx.packets;
    cstats->bytes = ctx.bytes;
    cstats->freezes = 0;

    pcap_live_close(&ctx);
    return status_ok;
}

/* The libpcap backend handles signals in the main thread rather than
 * delegating them to a backend-specific helper thread.
 */
bool capture_backend_blocks_main_thread_signals() {
    return false;
}
