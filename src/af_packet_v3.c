/*
 * af_packet_v3.c
 *
 * interface to AF_PACKET/TPACKETv3 with RX_RING and FANOUT
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* The following provides gettid (or a stub function) on all platforms. */
#if defined(__gnu_linux__) /* Linux */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE    /* Needed for gettid() definition from unistd.h */
#endif /* _GNU_SOURCE */
#include <unistd.h>
/* Use system call if gettid() is not available, e.g., before glibc 2.30 */
#if (!HAVE_GETTID)
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#endif /* (!HAVE_GETTID) */
#elif defined(__APPLE__) && defined(__MACH__)  /* macOS */
#define gettid() 0     /* TODO: return a meaningful value on macOS */
#elif defined(_WIN32) /* defined for both Windows 32-bit and 64-bit */
#define gettid() 0     /* TODO: return a meaningful value on Windows */
#else /* Unknown operating system */
#define gettid() 0
#endif /* defined(__gnu_linux__) */

#include <signal.h>

#include <errno.h>
#include <pthread.h>
#include <sched.h>

#include <sys/mman.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h> /* the L2 protocols */

#include <time.h>
#include <math.h>

#include "af_packet_v3.h"
#include "signal_handling.h"
#include "libmerc/utils.h"
#include "rnd_pkt_drop.h"
#include "output.h"
#include "pkt_processing.h"

/*
 * The thread_storage, stats_tracking, and ring_limits structs are
 * local to this file.
 */

/* The struct that describes the limits on allocating ring memory */
struct ring_limits {
    uint64_t af_desired_memory;
    uint32_t af_ring_limit;
    uint32_t af_framesize;
    uint32_t af_blocksize;
    uint32_t af_min_blocksize;
    uint32_t af_target_blocks;
    uint32_t af_min_blocks;
    uint32_t af_blocktimeout;
    int af_fanout_type;
};


/*
 * Our stats tracking function will get a pointer to a struct
 * that has the info it needs to track stats for each thread
 * and a place to store those stats
 */
struct stats_tracking {
    pid_t kpid;               /* Process ID (the kernel's PID for this thread) */
    pthread_t tid;            /* pthread ID */
    struct thread_storage *tstor;
    int num_threads;
    uint64_t received_packets;
    uint64_t received_bytes;
    uint64_t socket_packets;
    uint64_t socket_drops;
    uint64_t socket_freezes;
    int *t_start_p;             /* The clean start predicate */
    pthread_cond_t *t_start_c;  /* The clean start condition */
    pthread_mutex_t *t_start_m; /* The clean start mutex */
    int verbosity;
};

/*
 * struct thread_storage stores information about each thread
 * including its thread id and socket file handle
 */
struct thread_storage {
    struct pkt_proc *pkt_processor;
    int tnum;                 /* Thread Number */
    pid_t kpid;               /* Process ID (the kernel's PID for this thread) */
    pthread_t tid;            /* pthread ID */
    pthread_attr_t thread_attributes;
    int sockfd;               /* Socket owned by this thread */
    const char *if_name;      /* The name of the interface to bind the socket to */
    uint8_t *mapped_buffer;   /* The pointer to the mmap()'d region */
    struct tpacket_block_desc **block_header; /* The pointer to each block in the mmap()'d region */
    struct tpacket_req3 ring_params; /* The ring allocation params to setsockopt() */
    struct stats_tracking *statst;   /* A pointer to the struct with the stats counters */
    int longest_bstreak;        /* Track the longers number of full blocks in a row */
    int *t_start_p;             /* The clean start predicate */
    pthread_cond_t *t_start_c;  /* The clean start condition */
    pthread_mutex_t *t_start_m; /* The clean start mutex */
    int force_stall;            /* Force thread to stall (unused but available for debugging) */
    int stall_cnt;              /* Counter for stalled thread detection */
};


struct thread_stall *global_thread_stall; /* global needed for signal handler access */


void ring_limits_init(struct ring_limits *rl, float frac);  // defined below

/*
 * == Signal handling ==
 *
 * We need the stats tracking thread to end before we stop processing
 * packets or else we run the risk of exiting the packet processing
 * loops and then later measuring "false" drops on those sockets right
 * at the end.  To that end, the stats tracking will watch
 * sig_close_flag and the packet worker threads will watch
 * sig_close_workers.
 */
extern volatile sig_atomic_t sig_close_flag; /* Watched by the stats tracking thread, defined in signal_handling.c */
static int sig_close_workers = 0; /* Packet proccessing var */

static double time_elapsed(struct timespec *ts) {

    double time_s;
    time_s = ts->tv_sec + (ts->tv_nsec / 1000000000.0);

    if (clock_gettime(CLOCK_REALTIME, ts) != 0) {
        perror("Unable to get clock time for elapsed calculation");
        return NAN;
    }

    return (ts->tv_sec + (ts->tv_nsec / 1000000000.0)) - time_s;
}

void af_packet_stats(int sockfd, struct stats_tracking *statst) {
    int err;
    struct tpacket_stats_v3 tp3_stats;

    socklen_t tp3_len = sizeof(tp3_stats);
    err = getsockopt(sockfd, SOL_PACKET, PACKET_STATISTICS, &tp3_stats, &tp3_len);
    if (err) {
        perror("error: could not get packet statistics for the given socket");
        return;
    }

    if (statst != NULL) {
        statst->socket_packets = tp3_stats.tp_packets;
        statst->socket_drops = tp3_stats.tp_drops;
        statst->socket_freezes = tp3_stats.tp_freeze_q_cnt;
    }
}

void process_all_packets_in_block(struct tpacket_block_desc *block_hdr,
                                  struct stats_tracking *statst,
                                  struct pkt_proc *pkt_processor) {
    int num_pkts = block_hdr->hdr.bh1.num_pkts, i;
    unsigned long byte_count = 0;
    struct tpacket3_hdr *pkt_hdr;
    //struct timespec ts;
    struct packet_info pi;

    pkt_hdr = (struct tpacket3_hdr *) ((uint8_t *) block_hdr + block_hdr->hdr.bh1.offset_to_first_pkt);
    for (i = 0; i < num_pkts; ++i) {

        /* The tp_snaplen value is the actual number of bytes of this packet
         * that made it into the ringbuffer block.
         * tp_len is the skb length which in special circumstances
         * could be more (because of extra headers from the ethernet card, truncation, etc.)
         */
        byte_count += pkt_hdr->tp_snaplen;

        /* Grab the times */
        pi.ts.tv_sec = pkt_hdr->tp_sec;
        pi.ts.tv_nsec = pkt_hdr->tp_nsec;

        pi.caplen = pkt_hdr->tp_snaplen;
        pi.len = pkt_hdr->tp_snaplen;

        uint8_t *eth = (uint8_t *)pkt_hdr + pkt_hdr->tp_mac;
        pkt_processor->apply(&pi, eth);

        pkt_hdr = (struct tpacket3_hdr *) ((uint8_t *)pkt_hdr + pkt_hdr->tp_next_offset);
    }

    /* Atomic operations
     * https://gcc.gnu.org/onlinedocs/gcc-4.1.0/gcc/Atomic-Builtins.html
     */
    __sync_add_and_fetch(&(statst->received_packets), num_pkts);
    __sync_add_and_fetch(&(statst->received_bytes), byte_count);
}

void check_socket_drops(int duration, uint64_t sdps, uint64_t sfps, int *socket_drops, int *zero_drops) {
    int current_percent;

    if (sdps == 0 && sfps == 0) {
        (*zero_drops)++;
        (*socket_drops) = 0;
        if (*zero_drops >= 60) {
            *zero_drops = 0;
            current_percent = increment_percent_accept(5);
            fprintf(stderr, "  Duration: %6d, Current percent acceptance Increased to %d\n", duration, current_percent);
        }
    } else {
        (*zero_drops) = 0;
        (*socket_drops)++;
        if (*socket_drops > 1) {
            *socket_drops = -58;
            current_percent = increment_percent_accept(-10);
            fprintf(stderr, "  Duration: %6d,    Current percent acceptance Decreased to %d\n", duration, current_percent);
        }
    }
}

void *stats_thread_func(void *statst_arg) {

    struct stats_tracking *statst = (struct stats_tracking *)statst_arg;

    statst->kpid = gettid();

    fprintf(stderr, "[STATISTICS OUTPUT] Stats thread with pthread id %lu (PID %u) started...\n", statst->tid, statst->kpid);

    /* The stats thread is one of the first to get started and it has to wait
     * for the other threads otherwise we'll be tracking bogus stats
     * until they get up to speed
     */
    int err;
    err = pthread_mutex_lock(statst->t_start_m);
    if (err != 0) {
        fprintf(stderr, "%s: error locking clean start mutex for stats thread\n", strerror(err));
        exit(255);
    }
    while (*(statst->t_start_p) != 1) {
        err = pthread_cond_wait(statst->t_start_c, statst->t_start_m);
        if (err != 0) {
            fprintf(stderr, "%s: error waiting on clean start condition for stats thread\n", strerror(err));
            exit(255);
        }
    }
    err = pthread_mutex_unlock(statst->t_start_m);
    if (err != 0) {
        fprintf(stderr, "%s: error unlocking clean start mutex for stats thread\n", strerror(err));
        exit(255);
    }

    char space[2] = " ";
    struct timespec ts;
    double time_d; /* time delta */
    memset(&ts, 0, sizeof(ts));

    struct stats_tracking *per_tsock_stats = (stats_tracking *)calloc(statst->num_threads, sizeof(struct stats_tracking));
    if (per_tsock_stats == NULL) {
        fprintf(stderr, "Unable to allocate per-thread socket stats tracking struct\n");
        exit(255);
    }

    /*
     * Enable all signals so that this thread shuts down first
     */
    enable_all_signals();
    /* Block USR1 though since that's only for recovering
     * stalled threads
     */
    disable_bt_signal();

    int duration = 0, socket_drops = 0, zero_drops = 0;

    while (sig_close_flag == 0) {
        uint64_t packets_before = statst->received_packets;
        uint64_t bytes_before = statst->received_bytes;
        uint64_t socket_packets_before = statst->socket_packets;
        uint64_t socket_drops_before = statst->socket_drops;
        uint64_t socket_freezes_before = statst->socket_freezes;

        (void)time_elapsed(&ts); /* Fills out the struct for us */

        /* == THIS IS WHERE WE WAIT A SECOND == */
        sleep(1);
        /* == WAIT DONE == */

        time_d = time_elapsed(&ts); /* compares to the previous time */

        /* Just give up if the time doesn't sound right */
        if ((time_d < 0.9) || (time_d > 1.1)) {
            fprintf(stderr, "Unable to compute statistics because sleep / clock strayed too far from 1 second: %f seconds\n", time_d);
            continue;
        }

        /* Now go grab the socket and streak statistics */
        double worst_bstreak_frac = 0;
        for (int thread = 0; thread < statst->num_threads; thread++) {
            /* Get the stats for this thread's socket */
            af_packet_stats(statst->tstor[thread].sockfd, &(per_tsock_stats[thread]));

            /* Add those stats into the overall counts */
            statst->socket_packets += per_tsock_stats[thread].socket_packets;
            statst->socket_drops += per_tsock_stats[thread].socket_drops;
            statst->socket_freezes += per_tsock_stats[thread].socket_freezes;

            /* Track the worst block streak fraction */
            double bstreak_frac = ((double)(statst->tstor[thread].longest_bstreak) / (double)(statst->tstor[thread].ring_params.tp_block_nr));
            if (bstreak_frac > worst_bstreak_frac) {
                worst_bstreak_frac = bstreak_frac;
            }
            statst->tstor[thread].longest_bstreak = 0; /* Reset streak tracking */

            /* Detect stalled thread */
            if (per_tsock_stats[thread].socket_packets > 100) {       /* we got plenty of packets */
                if ((per_tsock_stats[thread].socket_drops > 100) &&   /* with plenty of drops */
                    (per_tsock_stats[thread].socket_freezes == 0) &&  /* with no new freezes */
                    ((double)per_tsock_stats[thread].socket_drops /
                     (double)per_tsock_stats[thread].socket_packets > 0.95)) { /* and almost all packets were dropped */
                    /* Socket drops without any new freezes are a sign
                     * that the thread stalled a while ago and never
                     * unfroze.  Note some socket drops without a
                     * frozen socket are possible in special cases
                     * like the kernel being out of space to allocate
                     * the SKB.  The check here makes sure that almost
                     * every packet was dropped which is a good
                     * indication that the socket is stuck frozen.
                     */

                    statst->tstor[thread].stall_cnt += 1;
                } else {
                    if (statst->tstor[thread].stall_cnt >= 3) {
                        fprintf(stderr, "INFO: Thread %d with thread id %lu has recovered from a stall!\n", statst->tstor[thread].tnum, statst->tstor[thread].tid);
                    }
                    statst->tstor[thread].stall_cnt  = 0;
                }

                if (statst->tstor[thread].stall_cnt == 3) {
                    fprintf(stderr, "CRITICAL: Thread %d with thread id %lu has stalled!\n", statst->tstor[thread].tnum, statst->tstor[thread].tid);
                    pthread_kill(statst->tstor[thread].tid, SIGUSR1);
                }
            }
        }

        /* The per-second stats scaled by the time delta */
        double pps  = (statst->received_packets - packets_before) / time_d;      /* packets */
        double byps  = (statst->received_bytes - bytes_before) / time_d;         /* bytes */
        double spps = (statst->socket_packets - socket_packets_before) / time_d; /* socket packets */

        /* The socket stats that don't need to be scaled */
        uint64_t sdps = statst->socket_drops - socket_drops_before;
        uint64_t sfps = statst->socket_freezes - socket_freezes_before;

        /* Compute the estimated Ethernet rate which accounts for the
         * "extra" per-packet data including the:
         * interpacket gap (12 bytes)
         * preamble (7 bytes)
         * start of frame delimiter (1 byte)
         * frame-check-sequence / FCS (4 bytes)
         */
        double ebips = (byps + (pps * (12 + 7 + 1 + 4))) * 8; /* in bits */

        /* Get the "readable" numbers */
        double r_pps;
        char *r_pps_s;
        get_readable_number_float(1000, pps, &r_pps, &r_pps_s);
        if (r_pps_s[0] == '\0') {
            r_pps_s = &(space[0]);
        }

        double r_byps;
        char *r_byps_s;
        get_readable_number_float(1000, byps, &r_byps, &r_byps_s);
        if (r_byps_s[0] == '\0') {
            r_byps_s = &(space[0]);
        }

        double r_spps;
        char *r_spps_s;
        get_readable_number_float(1000, spps, &r_spps, &r_spps_s);
        if (r_spps_s[0] == '\0') {
            r_spps_s = &(space[0]);
        }

        double r_ebips;
        char *r_ebips_s;
        get_readable_number_float(1000, ebips, &r_ebips, &r_ebips_s);
        if (r_ebips_s[0] == '\0') {
            r_ebips_s = &(space[0]);
        }

        if (statst->verbosity) {
            fprintf(stderr,
                    "Stats: "
                    "Time %14.3f ; "
                    "%7.3f%s Packets/s; Data Rate %7.3f%s bytes/s; "
                    "Ethernet Rate (est.) %7.3f%s bits/s; "
                    "Socket Packets %7.3f%s ; Socket Drops %" PRIu64 " (packets); Socket Freezes %" PRIu64 "; "
                    "Worst contiguous buffer processing streak %7.3f%%\n",
                    (ts.tv_sec + (ts.tv_nsec / 1000000000.0)),
                    r_pps, r_pps_s, r_byps, r_byps_s,
                    r_ebips, r_ebips_s,
                    r_spps, r_spps_s, sdps, sfps, worst_bstreak_frac * 100.0);
        }

        duration++;
        if (get_percent_accept() > 0) {
            /* check socket drops and update accept percentage only when percent accept > 0 */
            check_socket_drops(duration, sdps, sfps, &socket_drops, &zero_drops);
        }
    }

    free(per_tsock_stats);

    fprintf(stderr, "[STATISTICS OUTPUT] Stats thread with pthread id %lu (PID %u) exiting...\n", statst->tid, statst->kpid);

    return NULL;
}


/*
 * The function af_packet_rx_ring_fanout_capture() sets up an
 * AF_PACKET socket with a memory-mapped RX_RING and FANOUT, then
 * performs a packet capture.  Reference docs:
 *
 *  http://yusufonlinux.blogspot.ru/2010/11/data-link-access-and-zero-copy.html
 *  https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
 */

int create_dedicated_socket(struct thread_storage *thread_stor, int fanout_arg) {
    int err;
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        fprintf(stderr, "%s: could not create AF_PACKET socket for thread %d\n", strerror(errno), thread_stor->tnum);
        return -1;
    }
    /* Now store this socket file descriptor in the thread storage */
    thread_stor->sockfd = sockfd;

    /*
     * set AF_PACKET version to V3, which is more performant, as it
     * reads in blocks of packets, not single packets
     */
    int version = TPACKET_V3;
    err = setsockopt(sockfd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    if (err) {
        perror("could not set socket to tpacket_v3 version");
        return -1;
    }

    /*
     * get the number for the interface on which we want to capture packets
     */
    int interface_number = if_nametoindex(thread_stor->if_name);
    if (interface_number == 0) {
        fprintf(stderr, "Can't get interface number by interface name (%s) for thread %d\n", thread_stor->if_name, thread_stor->tnum);
        return -1;
    }

    /*
     * set interface to PROMISC mode
     */
    struct packet_mreq sock_params;
    memset(&sock_params, 0, sizeof(sock_params));
    sock_params.mr_type = PACKET_MR_PROMISC;
    sock_params.mr_ifindex = interface_number;
    err = setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void *)&sock_params, sizeof(sock_params));
    if (err) {
        fprintf(stderr, "could not enable promiscuous mode for thread %d\n", thread_stor->tnum);
        return -1;
    }

    /*
     * set up RX_RING
     */
    fprintf(stderr, "Requesting PACKET_RX_RING with %u bytes (%d blocks of size %d) for thread %d\n",
            thread_stor->ring_params.tp_block_size * thread_stor->ring_params.tp_block_nr,
            thread_stor->ring_params.tp_block_nr, thread_stor->ring_params.tp_block_size, thread_stor->tnum);
    err = setsockopt(sockfd, SOL_PACKET, PACKET_RX_RING, (void*)&(thread_stor->ring_params), sizeof(thread_stor->ring_params));
    if (err == -1) {
        perror("could not enable RX_RING for AF_PACKET socket");
        return -1;
    }

    /*
     * each thread has its own mmaped buffer
     */
    size_t map_buf_len = thread_stor->ring_params.tp_block_size * thread_stor->ring_params.tp_block_nr;
    uint8_t *mapped_buffer = (uint8_t*)mmap(NULL, map_buf_len,
                                            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED,
                                            sockfd, 0);
    if (mapped_buffer == MAP_FAILED) {
        fprintf(stderr, "%s: mmap failed for thread %d\n", strerror(errno), thread_stor->tnum);
        return -1;
    }

    /* Now store this mmap()'d region in the thread storage */
    thread_stor->mapped_buffer = mapped_buffer;

    /*
     * The start of each block is a struct tpacket_block_desc so make
     * array of pointers to the start of each block struct
     */
    struct tpacket_block_desc **block_header = (struct tpacket_block_desc**)malloc(thread_stor->ring_params.tp_block_nr * sizeof(struct tpacket_hdr_v1 *));
    if (block_header == NULL) {
        fprintf(stderr, "error: could not allocate block_header pointer array for thread %d\n", thread_stor->tnum);
        munmap(mapped_buffer, map_buf_len);
        return -1;
    }

    /* Now store this block pointer array the thread storage */
    thread_stor->block_header = block_header;


    for (unsigned int i = 0; i < thread_stor->ring_params.tp_block_nr; ++i) {
        block_header[i] = (struct tpacket_block_desc *)(mapped_buffer + (i * thread_stor->ring_params.tp_block_size));
    }

    /*
     * bind to interface
     */
    struct sockaddr_ll bind_address;
    memset(&bind_address, 0, sizeof(bind_address));
    bind_address.sll_family = AF_PACKET;
    bind_address.sll_protocol = htons(ETH_P_ALL);
    bind_address.sll_ifindex = interface_number;
    err = bind(sockfd, (struct sockaddr *)&bind_address, sizeof(bind_address));
    if (err) {
        fprintf(stderr, "could not bind interface %s to AF_PACKET socket for thread %d\n", thread_stor->if_name, thread_stor->tnum);
        return -1;
    }
    /*
     * verify that interface number matches requested interface
     */
    char actual_ifname[IF_NAMESIZE];
    char *retval = if_indextoname(interface_number, actual_ifname);
    if (retval == NULL) {
        fprintf(stderr, "%s: could not get interface name\n", strerror(errno));
        return -1;
    } else {
        if (strncmp(actual_ifname, thread_stor->if_name, IF_NAMESIZE) != 0) {
            fprintf(stderr, "error: interface name \"%s\" does not match that requested (%s)\n",
                    actual_ifname, thread_stor->if_name);
        }
    }

    /*
     * set up fanout (each thread gets some portion of packets)
     */


    err = setsockopt(sockfd, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg));
    if (err) {
        perror("error: could not configure fanout");
        return -1;
    }

    return 0;
}


int af_packet_rx_ring_fanout_capture(struct thread_storage *thread_stor) {

    /* Fetch the kernel's PID for this thread */
    thread_stor->kpid = gettid();

    int err;
    /* At this point this thread is ready to go
     * but we need to wait for all the other threads to be ready too
     * so we'll wait on a condition broadcast from the main thread to
     * let us know we can go
     */
    err = pthread_mutex_lock(thread_stor->t_start_m);
    if (err != 0) {
        fprintf(stderr, "%s: error locking clean start mutex for thread %lu\n", strerror(err), thread_stor->tid);
        exit(255);
    }
    while (*(thread_stor->t_start_p) != 1) {
        err = pthread_cond_wait(thread_stor->t_start_c, thread_stor->t_start_m);
        if (err != 0) {
            fprintf(stderr, "%s: error waiting on clean start condition for thread %lu\n", strerror(err), thread_stor->tid);
            exit(255);
        }
    }
    err = pthread_mutex_unlock(thread_stor->t_start_m);
    if (err != 0) {
        fprintf(stderr, "%s: error unlocking clean start mutex for thread %lu\n", strerror(err), thread_stor->tid);
        exit(255);
    }

    /* get local copies from the thread_stor struct so we can skip
     * pointer dereferences each time we access one
     */
    int sockfd = thread_stor->sockfd;
    struct tpacket_block_desc **block_header = thread_stor->block_header;
    struct stats_tracking *statst = thread_stor->statst;
    struct pkt_proc *pkt_processor = thread_stor->pkt_processor;

    /* We got the clean start all clear so we can get started but
     * while we were waiting our socket was filling up with packets
     * and drops were accumulating so we need to return everything to
     * the kernel
     */
    uint32_t thread_block_count = thread_stor->ring_params.tp_block_nr;
    af_packet_stats(sockfd, NULL); // Discard bogus stats
    for (unsigned int b = 0; b < thread_block_count; b++) {
        if ((block_header[b]->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
            continue;
        }
        else {
            block_header[b]->hdr.bh1.block_status = TP_STATUS_KERNEL;
        }
    }
    af_packet_stats(sockfd, NULL); // Discard bogus stats

    fprintf(stderr, "[PACKET PROCESSOR] Thread %d with pthread id %lu (PID %u) started...\n", thread_stor->tnum, thread_stor->tid, thread_stor->kpid);


    /* Enable the bt signal for this thread which must be done before
     * sigsetjmp since that saves the signal mask and the siglongjmp
     * restores it.
     *
     * There is a brief window of time after we enable this signal
     * but before we call sigsetjmp() where if USR1 is recieved
     * the signal handler will be unable to locate the longjmp
     * environment and will call abort().
     */
    enable_bt_signal();

    /* Save this execution context so that we can restore the thread back
     * to this point if it stalls during packet processing.
     */
    if (sigsetjmp(global_thread_stall[thread_stor->tnum].jmp_env, 1) == 0) {
        /* This branch of the if means we have just saved execution
         * so that a later siglongjump can be performed
         */

        /* env saved, store thread id and mark this as used */
        global_thread_stall[thread_stor->tnum].tid = thread_stor->tid;

        __sync_synchronize(); /* enforce memory ordering */
        global_thread_stall[thread_stor->tnum].used = 1;

    } else {
        /* This branch of the if means a siglongjump was just performed
         * from our signal handler and execution is being restored
         * from a stall
         */

        /* Flush all the packet blocks to discard whatever caused the stall */
        for (unsigned int b = 0; b < thread_block_count; b++) {
            if ((block_header[b]->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
                continue;
            }
            else {
                block_header[b]->hdr.bh1.block_status = TP_STATUS_KERNEL;
            }
        }

        fprintf(stderr, "[PACKET PROCESSOR] Thread %d with pthread id %lu (PID %u) resumed execution from stall...\n", thread_stor->tnum, thread_stor->tid, thread_stor->kpid);

    }

    /*
     * The kernel keeps a pointer to one of the blocks in the ringbuffer
     * (starting at 0) and every time the kernel fills a block and
     * returns it to userspace (by setting block_status to
     * TP_STATUS_USER) the kernel increments (modulo the number of
     * blocks) the block pointer.
     *
     * The tricky & undocumented bit is that if the kernel's block
     * pointer ever ends up pointing at a block that isn't marked
     * TP_STATUS_KERNEL the kernel will freeze the queue and discard
     * packets until the block it is pointing at is returned back to the
     * kernel.  See kernel-src/net/packet/af_packet.c for details of the
     * queue freezing behavior.
     *
     * This means that in a worst-case scenario, only a single block in
     * the ringbuffer could be marked for userspace and the kernel could
     * get stuck on that block and throw away packets even though the
     * entire rest of the ringbuffer is free to use.  The kernel DOES
     * NOT go hunt for free blocks to use if the current one is taken.
     *
     * The following loop tries to keep the current block (cb) pointed
     * to the block that the kernel is about to return, and then
     * increment to the next block the kernel will return, and so
     * forth. If for some reason they get out of sync, the kernel can
     * get stuck and freeze the queue while we can get stuck trying to
     * check the wrong block to see if it has returned yet.
     *
     * To address this case, we count how many times poll() has returned
     * saying data is ready (pstreak) but we haven't gotten any new
     * data.  If this happens a few times in a row it likely means we're
     * checking the wrong block and the kernel has frozen the queue and
     * is stuck on another block.  The fix is to increment our block
     * pointer to go find the block the kernel is stuck on.  This will
     * quickly move this thread and the kernel back into sync.
     */

    struct pollfd psockfd;
    memset(&psockfd, 0, sizeof(psockfd));
    psockfd.fd = sockfd;
    psockfd.events = POLLIN | POLLERR;
    psockfd.revents = 0;

    int pstreak = 0;      /* Tracks the number of times in a row (the streak) poll() has told us there is data */
    int bstreak = 0;      /* The number of blocks in a row we've gotten without a poll() */
    int polret;           /* The return value from poll() */
    int haveflushed = 0;  /* Tracks whether we've opportunistically flushed yet or not */
    unsigned int cb = 0;  /* The current block pointer (index) */
    struct timespec ts;
    (void)time_elapsed(&ts); /* init the struct for us */
    while (sig_close_workers == 0) {

        /* Debugging thread stalling:
         * If force_stall is set (say by the stats thread)
         * this worker will stall which allows for simulating
         * a stall in packet processing.
         *
         * This isn't used in practice but is left here commented out
         * to preserve the logic should such debugging be needed
         * in the future.
         */
        /* if (thread_stor->force_stall != 0) { */
        /*     fprintf(stderr, "Thread %d with thread id %lu forcefully stalling\n", thread_stor->tnum, thread_stor->tid); */
        /*     while ((sig_close_workers == 0) && (thread_stor->force_stall != 0)) { */
        /*         sleep(1); */
        /*     } */
        /* } */

        /* This checks if the 'user' bit is NOT set on the block.  If the
         * block isn't set, the block is still owned by the kernel and we
         * should wait.  If the bit is set, the block has been filled by
         * the kernel and we should process the block.
         */
        if ((block_header[cb]->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
            /* In this branch the bit is not set meaning the kernel still
             * owns this block and the kernel is still filling up the block
             * with new packets
             */

            /* The set-after-check race here poses no stability issue
             * and only runs the chance of a streak getting lost which
             * is acceptable.
             */
            if (bstreak > thread_stor->longest_bstreak) {
                thread_stor->longest_bstreak = bstreak;
            }

            /* This streak has ended */
            bstreak = 0;

            /* we have processed all previously received packets.  since we
             * may potentially wait during poll, let us flush the output
             * file.  We'll only do this once before calling poll() as this
             * could allow us to avoid calling poll since the flush may take
             * just long enough for another block to have been returned to
             * us.
             */
            if ((haveflushed == 0) && (pstreak == 0)) {
                pkt_processor->flush();
                haveflushed = 1;
                continue; /* Restart the cb status check now that we flushed */
            }

            /* If poll() has returned but we haven't found any data... */
            if (pstreak > 2) {
                /* Since poll() keeps telling us there is data but we aren't
                 * seeing it in the current block our curent block pointer
                 * could be out of sync with the kernel's so we should go
                 * probe all the blocks and reset our pointer to the first
                 * filled block */
                for (uint32_t i = 0; i < thread_block_count; i++) {
                    if ((block_header[i]->hdr.bh1.block_status & TP_STATUS_USER) != 0) {
                        cb = i;
                        break; /* just stop at the first block found */
                    }
                }
            }

            /* Now that we've done the housekeeping, poll the kernel for
             * when data has been returned to us
             */
            polret = poll(&psockfd, 1, 1000); /* Let poll wait up to a second */
            if (polret < 0) {
                perror("poll returned error");
            } else if (polret == 0) {
                /* This was a timeout meaning we just aren't getting any
                 * packets at the moment. This isn't an error and there isn't
                 * anything special for us to do here.
                 */
            } else if (polret > 0) {
                pstreak++; /* This wasn't a timeout */
            }

        } else {
            /* In this branch the bit is set meaning the kernel has filled
             * this block and returned it to us for processing.
             */
            bstreak++; /* We've gotten another block */

            /* We found data, process it! */
            process_all_packets_in_block(block_header[cb], statst, pkt_processor);

            /* Reset our accounting */
            pstreak = 0; /* Reset the poll streak tracking */
            haveflushed = 0; /* We now have the chance to opportunistically flush again */

            /* return this block to the kernel */
            block_header[cb]->hdr.bh1.block_status = TP_STATUS_KERNEL;

            cb += 1; /* Advanced our current block pointer */
            cb %= thread_block_count; /* Wrap it */
        }

    } /* end while (sig_close_workers == 0) */

    fprintf(stderr, "[PACKET PROCESSOR] Thread %d with pthread id %lu (PID %u) exiting...\n", thread_stor->tnum, thread_stor->tid, thread_stor->kpid);
    return 0;
}


void *packet_capture_thread_func(void *arg)  {
    struct thread_storage *thread_stor = (struct thread_storage *)arg;

    /*
     * Disable all signals so that this worker thread is not disturbed
     * in the middle of packet processing.
     */
    disable_all_signals();

    /* now process the packets */
    if (af_packet_rx_ring_fanout_capture(thread_stor) < 0) {
        fprintf(stdout, "error: could not perform packet capture\n");
        exit(255);
    }
    return NULL;
}

enum status bind_and_dispatch(struct mercury_config *cfg,
                              mercury_context mc,
                              struct output_file *out_ctx,
                              struct cap_stats *cstats) {

     /* sanity check memory fractions */
    if (cfg->buffer_fraction < 0.0 || cfg->buffer_fraction > 1.0 ) {
        fprintf(stdout, "error: refusing to allocate buffer fraction %.3f\n", cfg->buffer_fraction);
        exit(255);
    }

    if (cfg->io_balance_frac < 0.0 || cfg->io_balance_frac > 1.0 ) {
        fprintf(stdout, "error: refusing to balance io buffers with %.3f\n", cfg->io_balance_frac);
        exit(255);
    }

    /* initialize the ring limits from the configuration */
    struct ring_limits rl;
    ring_limits_init(&rl, cfg->buffer_fraction * cfg->io_balance_frac);

    int err;
    int num_threads = cfg->num_threads;
    int fanout_arg = ((getpid() & 0xffff) | (rl.af_fanout_type << 16));

    /* We need all our threads to get a clean start at the same time or
     * else some threads will start working before other threads are ready
     * and this makes a mess of drop counters and gets in the way of
     * dropping privs and other such things that need to happen in a
     * coordinated manner. We pass a pointer to these via the thread
     * storage struct.
     */
    int t_start_p = 0;
    pthread_cond_t t_start_c  = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t t_start_m = PTHREAD_MUTEX_INITIALIZER;

    struct stats_tracking statst;
    memset(&statst, 0, sizeof(statst));
    statst.num_threads = num_threads;
    statst.t_start_p = &t_start_p;
    statst.t_start_c = &t_start_c;
    statst.t_start_m = &t_start_m;
    statst.verbosity = cfg->verbosity;

    struct thread_storage *tstor;  // Holds the array of struct thread_storage, one for each thread
    tstor = (struct thread_storage *)malloc(num_threads * sizeof(struct thread_storage));
    if (!tstor) {
        perror("could not allocate memory for strocut thread_storage array\n");
    }
    statst.tstor = tstor; // The stats thread needs to know how to access the socket for each packet worker

    global_thread_stall = (struct thread_stall *)malloc((num_threads + 1) * sizeof(struct thread_stall));
    if (!global_thread_stall) {
        perror("could not allocate memory for global thread stall structs\n");
    }
    for (int i = 0; i <= num_threads; i++) {
        global_thread_stall[i].used = 0;
        global_thread_stall[i].tid = 0;
    }

    /* Now that we know how many threads we will have, we need
     * to figure out what our ring parameters will be */
    uint32_t thread_ring_size;
    if (rl.af_desired_memory / num_threads > rl.af_ring_limit) {
        thread_ring_size = rl.af_ring_limit;
        fprintf(stderr, "Notice: desired memory exceeds %x memory for %d threads\n", rl.af_ring_limit, num_threads);
    } else {
        thread_ring_size = rl.af_desired_memory / num_threads;
    }

    /* If the number of blocks is fewer than our target
     * decrease the block size to increase the block count
     */
    uint32_t thread_ring_blocksize = rl.af_blocksize;
    while (((thread_ring_blocksize >> 1) >= rl.af_min_blocksize) &&
           (thread_ring_size / thread_ring_blocksize < rl.af_target_blocks)) {
        thread_ring_blocksize >>= 1; /* Halve the blocksize */
    }
    uint32_t thread_ring_blockcount = thread_ring_size / thread_ring_blocksize;
    if (thread_ring_blockcount < rl.af_min_blocks) {
        fprintf(stderr, "Error: only able to allocate %u blocks per thread (minimum %u)\n", thread_ring_blockcount, rl.af_min_blocks);
        exit(255);
    }

    /* blocks must be a multiple of the framesize */
    if (thread_ring_blocksize % rl.af_framesize != 0) {
        fprintf(stderr, "Error: computed thread blocksize (%u) is not a multiple of the framesize (%u)\n", thread_ring_blocksize, rl.af_framesize);
        exit(255);
    }

    if ((uint64_t)num_threads * (uint64_t)thread_ring_blockcount * (uint64_t)thread_ring_blocksize < rl.af_desired_memory) {
        fprintf(stderr, "Notice: requested input buffer memory %" PRIu64 " will be less than desired memory %" PRIu64 "\n",
                (uint64_t)num_threads * (uint64_t)thread_ring_blockcount * (uint64_t)thread_ring_blocksize, rl.af_desired_memory);
    }

    /* Fill out the ring request struct */
    struct tpacket_req3 thread_ring_req;
    memset(&thread_ring_req, 0, sizeof(thread_ring_req));
    thread_ring_req.tp_block_size = thread_ring_blocksize;
    thread_ring_req.tp_frame_size = rl.af_framesize;
    thread_ring_req.tp_block_nr = thread_ring_blockcount;
    thread_ring_req.tp_frame_nr = (thread_ring_blocksize * thread_ring_blockcount) / rl.af_framesize;
    thread_ring_req.tp_retire_blk_tov = rl.af_blocktimeout;
    thread_ring_req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    /* Get all the thread storage ready and allocate the sockets */
    for (int thread = 0; thread < num_threads; thread++) {
        /* Init the thread storage for this thread */
        tstor[thread].tnum = thread;
        tstor[thread].tid = 0;
        tstor[thread].sockfd = -1;
        tstor[thread].if_name = cfg->capture_interface;
        tstor[thread].statst = &statst;
        tstor[thread].t_start_p = &t_start_p;
        tstor[thread].t_start_c = &t_start_c;
        tstor[thread].t_start_m = &t_start_m;
        tstor[thread].longest_bstreak = 0;
        tstor[thread].force_stall = 0;
        tstor[thread].stall_cnt = 0;

        err = pthread_attr_init(&(tstor[thread].thread_attributes));
        if (err) {
            fprintf(stderr, "%s: error initializing attributes for thread %d\n", strerror(err), thread);
            exit(255);
        }

        pthread_mutexattr_t m_attr;
        err = pthread_mutexattr_init(&m_attr);
        if (err) {
            fprintf(stderr, "%s: error initializing block streak mutex attributes for thread %d\n", strerror(err), thread);
            exit(255);
        }

        memcpy(&(tstor[thread].ring_params), &thread_ring_req, sizeof(thread_ring_req));

        err = create_dedicated_socket(&(tstor[thread]), fanout_arg);

        if (err != 0) {
            fprintf(stderr, "error creating dedicated socket for thread %d\n", thread);
            exit(255);
        }
    }

    /* drop privileges from root to normal user */
    if (drop_root_privileges(cfg->user, cfg->working_dir) != status_ok) {
        return status_err;
    }
    if (cfg->user) {
        fprintf(stderr, "running as user %s\n", cfg->user);
    } else {
        fprintf(stderr, "dropped root privileges\n");
    }

    /*
     * initialze frame handlers
     */
    for (int thread = 0; thread < num_threads; thread++) {

        tstor[thread].pkt_processor = pkt_proc_new_from_config(cfg, mc, thread, &out_ctx->qs.queue[thread]);
        if (tstor[thread].pkt_processor == NULL) {
            printf("error: could not initialize frame handler\n");
            return status_err;
        }
    }

    // Some platforms (like OS X) have stack sizes that are too small
    pthread_attr_t pt_stack_size;

    err = pthread_attr_init(&pt_stack_size);
    if (err != 0) {
        printf("Unable to init stack size attribute for worker pthread: %s\n", strerror(err));
    }

    err = pthread_attr_setstacksize(&pt_stack_size, 16 * 1024 * 1024); // 16 MB is plenty big enough
    if (err != 0) {
        printf("Unable to set stack size attribute for worker pthread: %s\n", strerror(err));
    }

    /* Start up the threads */
    err = pthread_create(&(statst.tid), &pt_stack_size, stats_thread_func, &statst);
    if (err != 0) {
        perror("error creating stats thread");
        exit(255);
    }

    for (int thread = 0; thread < num_threads; thread++) {
        pthread_attr_t thread_attributes;
        err = pthread_attr_init(&thread_attributes);
        if (err) {
            fprintf(stderr, "%s: error initializing attributes for thread %d\n", strerror(err), thread);
            exit(255);
        }

        err = pthread_create(&(tstor[thread].tid), &thread_attributes, packet_capture_thread_func, &(tstor[thread]));
        if (err) {
            fprintf(stderr, "%s: error creating af_packet capture thread %d\n", strerror(err), thread);
            exit(255);
        }
    }

    /* Wake up output thread so it's polling the queues waiting for data */
    out_ctx->t_output_p = 1;
    err = pthread_cond_broadcast(&(out_ctx->t_output_c)); /* Wake up output */
    if (err != 0) {
        printf("%s: error broadcasting all clear on output start condition\n", strerror(err));
        exit(255);
    }

    /* At this point all threads are started but they're waiting on
       the clean start condition
    */
    t_start_p = 1;
    err = pthread_cond_broadcast(&t_start_c); // Wake up all the waiting threads
    if (err != 0) {
        printf("%s: error broadcasting all clear on clean start condition\n", strerror(err));
        exit(255);
    }

    /* Wait for the stats thread to close (which only happens on a sigint/sigterm) */
    pthread_join(statst.tid, NULL);

    /* stats tracking closed, let the packet processing workers know */
    sig_close_workers = 1;

    /* wait for each thread to exit */
    for (int thread = 0; thread < num_threads; thread++) {
        pthread_join(tstor[thread].tid, NULL);
    }

    /* free up resources */
    for (int thread = 0; thread < num_threads; thread++) {
        free(tstor[thread].block_header);
        munmap(tstor[thread].mapped_buffer, tstor[thread].ring_params.tp_block_size * tstor[thread].ring_params.tp_block_nr);
        close(tstor[thread].sockfd);
        delete tstor[thread].pkt_processor;
    }
    free(tstor);
    free(global_thread_stall);

    /* Report final capture stats back to main mercury thread */
    cstats->packets = statst.received_packets;
    cstats->bytes = statst.received_bytes;
    cstats->sock_packets = statst.socket_packets;
    cstats->drops = statst.socket_drops;
    cstats->freezes = statst.socket_freezes;

    return status_ok;
}

#define RING_LIMITS_DEFAULT_FRAC 0.01

void ring_limits_init(struct ring_limits *rl, float frac) {

    /* This is the only parameter you should need to change */
    rl->af_desired_memory = (uint64_t) sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE) * frac;
    //rl->af_desired_memory = 128 * (uint64_t)(1 << 30);  /* 8 GiB */
    fprintf(stderr, "mem: %" PRIu64 "\tfrac: %f\n", rl->af_desired_memory, frac);

    /* Note that with TPACKET_V3 the tp_frame_size value is effectively
     * ignored because packets are packed together tightly
     * to fill up a block.  There are still some restrictions
     * but for the most part changing it won't have any effect
     * and setting it small won't actually truncate any frames.
     */

    /* Don't change any of the following parameters without good reason */
    rl->af_ring_limit     = 0xffffffff;      /* setsockopt() can't allocate more than this so don't even try */
    rl->af_framesize      = 2  * (1 << 10);  /* default in docs is 2 KiB, don't go lower than this */
    rl->af_blocksize      = 4  * (1 << 20);  /* 4 MiB (MUST be a multiple of af_framesize) */
    rl->af_min_blocksize  = 64 * (1 << 10);  /* 64 KiB is the smallest we'd ever want to go */
    rl->af_target_blocks  = 64;              /* Fewer than this and we'll decrease the block size to get more blocks */
    rl->af_min_blocks     = 8;               /* 8 is a reasonable absolute minimum */
    rl->af_blocktimeout   = 100;             /* milliseconds before a block is returned partially full */
    rl->af_fanout_type    = PACKET_FANOUT_HASH;

}
