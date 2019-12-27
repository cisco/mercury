/*
 * af_packet_v3.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef AF_PACKET_V3
#define AF_PACKET_V3

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

#include "mercury.h"
#include "af_packet_io.h"

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


typedef void (*packet_callback_t)(const struct packet_info *,
				  const uint8_t *);
/*
 * Our stats tracking function will get a pointer to a struct
 * that has the info it needs to track stats for each thread
 * and a place to store those stats
 */
struct stats_tracking {
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
};

/*
 * struct thread_storage stores information about each thread
 * including its thread id and socket file handle
 */
struct thread_storage {
  struct pkt_proc *pkt_processor;
  int tnum;                 /* Thread Number */
  pthread_t tid;            /* Thread ID */
  pthread_attr_t thread_attributes;
  int sockfd;               /* Socket owned by this thread */
  const char *if_name;      /* The name of the interface to bind the socket to */
  uint8_t *mapped_buffer;   /* The pointer to the mmap()'d region */
  struct tpacket_block_desc **block_header; /* The pointer to each block in the mmap()'d region */
  struct tpacket_req3 ring_params; /* The ring allocation params to setsockopt() */
  struct stats_tracking *statst;   /* A pointer to the struct with the stats counters */
  double *block_streak_hist;  /* The block streak histogram */
  pthread_mutex_t bstreak_m;  /* The block streak mutex */
  int *t_start_p;             /* The clean start predicate */
  pthread_cond_t *t_start_c;  /* The clean start condition */
  pthread_mutex_t *t_start_m; /* The clean start mutex */
};


int af_packet_bind_and_dispatch(//const char *if_name,
				//packet_callback_t p_callback,
				struct mercury_config *cfg,
				const struct ring_limits *rlp);

void ring_limits_init(struct ring_limits *rl, float frac);

#endif /* AF_PACKET_V3 */
