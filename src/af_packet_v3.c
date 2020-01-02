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

#include <time.h>
#include <math.h>

#include "af_packet_io.h"
#include "af_packet_v3.h"
#include "signal_handling.h"
#include "utils.h"
#include "rnd_pkt_drop.h"

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
extern int sig_close_flag; /* Watched by the stats tracking thread, defined in mercury.c */
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
    statst->socket_packets += tp3_stats.tp_packets;
    statst->socket_drops += tp3_stats.tp_drops;
    statst->socket_freezes += tp3_stats.tp_freeze_q_cnt;
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
    byte_count += pkt_hdr->tp_snaplen;

    /* Grab the times */
    pi.ts.tv_sec = pkt_hdr->tp_sec;
    pi.ts.tv_nsec = pkt_hdr->tp_nsec;

    pi.caplen = pkt_hdr->tp_snaplen;
    pi.len = pkt_hdr->tp_snaplen; // Is this right??

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
    int duration = 0, socket_drops = 0, zero_drops = 0;

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
  /**
   * Enable all signals so that this thread shuts down first
   */
  enable_all_signals();

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
    double tot_rusage = 0;   /* Sum of all threads rusage */
    double worst_rusage = 0; /* Worst average rbuffer usage */
    double worst_i_rusage = 0; /* Worst instantanious rbuffer usage */
    for (int thread = 0; thread < statst->num_threads; thread++) {
      af_packet_stats(statst->tstor[thread].sockfd, statst);

      int thread_block_count = statst->tstor[thread].ring_params.tp_block_nr;
      double *bstreak_hist = statst->tstor[thread].block_streak_hist;

      /* Get the lock for the bstreak histogram computation */
      err = pthread_mutex_lock(&(statst->tstor[thread].bstreak_m));
      if (err != 0) {
	fprintf(stderr, "%s: stats func error acquiring bstreak mutex lock\n", strerror(err));
	exit(255);
      }

      /* First compute the time total */
      double ttot = 0;
      for (int i = 0; i <= thread_block_count; i++) {
	ttot += bstreak_hist[i];

	if (bstreak_hist[i] > 0) {
	  double utmp = (double)(i) / (double)thread_block_count;
	  if (utmp > worst_i_rusage) {
	    worst_i_rusage = utmp;
	  }
	}
	//fprintf(stderr, "%d: %lu\n", i, bstreak_hist[i]);
      }
      //fprintf(stderr, "time total: %f\n", ttot);

      /* Now compute the average (weighted) ring usage */
      double rusage = 0;
      if (ttot > 0) {
	for (int i = 0; i <= thread_block_count; i++) {
	  rusage += (bstreak_hist[i] / ttot) * ((double)(i) / (double)thread_block_count);
	}
      }

      /* Now clear the bstreak histogram */
      for (int i = 0; i <= thread_block_count; i++) {
	bstreak_hist[i] = 0;
      }

      err = pthread_mutex_unlock(&(statst->tstor[thread].bstreak_m));
      if (err != 0) {
	fprintf(stderr, "%s: stats func error releasing bstreak mutex lock\n", strerror(err));
	exit(255);
      }

      //fprintf(stderr, "[thread %d] Got ring usage of %4f\n", thread, rusage);
      tot_rusage += rusage;
      if (rusage > worst_rusage) {
	worst_rusage = rusage;
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

    fprintf(stderr,
	    "Stats: "
	    "%7.03f%s Packets/s; Data Rate %7.03f%s bytes/s; "
	    "Ethernet Rate (est.) %7.03f%s bits/s; "
	    "Socket Packets %7.03f%s; Socket Drops %" PRIu64 " (packets); Socket Freezes %" PRIu64 "; "
	    "All threads avg. rbuf %4.1f%%; Worst thread avg. rbuf %4.1f%%; Worst instantanious rbuf %4.1f%%\n",
	    r_pps, r_pps_s, r_byps, r_byps_s,
	    r_ebips, r_ebips_s,
	    r_spps, r_spps_s, sdps, sfps,
	    (tot_rusage / (statst->num_threads)) * 100.0, worst_rusage * 100.0,
	    worst_i_rusage * 100.0);
 
    duration++;
    if (get_percent_accept() > 0) {
        /* check socket drops and update accept percentage only when percent accept > 0 */
        check_socket_drops(duration, sdps, sfps, &socket_drops, &zero_drops);
    }
  }

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
  uint8_t *mapped_buffer = (uint8_t*)mmap(NULL, thread_stor->ring_params.tp_block_size * thread_stor->ring_params.tp_block_nr,
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
  double *block_streak_hist = thread_stor->block_streak_hist;
  pthread_mutex_t *bstreak_m = &(thread_stor->bstreak_m);
  //packet_callback_t p_callback = thread_stor->p_callback;
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

  fprintf(stderr, "Thread %d with thread id %lu started...\n", thread_stor->tnum, thread_stor->tid);

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
  uint64_t bstreak = 0; /* The number of blocks in a row we've gotten without a poll() */
  int polret;           /* The return value from poll() */
  int haveflushed = 0;  /* Tracks whether we've opportunistically flushed yet or not */
  unsigned int cb = 0;  /* The current block pointer (index) */
  struct timespec ts;
  (void)time_elapsed(&ts); /* init the struct for us */
  double time_d; /* The time delta */
  while (sig_close_workers == 0) {

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

      /* Track the number of blocks in a row in this streak */
      time_d = time_elapsed(&ts); /* How long this streak lasted */

      if (bstreak > thread_block_count) {
	bstreak = thread_block_count;
      }

      /* The use of a mutex can be justified in this case
       * because 1) this will rarely ever clash with the stats
       * thread and 2) there aren't any blocks for us to process
       * at the moment so we can take a tiny bit of time tracking
       * stats and such
       */
      err = pthread_mutex_lock(bstreak_m);
      if (err != 0) {
	fprintf(stderr, "%s: error acquiring bstreak mutex lock\n", strerror(err));
	exit(255);
      }

      block_streak_hist[bstreak] += time_d;

      err = pthread_mutex_unlock(bstreak_m);
      if (err != 0) {
	fprintf(stderr, "%s: error releasing bstreak mutex lock\n", strerror(err));
	exit(255);
      }

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

  fprintf(stderr, "Thread %d with thread id %lu exiting...\n", thread_stor->tnum, thread_stor->tid);
  return 0;
}


void *packet_capture_thread_func(void *arg)  {
  struct thread_storage *thread_stor = (struct thread_storage *)arg;

  /**
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


int af_packet_bind_and_dispatch(struct mercury_config *cfg,
				const struct ring_limits *rlp) {
  int err;
  int num_threads = cfg->num_threads;
  int fanout_arg = ((getpid() & 0xffff) | (rlp->af_fanout_type << 16));

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

  struct thread_storage *tstor;  // Holds the array of struct thread_storage, one for each thread
  tstor = (struct thread_storage *)malloc(num_threads * sizeof(struct thread_storage));
  if (!tstor) {
    perror("could not allocate memory for strocut thread_storage array\n");
  }
  statst.tstor = tstor; // The stats thread needs to know how to access the socket for each packet worker

  /* Now that we know how many threads we will have, we need
   * to figure out what our ring parameters will be */
  uint32_t thread_ring_size;
  if (rlp->af_desired_memory / num_threads > rlp->af_ring_limit) {
    thread_ring_size = rlp->af_ring_limit;
    fprintf(stderr, "Notice: desired memory exceedes %x memory for %d threads\n", rlp->af_ring_limit, num_threads);
  } else {
    thread_ring_size = rlp->af_desired_memory / num_threads;
  }

  /* If the number of blocks is fewer than our target
   * decrease the block size to increase the block count
   */
  uint32_t thread_ring_blocksize = rlp->af_blocksize;
  while (((thread_ring_blocksize >> 1) >= rlp->af_min_blocksize) &&
	 (thread_ring_size / thread_ring_blocksize < rlp->af_target_blocks)) {
    thread_ring_blocksize >>= 1; /* Halve the blocksize */
  }
  uint32_t thread_ring_blockcount = thread_ring_size / thread_ring_blocksize;
  if (thread_ring_blockcount < rlp->af_min_blocks) {
    fprintf(stderr, "Error: only able to allocate %u blocks per thread (minimum %u)\n", thread_ring_blockcount, rlp->af_min_blocks);
    exit(255);
  }

  /* blocks must be a multiple of the framesize */
  if (thread_ring_blocksize % rlp->af_framesize != 0) {
    fprintf(stderr, "Error: computed thread blocksize (%u) is not a multiple of the framesize (%u)\n", thread_ring_blocksize, rlp->af_framesize);
    exit(255);
  }

  if ((uint64_t)num_threads * (uint64_t)thread_ring_blockcount * (uint64_t)thread_ring_blocksize < rlp->af_desired_memory) {
    fprintf(stderr, "Notice: requested memory %" PRIu64 " will be less than desired memory %" PRIu64 "\n",
	    (uint64_t)num_threads * (uint64_t)thread_ring_blockcount * (uint64_t)thread_ring_blocksize, rlp->af_desired_memory);
  }

  /* Fill out the ring request struct */
  struct tpacket_req3 thread_ring_req;
  memset(&thread_ring_req, 0, sizeof(thread_ring_req));
  thread_ring_req.tp_block_size = thread_ring_blocksize;
  thread_ring_req.tp_frame_size = rlp->af_framesize;
  thread_ring_req.tp_block_nr = thread_ring_blockcount;
  thread_ring_req.tp_frame_nr = (thread_ring_blocksize * thread_ring_blockcount) / rlp->af_framesize;
  thread_ring_req.tp_retire_blk_tov = rlp->af_blocktimeout;
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

    err = pthread_mutex_init(&(tstor[thread].bstreak_m), &m_attr);
    if (err) {
      fprintf(stderr, "%s: error initializing block streak mutex for thread %d\n", strerror(err), thread);
      exit(255);
    }

    tstor[thread].tnum = thread;
    tstor[thread].tid = 0;
    tstor[thread].sockfd = -1;
    tstor[thread].if_name = cfg->capture_interface;
    tstor[thread].statst = &statst;
    tstor[thread].t_start_p = &t_start_p;
    tstor[thread].t_start_c = &t_start_c;
    tstor[thread].t_start_m = &t_start_m;

    tstor[thread].block_streak_hist = (double *)calloc(thread_ring_blockcount + 1, sizeof(double));
    if (!(tstor[thread].block_streak_hist)) {
      perror("could not allocate memory for thread stats block streak histogram\n");
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
      printf("running as user %s\n", cfg->user);
  } else {
      printf("dropped root privileges\n");
  }

  if (num_threads > 1) {
      
      /*
       * create subdirectory into which each thread will write its output
       */
      char *outdir = cfg->fingerprint_filename ? cfg->fingerprint_filename : cfg->write_filename;
      enum create_subdir_mode mode = cfg->rotate ? create_subdir_mode_overwrite : create_subdir_mode_do_not_overwrite;
      create_subdirectory(outdir, mode);
  }

  /*
   * initialze frame handlers 
   */
  for (int thread = 0; thread < num_threads; thread++) {
      char *fileset_id = NULL;
      char hexname[MAX_HEX];
      
      if (num_threads > 1) {
	  /*
	   * use thread number as a fileset file identifier (filename = short hex number)
	   */
	  snprintf(hexname, MAX_HEX, "%x", thread);
	  fileset_id = hexname;
      }

      tstor[thread].pkt_processor = pkt_proc_new_from_config(cfg, thread, fileset_id);
      if (tstor[thread].pkt_processor == NULL) {
          printf("error: could not initialize frame handler\n");
          return status_err;
      }
  }

  /* Start up the threads */
  pthread_t stats_thread;
  err = pthread_create(&stats_thread, NULL, stats_thread_func, &statst);
  if (err != 0) {
    perror("error creating stats thread");
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

  /* At this point all threads are started but they're waiting on
     the clean start condition
  */
  t_start_p = 1;
  err = pthread_cond_broadcast(&(t_start_c)); // Wake up all the waiting threads
  if (err != 0) {
    printf("%s: error broadcasting all clear on clean start condition\n", strerror(err));
    exit(255);
  }

  /* Wait for the stats thread to close (which only happens on a sigint/sigterm) */
  pthread_join(stats_thread, NULL);

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
    free(tstor[thread].block_streak_hist);
    close(tstor[thread].sockfd);
    delete tstor[thread].pkt_processor;
  }
  free(tstor);

  fprintf(stderr, "--\n"
	  "%" PRIu64 " packets captured\n"
	  "%" PRIu64 " bytes captured\n"
	  "%" PRIu64 " packets seen by socket\n"
	  "%" PRIu64 " packets dropped\n"
	  "%" PRIu64 " socket queue freezes\n",
	  statst.received_packets, statst.received_bytes, statst.socket_packets, statst.socket_drops, statst.socket_freezes);

  return 0;
}

#define RING_LIMITS_DEFAULT_FRAC 0.01

void ring_limits_init(struct ring_limits *rl, float frac) {

    if (frac < 0.0 || frac > 1.0 ) { /* sanity check */
	frac = RING_LIMITS_DEFAULT_FRAC;
    }
    
    /* This is the only parameter you should need to change */
    rl->af_desired_memory = (uint64_t) sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE) * frac;
    //rl->af_desired_memory = 128 * (uint64_t)(1 << 30);  /* 8 GiB */
    printf("mem: %" PRIu64 "\tfrac: %f\n", rl->af_desired_memory, frac); 

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
