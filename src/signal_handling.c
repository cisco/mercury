/*
 * signal_handling.c
 *
 * signal handling code for mercury and its threads
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include "signal_handling.h"

int sig_close_flag = 0; /* Watched by the threads while processing packets */

/*
 * sig_close() causes a graceful shutdown of the program after recieving
 * an appropriate signal
 */
void sig_close (int signal_arg) {
    psignal(signal_arg, "\nGracefully shutting down");
    sig_close_flag = 1; /* tell all threads to shutdown gracefully */
}

/*
 * set up signal handlers, so that output is flushed upon close
 *
 */
enum status setup_signal_handler(void) {
    /* Ctl-C causes graceful shutdown */
    if (signal(SIGINT, sig_close) == SIG_ERR) {
        return status_err;
    }

    /* kill -15 causes graceful shutdown */
    if (signal(SIGTERM, sig_close) == SIG_ERR) {
        return status_err;
    }

    return status_ok;
}

/**
 * Enable all signals
 */
void enable_all_signals(void) {
  sigset_t signal_set;
  sigfillset(&signal_set);
  if (pthread_sigmask(SIG_UNBLOCK, &signal_set, NULL) != 0) {
      fprintf(stderr, "%s: error in pthread_sigmask unblocking signals\n", 
              strerror(errno));
  }
}

  /**
   * Disable signals
   */
void disable_all_signals(void) {
  sigset_t signal_set;
  sigfillset(&signal_set);
  if (pthread_sigmask(SIG_BLOCK, &signal_set, NULL) != 0) {
      fprintf(stderr, "%s: error in pthread_sigmask blocking signals\n", 
              strerror(errno));
  }
}
