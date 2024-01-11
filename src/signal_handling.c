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
#include <execinfo.h>

#include <setjmp.h>    /* For thread stall recovery */

#include "signal_handling.h"
#include "af_packet_v3.h"

int sig_close_flag = 0; /* Watched by the threads while processing packets */

/*
 * sig_close() causes a graceful shutdown of the program after recieving
 * an appropriate signal
 */
void sig_close (int signal_arg) {
    psignal(signal_arg, "\nshutting down");
    sig_close_flag = 1; /* tell all threads to shutdown gracefully */
    fclose(stdin);      /* if are reading from stdin, stop reading */
}


void sig_backtrace (int signal_arg) {

    int nptrs;
    void *buffer[128];

    psignal(signal_arg, "\ngetting backtrace");
    nptrs = backtrace(buffer, 128);
    fprintf(stderr, "backtrace() returned %d addresses\n", nptrs);
    backtrace_symbols_fd(buffer, nptrs, STDERR_FILENO);

    /* Find an execution context to restore */
    pthread_t tid = pthread_self();
    int tnum = 0;

    while (global_thread_stall[tnum].used != 0) {
        if (global_thread_stall[tnum].tid == tid) {
            /* We found which global context was saved
             * for this thread so we can now break out
             * of this stall
             */
            siglongjmp(global_thread_stall[tnum].jmp_env, 1);
        }

        tnum++;
    }
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

    /* kill -USR1 causes (thread) to print backtrace */
    if (signal(SIGUSR1, sig_backtrace) == SIG_ERR) {
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
  sigdelset(&signal_set, SIGUSR1); /* except the USR1 signal for backtraces */
  if (pthread_sigmask(SIG_BLOCK, &signal_set, NULL) != 0) {
      fprintf(stderr, "%s: error in pthread_sigmask blocking signals\n", 
              strerror(errno));
  }
}
