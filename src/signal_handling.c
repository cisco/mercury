/*
 * signal_handling.c
 *
 * signal handling code for mercury and its threads
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <execinfo.h>

#include <setjmp.h>    /* For thread stall recovery */

#include "signal_handling.h"
#include "af_packet_v3.h"

volatile sig_atomic_t sig_close_flag = 0; /* Watched by the threads while processing packets */

/*
 * sig_close() causes a graceful shutdown of the program after recieving
 * an appropriate signal
 */
void sig_close (int signal_arg) {
    int saved_errno = errno; /* in case we modify it */

    (void)signal_arg; /* "use" argument */

    static const char *msg = "\nshutting down\n";

    int l = write(STDERR_FILENO, msg, strlen(msg));
    (void)l;

    sig_close_flag = 1; /* tell all threads to shutdown gracefully */

    fclose(stdin);      /* if are reading from stdin, stop reading */

    errno = saved_errno; /* restore */
}


__attribute__((noreturn)) void sig_backtrace (int signal_arg) {

    int saved_errno = errno; /* in case we modify it */

    (void)signal_arg; /* "use" argument */
    /* We can't call perror() or psignal() here with signal_arg because
       both are AS-Unsafe corrupt i18n heap */

    void *buffer[128];

    static const char *msg = "\nThread stall handled: getting backtrace\n";

    int nptrs = backtrace(buffer, 128); /* MT-Safe | AS-Unsafe init heap dlopen plugin lock */

    int l = write(STDERR_FILENO, msg, strlen(msg)); /* POSIX 2016 signal safe */
    if (l > 0) {
        backtrace_symbols_fd(buffer, nptrs, STDERR_FILENO); /* MT-Safe | AS-Safe | AC-Unsafe lock */
    }

    /* Find an execution context to restore */
    pthread_t tid = pthread_self();
    int tnum = 0;

    while (global_thread_stall[tnum].used != 0) {
        if (global_thread_stall[tnum].tid == tid) {
            /* We found which global context was saved
             * for this thread so we can now break out
             * of this stall
             */

            errno = saved_errno; /* restore from possible modification */

            siglongjmp(global_thread_stall[tnum].jmp_env, 1);
        }

        tnum++;
    }

    /* We are never supposed to get to the end of this signal handler since
     * we longjmp out
     */
    abort();
}


void sig_init_backtrace() {

    /* backtrace() is not safe if first called from a
     * signal handler because it calls dlopen() to load
     * the library needed to perform said backtrace which
     * in turn calls malloc() which is strictly forbidden
     * in a signal handler.
     *
     * So the solution is to call backtrace once first to
     * get the library open before registering the signal
     * handler.
     */

    void *buffer[128];
    int nptrs = backtrace(buffer, 128);
    (void)nptrs;
}


/*
 * set up signal handlers, so that output is flushed upon close
 *
 */
enum status setup_signal_handler(void) {

    static int load_bt = 0;

    /* Pre-load backtrace library */
    if (load_bt == 0) {
        sig_init_backtrace();
        load_bt = 1;
    }

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
