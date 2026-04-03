/*
 * signal_handling_stub.c
 *
 * signal handling code for mercury on non-Linux platforms
 *
 * Copyright (c) 2025 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "signal_handling.h"
#include "af_packet_v3.h"

volatile sig_atomic_t sig_close_flag = 0; /* Watched by the threads while processing packets */
struct thread_stall *global_thread_stall = NULL;

/*
 * sig_close() causes a graceful shutdown of the program after recieving
 * an appropriate signal
 */
void sig_close([[maybe_unused]] int signal_arg) {
    int saved_errno = errno;

    static const char msg[] = "\nshutting down\n";
    int l = write(STDERR_FILENO, msg, sizeof(msg) - 1);
    (void)l;

    sig_close_flag = 1;
    close(STDIN_FILENO);

    errno = saved_errno;
}

void sig_backtrace([[maybe_unused]] int signal_arg) { }

void sig_init_backtrace() { }


/*
 * set up signal handlers, so that output is flushed upon close
 */
enum status setup_signal_handler() {
    struct sigaction sa;
    struct sigaction old_sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_close;

    if (sigaction(SIGINT, &sa, &old_sa) != 0) {
        perror("Unable to register sig_close() for SIGINT");
        return status_err;
    }

    if (sigaction(SIGTERM, &sa, &old_sa) != 0) {
        perror("Unable to register sig_close() for SIGTERM");
        return status_err;
    }

    return status_ok;
}


/*
 * Enable all signals
 */
void enable_all_signals() {
    sigset_t signal_set;

    sigfillset(&signal_set);

    if (pthread_sigmask(SIG_UNBLOCK, &signal_set, NULL) != 0) {
        fprintf(stderr, "%s: error in pthread_sigmask unblocking signals\n",
                strerror(errno));
    }
}


/*
 * Disable signals
 */
void disable_all_signals() {
    sigset_t signal_set;

    sigfillset(&signal_set);

    if (pthread_sigmask(SIG_BLOCK, &signal_set, NULL) != 0) {
        fprintf(stderr, "%s: error in pthread_sigmask blocking signals\n",
                strerror(errno));
    }
}


/*
 * Enable backtrace signal (USR1)
 */
void enable_bt_signal() {
    sigset_t signal_set;

    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGUSR1);

    if (pthread_sigmask(SIG_UNBLOCK, &signal_set, NULL) != 0) {
        fprintf(stderr, "%s: error in pthread_sigmask unblocking backtrace signal\n",
                strerror(errno));
    }
}


/*
 * Disable backtrace signal (USR1)
 */
void disable_bt_signal() {
    sigset_t signal_set;

    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGUSR1);

    if (pthread_sigmask(SIG_BLOCK, &signal_set, NULL) != 0) {
        fprintf(stderr, "%s: error in pthread_sigmask blocking backtrace signal\n",
                strerror(errno));
    }
}
