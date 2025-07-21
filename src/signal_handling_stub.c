/*
 * signal_handling_stub.c
 *
 * signal handling stub code for mercury (non-Linux platforms)
 *
 * Copyright (c) 2025 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */


#include "signal_handling.h"
#include "af_packet_v3.h"

volatile sig_atomic_t sig_close_flag = 0; /* Watched by the threads while processing packets */

/*
 * sig_close() causes a graceful shutdown of the program after recieving
 * an appropriate signal
 */
void sig_close ([[maybe_unused]] int signal_arg) { }

void sig_backtrace ([[maybe_unused]] int signal_arg) { }

void sig_init_backtrace() { }


/*
 * set up signal handlers, so that output is flushed upon close
 */
enum status setup_signal_handler() { return status_ok; }


/*
 * Enable all signals
 */
void enable_all_signals() { }


/*
 * Disable signals
 */
void disable_all_signals() { }


/*
 * Enable backtrace signal (USR1)
 */
void enable_bt_signal() { }


/*
 * Disable backtrace signal (USR1)
 */
void disable_bt_signal() { }
