/*
 * signal_handling.h
 * 
 * header file for signal handling in mercury.
 * 
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at 
 * https://github.com/cisco/mercury/blob/master/LICENSE 
 */

#ifndef SIGNAL_HANDLING_H
#define SIGNAL_HANDLING_H

#include <signal.h>
#include "mercury.h"

extern volatile sig_atomic_t sig_close_flag; /* Watched by the threads while processing packets */
extern struct thread_stall *global_thread_stall;

void sig_close (int signal_arg);

void sig_backtrace (int signal_arg);
void sig_init_backtrace();

enum status setup_signal_handler(void);

void enable_all_signals(void);

void disable_all_signals(void);

#endif /* SIGNAL_HANDLING_H */
