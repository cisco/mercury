/*
 * capture.c
 *
 * Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <stdio.h>
#include "mercury.h"
#include "output.h"


/* global_thread_stall is needed for signal handler access. However,
 * if Linux AF_PACKET TPACKETv3 is not available, it should be unused.
 * Therefore the bind_and_dispatch() stub below simply sets it to NULL.
 */
struct thread_stall *global_thread_stall;


/*
 * bind_and_dispatch() is a stub function, used only when Linux
 * AF_PACKET TPACKETv3 is not available.  In the future, it may be
 * replaced by a more functional alternative.
 */
enum status bind_and_dispatch(struct mercury_config *,
                              mercury_context,
                              struct output_file *,
                              struct cap_stats *) {

  fprintf(stderr, "error: packet capture is unavailable; AF_PACKET TPACKETv3 not present\n");

  global_thread_stall = NULL;

  return status_err;
}
