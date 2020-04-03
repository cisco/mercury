/*
 * capture.c
 *
 * Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <stdio.h>
#include "mercury.h"
#include "output.h"

/*
 * bind_and_dispatch() is a stub function, used only when Linux
 * AF_PACKET TPACKETv3 is not available.  In the future, it may be
 * replaced by a more functional alternative.
 */
enum status bind_and_dispatch(struct mercury_config *cfg,
			      struct output_file *out_ctx) {

  (void)cfg;     // suppress compiler warnings
  (void)out_ctx;
  
  fprintf(stderr, "error: packet capture is unavailable; AF_PACKET TPACKETv3 not present\n");
  
  return status_err;
}


