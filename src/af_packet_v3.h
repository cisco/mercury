/*
 * af_packet_v3.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef AF_PACKET_V3
#define AF_PACKET_V3

#include "mercury.h"
#include "output.h"

enum status bind_and_dispatch(struct mercury_config *cfg,
                              mercury_context mc,
                              struct output_file *out_ctx);

#endif /* AF_PACKET_V3 */
