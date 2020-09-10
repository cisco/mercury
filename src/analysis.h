/*
 * analysis.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <stdio.h>
#include "pkt_proc.h"
#include "packet.h"
#include "addr.h"
#include "buffer_stream.h"

int analysis_init(int verbosity, const char *resource_dir);

int analysis_finalize();

void write_analysis_from_extractor_and_flow_key(struct buffer_stream &buf,
                                                const struct tls_client_hello &hello,
                                                const struct key &key);


#endif /* ANALYSIS_H */
