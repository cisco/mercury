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

enum analysis_cfg { analysis_off = 0, analysis_on = 1 };

int analysis_init();

int analysis_finalize();

void fprintf_analysis_from_extractor_and_flow_key(FILE *file,
						  const struct extractor *x,
						  const struct flow_key *key);

void write_analysis_from_extractor_and_flow_key(struct buffer_stream &buf,
                                                const struct extractor *x,
                                                const struct flow_key *key);

#endif /* ANALYSIS_H */
