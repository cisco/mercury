/*
 * addr.h
 *
 * interface into address processing functions, including longest
 * prefix matching
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef ADDR_H
#define ADDR_H

#include <string>
#include "archive.h"

uint32_t get_asn_info(const char* dst_ip);

int addr_init(encrypted_compressed_archive &archive);

void addr_finalize();

#endif // ADDR_H
