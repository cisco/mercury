/*
 * addr.h
 *
 * interface into address processing functions, including longest
 * prefix matching
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */


#include <string>

uint32_t get_asn_info(const char* dst_ip);

int addr_init(const char *resources_dir);

void addr_finalize();
