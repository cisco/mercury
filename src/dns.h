/*
 * dns.h
 *
 * Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

/**
 * \file dns.h
 *
 * \brief interface file for DNS code
 */
#ifndef DNS_H
#define DNS_H

/** maximum DNS name length */
#define MAX_DNS_NAME_LEN 256

void write_dns_server_data(const uint8_t *data, size_t length, struct buffer_stream &buf);

#endif /* DNS_H */
