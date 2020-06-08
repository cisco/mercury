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


/** usage string */
#define dns_usage "  dns=1                      report DNS response information\n"

/** dns filter key */
#define dns_filter(record) \
    ((record->key.prot == 17) && \
     (record->app == 53 || (record->key.dp == 53 || record->key.sp == 53)) \
    )

/** maximum number of DNS packets */
#define MAX_NUM_DNS_PKT 200

/** maximum DNS name length */
#define MAX_DNS_NAME_LEN 256

/** DNS structure */
typedef struct dns_ {
  unsigned int pkt_count;                      /*!< packet count       */
  char *dns_name[MAX_NUM_DNS_PKT];             /*!< DNS packets        */
  unsigned short int pkt_len[MAX_NUM_DNS_PKT]; /*!< DNS packet lengths */
} dns_t;

/** initialize DNS structure */
void dns_init(dns_t **dns_handle);

/** DNS structure update */
void dns_update(dns_t *dns, 
		const struct pcap_pkthdr *header,
		const void *data, 
		unsigned int len, 
		unsigned int report_dns);

/** print DNS data out in JSON format */
//void dns_print_json(const dns_t *dns1, const dns_t *dns2, zfile f);

/** remove a DNS entry */
//void dns_delete(dns_t **dns_handle);

/** main entry point for DNS unit testing */
//void dns_unit_test(void);

void write_dns_server_data(const uint8_t *data, size_t length, struct buffer_stream &buf);

#endif /* DNS_H */
