/*
 * udp.h
 *
 * UDP protocol processing
 */

#ifndef UDP_H
#define UDP_H

#include "extractor.h"

unsigned int packet_filter_process_udp(struct packet_filter *pf, struct key *k);

#endif

