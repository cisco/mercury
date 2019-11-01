/*
 * tcp.c
 *
 */



#include "tcp.h"

enum status tcp_initial_message_filter_init(struct tcp_initial_message_filter *filter) {

    (void)filter;

    return status_ok;
}

unsigned int tcp_initial_message_filter_tcp_packet(const struct flow_key *k,
                                                   const tcp_state *tcp_state) {
    (void)k;
    (void)tcp_state;

    return 0;
}
