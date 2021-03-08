/**
 * rand_pkt_drop.c
 *
 * random packet drops, to enable testing that adaptively finds the
 * maximum packet throughput
 *
 * Copyright (c) 2021 Cisco Systems, Inc.  All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <stdlib.h>

int rnd_pkt_drop_percent_accept = 0; /* default */

int get_percent_accept(void) {
    int zero = 0;
    return __sync_add_and_fetch(&rnd_pkt_drop_percent_accept, zero);
}

void set_percent_accept(unsigned int p) {
    rnd_pkt_drop_percent_accept = p;
}


int increment_percent_accept(int incr) {
    int val = get_percent_accept();
    int new_val = val + incr;
    if (new_val <= 10 || new_val >= 100) {
       /* do not set the value out of range 10 to 100 */
       return val;
    } else {
       return __sync_add_and_fetch(&rnd_pkt_drop_percent_accept, incr);
    }
}

int select_random(int percent) {
    /* get random number in the range of 1 to 101 */
    int random_num = rand() % 101 + 1;

    /**
     * from the random_num, determine if we want to select this packet
     * depending on the accept_percentage (defined and set in configure.c)
     */
    if (random_num < percent) {
        return 1;
    } else {
        return 0;
    }
}


unsigned int drop_this_packet(void) {
    int percent = get_percent_accept();
    if (percent > 0) {
        if (select_random(percent) == 0) {
            return 1;
        }
    }
    return 0;
}
