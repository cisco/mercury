/*
 * rnd_pkt_drop.h
 */

#ifndef RND_PKT_DROP_H
#define RND_PKT_DROP_H

int get_percent_accept(void);

void set_percent_accept(unsigned int p);

int increment_percent_accept(int incr);

int select_random(int percent);

unsigned int drop_this_packet(void);

#endif /* RND_PKT_DROP_H */
