/*
 * llq - lockless queue (ringbuffer) for inter-thread communication
 *
 * Copyright (c) 2021 Cisco Systems, Inc.  All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef LLQ_H
#define LLQ_H

#include <unistd.h>
#include <stdint.h>

#define LLQ_MAX_MSG_SIZE (1 << 20)   /* At least this many bytes must be free */


/* The message object suitable for the std::priority_queue */
struct llq_msg {
    uint8_t *buf; /* Will end up pointing right after this struct */
    ssize_t len;
    struct timespec ts;
};


/* a lockless ringbuffer */
struct ll_queue {
    int qnum;           /* This is the queue number and is only needed for debugging */
    int llq_len;        /* The length of the ringbuffer */
    volatile int ridx;  /* The read index */
    int widx;           /* The write index */
    int need_read;      /* Has writer wraped around and ran into reader */
    int drops;          /* Output drop counter */
    uint8_t *rbuf;      /* The ringbuffer */

    struct llq_msg * init_msg(bool blocking, unsigned int sec, unsigned int nsec) {

        /* If we're blocking we gotta restart from here */
    blocking_retry_loop:

        struct llq_msg *m = (struct llq_msg *)&rbuf[widx];


        int cur_ridx = __atomic_load_n(&ridx, __ATOMIC_RELAXED);
        int cur_need_read = __atomic_load_n(&need_read, __ATOMIC_RELAXED);

        int space_available = 0;

        if (cur_need_read == 1) {
            if (widx != cur_ridx) {

                /* Looks like we no longer need a read */
                __atomic_store_n(&need_read, 0, __ATOMIC_RELAXED);
                cur_need_read = 0;
            }
        }

        if (cur_need_read == 0) {
            if (widx >= cur_ridx) {
                space_available = llq_len - widx;
            } else {
                space_available = cur_ridx - widx;
            }
        }


        if (space_available >= LLQ_MAX_MSG_SIZE) {

            m->ts.tv_sec = sec;
            m->ts.tv_nsec = nsec;
            m->buf = &(rbuf[widx + sizeof(struct llq_msg)]);

            return m;

        } else {
            if (blocking) {
                usleep(1000); /* don't spin too fast */
                goto blocking_retry_loop;

            } else {
                __sync_add_and_fetch(&(drops), 1);

                return nullptr;
            }
        }
    }

    void send(ssize_t length) {
        struct llq_msg *m = (struct llq_msg *)&rbuf[widx];

        m->len = length;

        int cur_ridx = __atomic_load_n(&ridx, __ATOMIC_RELAXED);

        int new_widx = widx + sizeof(llq_msg) + length;

        if (new_widx + LLQ_MAX_MSG_SIZE >= llq_len) {
            /* wrap ringbuffer */
            new_widx = 0;
        }

        if (new_widx == cur_ridx) {
            /* We just ran into reader, we need a read before we can write again */
            __atomic_store_n(&need_read, 1, __ATOMIC_RELAXED);
        }

        /* Update writer index */
        __atomic_store_n(&widx, new_widx, __ATOMIC_RELAXED);
    }


    struct llq_msg * try_read() {
        struct llq_msg *m = (struct llq_msg *)&rbuf[ridx];

        int cur_widx = __atomic_load_n(&widx, __ATOMIC_RELAXED);

        if (cur_widx != ridx) {
            /* we're not at the writer, reading is fine */
            return m;
        } else {
            int cur_need_read = __atomic_load_n(&need_read, __ATOMIC_RELAXED);

            if (cur_need_read == 1) {
                /* Writer is waiting for our read */
                return m;
            } else {
                /* We're waiting for a message */
                return nullptr;
            }
        }
    }

    void complete_read() {
        struct llq_msg *m = (struct llq_msg *)&rbuf[ridx];

        int new_ridx = ridx + sizeof(llq_msg) + m->len;

        if (new_ridx + LLQ_MAX_MSG_SIZE >= llq_len) {
            /* wrap ringbuffer */
            new_ridx = 0;
        }

        /* Update reader index */
        __atomic_store_n(&ridx, new_ridx, __ATOMIC_RELAXED);
    }
};


struct thread_queues {
    int qnum;                    /* The number of queues that have been allocated */
    int qidx;                    /* The index of the first free queue */
    struct ll_queue *queue;      /* The actual queue datastructure */
};


#endif // LLQ_H
