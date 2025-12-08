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
#include <stdio.h>
#include <stdlib.h>

#define LLQ_MAX_MSG_SIZE (1 << 20)   /* At least this many bytes must be free */


/* The message object suitable for the std::priority_queue */
struct llq_msg {
    uint8_t *buf; /* Will end up pointing right after this struct */
    ssize_t len;
    struct timespec ts;
};


/* a lockless ringbuffer */
struct ll_queue {
    int qnum;             /* This is the queue number and is only needed for debugging */
    uint8_t *rbuf;        /* The ringbuffer */
    uint64_t llq_len;     /* The length of the ringbuffer */
    uint64_t ridx;        /* The read index */
    uint64_t widx;        /* The write index */
    int need_read;        /* Special case: writer wraped around and ran into reader */
    uint64_t drops;       /* Output drop counter */
    uint64_t drops_trunc; /* Drops due to truncation counter */


    /* This lockless ringbuffer supports a thread writing separately
     * from a thread reading without the need for locks. This is achieved with
     * atomic loads and stores.
     *
     * Both writing and reading are two-step operations with two
     * access member functions.
     *
     * writing: init_msg() followed by send()
     * reading: try_read() followed by complete_read()
     *
     * init_msg() makes sure there is enough space free
     * for a message (the struct header + the message bytes)
     * so that writing doesn't run into the reader.
     *
     * send() recieves the true message size written (which is almost
     * always less than the maximum allowed size) and updates the
     * write index accordingly. send() handles wrapping the write
     * index around as not to run into the end of the buffer.  There
     * is an edge-case when sending where the message just written
     * causes the write index to catch up to the read index (meaning
     * the write index is actually so far ahead of the read index that
     * it has wrapped around and run into reading). In this situation
     * the writer must wait for the reader. This is different than the
     * starting situation where the write and read index are equal
     * because the reader is fully caught up and waiting on the
     * writer.
     *
     * try_read() checks that either it is behind the writer or is in
     * the special case described in send() where reading is so far
     * behind the writer has caught up to the reader and must wait on
     * the reader.
     *
     * complete_read() simply advances the read index and handles the
     * buffer wrapping logic. Note that complete_read() does not need
     * to handle clearing the special case flag because init_msg()
     * checks and identifies when the reader has advanced again and
     * the writer is no longer in the special case of needing to wait
     * for the reader.
     *
     */

    struct llq_msg * init_msg(bool blocking, unsigned int sec,
    unsigned int nsec) {

        /* If we're blocking we gotta restart from here */
    blocking_retry_loop:

        struct llq_msg *m = (struct llq_msg *)&rbuf[widx];

        uint64_t cur_ridx = __atomic_load_n(&ridx, __ATOMIC_ACQUIRE);
        uint64_t cur_need_read = __atomic_load_n(&need_read, __ATOMIC_ACQUIRE);

        uint64_t space_available = 0;

        if (cur_need_read == 1) {
            if (widx != cur_ridx) {
                /* Looks like we no longer need a read */
                __atomic_store_n(&need_read, 0, __ATOMIC_RELEASE);
                cur_need_read = 0;
            }
        }

        if (cur_need_read == 0) {
            if (widx >= cur_ridx) {
                /* In this case the space_available will always be
                 * greater than is needed for another message because
                 * the send() function always wraps the write idex
                 * around anytime the write index would be too close
                 * to the end. As such, the following space available
                 * check will always pass
                 */

                space_available = llq_len - widx;
            } else {
                /* In this case the writer could actually be catching
                 * up to the reader and the following space avaialable
                 * check could fail which either results in a drop or
                 * in blocking-mode the loop is restarted via the goto
                 */

                space_available = cur_ridx - widx;
            }
        }


        if (space_available >= LLQ_MAX_MSG_SIZE + sizeof(struct llq_msg)) {

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
        if (length > LLQ_MAX_MSG_SIZE) {
            fprintf(stderr, "llq bug: attempted to enqueue oversized message (%zd > %d)\n",
                    length, LLQ_MAX_MSG_SIZE);
            abort();
        }

        struct llq_msg *m = (struct llq_msg *)&rbuf[widx];

        m->len = length;

        uint64_t cur_ridx = __atomic_load_n(&ridx, __ATOMIC_ACQUIRE);

        uint64_t new_widx = widx + sizeof(struct llq_msg) + length;

        /* There must be space free at the end of the ringbuffer for a
        * struct + the max message size or else we wrap to the start.
        */
        if (new_widx + sizeof(struct llq_msg) + LLQ_MAX_MSG_SIZE >= llq_len) {
            /* wrap ringbuffer */
            new_widx = 0;
        }

        if (new_widx == cur_ridx) {
            /* We just ran into reader, we need a read before we can write again */
            __atomic_store_n(&need_read, 1, __ATOMIC_RELEASE);
        }

        /* Update writer index: The __ATOMIC_RELEASE should prevent
         * reoredring and speculation into this update which in rather
         * extreme cases of re-ordering (which may be impossible on x86)
         * could cause the index to update to the writer to show "too
         * soon".
         */
        __atomic_store_n(&widx, new_widx, __ATOMIC_RELEASE);
    }


    struct llq_msg * try_read() {
        struct llq_msg *m = (struct llq_msg *)&rbuf[ridx];

        uint64_t cur_widx = __atomic_load_n(&widx, __ATOMIC_ACQUIRE);

        if (cur_widx != ridx) {
            /* we're not at the writer, reading is fine */
            return m;
        } else {
            int cur_need_read = __atomic_load_n(&need_read, __ATOMIC_ACQUIRE);

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

        uint64_t new_ridx = ridx + sizeof(struct llq_msg) + m->len;

        /* Same struct + msg wrapping logic as used by the sender */
        if (new_ridx + sizeof(struct llq_msg) + LLQ_MAX_MSG_SIZE >= llq_len) {
            /* wrap ringbuffer */
            new_ridx = 0;
        }

        /* Update reader index with release to enforce well ordering */
        __atomic_store_n(&ridx, new_ridx, __ATOMIC_RELEASE);
    }


    void drop_trunc() {
        __sync_add_and_fetch(&(drops_trunc), 1);
    }
};


struct thread_queues {
    int qnum;                    /* The number of queues that have been allocated */
    int qidx;                    /* The index of the first free queue */
    struct ll_queue *queue;      /* The actual queue datastructure */
};


#endif // LLQ_H
