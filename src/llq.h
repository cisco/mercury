/*
 * llq - lockless queue for inter-thread communication
 */

#ifndef LLQ_H
#define LLQ_H

#include <unistd.h>

#define LLQ_MSG_SIZE 16384   /* The number of bytes allowed for each message in the lockless queue */
#define LLQ_DEPTH    2048    /* The number of "buckets" (queue messages) allowed */
#define LLQ_MAX_AGE  5       /* Maximum age (in seconds) messages are allowed to sit in a queue */

/* The message object suitable for the std::priority_queue */
struct llq_msg {
    volatile int used; /* The flag that says if this object is actually in use (if not, it's available) */
    char buf[LLQ_MSG_SIZE];
    ssize_t len;
    struct timespec ts;
};


/* a "lockless" queue */
struct ll_queue {
    int qnum;  /* This is the queue number and is only needed for debugging */
    int ridx;  /* The read index */
    int widx;  /* The write index */
    struct llq_msg msgs[LLQ_DEPTH];

    static const size_t msg_length = LLQ_DEPTH;

    struct llq_msg &init_msg(bool blocking) {
        struct llq_msg &m = msgs[widx];
        if (blocking) {
            while (m.used != 0) {
                usleep(50); // sleep for fifty microseconds
            }
        }
        return m;
    }
    void write_buffer_to_queue() {
    }
    void increment_widx() {
        widx = (widx + 1) % LLQ_DEPTH;
    }
};


struct thread_queues {
    int qnum;             /* The number of queues that have been allocated */
    int qidx;             /* The index of the first free queue */
    struct ll_queue *queue;      /* The actual queue datastructure */
};


struct tourn_tree {
    int qnum;
    int qp2;
    int *tree;
    int stalled;
};

#endif // LLQ_H
