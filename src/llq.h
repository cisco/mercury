/*
 * llq - lockless queue for inter-thread communication
 */

#ifndef LLQ_H
#define LLQ_H

#define LLQ_MSG_SIZE       2048   /* The number of bytes allowed for each message in the lockless queue */
#define LLQ_DEPTH          2048   /* The number of "buckets" (queue messages) allowed */
#define LLQ_MSG_SIZE_JUMBO 65536  /* The size of a "jumbo" message */
#define LLQ_DEPTH_JUMBO    128    /* The number of "buckets" (queue messages) allowed */
#define LLQ_MAX_AGE  5       /* Maximum age (in seconds) messages are allowed to sit in a queue */

/* The "standard" message object */
struct llq_msg {
    volatile int used; /* The flag that says if this object is actually in use (if not, it's available) */
    int jumbo; /* Did this message have to spill into a "jumbo" message? */
    int jidx;  /* The jumbo message index */
    char buf[LLQ_MSG_SIZE];
    ssize_t len;
    struct timespec ts;
};

/* The jumbo spillover message */
struct llq_msg_jumbo {
    volatile int used; /* The flag that says if this object is actually in use (if not, it's available) */
    char buf[LLQ_MSG_SIZE_JUMBO];
};


/* a "lockless" queue */
struct ll_queue {
    int qnum;  /* This is the queue number and is only needed for debugging */
    int ridx;  /* The read index */
    int widx;  /* The write index */
    int jwidx; /* The jumbo write index */
    struct llq_msg msgs[LLQ_DEPTH];
    struct llq_msg_jumbo jmsgs[LLQ_DEPTH_JUMBO];
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
