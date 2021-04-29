/*
 * queue.h
 *
 * a threadsafe queue for fixed-length messages, based on a ring
 * buffer
 */

#ifndef QUEUE_H
#define QUEUE_H

#include <string.h>
#include <mutex>

struct message {
    uint8_t buffer[1024];   // data buffer
    size_t length;          // number of bytes of data in buffer

    bool copy(const uint8_t *data, size_t data_length) {
        if (data_length > sizeof(buffer)) {
            fprintf(stderr, "error: data too long in %s (length: %zu)\n", __func__, data_length);
            return false;  // error: data too long
        }
        memcpy(buffer, data, data_length);
        length = data_length;
        return true;
    }
};


class message_queue {
    std::mutex m;
    size_t first;
    size_t last;
    long unsigned int err_count;
    message msg_buf[256];

    constexpr static size_t msg_buf_size = sizeof(msg_buf) / sizeof(message);

public:
    message_queue() : m{}, first{0}, last{0}, err_count{0} { }

    ~message_queue() {
        // TBD: connect error_count to verbosity > 0
        // fprintf(stderr, "note: message_queue::error_count: %lu\n", err_count);
    }

    void fprint(FILE *f) {
        fprintf(f, "STATE: first: %zu\tlast: %zu\n", first, last);
    }

    bool push(uint8_t *data, size_t data_length) {
        std::unique_lock<std::mutex> m_lock(m);
        if (is_full()) {
            err_count++;
            //fprintf(stderr, "%s: no room in queue %p\n", __func__, (void *)this);
            return false; // error: no room in queue
        }
        if (msg_buf[last].copy(data, data_length)) {
            increment(last);
            //fprintf(stderr, "%s (length %zu)\n", __func__, data_length);
            return true;
        }
        err_count++;
        // fprintf(stderr, "%s: message could not be copied to queue %p\n", __func__, (void *)this);
        return false;  // error: message could not be copied
    }

    message *pop() {
        std::unique_lock<std::mutex> m_lock(m);
        if (is_empty()) {
            return nullptr;
        }
        message *entry = &msg_buf[first];
        increment(first);
        //fprintf(stderr, "%s (length %zu)\n", __func__, entry->length);
        return entry;
    }

    void increment(size_t &idx) {
        idx = next_index(idx);
    }

    size_t next_index(size_t idx) const {
        size_t tmp = idx + 1;
        if (tmp == msg_buf_size) {
            return 0;
        }
        return tmp;
    }

    bool is_full() const {
        //fprintf(stdout, "%s: next_index: %zu\n", __func__, next_index(last));
        return (next_index(last) == first);
    }

    bool is_empty() const {
        return (first == last);
    }

    ssize_t size() {
        if (last >= first) {
            return last - first;
        }
        return msg_buf_size - (first - last);
    }
};


#endif // QUEUE_H
