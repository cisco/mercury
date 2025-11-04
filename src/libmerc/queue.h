/*
 * queue.h
 *
 * a threadsafe queue for fixed-length messages, based on a ring
 * buffer
 */

#ifndef QUEUE_H
#define QUEUE_H

#include <string.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#include <mutex>
#include <tuple>
#include <chrono>

typedef std::tuple<std::string, std::string, std::string, std::string> event_msg;
#define EVENT_BUF_SIZE 512

class message_queue {
    std::mutex m;
    size_t first;
    size_t last;
    long unsigned int err_count;
    bool blocking;
    event_msg msg_buf[EVENT_BUF_SIZE];

private:
    void increment(size_t &idx) {
        idx = next_index(idx);
    }

    size_t next_index(size_t idx) const {
        size_t tmp = idx + 1;
        if (tmp == EVENT_BUF_SIZE) {
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

public:
    message_queue(bool blocking=false)
        : m{}, first{0}, last{0}, err_count{0}, blocking{blocking} { }

    ~message_queue() {
        // TBD: connect error_count to verbosity > 0
        // fprintf(stderr, "note: message_queue::error_count: %lu\n", err_count);
    }

    void fprint(FILE *f) {
        std::unique_lock<std::mutex> m_lock(m);
        fprintf(f, "STATE: first: %zu\tlast: %zu\n", first, last);
    }

    bool push(const event_msg& ev_str) {
        std::unique_lock<std::mutex> m_lock(m);
        if (is_full()) {
            if (blocking) {
                [[maybe_unused]] unsigned long blocked_count = 0;
                const unsigned long SLEEP_MICROSEC = 2;
                while (is_full()) {
                    blocked_count++;
                    m_lock.unlock();
                    std::this_thread::sleep_for(std::chrono::microseconds(SLEEP_MICROSEC));
                    m_lock.lock();
                }
                //fprintf(stderr, "%s: message_queue %p blocked for %lu microseconds\n",
                //        __func__, (void *)this, blocked_count * SLEEP_MICROSEC);
            } else {
                err_count++;
                //fprintf(stderr, "%s: message_queue %p is full\n", __func__, (void *)this);
                return false; // error: no room in queue
            }
        }
        //fprintf(stderr, "src_ip = %s, fp = %s, user-agent= %s, dest_info= %s\n", std::get<0>(ev_str).c_str(), std::get<1>(ev_str).c_str(), std::get<2>(ev_str).c_str(), std::get<3>(ev_str).c_str());
        msg_buf[last] = ev_str;
        increment(last);
        return true;
    }

    bool pop(event_msg &entry) {
        std::unique_lock<std::mutex> m_lock(m);
        //fprintf(stderr, "%s: queue size: %zd\n", __func__, size());
        if (is_empty()) {
            return false;
        }
        entry = msg_buf[first];
        increment(first);
        return true;
    }

    ssize_t size() {
        std::unique_lock<std::mutex> m_lock(m);
        if (last >= first) {
            return last - first;
        }
        return EVENT_BUF_SIZE - (first - last);
    }

    ssize_t capacity() const {
        return EVENT_BUF_SIZE - 1;
    }
};


#endif // QUEUE_H
