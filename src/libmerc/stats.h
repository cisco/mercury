/*
 * stats.h
 *
 * track and report aggregate statistics for fingerprints, destations,
 * and other events
 */

#ifndef STATS_H
#define STATS_H

#ifdef _WIN32
#include <io.h>
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
typedef uint32_t useconds_t;
#else
#include <unistd.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <limits>
#include <thread>
#include <chrono>
#include "printf_err.hpp"
#include <atomic>
#include <functional>
#include <tuple>

#include "dict.h"
#include "queue.h"
#include "event.hpp"


// class stats_aggregator manages all of the data needed to gather and
// report aggregate statistics about (fingerprint and destination)
// events
//
class stats_aggregator {

    std::unordered_map<event_key, uint64_t, universal61::event_key_hasher> event_table;
    event_encoder encoder;
    size_t max_entries;
    size_t estimated_memory_bytes;
    size_t event_table_memory_bytes;
    size_t max_memory_bytes;

    static size_t add_memory(size_t current, size_t amount) {
        if (amount > std::numeric_limits<size_t>::max() - current) {
            return std::numeric_limits<size_t>::max();
        }
        return current + amount;
    }

    static size_t event_memory_cost() {
        return sizeof(std::pair<const event_key, uint64_t>)
             + 8 * sizeof(void *);
    }

    void update_estimated_memory() {
        const size_t dictionary_bytes = encoder.dictionary_bytes();
        if (event_table_memory_bytes > std::numeric_limits<size_t>::max() - dictionary_bytes) {
            estimated_memory_bytes = std::numeric_limits<size_t>::max();
        } else {
            estimated_memory_bytes = dictionary_bytes + event_table_memory_bytes;
        }
    }

public:

    static constexpr size_t default_max_memory_bytes = 16 * 1024 * 1024;

    stats_aggregator(size_t size_limit,
                     size_t memory_limit=default_max_memory_bytes) :
        event_table{},
        encoder{},
        max_entries{size_limit},
        estimated_memory_bytes{0},
        event_table_memory_bytes{0},
        max_memory_bytes{memory_limit} { }

    void observe_event_string(const event_msg &obs) {

        bool no_new_entries = (max_entries && event_table.size() >= max_entries) ||
                              (max_memory_bytes && estimated_memory_bytes >= max_memory_bytes);

        event_key key{};
        if (encoder.compress_event(key, obs, no_new_entries) == false) {
            update_estimated_memory();
            return;  // error: can't observe this event
        }

        const auto entry = event_table.find(key);
        if (entry != event_table.end()) {
            entry->second = entry->second + 1;
        } else {
            if (no_new_entries) {
                return;  // don't create another stats entry
            }
            auto inserted = event_table.emplace(key, 1);
            if (!inserted.second) {
                update_estimated_memory();
                return;
            }
            event_table_memory_bytes = add_memory(event_table_memory_bytes,
                                                  event_memory_cost());
        }
        update_estimated_memory();
    }

    bool is_empty() const { return event_table.empty(); }

    void gzprint(gzFile f, const char *version,
                 const char *resource_version,
                 const char *git_commit_id,
                 uint32_t git_count,
                 const char *init_time,
                 std::atomic<bool> &interrupt ) {

        if (event_table.empty()) {
            return;  // nothing to report
        }

        // note: this function is not const because of compute_inverse_map()

        // compute decoding table for elements
        if (encoder.compute_inverse_map() == false) {
            return;  // error; unable to compute fingerprint decompression map
        }

        std::vector<std::pair<event_msg, uint64_t>> v;
        v.reserve(event_table.size());
        for (const auto &entry : event_table) {
            event_msg event;
            encoder.get_inverse(event, entry.first);
            v.emplace_back(std::move(event), entry.second);
        }
        event_table.clear();
        event_table.rehash(0);
        event_table_memory_bytes = 0;
        update_estimated_memory();
        std::sort(v.begin(), v.end(), [&interrupt](auto &l, auto &r){
            if (interrupt.load() == true) {
                throw std::runtime_error("error: stats dump interrupted");
            }
            const auto &le = l.first;
            const auto &re = r.first;
            if (le[0] != re[0]) {
                return le[0] < re[0];
            }
            auto type_rank = [](event_type t) {
                switch (t) {
                case event_type::cert_label:
                    return 0;
                case event_type::snmp_oid:
                    return 1;
                case event_type::fingerprint:
                default:
                    return 2;
                }
            };
            int l_rank = type_rank(le.type);
            int r_rank = type_rank(re.type);
            if (l_rank != r_rank) {
                return l_rank < r_rank;
            }
            if (le.type == event_type::cert_label || le.type == event_type::snmp_oid) {
                return le[3] < re[3];
            }
            return le < re;
        } );

        event_processor_gz ep(f);
        ep.process_init();
        for (auto &entry : v) {
            if (interrupt.load() == true) {
                ep.process_final();
                throw std::runtime_error("error: stats dump interrupted");
            }
            ep.process_update(entry.first, entry.second, version, resource_version, git_commit_id, git_count, init_time);
        }
        ep.process_final();

        encoder.clear();
        update_estimated_memory();

        // if (fp_dict.unit_test(stderr)) {
        //     fprintf(stderr, "passed fp_dict.unit_test()\n");
        // }

        return;
    }

    size_t get_num_entries() const
    {
        return event_table.size();
    }
};

#define MAX_VERSION_STRING 15

class data_aggregator {
    std::vector<class message_queue<event_msg> *> q;
    stats_aggregator ag1, ag2, *ag;
    std::atomic<bool> shutdown_requested;
    bool blocking;  // stats event collection: lossless but blocking
    useconds_t consumer_sleep; // microseconds
    std::thread consumer_thread;
    std::mutex m;
    std::mutex output_mutex;
    char version[MAX_VERSION_STRING];
    std::string resource_version;

    // stop_processing() MUST NOT be called until all writing to the
    // message_queues has stopped
    //
    void stop_processing() {

        // shut down consumer thread
        shutdown_requested.store(true);
        if(consumer_thread.joinable()) {
             consumer_thread.join();
        }
    }

    void empty_event_queue(message_queue<event_msg> *q) {
        //fprintf(stderr, "note: emptying message queue in %p\n", (void *)this);
        event_msg event;
        while (q->pop(event)) {
            //fprintf(stderr, "note: got message\n");
            ag->observe_event_string(event);
        }
    }

    double event_queue_fill_ratio(message_queue<event_msg> *q) {
        return static_cast<double>(q->size()) / static_cast<double>(q->capacity());
    }

    void adjust_consumer_sleep(double max_fill_ratio) {
        // Aim for busiest queue to be between 25% and 50% full before emptying.
        // However, always bound the sleep time within [1us, 50us].
        useconds_t new_sleep;
        if (max_fill_ratio < 0.25) {
            new_sleep = consumer_sleep + 1; // additive increase
            new_sleep = std::min(new_sleep, (useconds_t)50);
        } else if (max_fill_ratio > 0.5) {
            new_sleep = consumer_sleep / 2; // multiplicative decrease
            new_sleep = std::max(new_sleep, (useconds_t)1);
        } else {
            return;                         // no change needed
        }
        //fprintf(stderr, "Max message_queue fill ratio: %3.3f   new_sleep: %u us\n",
        //        max_fill_ratio, new_sleep);
        consumer_sleep = new_sleep;
    }

    void process_event_queues() {
        std::lock_guard m_guard{m};
        //fprintf(stderr, "note: processing event queue of size %zd in %p\n", q.size(), (void *)this);
        double max_fill_ratio = 0.0; // max over queues (worker threads) at the current moment
        if (q.size()) {
            for (auto & qr : q) {
                //fprintf(stderr, "note: processing event queue %p in %p with size %zd\n", (void *)qr, (void *)this, qr->size());
                double fill_ratio = event_queue_fill_ratio(qr);
                max_fill_ratio = std::max(max_fill_ratio, fill_ratio);
                empty_event_queue(qr);
            }
            adjust_consumer_sleep(max_fill_ratio);
        }
    }

    void consumer() {
        //fprintf(stderr, "note: running consumer in %p\n", (void *)this);
        while(shutdown_requested.load() == false) {
            process_event_queues();
            std::this_thread::sleep_for(std::chrono::microseconds(consumer_sleep)); // sleep for consumer_sleep microseconds
        }
    }

public:

    data_aggregator(size_t size_limit=0,
                    bool blocking=false,
                    size_t memory_limit=stats_aggregator::default_max_memory_bytes) :
        q{},
        ag1{size_limit, memory_limit},
        ag2{size_limit, memory_limit},
        ag{&ag1},
        shutdown_requested{false},
        blocking{blocking},
        consumer_sleep{1} {
        mercury_get_version_string(version, MAX_VERSION_STRING);
        start_processing();
        //fprintf(stderr, "note: constructing data_aggregator %p\n", (void *)this);
    }

    ~data_aggregator() {
        //fprintf(stderr, "note: destructing data_aggregator %p\n", (void *)this);
        stop_processing();

        // delete message_queues, if any
        for (auto & x : q) {
            //fprintf(stderr, "%s: deleting message_queue %p\n", __func__, (void *)x);
            delete x;
        }
    }

    message_queue<event_msg> *add_producer() {
        std::lock_guard m_guard{m};
        //fprintf(stderr, "note: adding producer in %p\n", (void *)this);
        q.push_back(new message_queue<event_msg>(blocking));
        return q.back();
    }

    void remove_producer(message_queue<event_msg> *p) {
        if (p == nullptr) {
            return;
        }
        std::lock_guard m_guard{m};
        //fprintf(stderr, "note: removing producer in %p\n", (void *)this);
        empty_event_queue(p);
        for (std::vector<message_queue<event_msg> *>::iterator it = q.begin(); it < q.end(); it++) {
            if (*it == p) {
                //fprintf(stderr, "%s: deleting and erasing message_queue p=%p in %p\n", __func__, (void *)p, (void *)this);
                delete *it;
                q.erase(it);
            }
        }
        if (q.size() == 0) {
            shutdown_requested.store(true);  // time to close up shop
        }
    }

    void start_processing() {
        //fprintf(stderr, "note: starting data_aggregator\n");
        consumer_thread = std::thread( [this](){ consumer(); } );  // lambda just calls member function
    }

    void gzprint(gzFile f,
                 const char *resource_version,
                 const char *git_commit_id,
                 uint32_t git_count,
                 const char *init_time
                 ) {

        // ensure that only one print function is running at a time
        //
        std::lock_guard output_guard{output_mutex};

        // swap ag pointer, so that we can print out the previously
        // gathered data while new events are tracked in the other
        // stats_aggregator
        //
        stats_aggregator *tmp;
        {
            std::lock_guard m_guard{m};
            tmp = ag;
            if (ag == &ag1) {
                ag = &ag2;
            } else {
                ag = &ag1;
            }
        }

        try {
            tmp->gzprint(f, version, resource_version, git_commit_id, git_count, init_time, std::ref(shutdown_requested));
        }
        catch (std::exception &e) {
            printf_err(log_err, "%s\n", e.what());
        }
    }

    size_t get_num_entries()
    {
        std::lock_guard m_guard{m};
        return ag->get_num_entries();
    }
};

#endif // STATS_H
