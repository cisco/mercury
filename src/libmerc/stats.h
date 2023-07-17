/*
 * stats.h
 *
 * track and report aggregate statistics for fingerprints, destations,
 * and other events
 */

#ifndef STATS_H
#define STATS_H

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <thread>
#include <atomic>
#include <zlib.h>
#include <functional>

#include "dict.h"
#include "queue.h"

// class event_processor_gz coverts a sequence of sorted event
// strings into an alternative JSON representation
//
class event_processor_gz {
    std::vector<std::string> prev;
    bool first_loop;
    gzFile gzf;
    std::array<std::string, 4> v;

public:
    event_processor_gz(gzFile gzfile) : prev{"", "", "", ""}, first_loop{true}, gzf{gzfile} {}

    void process_init() {
        first_loop = true;
        prev = { "", "", "", "" };
    }

    void process_update(const event_msg &event, uint32_t count, const char *version,
                    const char *git_commit_id, uint32_t git_count, const char *init_time) {

        std::tie(v[0], v[1], v[2], v[3]) = event;

        // find number of elements that match previous vector
        size_t num_matching = 0;
        for (num_matching=0; num_matching<3; num_matching++) {
            if (prev[num_matching].compare(v[num_matching]) != 0) {
                break;
            }
        }
        // set mismatched previous values
        for (size_t i=num_matching; i<3; i++) {
            prev[i] = v[i];
        }

        //Format the optional parameter user-agent only if it is present
        //Extra 15 bytes is to account for additional data required for json
        char user_agent[MAX_USER_AGENT_LEN + 15]{"\0"};
        if(v[2][0] != '\0') {
            snprintf(user_agent, MAX_USER_AGENT_LEN - 1, "\"user_agent\":\"%s\", ", v[2].c_str());
        }

        // output unique elements
        int gz_ret = 1;
        switch(num_matching) {
        case 0:
            if (!first_loop) {
                gz_ret = gzprintf(gzf, "}]}]}]}\n");
            }
            if (gz_ret <= 0)
                throw std::runtime_error("error in gzprintf");
            gz_ret = gzprintf(gzf, "{\"src_ip\":\"%s\", \"libmerc_init_time\" : \"%s\",\"libmerc_version\": \"%s\","
                                   " \"build_number\" : \"%u\", \"git_commit_id\": \"%s\", \"fingerprints\":"
                                   "[{\"str_repr\":\"%s\", \"sessions\": [{%s\"dest_info\":[{\"dst\":\"%s\",\"count\":%u", 
                v[0].c_str(), init_time, version, git_count, git_commit_id, v[1].c_str(), user_agent, v[3].c_str(), count);
            break;
        case 1:
            gz_ret = gzprintf(gzf, "}]}]},{\"str_repr\":\"%s\", \"sessions\": [{%s\"dest_info\":[{\"dst\":\"%s\",\"count\":%u", v[1].c_str(), user_agent, v[3].c_str(), count);
            break;
        case 2:
            gzprintf(gzf, "}]},{%s\"dest_info\":[{\"dst\":\"%s\",\"count\":%u", user_agent, v[3].c_str(), count);
            break;
        case 3:
            gz_ret = gzprintf(gzf, "},{\"dst\":\"%s\",\"count\":%u", v[3].c_str(), count);
            break;
        default:
            ;
        }
        first_loop = false;
        if (gz_ret <= 0)
            throw std::runtime_error("error in gzprintf");
    }

    void process_final() {
        int gz_ret = gzprintf(gzf, "}]}]}]}\n");
        if (gz_ret <= 0)
            throw std::runtime_error("error in gzprintf");
    }

};

#define ANON_SRC_IP

// class event_encoder provides methods to compress/decompress event string.
// Its member functions are not const because they may update the dict
// member.

class event_encoder {
    dict fp_dict;
    dict ua_dict;

public:

    event_encoder() : fp_dict{}, ua_dict{} {}

    bool compute_inverse_map() {
        return fp_dict.compute_inverse_map() && ua_dict.compute_inverse_map();
    }

    void get_inverse(event_msg &event) {
        const std::string &fngr = std::get<1>(event);
        const std::string &ua   = std::get<2>(event);

        size_t compressed_fp_num = strtol(fngr.c_str(), NULL, 16);
        size_t compressed_ua_num = strtol(ua.c_str(), NULL, 16);

        std::get<1>(event) = fp_dict.get_inverse(compressed_fp_num);
        std::get<2>(event) = ua_dict.get_inverse(compressed_ua_num);
    }

    void compress_event_string(event_msg& event, dict& addr_dict) {

        const std::string &addr = std::get<0>(event);
        const std::string &fngr = std::get<1>(event);
        const std::string &ua   = std::get<2>(event);

        // compress source address string, for anonymization (regardless of ANON_SRC_IP)
        char src_addr_buf[9];
        addr_dict.compress(addr, src_addr_buf);

        // compress fingerprint string
        char compressed_fp_buf[9];
        fp_dict.compress(fngr, compressed_fp_buf);

        char compressed_ua_buf[9];
        ua_dict.compress(ua, compressed_ua_buf);

        std::get<0>(event) = src_addr_buf;
        std::get<1>(event) = compressed_fp_buf;
        std::get<2>(event) = compressed_ua_buf;

    }

};

struct hash_tuple {
    template <class T1, class T2, class T3, class T4>

    size_t operator()(const std::tuple<T1, T2, T3, T4>& x) const {
        std::hash<std::string> hasher;
        return hasher(std::get<0>(x))
                ^ hasher(std::get<1>(x))
                ^ hasher(std::get<2>(x))
                ^ hasher(std::get<3>(x));
    }
};

// class stats_aggregator manages all of the data needed to gather and
// report aggregate statistics about (fingerprint and destination)
// events
//
class stats_aggregator {
    std::unordered_map<event_msg, uint64_t, hash_tuple> event_table;
    event_encoder encoder;
    std::string observation;  // used as preallocated temporary variable
    size_t num_entries;
    size_t max_entries;
    dict &addr_dict;

public:

    stats_aggregator(dict& _addr_dict, size_t size_limit) : event_table{}, encoder{}, observation{}, num_entries{0}, max_entries{size_limit}, addr_dict{_addr_dict} { }

    ~stats_aggregator() {  }

    void observe_event_string(event_msg &obs) {

        encoder.compress_event_string(obs, addr_dict);

        const auto entry = event_table.find(obs);
        if (entry != event_table.end()) {
            entry->second = entry->second + 1;
        } else {
            if (max_entries && num_entries >= max_entries) {
                return;  // don't go over the max_entries limit
            }
            event_table.emplace(obs, 1);  // TODO: check return value for allocation failure
            ++num_entries;
        }
    }

    bool is_empty() const { return event_table.size() == 0; }

    void gzprint(gzFile f, const char *version, const char *git_commit_id,
                 uint32_t git_count,
                 const char *init_time,
                 std::atomic<bool> &interrupt ) {

        if (event_table.size() == 0) {
            return;  // nothing to report
        }

        // note: this function is not const because of compute_inverse_map()

        // compute decoding table for elements
        if (encoder.compute_inverse_map() == false) {
            return;  // error; unable to compute fingerprint decompression map
        }

        std::vector<std::pair<event_msg, uint64_t>> v(event_table.begin(), event_table.end());
        event_table.clear();
        num_entries = 0;
        std::sort(v.begin(), v.end(), [&interrupt](auto &l, auto &r){
            if (interrupt.load() == true) {
                throw std::runtime_error("error: stats dump interrupted");
            } else {
                return l.first < r.first;
            } 
        } );

        event_processor_gz ep(f);
        ep.process_init();
        for (auto &entry : v) {
            if (interrupt.load() == true) {
                ep.process_final();
                throw std::runtime_error("error: stats dump interrupted");
            }
            encoder.get_inverse(entry.first);
            ep.process_update(entry.first, entry.second, version, git_commit_id, git_count, init_time);
        }
        ep.process_final();

        // if (fp_dict.unit_test(stderr)) {
        //     fprintf(stderr, "passed fp_dict.unit_test()\n");
        // }

        return;
    }

    size_t get_num_entries() const
    {
        return num_entries;
    }
};

#define MAX_VERSION_STRING 15

class data_aggregator {
    std::vector<class message_queue *> q;
    stats_aggregator ag1, ag2, *ag;
    std::atomic<bool> shutdown_requested;
    dict addr_dict;
    std::thread consumer_thread;
    std::mutex m;
    std::mutex output_mutex;
    char version[MAX_VERSION_STRING];

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

    void empty_event_queue(message_queue *q) {
        //fprintf(stderr, "note: emptying message queue in %p\n", (void *)this);
        event_msg event;
        while (q->pop(event)) {
            //fprintf(stderr, "note: got message\n");
            ag->observe_event_string(event);
        }
    }

    void process_event_queues() {
        std::lock_guard m_guard{m};
        //fprintf(stderr, "note: processing event queue of size %zd in %p\n", q.size(), (void *)this);
        if (q.size()) {
            for (auto & qr : q) {
                //fprintf(stderr, "note: processing event queue %p in %p with size %zd\n", (void *)qr, (void *)this, qr->size());
                empty_event_queue(qr);
            }
        }
    }

    void consumer() {
        //fprintf(stderr, "note: running consumer in %p\n", (void *)this);
        while(shutdown_requested.load() == false) {
            process_event_queues();
            usleep(50); // sleep for fifty microseconds
        }
    }

public:

    data_aggregator(size_t size_limit=0) : q{}, ag1{addr_dict, size_limit}, ag2{addr_dict, size_limit}, ag{&ag1}, shutdown_requested{false} {
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

    message_queue *add_producer() {
        std::lock_guard m_guard{m};
        //fprintf(stderr, "note: adding producer in %p\n", (void *)this);
        q.push_back(new message_queue);
        return q.back();
    }

    void remove_producer(message_queue *p) {
        if (p == nullptr) {
            return;
        }
        std::lock_guard m_guard{m};
        //fprintf(stderr, "note: removing producer in %p\n", (void *)this);
        empty_event_queue(p);
        for (std::vector<message_queue *>::iterator it = q.begin(); it < q.end(); it++) {
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
            tmp->gzprint(f, version, git_commit_id, git_count, init_time, std::ref(shutdown_requested));
        }
        catch (std::exception &e) {
            printf_err(log_err, "%s\n", e.what());
        }
    }

    size_t get_num_entries() const
    {
        return ag->get_num_entries();
    }
};

#endif // STATS_H
