/*
 * stats.h
 *
 * track and report aggregate statistics for fingerprints, destations,
 * and other events
 */

#ifndef STATS_H
#define STATS_H

#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <thread>
#include <atomic>

#include <zlib.h>

#include "dict.h"
#include "queue.h"

// class event_processor coverts a sequence of sorted event strings into a
// JSON representation
//
class event_processor {
    std::vector<std::string> prev;
    bool first_loop;
    FILE *f;

public:
    event_processor(FILE *file) : prev{"", "", ""}, first_loop{true}, f{file} {}

    void process_init() {
        first_loop = true;
        prev = { "", "", "" };
    }

    void process_update(std::array<const char *, 3> v, uint32_t count) {

        // find number of elements that match previous vector
        size_t num_matching = 0;
        for (num_matching=0; num_matching<2; num_matching++) {
            if (prev[num_matching].compare(v[num_matching]) != 0) {
                break;
            }
        }
        // set mismatched previous values
        for (size_t i=num_matching; i<2; i++) {
            prev[i] = v[i];
        }

        // output unique elements
        switch(num_matching) {
        case 0:
            if (!first_loop) {
                fputs("}}}\n", f);
            }
            fprintf(f, "{\"%s\":{\"%s\":{\"%s\":%u", v[0], v[1], v[2], count);
            break;
        case 1:
            fprintf(f, "},\"%s\":{\"%s\":%u", v[1], v[2], count);
            break;
        case 2:
            fprintf(f, ",\"%s\":%u", v[2], count);
            break;
        default:
            ;
        }
        first_loop = false;

    }

    void process_final() { fputs("}}}\n", f); }

};

// class event_processor_alt coverts a sequence of sorted event
// strings into an alternative JSON representation
//
class event_processor_alt {
    std::vector<std::string> prev;
    bool first_loop;
    FILE *f;

public:
    event_processor_alt(FILE *file) : prev{"", "", ""}, first_loop{true}, f{file} {}

    void process_init() {
        first_loop = true;
        prev = { "", "", "" };
    }

    void process_update(std::array<const char *, 3> v, uint32_t count) {

        // find number of elements that match previous vector
        size_t num_matching = 0;
        for (num_matching=0; num_matching<2; num_matching++) {
            if (prev[num_matching].compare(v[num_matching]) != 0) {
                break;
            }
        }
        // set mismatched previous values
        for (size_t i=num_matching; i<2; i++) {
            prev[i] = v[i];
        }

        // output unique elements
        switch(num_matching) {
        case 0:
            if (!first_loop) {
                fputs("}]}]}\n", f);
            }
            fprintf(f, "{\"src_ip\":\"%s\",\"fingerprints\":[{\"str_repr\":\"%s\",\"dest_info\":[{\"dst\":\"%s\",\"count\":%u", v[0], v[1], v[2], count);
            break;
        case 1:
            fprintf(f, "}]},{\"str_repr\":\"%s\",\"dest_info\":[{\"dst\":\"%s\",\"count\":%u", v[1], v[2], count);
            break;
        case 2:
            fprintf(f, "},{\"dst\":\"%s\",\"count\":%u", v[2], count);
            break;
        default:
            ;
        }
        first_loop = false;

    }

    void process_final() { fputs("}]}]}\n", f); }

};

// class event_processor_alt coverts a sequence of sorted event
// strings into an alternative JSON representation
//
class event_processor_gz {
    std::vector<std::string> prev;
    bool first_loop;
    gzFile gzf;

public:
    event_processor_gz(gzFile gzfile) : prev{"", "", ""}, first_loop{true}, gzf{gzfile} {}

    void process_init() {
        first_loop = true;
        prev = { "", "", "" };
    }

    void process_update(std::array<const char *, 3> v, uint32_t count) {

        // find number of elements that match previous vector
        size_t num_matching = 0;
        for (num_matching=0; num_matching<2; num_matching++) {
            if (prev[num_matching].compare(v[num_matching]) != 0) {
                break;
            }
        }
        // set mismatched previous values
        for (size_t i=num_matching; i<2; i++) {
            prev[i] = v[i];
        }

        // output unique elements
        switch(num_matching) {
        case 0:
            if (!first_loop) {
                gzprintf(gzf, "}]}]}\n");
            }
            gzprintf(gzf, "{\"src_ip\":\"%s\",\"fingerprints\":[{\"str_repr\":\"%s\",\"dest_info\":[{\"dst\":\"%s\",\"count\":%u", v[0], v[1], v[2], count);
            break;
        case 1:
            gzprintf(gzf, "}]},{\"str_repr\":\"%s\",\"dest_info\":[{\"dst\":\"%s\",\"count\":%u", v[1], v[2], count);
            break;
        case 2:
            gzprintf(gzf, "},{\"dst\":\"%s\",\"count\":%u", v[2], count);
            break;
        default:
            ;
        }
        first_loop = false;

    }

    void process_final() { gzprintf(gzf, "}]}]}\n"); }

};

#define ANON_SRC_IP

// class event_encoder converts a bunch of variables to an event
// string (with the set_string() method) and converts an event string
// into an array of char * (with the get_vector() method).  Its member
// functions are not const because they may update the fp_dict dict
// member.
//
class event_encoder {
    dict fp_dict;
    dict addr_dict;
public:

    event_encoder() : fp_dict{} {}

    bool compute_inverse_map() {
        return fp_dict.compute_inverse_map() && addr_dict.compute_inverse_map();
    }

    void set_string(std::string &tmp,  const char *src_ip, const char *fp_str, const char *server_name, const char *dst_ip, uint16_t dst_port) {

#ifdef ANON_SRC_IP
        // compress source address string, for anonymization
        char src_addr_buf[9];
        addr_dict.compress(src_ip, src_addr_buf);
#endif

        // compress fingerprint string
        char compressed_fp_buf[9];
        fp_dict.compress(fp_str, compressed_fp_buf);

        tmp.clear();
        tmp.append(src_addr_buf);      // tmp.append(src_ip);
        tmp += '#';
        tmp.append(compressed_fp_buf); // tmp.append(fp); to omit compression
        tmp += '#';
        tmp.append("(");
        tmp.append(server_name);
        tmp += ')';
        tmp += '(';
        tmp.append(dst_ip);
        char dst_port_string[8];
        sprintf(dst_port_string, "%hu", htons(dst_port));
        tmp += ')';
        tmp += '(';
        tmp.append(dst_port_string);
        tmp += ')';
    }

    std::array<const char *, 3> get_vector(std::string &s) {

        const char *c = s.c_str();
        const char *head = c;
        while (*c != '\0') {
            if (*c == '#') {
                break;
            }
            c++;
        }
        s[c - head] = '\0';      // replace # with null
        c++;                     // advance past #
        const char *comp_fp = c;
        while (*c != '\0') {
            if (*c == '#') {
                break;
            }
            c++;
        }
        s[c - head] = '\0';      // replace # with null
        c++;                     // advance past #
        const char *tail = c;

#ifdef COMP_SRC_ADDR
        size_t compressed_addr_num = strtol(head, NULL, 16);
        head = addr_dict.get_inverse(compressed_addr_num);
#endif
        size_t compressed_fp_num = strtol(comp_fp, NULL, 16);
        const char *decomp_fp = fp_dict.get_inverse(compressed_fp_num); // TODO

        return {head, decomp_fp, tail};
    }

    void compress_event_string(std::string &s) {

        const char *c = s.c_str();
        const char *head = c;
        while (*c != '\0') {
            if (*c == '#') {
                break;
            }
            c++;
        }
        s[c - head] = '\0';      // replace # with null
        c++;                     // advance past #
        const char *fp = c;
        while (*c != '\0') {
            if (*c == '#') {
                break;
            }
            c++;
        }
        s[c - head] = '\0';      // replace # with null
        c++;                     // advance past #
        const char *tail = c;

        // compress source address string, for anonymization (regardless of ANON_SRC_IP)
        char src_addr_buf[9];
        addr_dict.compress(head, src_addr_buf);
        head = src_addr_buf;

        // compress fingerprint string
        char compressed_fp_buf[9];
        fp_dict.compress(fp, compressed_fp_buf);

        //fprintf(stderr, "%s\t%s\t%s\n", s.c_str(), head, compressed_fp_buf);

        // create new string (in a tmp, to avoid overlapping append() calls) then return it
        std::string tmp;
        tmp.append(head).append("#");
        tmp.append(compressed_fp_buf).append("#");
        tmp.append(tail);
        s = tmp;

        //fprintf(stderr, "compressed event string: %s\n", s.c_str());
    }

};

// class stats_aggregator manages all of the data needed to gather and
// report aggregate statistics about (fingerprint and destination)
// events
//
class stats_aggregator {
    std::unordered_map<std::string, uint64_t> event_table;
    event_encoder encoder;
    std::string observation;  // used as preallocated temporary variable
    size_t num_entries;
    size_t max_entries;

public:

    stats_aggregator(size_t size_limit) : event_table{}, encoder{}, observation{}, num_entries{0}, max_entries{size_limit} { }

    ~stats_aggregator() {  }

    void observe_event_string(std::string &obs) {

        encoder.compress_event_string(obs);

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

    void gzprint(gzFile f) {

        if (event_table.size() == 0) {
            return;  // nothing to report
        }

        // note: this function is not const because of compute_inverse_map()

        // compute decoding table for elements
        if (encoder.compute_inverse_map() == false) {
            return;  // error; unable to compute fingerprint decompression map
        }

        std::vector<std::pair<std::string, uint64_t>> v(event_table.begin(), event_table.end());
        event_table.clear();
        num_entries = 0;
        std::sort(v.begin(), v.end(), [](auto &l, auto &r){ return l.first < r.first; } );

        event_processor_gz ep(f);
        ep.process_init();
        for (auto &entry : v) {
            ep.process_update(encoder.get_vector(entry.first), entry.second);
        }
        ep.process_final();

        // if (fp_dict.unit_test(stderr)) {
        //     fprintf(stderr, "passed fp_dict.unit_test()\n");
        // }

        return;
    }

};

class data_aggregator {
    std::vector<class message_queue *> q;
    stats_aggregator ag1, ag2, *ag;
    std::atomic<bool> shutdown_requested;
    std::thread consumer_thread;
    std::mutex m;
    std::mutex output_mutex;

    // stop_processing() MUST NOT be called until all writing to the
    // message_queues has stopped
    //
    void stop_processing() {

        // shut down consumer thread
        shutdown_requested.store(true);
        if(consumer_thread.joinable()) {
             consumer_thread.join();
        }

        return;
    }

    void empty_event_queue(message_queue *q) {
        //fprintf(stderr, "note: emptying message queue in %p\n", (void *)this);
        message *msg = q->pop();
        while (msg) {
            //fprintf(stderr, "note: got message\n");
            std::string event{(char *)msg->buffer, msg->length};  // TODO: move string constructor outside of loop
            ag->observe_event_string(event);
            msg = q->pop();
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

    data_aggregator(size_t size_limit=0) : q{}, ag1{size_limit}, ag2{size_limit}, ag{&ag1}, shutdown_requested{false} {
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

    void gzprint(gzFile f) {

        // ensure that only one print function is running at a time
        //
        std::lock_guard output_guard{output_mutex};

        // swap ag pointer, so that we can print out the previously
        // gathered data while new events are tracked in the other
        // stats_aggregator
        //
        stats_aggregator *tmp = ag;
        {
            std::lock_guard m_guard{m};
            tmp = ag;
            if (ag == &ag1) {
                ag = &ag2;
            } else {
                ag = &ag1;
            }
        }
        tmp->gzprint(f);
    }
};

#endif // STATS_H
