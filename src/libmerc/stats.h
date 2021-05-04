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

#if 1 // def ANON_SRC_IP
        // compress source address string, for anonymization
        char src_addr_buf[9];
        addr_dict.compress(head, src_addr_buf);
        head = src_addr_buf;
#endif
        // compress fingerprint string
        char compressed_fp_buf[9];
        fp_dict.compress(fp, compressed_fp_buf);

        s.clear();
        s.append(head).append("#");
        s.append(compressed_fp_buf).append("#");
        s.append(tail);

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

public:

    stats_aggregator() : event_table{}, encoder{}, observation{} {  }

    ~stats_aggregator() {  }

    void observe(const char *src_ip, const char *fp_str, const char *server_name, const char *dst_ip, uint16_t dst_port) {

        encoder.set_string(observation, src_ip, fp_str, server_name, dst_ip, dst_port);
        //fprintf(stdout, "event string %s\tlength: %zu\n", observation.c_str(), observation.length());
        const auto entry = event_table.find(observation);
        if (entry != event_table.end()) {
            entry->second = entry->second + 1;
        } else {
            event_table.emplace(observation, 1);  // TODO: check return value for allocation failure
        }
    }

    void observe_event_string(std::string &obs) {

        encoder.compress_event_string(obs);

        const auto entry = event_table.find(obs);
        if (entry != event_table.end()) {
            entry->second = entry->second + 1;
        } else {
            event_table.emplace(obs, 1);  // TODO: check return value for allocation failure
        }
    }

    void gzprint(gzFile f) {

        // fprintf(stderr, "%s with gzFile %p\n", __func__, (void *)f);
        // int retval = gzprintf(f, "\"this is just a test\"");
        // fprintf(stderr, "gzprintf returned %d\n", retval);

        if (event_table.size() == 0) {
            return;  // nothing to report
        }

        // note: this function is not const because of compute_inverse_map()

        // compute decoding table for elements
        if (encoder.compute_inverse_map() == false) {
            return;  // error; unable to compute fingerprint decompression map
        }

        std::vector<std::pair<std::string, uint64_t>> v(event_table.begin(), event_table.end());
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
    stats_aggregator ag;
    std::atomic<bool> shutdown_requested;
    std::thread consumer_thread;

    void halt_and_join() {
        shutdown_requested.store(true);
        if(consumer_thread.joinable()) {
             consumer_thread.join();
        }
    }

public:
    data_aggregator() : q{}, ag{}, shutdown_requested{false} {
        start_processing();
    }

    ~data_aggregator() {
        //fprintf(stderr, "note: halting data_aggregator\n");
        halt_and_join();
        for (auto & x : q) {
            //fprintf(stderr, "note: deleting message_queue %p\n", (void *)x);
            delete x;
        }
    }

    message_queue *add_producer() {
        q.push_back(new message_queue);
        return q.back();
    }

    void start_processing() {
        //fprintf(stderr, "note: starting data_aggregator\n");
        consumer_thread = std::thread( [this](){ consumer(); } );  // lambda just calls member function
    }

    void process_event_queues() {
        if (q.size()) {
            for (auto & qr : q) {
                message *msg = qr->pop();
                if (msg) {
                    //fprintf(stderr, "note: got message %zu\t'%.*s'\n", count++, (int)msg->length, msg->buffer);
                    std::string event{(char *)msg->buffer, msg->length};  // TODO: move string constructor outside of loop
                    ag.observe_event_string(event);
                } else {
                    //fprintf(stderr, "consumer thread saw empty queue\n");
                }
            }
        } else {
            //fprintf(stderr, "consumer thread has no queues (yet)\n");
        }
    }

    void consumer() {
        //fprintf(stderr, "note: running consumer()\n");
        //size_t count = 0;
        while(shutdown_requested.load() == false) {
            process_event_queues();
            usleep(50); // sleep for fifty microseconds
        }
        process_event_queues();
    }

    void gzprint(gzFile f) { ag.gzprint(f); }
};

#endif // STATS_H
