/*
 * stats.h
 *
 * track and report aggregate statistics for fingerprints, destations,
 * and other events
 */

#ifndef STATS_H
#define STATS_H

#include <stdint.h>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <algorithm>

#include "json_object.h"

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


// class event_encoder converts a bunch of variables to an event
// string (with the set_string() method) and converts an event string
// into an array of char * (with the get_vector() method).  Its member
// functions are not const because they may update the fp_dict dict
// member.
//
class event_encoder {
    dict fp_dict;
public:

    event_encoder() : fp_dict{} {}

    bool compute_inverse_map() { return fp_dict.compute_inverse_map();  }

    void set_string(std::string &tmp,  const char *src_ip, const char *fp_str, const char *server_name, const char *dst_ip, uint16_t dst_port) {

        // compress fingerprint string
        char compressed_fp_buf[9];
        fp_dict.compress(fp_str, compressed_fp_buf);

        tmp.clear();
        tmp.append(src_ip);
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

        size_t compressed_fp_num = strtol(comp_fp, NULL, 16);
        const char *decomp_fp = fp_dict.get_inverse(compressed_fp_num);

        return {head, decomp_fp, tail};
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
    stats_aggregator() : event_table{}, encoder{}, observation{'\0', 128} {
    }

    ~stats_aggregator() {
        // TODO: connect this output to mercury in a more useful way
        //
        FILE *fpfile = stderr; // nullptr; // stderr; // fopen("fingerprint_stats.txt", "w");
        if (fpfile) {
            fprint(fpfile);
        }
    }

    void observe(const char *src_ip, const char *fp_str, const char *server_name, const char *dst_ip, uint16_t dst_port) {

        encoder.set_string(observation, src_ip, fp_str, server_name, dst_ip, dst_port);

        const auto entry = event_table.find(observation);
        if (entry != event_table.end()) {
            entry->second = entry->second + 1;
        } else {
            event_table.emplace(observation, 1);  // TODO: check return value for allocation failure
        }
    }

    void fprint(FILE *f) {

        // note: this function is not const because of compute_inverse_map()

        // compute fingerprint inverse table
        if (encoder.compute_inverse_map() == false) {
            return;  // error; unable to compute fingerprint decompression map
        }

        std::vector<std::pair<std::string, uint64_t>> v(fp_dst_table.begin(), fp_dst_table.end());
        std::sort(v.begin(), v.end(), [](auto &l, auto &r){ return l.first < r.first; } );

        event_processor ep(f);
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


#endif // STATS_H
