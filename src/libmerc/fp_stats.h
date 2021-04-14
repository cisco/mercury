/*
 * fp_stats.h
 *
 * track and report aggregate fingerprint statistics
 */

#ifndef FP_STATS_H
#define FP_STATS_H

#include <stdint.h>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <algorithm>

#include "json_object.h"

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


class dict {
public:
    std::unordered_map<std::string, uint32_t> d;
    unsigned int count;
    std::vector<std::pair<const char *, uint32_t>> inverse;
    unsigned int inverse_size;

    dict() : d{}, count{0}, inverse{}, inverse_size{0} { }

    unsigned int get(const std::string &value) {
        auto x = d.find(value);
        if (x == d.end()) {
            d.emplace(value, count);
            return count++;
        }
        return x->second;
    }

    void compress(const std::string &value,
                  char fp_index_string[9]) {
        auto x = d.find(value);
        if (x == d.end()) {
            d.emplace(value, count);
            sprintf(fp_index_string, "%x", count);
            count++;
            return;
        }
        sprintf(fp_index_string, "%x", x->second);
    }

    bool compute_inverse_map() {

        try {
            inverse.reserve(d.size());
            for (const auto &x : d) {
                inverse.push_back({x.first.c_str(), x.second});
            }
            std::stable_sort(inverse.begin(), inverse.end(), [](auto &l, auto &r){ return l.second < r.second; });
            inverse_size = inverse.size();
            return true;
        }
        catch (...) {
            return false;
        }
    }

    const char *get_inverse(unsigned int index) const {
        if (index < inverse_size) {
            return inverse[index].first;
        }
        return unknown_fp_string;
    }

    inline static const char *unknown_fp_string{"unknown"};

    // unit_test(f) verifies that the dictionary is the same in both
    // the forard and inverse directions; perform this test only after
    // the dictionary has been populated.  Returns true if the test passed,
    // and false otherwise.
    //
    bool unit_test(FILE *f) {
        // sanity check: output forward and reverse mappings, to enable comparison
        bool passed = true;
        for (const auto &a : d) {
            if (a.first.compare(get_inverse(a.second)) != 0) {
                if (f) {
                    fprintf(f, "dict unit test error: mismatch at dict table entry (%s: %u)\n", a.first.c_str(), a.second);
                }
                passed = false;
            }
        }
        for (const auto &b : inverse) {
            if (get(b.first) != b.second) {
                if (f) {
                    fprintf(f, "dict unit test error: mismatch at inverse table entry (%s: %u)\n", b.first, b.second);
                }
                passed = false;
            }
        }
        return passed;
    }

};

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


class fingerprint_stats {
    std::unordered_map<std::string, uint64_t> fp_dst_table;
    event_encoder encoder;
    std::string observation;  // used as preallocated temporary variable

public:
    fingerprint_stats() : fp_dst_table{}, encoder{}, observation{'\0', 128} {
    }

    ~fingerprint_stats() {
        // TODO: connect this output to mercury in a more useful way
        //
        FILE *fpfile = stderr; // nullptr; // stderr; // fopen("fingerprint_stats.txt", "w");
        if (fpfile) {
            fprint(fpfile);
        }
    }

    void observe(const char *src_ip, const char *fp_str, const char *server_name, const char *dst_ip, uint16_t dst_port) {

        encoder.set_string(observation, src_ip, fp_str, server_name, dst_ip, dst_port);

        const auto entry = fp_dst_table.find(observation);
        if (entry != fp_dst_table.end()) {
            entry->second = entry->second + 1;
        } else {
            fp_dst_table.emplace(observation, 1);  // TODO: check return value for allocation failure
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
        // fprintf(stderr, "total_len: %zu\n", total_len);

        return;
    }

};


#endif // FP_STATS_H
