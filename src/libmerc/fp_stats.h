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

    void process_update(std::vector<const char *> v, uint32_t count) {

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

    dict() : d{}, count{0}, inverse{}, inverse_size{0} {}

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

class fingerprint_stats {
    std::unordered_map<std::string, uint64_t> fp_dst_table;
    dict fp_dict;
    std::string observation;

public:
    fingerprint_stats() : fp_dst_table{}, fp_dict{}, observation{'\0', 128} {
    }

    ~fingerprint_stats() {
        // TODO: connect this output to mercury in a more useful way
        //
        FILE *fpfile = stderr; // nullptr; // stderr; // fopen("fingerprint_stats.txt", "w");
        if (fpfile) {
            fprint(fpfile);
        }
    }

    void observe_event(const char *src_ip, const char *fp_str, const char *server_name, const char *dst_ip, uint16_t dst_port) {

        set_string_to_observation(observation, src_ip, fp_str, server_name, dst_ip, dst_port);

        const auto entry = fp_dst_table.find(observation);
        if (entry != fp_dst_table.end()) {
            entry->second = entry->second + 1;
        } else {
            fp_dst_table.emplace(observation, 1);  // check return value?
        }
    }

    void set_string_to_observation(std::string &tmp, const char *src_ip, const char *fp, const char *server_name, const char *dst_ip, uint16_t dst_port) {

        // compress fingerprint string
        //        uint32_t fp_index = fp_dict.get(fp);
        char compressed_fp_buf[9];
        fp_dict.compress(fp, compressed_fp_buf);
        // sprintf(fp_index_string, "%x", fp_index);

        //fprintf(stdout, "compressed: %s\tdecompressed: %s\tin\n", compressed_fp_buf, fp);

        tmp.clear();
        tmp.append(src_ip);
        tmp += '#';
        tmp.append(compressed_fp_buf); //tmp.append(fp);
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

        // fprintf(stderr, "observe: %s\n", tmp.c_str());
    }

    void fprint(FILE *f) {

        // note: this function is not const because of compute_inverse_map()

        // compute fingerprint inverse table
        if (fp_dict.compute_inverse_map() == false) {
            return;  // error; unable to compute fingerprint decompression map
        }

        std::vector<std::pair<std::string, uint64_t>> v(fp_dst_table.begin(), fp_dst_table.end());
        std::sort(v.begin(), v.end(), [](auto &l, auto &r){ return l.first < r.first; } );

        size_t total_len = 0;
        event_processor ep(f);
        ep.process_init();
        for (auto &entry : v) {

            // fprintf(stdout, "%s\n", entry.first.c_str());  // HACK for debugging

            total_len += entry.first.length();

            size_t idx = entry.first.find('#');
            std::string head = entry.first.substr(0, idx);
            std::string tail = entry.first.substr(idx+1, std::string::npos);

            size_t fp_idx = tail.find('#');
            std::string compressed_fp = tail.substr(0, fp_idx);
            std::string suffix = tail.substr(fp_idx+1, std::string::npos);

            // decompress fingerprint string
            size_t compressed_fp_num = strtol(compressed_fp.c_str(), NULL, 16);
            std::string decompressed_fp = fp_dict.get_inverse(compressed_fp_num);
            //  std::string fp_str = decompressed_fp + suffix;

            //fprintf(stdout, "compressed: %s\tdecompressed: %s\tout\n", compressed_fp.c_str(), decompressed_fp.c_str());

            ep.process_update({head.c_str(), decompressed_fp.c_str(), suffix.c_str()}, entry.second);
        }
        ep.process_final();

        // if (fp_dict.unit_test(stderr)) {
        //     fprintf(stderr, "passed fp_dict.unit_test()\n");
        // }

        // fprintf(stderr, "total_len: %zu\n", total_len);

        return;
    }

};


//// OBSOLETE CODE /////

#if 0 // obsolete fp_stats code

class destination_stats {
    std::unordered_map<std::string, uint64_t> dest_count;
public:
    destination_stats() : dest_count{} {}

    void observe(const char *server_name, const char *dst_ip, uint16_t dst_port) {
        std::string tmp("(");
        tmp.append(server_name);
        tmp += ')';
        tmp += '(';
        tmp.append(dst_ip);
        char dst_port_string[8];
        sprintf(dst_port_string, "%hu", dst_port);
        tmp += ')';
        tmp += '(';
        tmp.append(dst_port_string);
        tmp += ')';

        // fprintf(stderr, "observe: %s\n", tmp.c_str());

        const auto &dc = dest_count.find(tmp);
        if (dc == dest_count.end()) {
            dest_count.emplace(tmp, 1);
        } else {
            dc->second = dc->second + 1;
        }
    }

    void fprint(FILE *f) const {
        std::vector<std::pair<std::string, uint64_t>> vec(dest_count.begin(), dest_count.end());
        std::sort(vec.begin(), vec.end(), [](auto &l, auto &r){ return l.second > r.second; } );
        bool first = true;
        for (const auto & x : vec) {
            if (!first) {
                fputc(',', f);
            }
            fprintf(f, "\"%s\": %lu", x.first.c_str(), x.second);
            first = false;
        }
    }
};

class fingerprint_stats_old {
    std::unordered_map<std::string, destination_stats> fp_dst_table;

    public:
    fingerprint_stats_old() : fp_dst_table{} { }

    ~fingerprint_stats_old() {
        fprint(stderr);
    }

    void observe(const char *fp_str, const char *server_name, const char *dst_ip, uint16_t dst_port) {
        const auto dst_table = fp_dst_table.find(fp_str);
        if (dst_table != fp_dst_table.end()) {
            //fprintf(stderr, "fp %s found in table\n", fp_str);
            dst_table->second.observe(server_name, dst_ip, dst_port);
        } else {
            //fprintf(stderr, "fp %s NOT found in table\n", fp_str);
            destination_stats tmp;
            auto [dst, dst_is_set] = fp_dst_table.emplace(fp_str, tmp);
            if (dst_is_set) {
                dst->second.observe(server_name, dst_ip, dst_port);
            }
        }
    }

    void fprint(FILE *f) const {
        for (const auto &x : fp_dst_table) {
            fprintf(f, "{\"str_repr\": \"%s\",\"destinations\":{", x.first.c_str());
            x.second.fprint(f);
            fprintf(f, "}}\n");
        }
    }
};

#endif

//// OBSOLETE CODE /////


#endif // FP_STATS_H
