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

class fingerprint_stats {
    std::unordered_map<std::string, uint64_t> fp_dst_table;
    std::string observation;

public:
    fingerprint_stats() : fp_dst_table{}, observation{'\0', 128} {
    }

    ~fingerprint_stats() {
        FILE *fpfile = stderr; // fopen("fingerprint_stats.txt", "w");
        if (fpfile) {
            fprint(fpfile);
        }
    }

    void observe(const char *fp_str, const char *server_name, const char *dst_ip, uint16_t dst_port) {

        set_string_to_observation(observation, fp_str, server_name, dst_ip, dst_port);

        const auto entry = fp_dst_table.find(observation);
        if (entry != fp_dst_table.end()) {
            entry->second = entry->second + 1;
        } else {
            fp_dst_table.emplace(observation, 1);  // check return value?
        }
    }

    void set_string_to_observation(std::string &tmp, const char *fp, const char *server_name, const char *dst_ip, uint16_t dst_port) {
        tmp.clear();
        tmp.append(fp);
        tmp += '#';
        tmp.append("(");
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

    }

    void fprint(FILE *f) const {
        std::unordered_map<std::string, std::unordered_map<std::string, uint64_t>> fp_to_dst_and_count;

        // aggregate data
        for (const auto &x : fp_dst_table) {
            size_t index_of_destination = x.first.find('#');
            std::string fp = x.first.substr(0, index_of_destination);
            std::string dst = x.first.substr(index_of_destination+1, std::string::npos);
            uint64_t c = x.second;

            // fprintf(f, "{\"fingerprint\":\"%s\",\"destination\":\"%s\"}}\n", fp.c_str(), dst.c_str());

            auto dst_and_count = fp_to_dst_and_count.find(fp);
            if (dst_and_count != fp_to_dst_and_count.end()) {
                auto count = dst_and_count->second.find(dst);
                if (count != dst_and_count->second.end()) {
                    count->second = count->second + c;
                } else {
                    dst_and_count->second.emplace(dst, c);
                }
            } else {
                std::unordered_map<std::string, uint64_t> tmp;
                auto [dc, dc_is_set] = fp_to_dst_and_count.emplace(fp, tmp);
                if (dc_is_set) {
                    dc->second.emplace(dst, c);
                }
            }
        }

        // print out sorted data
        for (const auto &dc : fp_to_dst_and_count) {
            fprintf(f, "{\"str_repr\":\"%s\",\"destinations\":{", dc.first.c_str());
            std::vector<std::pair<std::string, uint64_t>> vec(dc.second.begin(), dc.second.end());
            std::sort(vec.begin(), vec.end(), [](auto &l, auto &r){ return l.second > r.second; } );
            bool first = true;
            for (const auto & x : vec) {
                if (!first) {
                    fputc(',', f);
                }
                fprintf(f, "\"%s\": %lu", x.first.c_str(), x.second);
                first = false;
            }
            fprintf(f, "}}\n");
        }

    }

};


//// OBSOLETE CODE /////

#if 0 // obsolete fp_status code

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
