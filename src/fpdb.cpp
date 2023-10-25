// fpdb.cpp

#include <fstream>

#include "fpdb_reader.hpp"
#include "libmerc/bench.h"

#include "options.h"

std::string get_fp_type(const std::string &s) {
    std::string::size_type pos = s.find('/');
    if (pos != std::string::npos) {
        return s.substr(0, pos);
    }
    return "unknown";
}

class fp_stats {
    size_t count = 0;
    benchmark::mean_and_standard_deviation processes_per_fingerprint;
    benchmark::mean_and_standard_deviation benign_processes_per_fingerprint;
    benchmark::mean_and_standard_deviation malware_processes_per_fingerprint;
    benchmark::mean_and_standard_deviation updates_per_process;

public:

    void observe_fp() {
        ++count;
    }
    size_t get_count() const { return count; }

    void observe_process(size_t benign_process_count, size_t malware_process_count, benchmark::mean_and_standard_deviation stats) {
        processes_per_fingerprint += (benign_process_count + malware_process_count);
        benign_processes_per_fingerprint += benign_process_count;
        malware_processes_per_fingerprint += malware_process_count;
        //  updates_per_process += stats;  // TODO: implement member function to enable merging these together
    }
    double get_process_mean() const { return processes_per_fingerprint.mean(); }
    double get_process_stddev() const { return processes_per_fingerprint.standard_deviation(); }

    void fprint(FILE *f) const {
        fprintf(f, "\tall processes:    \tmean: %f\tstddev: %f\n", processes_per_fingerprint.mean(), processes_per_fingerprint.standard_deviation());
        fprintf(f, "\tbenign processes: \tmean: %f\tstddev: %f\n", benign_processes_per_fingerprint.mean(), benign_processes_per_fingerprint.standard_deviation());
        fprintf(f, "\tmalware processes:\tmean: %f\tstddev: %f\n", malware_processes_per_fingerprint.mean(), malware_processes_per_fingerprint.standard_deviation());
    }
};

class process_stats {
    size_t num_fingerprints = 0;
    size_t num_updates = 0;

public:

    void observe(size_t updates) {
        num_updates += updates;
        ++num_fingerprints;
    }

    void fprint(FILE *f) const {
        fprintf(f, "\tfps: %zu\tupdates: %zu\n", num_fingerprints, num_updates);
    }

};

class proc_statistics {
    std::unordered_map<std::string, process_stats> stats;
public:

    void observe(const std::string &name, size_t updates) {
        auto result = stats.find(name);
        if (result == stats.end()) {
            result = stats.insert({name, process_stats{}}).first;
        }
        result->second.observe(updates);
    }

    void fprint(FILE *f) const {
        for (const auto & s : stats) {
            fprintf(f, "%s\t", s.first.c_str());
            s.second.fprint(f);
        }
    }

};

class fpdb_stats {

    std::unordered_map<std::string, fp_stats> stats;

public:

    void observe_fp(std::string type) {
        auto result = stats.find(type);
        if (result == stats.end()) {
            result = stats.insert({type, fp_stats{}}).first;
        }
        result->second.observe_fp();
    }

    void observe_process(std::string type, size_t benign_process_count, size_t malware_process_count, benchmark::mean_and_standard_deviation update_stats) {
        auto result = stats.find(type);
        if (result == stats.end()) {
            result = stats.insert({type, fp_stats{}}).first;
        }
        result->second.observe_process(benign_process_count, malware_process_count, update_stats);
    }

    void fprint(FILE *f) const {
        for (const auto & x : stats) {
            fprintf(f, "type: %s     \tcount: %zu\n", x.first.c_str(), x.second.get_count());
            // fprintf(f, "\tall processes:\tmean: %f\tstddev: %f\n", x.second.get_process_mean(), x.second.get_process_stddev());
            x.second.fprint(f);
        }
    }
};

using namespace mercury_option;

int main(int argc, char *argv[]) {

    std::ios::sync_with_stdio(false);  // for performance

    class option_processor opt({
        { argument::none,       "--help",               "print help message"               },
        { argument::none,       "--fp-stats",           "print per-fingerprint statistics" },
        { argument::none,       "--process-stats",      "print per-process statistics"     },
        { argument::none,       "--proc-view",          "print process view of statistics" },
        { argument::required,   "--fpdb",               "fingerprint_db.json file"         },
    });
    const char summary[] =
        "usage:\n"
        "   fpdb [OPTIONS]\n"
        "\n"
        "OPTIONS\n"
        ;
    if (!opt.process_argv(argc, argv)) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    auto [ fpdb_is_set, fpdb ]        = opt.get_value("--fpdb");
    bool help                         = opt.is_set("--help");
    bool write_fingerprint_stats      = opt.is_set("--fp-stats");
    bool write_process_stats          = opt.is_set("--process-stats");
    bool write_proc_view              = opt.is_set("--proc-view");

    if (help) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_SUCCESS;
    }
    if (write_fingerprint_stats & write_process_stats) {
        fprintf(stderr, "error: both --fp-stats and --process-stats specified\n");
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    if (fpdb_is_set) {

        fpdb_stats stats;
        proc_statistics proc_stats;

        std::ifstream fpdb_file{fpdb};
        if (!fpdb_file) {
            fprintf(stderr, "error: could not open file %s\n", fpdb.c_str());
            return EXIT_FAILURE;
        }
        resources fingerprint_db(fpdb_file, resources::verbosity::verbose);

        const std::unordered_map<std::string, std::vector<process_info>> & fp_and_process_info = fingerprint_db.get_fpdb();
        for (const auto & fp_data : fp_and_process_info) {
            std::string fp_type = get_fp_type(fp_data.first);

            if (write_process_stats) {
                fprintf(stdout, "%s:\n", fp_data.first.c_str());
            }

            stats.observe_fp(fp_type);
            size_t malware_process_count = 0;
            size_t benign_process_count = 0;
            size_t total_update_count = 0;
            benchmark::mean_and_standard_deviation update_stats;
            for (const auto & pi : fp_data.second) {

                // count the number of malware and benign processes
                //
                if (pi.malware) {
                    ++malware_process_count;
                } else {
                    ++benign_process_count;
                }

                // compute the count, mean and standard deviation of the number of updates in each process
                //
                size_t update_count = 0;
                for (auto &x : pi.ip_as)                 {  ++update_count; (void)x; }
                for (auto &x : pi.hostname_domains)      {  ++update_count; (void)x; }
                for (auto &x : pi.portname_applications) {  ++update_count; (void)x; }
                for (auto &x : pi.ip_ip)                 {  ++update_count; (void)x; }
                for (auto &x : pi.hostname_sni)          {  ++update_count; (void)x; }
                for (auto &x : pi.user_agent)            {  ++update_count; (void)x; }
                update_stats += update_count;
                total_update_count += update_count;

                std::string name{pi.name};
                std::replace(name.begin(), name.end(), ' ', '_');  // remove blanks, to facilitate POSIX pipeline processing
                if (write_process_stats) {
                    fprintf(stdout, "\t%s:\t%zu\n", name.c_str(), update_count);
                }
                proc_stats.observe(fp_type + ':' + name, update_count);
            }
            stats.observe_process(fp_type, benign_process_count, malware_process_count, update_stats);
            if (write_fingerprint_stats) {
                size_t total_process_count = benign_process_count + malware_process_count;
                fprintf(stdout, "%s:\t%zu\t%zu\t%zu\n", fp_data.first.c_str(), total_process_count, malware_process_count, total_update_count);
            }

        }

        if (!write_fingerprint_stats && !write_process_stats && !write_proc_view) {
            //
            // write overall statistics
            //
            stats.fprint(stdout);
        }

        if (write_proc_view) {
            proc_stats.fprint(stdout);
        }
    }

    return 0;
}
