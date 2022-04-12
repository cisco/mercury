// control.h
//
// control thread, to perform scheduled tasks


#ifndef CONTROL_H
#define CONTROL_H

#include <unistd.h>
#include <string>
#include <atomic>
#include <stdexcept>
#include "rotator.h"
#include "output.h"
#include "libmerc/libmerc.h"

class controller {
public:

    controller(mercury_context merc_ctx,
               const char *stats_filename,
               size_t num_secs,
               output_file* file,
               const struct mercury_config &cfg,
               bool do_stats) :
        mc{merc_ctx},
        stats_file{stats_filename, ".json.gz"},
        num_secs_between_writes{num_secs},
        count{num_secs},
        controller_thread{},
        shutdown_requested{false},
        has_run_at_least_once{false},
        out_file{file},
        stats_dump{do_stats}
    {
        if (mc == nullptr) {
            throw std::runtime_error("error: null mercury context passed to control thread");
        }
        //set json output config
        out_file->max_records = cfg.rotate;
        out_file->file_num = 0;
        out_file->mode = cfg.mode;
        out_file->rotate_time = cfg.out_rotation_duration;

        if (cfg.fingerprint_filename) {
            out_file->outfile_name = cfg.fingerprint_filename;
            out_file->type = file_type_json;
        } else if (cfg.write_filename) {
            out_file->outfile_name = cfg.write_filename;
            out_file->type = file_type_pcap;
        } else {
            out_file->type = file_type_stdout;  // default output type
        }

        if (out_file->max_records == 0) {
            out_file->max_records = UINT64_MAX;
        }
        if (out_file->rotate_time == 0) {
            out_file->rotate_time = UINT64_MAX;
        }
        out_count = out_file->rotate_time;

        start();
    }

    ~controller() {
        stop();
    }

private:

    mercury_context mc;
    rotator stats_file;
    size_t num_secs_between_writes;
    size_t count;
    size_t out_count;
    std::thread controller_thread;
    std::atomic<bool> shutdown_requested;
    bool has_run_at_least_once;
    struct output_file* out_file = nullptr;
    bool stats_dump = false;

    void run_tasks() {
        while (shutdown_requested.load() == false) {
            outfile_routine();

            if (stats_dump) {
                if (count == 0) {
                    count = num_secs_between_writes;
                    has_run_at_least_once = true;
                    const char *fname = stats_file.get_next_name();
                    if (mercury_write_stats_data(mc, fname) == false) {
                        fprintf(stderr, "error: could not write stats file %s\n", fname);
                    }
                }
                --count;
            }
            sleep(1);
        }
    }

    void outfile_routine() {
        if (out_file->file_pri == nullptr || out_file->rotation_req.load() == true) {
            enum status status = output_file_rotate(out_file);
            if (status != status_ok) {
                exit(EXIT_FAILURE);
            }
        }

        if (out_file->rotate_time) {
            if (out_count == 0) {
                if (out_file->time_rotation_req.load() == true) {
                    return; //wait till previous rotaion is completed
                }
                out_count = out_file->rotate_time;
                out_file->time_rotation_req = true;
            }
            --out_count;
        }
    }

    void start() {
        controller_thread = std::thread( [this](){ run_tasks(); } );  // lambda just calls member function
    }

    void stop() {
        shutdown_requested.store(true);
        if(controller_thread.joinable()) {
            controller_thread.join();
        }
        if (stats_dump) {
            const char *fname = has_run_at_least_once ? stats_file.get_next_name() : stats_file.get_current_name();
            if (mercury_write_stats_data(mc, fname) == false) {
                fprintf(stderr, "error: could not write stats file %s\n", fname);
            }
        }
    }

};

#endif // CONTROL_H
