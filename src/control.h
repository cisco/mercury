// control.h
//
// control thread, to perform scheduled tasks


#ifndef CONTROL_H
#define CONTROL_H

#include <unistd.h>
#include <string>
#include <atomic>
#include "rotator.h"
#include "libmerc/libmerc.h"

class controller {
public:

    controller(mercury_context merc_ctx,
               const char *stats_filename,
               size_t num_secs) :
        mc{merc_ctx},
        stats_file{stats_filename, ".json.gz"},
        num_secs_between_writes{num_secs},
        count{num_secs},
        controller_thread{},
        shutdown_requested{false},
        has_run_at_least_once{false}
    {
        if (mc == nullptr) {
            throw "error: null mercury context passed to control thread";
        }
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
    std::thread controller_thread;
    std::atomic<bool> shutdown_requested;
    bool has_run_at_least_once;

    void run_tasks() {
        while (shutdown_requested.load() == false) {
            if (count == 0) {
                count = num_secs_between_writes;
                const char *fname = stats_file.get_next_name();
                if (mercury_write_stats_data(mc, fname) == false) {
                    fprintf(stderr, "error: could not write stats file %s\n", fname);
                }
            }
            --count;
            sleep(1);
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
        if (!has_run_at_least_once) {
            const char *fname = stats_file.get_current_name();
            if (mercury_write_stats_data(mc, fname) == false) {
                fprintf(stderr, "error: could not write stats file %s\n", fname);
            }
        }
    }

};

#endif // CONTROL_H
