// control.h
//
// control thread, to perform scheduled tasks


#ifndef CONTROL_H
#define CONTROL_H

#include <unistd.h>
#include <string>
#include <atomic>
#include "libmerc/libmerc.h"

class controller {
public:

    controller(mercury_context merc_ctx,
               const char *stats_filename,
               size_t num_secs) :
        mc{merc_ctx},
        stats_file{stats_filename},
        num_secs_between_writes{num_secs},
        count{num_secs},
        controller_thread{},
        shutdown_requested{false}
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
    std::string stats_file;
    size_t num_secs_between_writes;
    size_t count;
    std::thread controller_thread;
    std::atomic<bool> shutdown_requested;

    void run_tasks() {
        while (shutdown_requested.load() == false) {
            if (count == 0) {
                count = num_secs_between_writes;
                if (mercury_write_stats_data(mc, stats_file.c_str()) == false) {
                    fprintf(stderr, "error: could not write stats file %s\n", stats_file.c_str());
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
    }

};

#endif // CONTROL_H
