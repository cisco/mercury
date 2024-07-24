// tsc_clock.hpp
//
// Methods to measure time elapsed using CPU ticks

#ifndef TSC_CLOCK_HPP
#define TSC_CLOCK_HPP

#if defined(__i386__) || defined(__x86_64__)
    #define read_timestamp_counter() ({ \
        uint32_t lo, hi; \
        asm volatile("rdtsc" : "=a" (lo), "=d" (hi)); \
        ((uint64_t)hi << 32) | lo; \
    })
    #define tsc_clock_is_valid true
#elif defined(__aarch64__)
    #define read_timestamp_counter() ({ \
        uint64_t ticks; \
        asm volatile("mrs %0, CNTVCT_EL0" : "=r" (ticks)); \
        ticks; \
    })
    #define tsc_clock_is_valid true
#else
    #define read_timestamp_counter() 0
    #define tsc_clock_is_valid false
#endif

#include <thread>
#include <chrono>

using namespace std::chrono_literals;

class tsc_clock
{
    uint64_t start_tick;

public:

    static uint64_t get_ticks_per_sec() {
        if (!tsc_clock_is_valid) {
            return 0;
        }

        static uint64_t ticks_per_second = 0;
        if (ticks_per_second == 0) {
            tsc_clock start;
            std::this_thread::sleep_for(1s);
            tsc_clock end;
            ticks_per_second = end.get_start_tick() - start.get_start_tick();
        }
        return ticks_per_second;
    }

    tsc_clock() {
        start_tick = read_timestamp_counter();
    }

    time_t time_in_seconds() const {
        if (!is_valid()) {
            return 0;
        }

        return (get_start_tick() / get_ticks_per_sec());
    }

    uint64_t elapsed_tick() const {
        if (!is_valid()) {
            return 0;
        }

        return(read_timestamp_counter() - get_start_tick());
    }

    time_t elapsed_time_in_sec() const {
        if (!is_valid()) {
            return 0;
        }

        return (elapsed_tick() / get_ticks_per_sec());
     }

    uint64_t get_start_tick() const {
        return start_tick;
    }

    static bool is_valid() {
        if (tsc_clock_is_valid) {
            return true;
        }

        return false;
    }

#ifndef NDEBUG
    static bool unit_test() {
        tsc_clock start;
        // Pass this test for unsupported platform
        if (!is_valid()) {
            return true;
        }
        std::this_thread::sleep_for(1s);
        if (start.elapsed_time_in_sec() == 1) {
            return true;
        }
        return false;
    }
#endif //NDEBUG
};

#endif //TSC_CLOCK_HPP
