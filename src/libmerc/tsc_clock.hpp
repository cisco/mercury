// tsc_clock.hpp
//
// Methods to measure time elapsed using CPU ticks

#ifndef TSC_CLOCK_HPP
#define TSC_CLOCK_HPP

#include <thread>
#include <chrono>

using namespace std::chrono_literals;

class tsc_clock
{
    uint64_t start_tick;

public:
    static uint64_t get_clock_ticks_per_sec() {
        tsc_clock start;
        std::this_thread::sleep_for(1s);
        tsc_clock end;
        return (end.get_tick() - start.get_tick());
    }
    static uint64_t clock_ticks_per_sec;

    static void initialize() {
        clock_ticks_per_sec = get_clock_ticks_per_sec();
    }

    tsc_clock() {
        start_tick = read_timestamp_counter();
    }

    time_t time_in_seconds() const {
        if (!is_valid()) {
            return 0;
        }

        return (start_tick / clock_ticks_per_sec);
    }

    uint64_t elapsed_time() const {
        if (!is_valid()) {
            return 0;
        }

        return(read_timestamp_counter() - get_tick());
    }

    time_t elapsed_time_in_sec() const {
        if (!is_valid()) {
            return 0;
        }

        return (elapsed_time() / clock_ticks_per_sec);
     }


    static uint64_t read_timestamp_counter() {
#if defined(__i386__) || defined(__x86_64__)
        uint32_t lo, hi;
        asm volatile("rdtsc" : "=a" (lo), "=d" (hi));
        return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
        uint64_t ticks;
        asm volatile("mrs %0, CNTVCT_EL0" : "=r" (ticks));
        return ticks;
#else
        return 0;
#endif
    }

    uint64_t get_tick() const {
        return start_tick;
    }

    static bool is_valid() {
        if (clock_ticks_per_sec) {
            return true;
        }

        return false;
    }

#ifndef NDEBUG
    static bool unit_test() {
        tsc_clock start;
        // Pass this test for unsupported platform
        if (is_valid()) {
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
