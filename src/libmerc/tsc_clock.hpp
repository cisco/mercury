/*
 * tsc_clock.hpp
 *
 * Methods to measure time elapsed using CPU ticks
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef TSC_CLOCK_HPP
#define TSC_CLOCK_HPP

#include <thread>
#include <chrono>
#include <cmath>

using namespace std::chrono_literals;

class tsc_clock
{
    uint64_t start_tick;

public:

    static uint64_t get_ticks_per_sec() {
        if (!is_valid()) {
            return 0;
        }
        static uint64_t ticks_per_second = 0;
        /*
         * Calculating the number of cpu ticks per second
         * by counting the number of cpu ticks in 1/100th of second
         * and then upscaling to get the number of cpu ticks per second
         */

        if (ticks_per_second == 0) {
            tsc_clock start;
            std::this_thread::sleep_for(10ms);
            tsc_clock end;
            ticks_per_second = (end.get_start_tick() - start.get_start_tick()) * 100;
        }
        return ticks_per_second;
    }

    static void init() {
        get_ticks_per_sec();
    }

    tsc_clock() {
        start_tick = read_timestamp_counter();
    }

    uint64_t time_in_seconds() const {
        if (!is_valid()) {
            return 0;
        }

        return (std::round(static_cast<double>(get_start_tick()) / get_ticks_per_sec()));
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

        return (std::round(static_cast<double>(elapsed_tick()) / get_ticks_per_sec()));
     }

    uint64_t get_start_tick() const {
        return start_tick;
    }

    static inline bool is_valid() {
        static bool tsc_counter = read_timestamp_counter();
        if (tsc_counter == 0) {
            return false;
        }

        return true;
    }

    static inline uint64_t read_timestamp_counter() {
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

    static bool unit_test() {
        tsc_clock start;
        // Pass this test for unsupported platform
        if (!is_valid()) {
            return true;
        }
        std::this_thread::sleep_for(1s);
        uint64_t elapsed_time = start.elapsed_time_in_sec();
        if (elapsed_time == 1) {
            return true;
        }
        return false;
    }
};

#endif //TSC_CLOCK_HPP
