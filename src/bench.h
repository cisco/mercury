// bench.h
//
// simple benchmarking

#ifndef BENCH_H
#define BENCH_H


// TODO: use autoconf to detect x86intrin.h, and add the corresponding
// AMD equivalent
//
#include <x86intrin.h>

namespace benchmark {

    // An object of class cycle_counter counts the number of clock
    // cycles between its construction and the invocation of the
    // delta() function
    //
    class cycle_counter {
        uint64_t value;

    public:

    cycle_counter() : value{__rdtsc()} { }

        uint64_t delta() const { return __rdtsc() - value; }
    };

    // An object of class statistics maintains a count, and mean, and
    // potentially other statistics about observed numbers.   Each observation
    // is reported with the member function +=, e.g. 's += x' observes x.
    //
    class statistics {
        uint64_t counter = 0;
        uint64_t mean_ = 0;
    public:

        void operator+=(uint64_t x) {
            counter++;
            mean_ += x;
        }

        double mean() const { return (double) mean_ / counter; }

        double total() const { return (double) mean_; }
    };

    // TODO: create a derived class from statistics that computes the
    // variance using Welford's algorithm, and also tracks the minimum
    // and maxiumum values.

} // namespace benchmark

#endif // BENCH_H
