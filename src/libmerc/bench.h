// bench.h
//
// simple benchmarking

#ifndef BENCH_H
#define BENCH_H

#include <cmath>  // for sqrt()
#include "tsc_clock.hpp"

namespace benchmark {

    static bool is_valid = tsc_clock::is_valid();

    // all of the observed numbers.  Each observation is reported with
    // the member function +=, e.g. 's += x' observes x.
    //
    class mean_and_count {
        uint64_t counter = 0;
        uint64_t mean_ = 0;
    public:

        void operator+=(uint64_t x) {
            counter++;
            mean_ += x;
        }

        // mean() returns a floating point number representing the
        // mean of all of the observations
        //
        double mean() const { return (double) mean_ / counter; }

        // total() returns a floating point number representing the
        // sum of all of the observations
        //
        double total() const { return (double) mean_; }
    };


    // The class mean_and_variance incrementally computes the mean and
    // variance of the observed values, using a numerically stable
    // algorithm following Welford (as described in Knuth Volume 2,
    // Section 4.2.2)
    //
    class mean_and_standard_deviation {
        uint64_t k = 0;
        double M = 0;
        double S = 0;

    public:

        void operator+=(uint64_t x) {
            k++;
            if (k == 1) {   // note: index effectively starts at one
                M = x;
                S = 0;
            } else {
                double M_new = M + ((x - M) / k);
                double S_new = S + ((x - M) * (x - M_new));
                M = M_new;
                S = S_new;
            }
        }

        // mean() returns a floating point number representing the
        // mean of all of the observations
        //
        double mean() const {
            if (k < 1) {
                return NAN; // too few observations to compute mean
            }
            return M;
        }

        // standard_deviation() returns a floating point number representing the
        // standard deviation of all of the observations
        //
        double standard_deviation() const {
            if (k < 2) {
                return NAN; // too few observations to compute standard deviation
            }
            return sqrt( S/(k-1) );
        }

        // total() returns a floating point number representing the
        // sum of all of the observations
        //
        double total() const {
            return M * k;
        }

    };

    /// An object of class min_and_max maintains the minimum and
    /// maximum of all of the observed numbers.  Each observation is
    /// reported with the member function +=, e.g. 's += x' observes
    /// x.
    ///
    class min_and_max {
        uint64_t minimum = std::numeric_limits<uint64_t>::max();
        uint64_t maximum = std::numeric_limits<uint64_t>::min();
    public:

        void operator+=(uint64_t x) {
            if (x < minimum) {
                minimum = x;
            }
            else if (x > maximum) {
                maximum = x;
            }
        }

        /// min() returns the minimum of all of the observations
        ///
        uint64_t min() const { return minimum; }

        /// max() returns the maximum of all of the observations
        ///
        double max() const { return maximum; }

    };

} // namespace benchmark

#endif // BENCH_H
