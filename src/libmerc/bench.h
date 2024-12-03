// bench.h
//
// simple benchmarking

#ifndef BENCH_H
#define BENCH_H

// The cycle_counter class will compile anywhere, but will only work
// correctly on platforms that provide a function to read the
// timestamp counter.  The following preprocessor conditionals
// identify the appropriate function, if one is present, and set
// benchmark_is_valid to true or false.   That value can be accessed
// through the constexpr static boolean benchmark::is_valid.
//
#ifdef HAVE_X86INTRIN_H
   #include <x86intrin.h>
   #define read_timestamp_counter() __rdtsc()
   #define benchmark_is_valid true
#else
   #define read_timestamp_counter() 0
   #define benchmark_is_valid false
#endif
//
// TODO: add the corresponding ARM equivalent function

#include <cmath>  // for sqrt()

namespace benchmark {

    static constexpr bool is_valid = benchmark_is_valid;

    // An object of class cycle_counter counts the number of clock
    // cycles between its construction and the invocation of the
    // delta() function
    //
    class cycle_counter {
        uint64_t value;

    public:

        cycle_counter() : value{read_timestamp_counter()} { }

        uint64_t delta() const { return read_timestamp_counter() - value; }

    };

    // An object of class count_and_mean maintains a count and mean of
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
