// markov.hpp

#ifndef MARKOV_HPP
#define MARKOV_HPP

#include <cstdio>
#include <cmath>
#include <string>
#include <stdexcept>
#include <vector>

[[maybe_unused]] static double plogp(double p) {
    if (p == 0.0) {
        return 0.0;
    }
    return p * log(p); // note: could divide by log(2.0)
}

struct example_char_set {

    static constexpr size_t N = 2;

    // char_to_index(c) maps the character c to its index
    //
    static size_t char_to_index(char c) {
        if (c >= '0' && c <= '1') { return c - '0'; }
        return 0;
    }

    // index_to_char(idx) maps the index idx to its character
    //
    static char index_to_char(char c) {
        if (c >= 0 && c <= 2) { return c + '0'; }
        return 0;
    }

};

struct dns_char_set {

    static constexpr size_t N = 39;

    // char_to_index(c) maps the character c to its index
    //
    static size_t char_to_index(char c) {
        if (c >= '0' && c <= '9') { return c - '0'; }
        if (c >= 'a' && c <= 'z') { return c - 'a' + 10; }
        if (c >= 'A' && c <= 'Z') { return c - 'A' + 10; }
        if (c == '-') { return 36; }
        if (c == '.') { return 37; }
        if (c == '_') { return 38; }
        return 0;
    }

    // index_to_char(idx) maps the index idx to its character
    //
    static char index_to_char(char c) {
        if (c >= 0 && c <= 9) { return c + '0'; }
        if (c >= 10 && c <= 35) { return c + 'a' - 10; }
        if (c == 36) { return '-'; }
        if (c == 37) { return '.'; }
        if (c == 38) { return '_'; }
        return 0;
    }

    static void check_reversibility(char c) {
        char i = char_to_index(c);
        char d = index_to_char(i);
        if (c != d) {
                throw std::runtime_error{"char_set::unit_test() failed forward test"};
        }
    }

    static bool unit_test() {
        for (int c='0'; c<='9'; c++) {
            check_reversibility(c);
        }
        for (int c='a'; c<='z'; c++) {
            check_reversibility(c);
        }
        check_reversibility('-');
        check_reversibility('.');
        check_reversibility('_');

        // check reverse direction
        //
        for (size_t i=0; i<N; i++) {
            char c = index_to_char(i);
            size_t j = char_to_index(c);
            if (i != j) {
                fprintf(stderr, "unit test failure on index %zu (character %c)\n", i, c);
                throw std::runtime_error{"char_set::unit_test() failed reverse test"};
            }
        }
        return true;
    }

};

#ifndef NDEBUG
//
// run unit test for dns_char_set
//
static inline bool dns_char_set_unit_test_passed = dns_char_set::unit_test();
#endif

template <typename char_set>
class model {
};

template <typename char_set>
class markov_model // : public model<char_set>
{
    size_t count = 0;
    size_t p[char_set::N] = { 0, };
    size_t x[char_set::N][char_set::N] = { {0, }, };
    size_t v[char_set::N] = { 0, };

    static constexpr size_t file_magic = 0xe9f3a2c7b8c6520c;

    void read_array_from_file(FILE *f, size_t *location, size_t array_length) {
        size_t tmp;
        // fprintf(stderr, "reading %zu bytes to %p from %p\n", sizeof(size_t)*array_length, location, f);
        if ((tmp=fread(location, sizeof(size_t), array_length, f)) != array_length) {
            // fprintf(stderr, "error: only read %zu bytes\n", tmp);
            throw std::runtime_error{"error reading array from file"};
        }
    }

    void write_array_to_file(FILE *f, const size_t *location, size_t array_length) {
        size_t tmp;
        // fprintf(stderr, "writing %zu bytes from %p to %p\n", sizeof(size_t)*array_length, location, f);
        if ((tmp = fwrite(location, sizeof(size_t), array_length, f)) != array_length) {
            // fprintf(stderr, "error: only wrote %zu bytes\n", tmp);
            throw std::runtime_error{"error writing array to file"};
        }
    }

public:

    markov_model(FILE *f) {
        if (f == nullptr) {
            throw std::runtime_error{"null file pointer in file read"};
        }
        size_t tmp_file_magic;
        read_array_from_file(f, &tmp_file_magic, 1);
        if (tmp_file_magic != file_magic) {
            throw std::runtime_error{"error: unexpected file type"};
        }
        read_array_from_file(f, &count, 1);
        read_array_from_file(f, &p[0], char_set::N);
        read_array_from_file(f, &x[0][0], char_set::N * char_set::N);
        read_array_from_file(f, &v[0], char_set::N);
    }

    markov_model() { }

    void write_to_file(FILE *f) {
        if (f == nullptr) {
            throw std::runtime_error{"null file pointer in file write"};
        }
        write_array_to_file(f, &file_magic, 1);
        write_array_to_file(f, &count, 1);
        write_array_to_file(f, &p[0], char_set::N);
        write_array_to_file(f, &x[0][0], char_set::N * char_set::N);
        write_array_to_file(f, &v[0], char_set::N);
    }

    void add(std::string &s) {
        if (s.length() == 0) {
            return;
        }
        ++p[char_set::char_to_index(s[0])];
        ++count;
        if (s.length() == 1) {
            return;
        }
        for (size_t i=0; i < s.length()-1; i++) {
            // fprintf(stderr, "c1: %c\tc2: %c\n", s[i], s[i+1]);
            // fprintf(stderr, "idx1: %zu\tidx2: %zu\n", char_set::char_to_index(s[i]), char_set::char_to_index(s[i+1]));
           ++x[char_set::char_to_index(s[i])][char_set::char_to_index(s[i+1])];
           ++v[char_set::char_to_index(s[i])];
        }
    }

    // probability(initial_char) returns the probability of the
    // initial character initial_char, in this model
    //
    double probability(char initial_char) const {
        return p_index(char_set::char_to_index(initial_char));
    }

    // p_index(initial_idx) returns the probability of the initial
    // index initial_idx, in this model
    //
    double p_index(size_t initial_idx) const {
        if (count) {
            return (double)p[initial_idx] / count;
        }
        return 0.0;
    }

    // probability(c1, c2) returns the probability of a transition
    // from character c1 to character c2, in this model
    //
    double probability(char c1, char c2) const {
        // fprintf(stderr, "c1: %c\tc2: %c\n", c1, c2);
        return p_index(char_set::char_to_index(c1), char_set::char_to_index(c2));
    }

    // p_index(idx1, idx2) returns the probability of a transition
    // from index idx1 to index idx2, in this model
    //
    double p_index(size_t idx1, size_t idx2) const {
        // fprintf(stderr, "idx1: %zu\tidx2: %zu\n", idx1, idx2);
        // fprintf(stderr, "p_index\tv:%zu\tx:%zu\n", v[idx1], x[idx1][idx2]);
        if (v[idx1]) {
            return (double)x[idx1][idx2]/v[idx1];
        }
        return 0.0;
    }

    // probability(s) returns the probability of the string s, in this
    // model
    //
    double probability(const std::string &s) const {
        double tmp = 0.0;
        if (s.length() == 0) {
            return tmp;
        }
        tmp = probability(s[0]);
        if (s.length() == 1) {
            return tmp;
        }
        for (size_t i=0; i < s.length()-1; i++) {
            tmp *= probability(s[i], s[i+1]);
        }
        return tmp;
    }

    // shannon_entropy(s) returns the empirical entropy of the string
    // s, in this model
    //
    double shannon_entropy(const std::string &s) const {
        double e = 0.0;
        if (s.length() == 0) {
            return e;
        }
        e += plogp(probability(s[0]));
        if (s.length() == 1) {
            return e;
        }
        for (size_t i=0; i < s.length()-1; i++) {
            e += plogp(probability(s[i], s[i+1]));
        }
        return - e;
    }

    double log_prob_per_char(const std::string &s) const {
        double log_prob = 0.0;
        if (s.length() == 0) {
            return log_prob;
        }
        log_prob = log((double)p[char_set::char_to_index(s[0])]/count);
        if (s.length() == 1) {
            return log_prob;
        }
        for (size_t i=0; i < s.length()-1; i++) {
            log_prob += log( (double)x[char_set::char_to_index(s[i])][char_set::char_to_index(s[i+1])]/v[char_set::char_to_index(s[i])] );
        }
        return log_prob / s.length();
        // return (tmp * log(tmp)) / s.length();
    }

    // test_random() tests the hypothesis that the input string s was
    // produced by this markov model, as opposed to a uniformly random
    // process
    //
    double test_random(const std::string &s) const {
        double log_prob = 0.0;
        if (s.length() == 0) {
            return log_prob;
        }
        log_prob = log(probability(s[0]));
        if (s.length() == 1) {
            return log_prob;
        }
        for (size_t i=0; i < s.length()-1; i++) {
            //fprintf(stderr, "log_prob: %.17f\n", log_prob);
            log_prob += log(probability(s[i], s[i+1]));
        }
        return log_prob - ((double)s.length() * log(1.0/char_set::N));
    }

    // entropy_rate() returns the entropy rate (entropy per symbol)
    // of this markov source
    //
    // note: if the stationary distribution has a single non-zero
    // element, then the entropy rate will be zero.
    //
    double entropy_rate() const {
        double rate = 0.0;
        std::vector<double> u = stationary_distribution();
        for (size_t i=0; i<char_set::N; i++) {
            for (size_t j=0; j<char_set::N; j++) {
                if (v[i]) {
                    rate -= u[i] * plogp(p_index(i, j));
                }
            }
        }
        return rate;
    }

    // stationary_distribution() returns a vector containing the
    // stationary probability distribution of this markov source
    //
    // The stationary distribution is a vector S of probabilities
    // representing the probability that each character will occur
    // after a very large number of transitions; that is,
    //
    //    S^T * P = S^T,
    //
    // where P is the probability transition matrix and S^T is the
    // transpose of S.
    //
    std::vector<double> stationary_distribution() const {
        std::vector<double> u(char_set::N, 1.0/char_set::N);
        size_t num_iterations = 100;
        for (size_t i=0; i<num_iterations; i++) {
            u = transpose_mult(u);
            double sum = 0.0;
            for (const auto &x : u) {
                sum += x;
            }
            for (auto &x : u) {
                x /= sum;
            }
        }
        return u;
    }

    std::vector<double> operator*(const std::vector<double> &rhs) const {
        std::vector<double> tmp(char_set::N, 0.0);
        for (size_t i=0; i < char_set::N; i++) {
            double a = 0.0;
            for (size_t j=0; j < char_set::N; j++) {
                a += rhs[j] * p_index(i, j);
            }
            tmp[i] = a;
        }
        return tmp;
    }

    std::vector<double> transpose_mult(const std::vector<double> &lhs) const {
        std::vector<double> tmp(char_set::N, 0.0);
        for (size_t i=0; i < char_set::N; i++) {
            double a = 0.0;
            for (size_t j=0; j < char_set::N; j++) {
                a += lhs[j] * p_index(j, i);
            }
            tmp[i] = a;
        }
        return tmp;
    }

    void fprint_dump(FILE *f) const {
        fprintf(f, "count: %zu\n", count);
        for (size_t i=0; i < char_set::N; i++) {
            fprintf(f, "p[%c]: %zu\n", char_set::index_to_char(i), p[i]);
        }
        for (size_t i=0; i < char_set::N; i++) {
            fprintf(f, "v[%c]: %zu\n", char_set::index_to_char(i), v[i]);
            for (size_t j=0; j < char_set::N; j++) {
                fprintf(stdout, "x[%c][%c]: %zu\n", char_set::index_to_char(i), char_set::index_to_char(j), x[i][j]);
            }
        }

    }

};

#endif // MARKOV_HPP
