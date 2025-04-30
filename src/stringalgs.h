/*
 * stringalgs.h
 */

#ifndef STRINGALGS_H
#define STRINGALGS_H

#include <string>
#include <vector>
#include <algorithm>
#include <memory>
#include <stdexcept>
#include <cassert>

// class matrix<T> is a dynamically-allocated two dimensional array of
// type T, which is indexed starting at zero.  For efficient access,
// increment the column index first, and the row index second.

template <typename T> class matrix {
    size_t _rows;
    size_t _columns;
    size_t num_elements;
    T *data;

public:
    matrix(size_t rows, size_t columns)
        : _rows{rows},
          _columns{columns},
          num_elements{rows * columns},
          data{new T[rows * columns]} {}

    ~matrix() { delete[] data; }

    void resize(size_t new_rows, size_t new_columns) {
        if (new_rows * new_columns > num_elements) {
            delete[] data;
            data = new T[new_rows * new_columns];
            num_elements = new_rows * new_columns;
        }
        _rows = new_rows;
        _columns = new_columns;
    }

    size_t rows() const { return _rows; }

    size_t columns() const { return _columns; }

    T &operator()(size_t row, size_t column) {
        return data[row * _columns + column];
    }
};


/*
 * struct edit_distance<T> computes the (Levenshtein) edit distance
 * between two byte strings.  The typename T should be the smallest
 * unsigned integer type that can represent the number of bytes in the
 * input strings, in order to save storage space.
 *
 * A dynamic programming approach is used at present, and computation
 * takes O(m*n) time and space for strings with lengths m and n.
 */

template <typename U, typename T>
struct edit_distance {
    const U *a, *b;
    matrix<T> D;

    edit_distance(const U *a, T Na, const U *b, T Nb) : a{a}, b{b}, D{Na+1,Nb+1} {
        recompute(a, Na, b, Nb);
    }

    void recompute(const U *a, T Na, const U *b, T Nb) {

        D.resize(Na+1, Nb+1);

        for (size_t i = 0; i < D.rows(); i++) {
            D(i,0) = i;
        }
        for (size_t j = 0; j < D.columns(); j++) {
            D(0,j) = j;
        }
        for (size_t i = 1; i < D.rows(); i++) {
            for (size_t j = 1; j < D.columns(); j++) {
                D(i,j) = std::min({D(i-1,j) + 1, D(i,j-1) + 1, D(i-1,j-1) + d(a[i-1], b[j-1])});
            }
        }
    }

    void print_table(FILE *f) {
        fputc(' ', f);
        fputc(' ', f);
        fputc(' ', f);
        for (size_t j = 1; j < D.columns(); j++) {
            fprintf(f, " %c", b[j-1]);
        }
        fputc('\n', f);
        fputc(' ', f);
        for (size_t i = 0; i < D.rows(); i++) {
            if (i > 0) {
                fputc(a[i-1], f);
            }
            for (size_t j = 0; j < D.columns(); j++) {
                fprintf(f, " %u", D(i,j));
            }
            fprintf(f, "\n");
        }
    }

    T d(U x, U y) {
        if (x == y) {
            return 0;
        }
        return 1;
    }

    T value() {
        return D(D.rows()-1, D.columns()-1);
    }

};




/*
 * struct longest_common_subsequence<T> computes the LCS between two
 * byte strings, and provides member functions that return the LCS as
 * a byte string, the length of the LCS, and the alignment of the LCS
 * relative to either of the input strings.  The typename T should be
 * the smallest unsigned integer type that can represent the number of
 * bytes in the input strings, in order to save storage space.
 *
 * A dynamic programming approach is used at present, and computation
 * takes O(m*n) time and space for strings with lengths m and n.
 */

template <typename T> struct longest_common_subsequence {
    const uint8_t *a, *b;
    matrix<T> L;

    longest_common_subsequence(const uint8_t *a, size_t Na, const uint8_t *b, size_t Nb) : a{a}, b{b}, L{Na+1,Nb+1} {

        recompute(a, Na, b, Nb);
    }

    /*
     *  Finding the Longest Common Subsequence (LCS) for the strings
     *  x[m], y[n] using dynamic programming.
     *
     *  The recurrence relation for extending the length of the LCS for
     *  each prefix pair x[1..i], y[1..j] is
     *
     *             /  0                         if i=0 or j=0
     *    L[i,j] = |  L[i-1,j-1] + 1            if x[i]=y[j]
     *             \  max(L[i-1,j], L[i,j-1])   otherwise,
     *
     *  where L[i,j] denotes the length of the LCS for the prefix pair
     *  x[l..i], y[l..j].  Once the table has been filled, the length
     *  of the LCS of x and y is L[m,n].  The LCS itself is found by
     *  backtracking from L[m,n], and at each element of L, either (a)
     *  follow pointers which were set during the calculation of the
     *  values or (b) recalculate the predecessor which yielded the
     *  value to the current table entry. Each time a match is found
     *  (the middle rule applies), we have found a symbol in the
     *  LCS. Traversing a path through the table until a length of
     *  zero is found gives the entire LCS (which is not necessarily
     *  unique).
     */
    void recompute(const uint8_t *a, size_t Na, const uint8_t *b, size_t Nb) {

        L.resize(Na+1, Nb+1);

        for (size_t i = 0; i < L.rows(); i++) {
            L(i,0) = 0;
        }
        for (size_t j = 0; j < L.columns(); j++) {
            L(0,j) = 0;
        }
        for (size_t i = 1; i < L.rows(); i++) {
            for (size_t j = 1; j < L.columns(); j++) {
                if (a[i-1] == b[j-1]) {
                    L(i, j) = L(i-1, j-1) + 1;
                } else {
                    L(i, j) = std::max({L(i-1, j), L(i, j-1)});
                }
            }
        }

    }

    void print_table(FILE *f) {
        fputc(' ', f);
        fputc(' ', f);
        fputc(' ', f);
        for (size_t j = 1; j < L.columns(); j++) {
            fprintf(f, " %c", b[j-1]);
        }
        fputc('\n', f);
        fputc(' ', f);
        for (size_t i = 0; i < L.rows(); i++) {
            if (i > 0) {
                fputc(a[i-1], f);
            }
            for (size_t j = 0; j < L.columns(); j++) {
                fprintf(f, " %u", L(i,j));
            }
            fprintf(f, "\n");
        }
    }

    T length() {
        return L(L.rows()-1, L.columns()-1);
    }

    std::basic_string<uint8_t> value() {
        std::basic_string<uint8_t> result;

        size_t i = L.rows()-1;
        size_t j = L.columns()-1;
        while (true) {
            if (L(i, j) == L(i-1, j)) {
                i--;
            } else if (L(i, j) == L(i,j-1)) {
                j--;
            } else {  // assume (L(i, j) == (L(i-i, j-1) + 1))
                result.push_back(a[i-1]);
                i--;
                j--;
            }
            if (i == 0 || j == 0) {
                break;
            }
        }

        std::reverse(result.begin(), result.end());
        return result;
    }

    std::basic_string<uint8_t> alignment() {
        std::basic_string<uint8_t> result;

        size_t i = L.rows()-1;
        size_t j = L.columns()-1;
        while (true) {
            if (L(i, j) == L(i-1, j)) {
                i--;
                result.push_back('*');
            } else if (L(i, j) == L(i,j-1)) {
                j--;
            } else {  // assume (L(i, j) == (L(i-i, j-1) + 1))
                result.push_back(a[i-1]);
                i--;
                j--;
            }
            if (i == 0 || j == 0) {
                break;
            }
        }
        while (i-- > 0) {
            result.push_back('*');
        }

        std::reverse(result.begin(), result.end());
        return result;
    }

    std::basic_string<uint8_t> second_alignment() {
        std::basic_string<uint8_t> result;

        size_t i = L.rows()-1;
        size_t j = L.columns()-1;
        while (true) {
            if (L(i, j) == L(i-1, j)) {
                i--;
            } else if (L(i, j) == L(i,j-1)) {
                j--;
                result.push_back('*');
            } else {  // assume (L(i, j) == (L(i-i, j-1) + 1))
                result.push_back(b[j-1]);
                i--;
                j--;
            }
            if (i == 0 || j == 0) {
                break;
            }
        }
        while (j-- > 0) {
            result.push_back('*');
        }

        std::reverse(result.begin(), result.end());
        return result;
    }

};

template <typename T> struct longest_common_substring {
    const uint8_t *a, *b;
    matrix<T> L;
    T z;
    const uint8_t *longest;

    longest_common_substring(const uint8_t *a, size_t Na, const uint8_t *b, size_t Nb) : a{a}, b{b}, L{Na+1,Nb+1}, z{0}, longest{NULL} {

        recompute(a, Na, b, Nb);
    }

    /*
     *  Finding the Longest Common Substring (LCStr) for the strings
     *  x[m], y[n] using dynamic programming.
     *
     *  Let L(i, j) denote the length of the longest common substring
     *  for x[1:i] and y[1:j] that includes both x[i] and y[j].  That
     *  is, L(i, j) is the length of the 'current' common substring
     *  while computing the table L starting from x[1] and y[1] and
     *  increasing i and j.  Then the rule for computing L(i, j) is
     *
     *     L(i, j) = / L(i-1, j-1) + 1   if x[i] = y[j],
     *               \ 0                 otherwise.
     *
     *  The overall longest common substring has length Q, where Q is
     *  is the largest table entry, that is,
     *
     *        Q = L(q, r) = max_{i,j} L(i, j)),
     *
     *  and it consists of the substring x[q-Q:q].  In words, q and r
     *  are the indicies of the largest entry in the L.  It is easy to
     *  keep track of Q and q during the computation of L.
     */

    void recompute(const uint8_t *a, size_t Na, const uint8_t *b, size_t Nb) {

        L.resize(Na+1, Nb+1);

        for (size_t i = 0; i < L.rows(); i++) {
            L(i,0) = 0;
        }
        for (size_t j = 0; j < L.columns(); j++) {
            L(0,j) = 0;
        }
        for (size_t i = 1; i < L.rows(); i++) {
            for (size_t j = 1; j < L.columns(); j++) {
                if (a[i-1] == b[j-1]) {

                    L(i, j) = L(i-1, j-1) + 1;
                    if (L(i, j) > z) {
                        z = L(i, j);
                        longest = &a[i-1];
                    }
                } else {
                    L(i, j) = 0;
                }
            }
        }

    }

    void print_table(FILE *f) {
        fputc(' ', f);
        fputc(' ', f);
        fputc(' ', f);
        for (size_t j = 1; j < L.columns(); j++) {
            fprintf(f, " %c", b[j-1]);
        }
        fputc('\n', f);
        fputc(' ', f);
        for (size_t i = 0; i < L.rows(); i++) {
            if (i > 0) {
                fputc(a[i-1], f);
            }
            for (size_t j = 0; j < L.columns(); j++) {
                fprintf(f, " %u", L(i,j));
            }
            fprintf(f, "\n");
        }
    }

    std::basic_string<uint8_t> lcstr() {
        std::basic_string<uint8_t> result;

        const uint8_t *tmp_longest = longest - (z-1);
        size_t i=0;
        for (i=0; i<z; i++) {
            result.push_back(*tmp_longest++);
        }
        result.push_back('\0');
        return result;
    }

    T length() {
        return z;
    }
};


template <typename T> struct matching_substrings {
    const uint8_t *a, *b;
    std::basic_string<uint8_t> result;
    T len;

    matching_substrings(const uint8_t *a, size_t Na, const uint8_t *b, size_t Nb) : a{a}, b{b}, result{}, len{0} {

        recompute(a, Na, b, Nb);
    }

    void recompute(const uint8_t *a, size_t Na, const uint8_t *b, size_t Nb) {

        size_t smaller_index = std::min({Na, Nb});

        len = 0;
        for (size_t i = 0; i < smaller_index; i++) {
            if (a[i] == b[i]) {
                result.push_back(a[i]);
                len++;
            } else{
                result.push_back('*');
            }
        }
        result.push_back('\0');

    }

    std::basic_string<uint8_t> value() {
        return result;
    }

    T length() {
        return len;
    }
};

inline uint8_t hamming_weight(uint8_t x)  {
    uint8_t w[] = {
        0,  // 00000000
        1,  // 00000001
        1,  // 00000010
        2,  // 00000011
        1,  // 00000100
        2,  // 00000101
        2,  // 00000110
        3,  // 00000111
        1,  // 00001000
        2,  // 00001001
        2,  // 00001010
        3,  // 00001011
        2,  // 00001100
        3,  // 00001101
        3,  // 00001110
        4,  // 00001111
    };

    return w[x >> 4] + w[x & 0x0f];
}

size_t weight(std::basic_string<uint8_t> z) {
    size_t tmp = 0;
      for (const auto & x : z) {
          tmp += hamming_weight(x);
    }
    return tmp;
}

std::basic_string<uint8_t> exor(std::basic_string<uint8_t> x, std::basic_string<uint8_t> y) {
    std::basic_string<uint8_t> z;
    assert(x.length() == y.length());
    size_t len = x.length();          // TODO: generalize to nonequal lengths
    for (size_t i=0; i<len; i++) {
        z.push_back(x[i] ^ y[i]);
    }
    return z;
}

std::basic_string<uint8_t> s_and(std::basic_string<uint8_t> x, std::basic_string<uint8_t> y) {
    std::basic_string<uint8_t> z;
    assert(x.length() == y.length());
    size_t len = x.length();          // TODO: generalize to nonequal lengths
    for (size_t i=0; i<len; i++) {
        z.push_back(x[i] & y[i]);
    }
    return z;
}

size_t hamming_distance(std::basic_string<uint8_t> x, std::basic_string<uint8_t> y) {
    std::basic_string<uint8_t> z = exor(x, y);
    return weight(z);
}

inline std::pair<char, char> raw_to_hex(uint8_t x) {
    const char hex[]= "0123456789abcdef";

    return { hex[x >> 4], hex[x & 0x0f] };
}

inline uint8_t hex_to_raw(const char hex[2]) {

    int value = 0;
    if(*hex >= '0' && *hex <= '9') {
        value = (*hex - '0');
    } else if (*hex >= 'A' && *hex <= 'F') {
        value = (10 + (*hex - 'A'));
    } else if (*hex >= 'a' && *hex <= 'f') {
        value = (10 + (*hex - 'a'));
    }
    value = value << 4;
    hex++;
    if(*hex >= '0' && *hex <= '9') {
        value |= (*hex - '0');
    } else if (*hex >= 'A' && *hex <= 'F') {
        value |= (10 + (*hex - 'A'));
    } else if (*hex >= 'a' && *hex <= 'f') {
        value |= (10 + (*hex - 'a'));
    }

    return value;
}

std::basic_string<uint8_t> uint8_string_from_hex(const char *h) {
    std::basic_string<uint8_t> s;
    while (true) {
        if (h[0] == '\0' || h[1] == '\0') {
            break;
        }
        s.push_back(hex_to_raw(h));
        h += 2;
    }
    return s;
}

void fprint_uint8_string(FILE *f, const std::basic_string<uint8_t> &s) {
    for (const auto & x : s) {
        std::pair<char, char> hi_and_lo = raw_to_hex(x);
        fputc(hi_and_lo.first, f);
        fputc(hi_and_lo.second, f);
    }
}

void fprint_uint8_string(FILE *f, const std::string &s) {
    for (const auto & x : s) {
        std::pair<char, char> hi_and_lo = raw_to_hex(x);
        fputc(hi_and_lo.first, f);
        fputc(hi_and_lo.second, f);
    }
}

// class mask_and_value implements mask and value computation
//
// This procedure can be used to find a pair of bitvectors that can
// be used to for pattern recognition, such as identifying
// particular protocol data elements.
//
// It is easy to understand a bitwise formulation of the problem: let
// m, v, p, p1, p2, ..., pN be boolean variables.  Here p1, p2, ...,
// pN can represent the same bit location in N different packets, for
// instance.  For a given set { p1, p2, ..., pN }, our goal is to find
// m and v such that:
//
//    (m & p) = v for all p in { p1, p2, ..., pN }
//
// The solution can be expressed as
//
//    m = / 1 if (p1 == p2 == ... == pN)
//        \ 0 otherwise
//    v = m & p1
//
// The variables m and v can be incrementally updated, to process p1,
// p2, ..., pN sequentially, as follows:
//
//    if m & p = v, then m and v do not need to be updated
//    if m & p != v, then set m and v to 0
//
// To apply this logic, in parallel, to each bit in a byte, we can use
// a boolean function that expresses the above update function. The
// logic for how m is updated can be summarized with the following
// truth table:
//
//     m | p | v | result
//    --------------------
//     0 | 0 | 0 |   0
//     0 | 0 | 1 |   0
//     0 | 1 | 0 |   0
//     0 | 1 | 1 |   0
//     1 | 0 | 0 |   1
//     1 | 0 | 1 |   0
//     1 | 1 | 0 |   0
//     1 | 1 | 1 |   1
//
// ... and that truth table is that of the boolean function
//
//    result = m AND (NOT(p XOR v)).
//
// In C notation, m &= ~(p ^ v).  The variable v can be updated after
// m is updated by simply computing m & p.
//
class mask_and_value {
    std::basic_string<uint8_t> mask;
    std::basic_string<uint8_t> val;
    size_t len;
    bool first;

public:

    mask_and_value(size_t N) : mask{}, val{}, len{N}, first{true} {
        for (size_t i=0; i<len; i++) {
            mask.push_back(0xff);
            val.push_back(0xff);
        }
    }

    void observe(const uint8_t *p, size_t N) {

        // if N < len, we observe the first N bytes and zeroize mask
        // bytes N, N+1, ..., len.
        //
        // if N > len, that's an error condition
        //
        if (N < len) {
            for (size_t i=N; i<len; i++) {
                mask[i] = 0x00;
            }
        } else if (N > len) {
            fprintf(stderr, "error: N=%zu, s=%.*s\n", N, (int)N, p);
            throw std::runtime_error("input string too long in observation");
        }

        if (first) {
            first = false;
            // first value, so leave mask alone
            //
            for (size_t i=0; i<N; i++) {
                val[i] = p[i];
            }
        }

        // adjust mask and value so that (mask & p == value), with the
        // largest possible mask (in the hamming weight sense)
        //
        for (size_t i=0; i<N; i++) {
            // uint8_t x = mask[i] & p[i];
            // if (x != val[i]) {
            //     mask[i] = ~(val[i] ^ x);
            //     val[i] = x;
            // }
            mask[i] &= ~(p[i] ^ val[i]);
            val[i] = mask[i] & val[i];
        }
    }

    std::pair<std::basic_string<uint8_t>, std::basic_string<uint8_t>> value() const {
        return { mask, val };
    }

    size_t weight() const {
        return ::weight(mask);
    }

    // check(s) checks the mask and value against a vector of strings; this function
    // can be used as a sanity check
    //
    bool check(std::vector<std::basic_string<uint8_t>> &s) {
        for (auto & x : s) {
            std::basic_string<uint8_t> s = uint8_string_from_hex((const char *)x.c_str());
            std::basic_string<uint8_t> ms = s_and(mask, s);
            std::basic_string<uint8_t> z = exor(ms, val);
            fprintf(stdout, "--------------------------------------\n");
            fprintf(stdout, "p:       %s\n", x.c_str());
            fprintf(stdout, "m and p: ");
            fprint_uint8_string(stdout, ms);
            fputc('\n', stdout);
            fprintf(stdout, "value:   ");
            fprint_uint8_string(stdout, val);
            fputc('\n', stdout);
            fprintf(stdout, "difference: %zu\n", ::weight(z));
            if (::weight(z) != 0) {
                return false;
            }
        }
        return true;
    }

};

#endif /* STRINGALGS_H */
