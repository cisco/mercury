/*
 * stringalgs.h
 */

#ifndef STRINGALGS_H
#define STRINGALGS_H

#include <string>
#include <algorithm>

#include <memory>

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

template <typename T> struct edit_distance {
    const uint8_t *a, *b;
    matrix<T> D;

    edit_distance(const uint8_t *a, T Na, const uint8_t *b, T Nb) : a{a}, b{b}, D{Na+1,Nb+1} {
        recompute(a, Na, b, Nb);
    }

    void recompute(const uint8_t *a, T Na, const uint8_t *b, T Nb) {

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

    T d(uint8_t x, uint8_t y) {
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
            if (0) {
                printf("error: no L conditions matched (L(i-1, j-1)+1: %u, L(i,j): %u)\n", L(i-1, j-1) + 1, L(i,j));
                break;
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
            if (0) {
                printf("error: no L conditions matched (L(i-1, j-1)+1: %u, L(i,j): %u)\n", L(i-1, j-1) + 1, L(i,j));
                break;
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

#endif /* STRINGALGS_H */
