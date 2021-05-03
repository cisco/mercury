/*
 * dict.h
 *
 * dictionary coder
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */


#ifndef DICT_H
#define DICT_H

#include <stdint.h>
#include <unordered_map>
#include <vector>
#include <algorithm>

#include "bytestring.h"

// class dict is a dictionary (substitution) coder that maps an
// arbitrary-length string to a short numeric value
//
// Usage:
//    1. construct a new dict object.
//    2. call compress() on your strings, to find their compressed representation
//    3. call compute_inverse_map() on the object
//    4. call get_inverse() on a compressed value to find its uncompressed form
//
// Do *not* call compress() after calling compute_inverse() or
// get_inverse(); doing so may get you garbage results.
//
class dict {
public:
    std::unordered_map<std::string, uint32_t> d;
    unsigned int count;
    std::vector<std::pair<const char *, uint32_t>> inverse;
    unsigned int inverse_size;

    dict() : d{}, count{0}, inverse{}, inverse_size{0} { }

    unsigned int get(const std::string &value) {
        auto x = d.find(value);
        if (x == d.end()) {
            d.emplace(value, count);
            return count++;
        }
        return x->second;
    }

    void compress(const std::string &value,
                  char fp_index_string[9]) {
        auto x = d.find(value);
        if (x == d.end()) {
            d.emplace(value, count);
            sprintf(fp_index_string, "%x", count);
            count++;
            return;
        }
        sprintf(fp_index_string, "%x", x->second);
    }

    bool compute_inverse_map() {

        try {
            inverse.reserve(d.size());
            for (const auto &x : d) {
                inverse.push_back({x.first.c_str(), x.second});
            }
            std::stable_sort(inverse.begin(), inverse.end(), [](auto &l, auto &r){ return l.second < r.second; });
            inverse_size = inverse.size();
            return true;
        }
        catch (...) {
            return false;
        }
    }

    const char *get_inverse(unsigned int index) const {
        if (index < inverse_size) {
            return inverse[index].first;
        }
        return unknown_fp_string;
    }

    inline static const char *unknown_fp_string{"unknown"};

    // unit_test(f) verifies that the dictionary is the same in both
    // the forard and inverse directions; perform this test only after
    // the dictionary has been populated.  Returns true if the test passed,
    // and false otherwise.
    //
    bool unit_test(FILE *f) {
        // sanity check: output forward and reverse mappings, to enable comparison
        bool passed = true;
        for (const auto &a : d) {
            if (a.first.compare(get_inverse(a.second)) != 0) {
                if (f) {
                    fprintf(f, "dict unit test error: mismatch at dict table entry (%s: %u)\n", a.first.c_str(), a.second);
                }
                passed = false;
            }
        }
        for (const auto &b : inverse) {
            if (get(b.first) != b.second) {
                if (f) {
                    fprintf(f, "dict unit test error: mismatch at inverse table entry (%s: %u)\n", b.first, b.second);
                }
                passed = false;
            }
        }
        return passed;
    }

};

struct dictionary {
    std::unordered_map<std::basic_string<uint8_t>, uint32_t> dict;
    unsigned int count;

    dictionary() : dict{}, count{0} {}

    // std::basic_string<uint8_t> s = p->get_bytestring();
    unsigned int get(std::basic_string<uint8_t> &value) {

        auto x = dict.find(value);
        if (x == dict.end()) {
            dict.insert({value, count++});
            return count;
        }
        return x->second;
    }

};

// class ptr_dict provides compact storage for a set of strings that
// would otherwise appear multiple times in runtime data structures
//
// This is a simple straightforward implementation, which performs
// adequately for thousands of strings.  Each get() operation is O(N)
// if N strings are entered, which means that entering N strings has
// cost O(N^2); if get() is called M times with N strings, then the
// cost is around O(M*N).
//
class ptr_dict {
    std::vector<std::string> d;
public:
    ptr_dict() : d{} {}

    // get(s) returns a const char * that is equivalent (under
    // string::compare()) to the string s.  The pointer returned will
    // be valid until the ptr_dict's destructor is called.
    //
    const char *get(std::string s) {
        const auto & it = find(d.begin(), d.end(), s);
        if (it != d.end()) {
            return it->c_str();
        } else {
            try {
                d.push_back(s);
                return d.back().c_str();
            }
            catch (...) {
                return ""; // error
            }
        }
    }

    // fprint() prints out the entries of this dictionary, in the
    // order in which they were entered
    //
    void fprint(FILE *f) {
        for (const auto &x : d) {
            fprintf(f, "\"%s\"\n", x.c_str());
        }
    }

};

#endif /* DICT_H  */
