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
#include <limits>
#include <cinttypes>
#include <utility>

#include "bytestring.h"
#include "universal61_bytes.hpp"

/// class dict is a dictionary (substitution) coder that maps an
/// arbitrary-length string to a short numeric value
///
/// Usage:
///    1. construct a new dict object.
///    2. call compress() on your strings, to find their compressed representation
///    3. call compute_inverse_map() on the object
///    4. call get_inverse() on a compressed value to find its uncompressed form
///
/// Do *not* call compress() after calling compute_inverse() or
/// get_inverse(); doing so may get you garbage results.
///
class dict {

private:
    static size_t memory_cost(const std::string &value) {
        constexpr size_t overhead = sizeof(std::pair<const std::string, uint64_t>)
                                   + 8 * sizeof(void *);
        if (value.capacity() > std::numeric_limits<size_t>::max() - overhead - 1) {
            return std::numeric_limits<size_t>::max();
        }
        return overhead + value.capacity() + 1;
    }

    static size_t add_memory(size_t current, size_t amount) {
        if (amount > std::numeric_limits<size_t>::max() - current) {
            return std::numeric_limits<size_t>::max();
        }
        return current + amount;
    }

public:
    std::unordered_map<std::string, uint64_t, universal61::byte_hasher> d;
    uint64_t count;
    std::vector<const char *> inverse;

private:
    size_t estimated_bytes;

public:

    dict() : d{}, count{0}, inverse{}, estimated_bytes{0} { }

    uint64_t get(const std::string &value) {
        auto x = d.find(value);
        if (x == d.end()) {
            auto inserted = d.emplace(value, count);
            if (inserted.second) {
                estimated_bytes = add_memory(estimated_bytes, memory_cost(value));
                return count++;
            }
            return inserted.first->second;
        }
        return x->second;
    }

    size_t memory_bytes() const {
        return estimated_bytes;
    }

    /// compresses the string \p value and writes the dictionary index to
    /// \p index.  If \p no_new_entries is `true`, this succeeds only when
    /// \p value is already present in the dictionary.
    ///
    bool compress(const std::string &value,
                  uint64_t &index,
                  bool no_new_entries=false)
    {
        auto x = d.find(value);
        if (x != d.end()) {
            index = x->second;
            return true;
        }
        if (no_new_entries || count == std::numeric_limits<uint64_t>::max()) {
            return false;
        }
        try {
            d.emplace(value, count);
        }
        catch (...) {
            return false;
        }
        estimated_bytes = add_memory(estimated_bytes, memory_cost(value));
        index = count++;
        return true;
    }

    bool compute_inverse_map() {

        try {
            inverse.clear();
            inverse.resize(d.size());
            for (const auto &x : d) {
                inverse[x.second] = x.first.c_str();
            }
            return true;
        }
        catch (...) {
            inverse.clear();
            return false;
        }
    }

    const char *get_inverse(uint64_t index) const {
        if (index < inverse.size()) {
            return inverse[index];
        }
        return unknown_fp_string;
    }

    inline static const char *unknown_fp_string{"unknown"};

    void clear() {
        d.clear();
        d.rehash(0);
        inverse.clear();
        count = 0;
        estimated_bytes = 0;
    }

    // LCOV_EXCL_START
    /// unit_test(f) verifies that the dictionary is the same in both
    /// the forward and inverse directions; perform this test only after
    /// the dictionary has been populated.  Returns true if the test passed,
    /// and false otherwise.
    ///
    bool unit_test(FILE *f) {
        // sanity check: output forward and reverse mappings, to enable comparison
        bool passed = true;
        for (const auto &a : d) {
            if (a.first.compare(get_inverse(a.second)) != 0) {
                if (f) {
                    fprintf(f, "dict unit test error: mismatch at dict table entry (%s: %" PRIx64 ")\n", a.first.c_str(), a.second);
                }
                passed = false;
            }
        }
        for (unsigned int i = 0; i < inverse.size(); i++) {
            if (get(inverse[i]) != i) {
                if (f) {
                    fprintf(f, "dict unit test error: mismatch at inverse table entry (%s: %u)\n", inverse[i], i);
                }
                passed = false;
            }
        }
        return passed;
    }
    // LCOV_EXCL_STOP

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

/// class ptr_dict provides compact storage for a set of strings that
/// would otherwise appear multiple times in runtime data structures
///
/// This is a simple straightforward implementation, which performs
/// adequately for thousands of strings.  Each get() operation is O(N)
/// if N strings are entered, which means that entering N strings has
/// cost O(N^2); if get() is called M times with N strings, then the
/// cost is around O(M*N).
///
class ptr_dict {
    std::vector<std::string> d;
public:
    ptr_dict() : d{} {}

    /// get(s) returns a const char * that is equivalent (under
    /// string::compare()) to the string s.  The pointer returned will
    /// be valid until the ptr_dict's destructor is called.
    ///
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

    /// fprint() prints out the entries of this dictionary, in the
    /// order in which they were entered
    ///
    void fprint(FILE *f) {
        for (const auto &x : d) {
            fprintf(f, "\"%s\"\n", x.c_str());
        }
    }

};

#endif /* DICT_H  */
