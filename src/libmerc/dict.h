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

/// A byte budget shared by a group of dictionaries.
///
/// The accounting is deliberately conservative.  It includes the string
/// capacity, the unordered-map node, and an allowance for hash-table bucket
/// storage.  It is therefore suitable for enforcing an upper bound, even
/// though allocator bookkeeping is implementation-dependent.
struct dict_memory_budget {
    size_t max_bytes;
    size_t used_bytes;

    explicit dict_memory_budget(size_t limit) : max_bytes{limit}, used_bytes{0} { }

    bool reserve(size_t bytes) {
        if (max_bytes == 0) {
            return true;
        }
        if (bytes > max_bytes - used_bytes) {
            return false;
        }
        used_bytes += bytes;
        return true;
    }

    void release(size_t bytes) {
        used_bytes = bytes >= used_bytes ? 0 : used_bytes - bytes;
    }
};

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

public:
    static constexpr size_t index_length = 17;
    static constexpr uint64_t unknown_index = std::numeric_limits<uint64_t>::max();

private:
    static size_t memory_cost(const std::string &value) {
        constexpr size_t overhead = sizeof(std::pair<const std::string, uint64_t>)
                                   + 8 * sizeof(void *);
        if (value.capacity() > std::numeric_limits<size_t>::max() - overhead - 1) {
            return std::numeric_limits<size_t>::max();
        }
        return overhead + value.capacity() + 1;
    }

    static void write_unknown(char index_string[index_length]) {
        snprintf(index_string, index_length, "%" PRIx64, unknown_index);
    }

public:
    std::unordered_map<std::string,uint64_t> d;
    uint64_t count;
    std::vector<const char *> inverse;

    dict() : d{}, count{0}, inverse{} { }

    uint64_t get(const std::string &value) {
        auto x = d.find(value);
        if (x == d.end()) {
            d.emplace(value, count);
            return count++;
        }
        return x->second;
    }

    /// compresses the string \p value and write the result into
    /// \p index_string and return `true` if successful; otherwise,
    /// return `false`, in which case the contents of
    /// `index_string` are undefined and must be ignored.  If
    /// \p no_new_entries is `true`, then no new dictionary entries will
    /// be created, and the function will only succeed if `value` is
    /// already present in the dictionary.
    /// When a budget is supplied and exhausted, the value is encoded as the
    /// unknown sentinel and no dictionary entry is created.
    ///
    bool compress(const std::string &value,
                  char index_string[index_length],
                  bool no_new_entries=false,
                  dict_memory_budget *budget=nullptr)
    {
        auto x = d.find(value);
        if (x == d.end()) {
            if (no_new_entries) {
                return false;
            }
            if (count == unknown_index) {
                write_unknown(index_string);
                return true;
            }
            const size_t charge = memory_cost(value);
            if (budget != nullptr && !budget->reserve(charge)) {
                write_unknown(index_string);
                return true;
            }
            try {
                auto inserted = d.emplace(value, count);
                if (!inserted.second) {
                    if (budget != nullptr) {
                        budget->release(charge);
                    }
                    snprintf(index_string, index_length, "%" PRIx64, inserted.first->second);
                    return true;
                }
            }
            catch (...) {
                if (budget != nullptr) {
                    budget->release(charge);
                }
                write_unknown(index_string);
                return true;
            }
            snprintf(index_string, index_length, "%" PRIx64, count);
            count++;
            return true;
        }
        snprintf(index_string, index_length, "%" PRIx64, x->second);
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
        if (index == unknown_index) {
            return unknown_fp_string;
        }
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
