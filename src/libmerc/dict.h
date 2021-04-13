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
