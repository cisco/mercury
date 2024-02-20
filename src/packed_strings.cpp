// packed_strings.cpp
//
// example / test driver for packed_strings.hpp
//
// compilation:
//    g++ -std=c++17 -Wall packed_strings.cpp -o packed_strings

#include "packed_strings.hpp"
#include "libmerc/datum.h"

int main(int, char *[]) {

    // create a packed_strings object
    //
    packed_strings pack{{ "com", "net", "org", "ai" }};

    // print out all strings in pack, by using the
    // packed_strings::next_string() to iterate through them all
    //
    datum s = pack.begin();
    while (s.is_readable()) {
       s.fprint(stdout); fputc('\n', stdout);
       s = pack.next_string(s);
   }

    // search for strings that are / are not in the packed_strings
    // object, and write out their indices
    //
    // note:
    //    pack.find(s) >= 0 means that s is in pack
    //    pack.find(s) < 0 means that s is not in pack
    //
    for (auto & s : { "com", "net", "org", "ai", "dog", "cat", "aardvark" }) {
        fprintf(stdout, "find(%s): %zd\n", s, pack.find(s, strlen(s)));
    }

    // create a packed_strings_map pmap out of a pair of vectors
    //
    packed_strings_map<uint32_t> pmap{
        { "com", "net", "org", "ai" },
        { 10,    20,    30,    40   }
    };

    // search for strings that are / are not in pmap, and write out
    // the data associated with them (or zero, if not present)
    //
    for (auto & s : { "com", "net", "org", "ai", "dog", "cat", "aardvark" }) {
        const uint32_t *result = pmap.find_value(s, strlen(s));
        fprintf(stdout, "find(%s): %u\n", s, result ? *result : 0);
    }

    // create a packed_strings_map out of a vector of pairs
    //
    packed_strings_map<uint32_t> pmap2{
       {
           { "com", 100 },
           { "net", 200 },
           { "org", 300 },
           { "ai", 400 },
       }
    };

    // search and report again
    //
    for (auto & s : { "com", "net", "org", "ai", "dog", "cat", "aardvark" }) {
        const uint32_t *result = pmap2.find_value(s, strlen(s));
        fprintf(stdout, "find(%s): %u\n", s, result ? *result : 0);
    }

    // for comparison
    //
    std::unordered_map<std::string, std::string> data {
        { "com", "tld" },
        { "net", "tld" },
        { "org", "tld" }
    };

   return 0;
}
