// packed_strings.hpp

#ifndef PACKED_STRINGS_HPP
#define PACKED_STRINGS_HPP

#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <stdexcept>
#include <algorithm>


// stores a sequece of zero or more character strings contiguously,
// and supports a find operation.  This class is more compact than an
// unordered_set, and when the number of strings is small, has
// comparable lookup times.  It is also trivially serializable.
//
class packed_strings {
    uint8_t *data = nullptr;

public:

    enum ordering { sort, do_not_sort };

    ~packed_strings() { delete [] data; }

    packed_strings(const std::vector<std::string> &input) : data{new uint8_t[total_length(input)]} {
        ordering ord=ordering::do_not_sort;
        std::vector<std::string> tmp{input};
        if (ord == ordering::sort) {
            //
            // sort the strings so that they are ordered by increasing lengths
            //

            std::sort(tmp.begin(),
                      tmp.end(),
                      [](const std::string &lhs, const std::string &rhs) {
                          return lhs.length() < rhs.length();
                      });
        }

        // write input strings into data buffer, prefixed by their lengths
        //
        uint8_t *d = data;
        for (const std::string & s : tmp) {
            *d++ = s.length();
            for (const char & c: s ) {
                *d++ = (uint8_t)c;
            }
        }
        *d = 0;  // add a zero-length string as a terminator

    }

    template <typename D>
    packed_strings(const std::vector<std::pair<std::string,D>> &input) : data{new uint8_t[total_length(input)]} {

        // write input strings into data buffer, prefixed by their lengths
        //
        uint8_t *d = data;
        for (const std::pair<std::string,D> & p : input) {
            *d++ = p.first.length();
            for (const char & c: p.first ) {
                *d++ = (uint8_t)c;
            }
        }
        *d = 0;  // add a zero-length string as a terminator

    }

    // find and return the index of the string str of length str_len
    // in the data buffer, if it exists; otherwise, return -1.  str
    // need not be null-terminated.
    //
    ssize_t find(const char *str, size_t str_len) {
        ssize_t idx = 0;
        uint8_t *d = data;
        while (true) {
            // fprintf(stdout, "target: %s\tlength: %zu\tcandidate: ", str, str_len);
            // print_string(stdout, d);
            uint8_t len = *d;
            d++;
            if (len == 0) {
                break;            // not found
            } else if (len == str_len) {
                if (memcmp(d, str, str_len) == 0) {
                    return idx;   // found
                }
            }
            d += len;
            idx++;
        }
        return -1;
    }

    std::pair<const uint8_t *, const uint8_t *> begin() const {
        const uint8_t * start = data;
        const uint8_t *d = start + 1;
        const uint8_t *d_end = d + *start;
        return { d, d_end };
    }

    std::pair<const uint8_t *, const uint8_t *> next_string(const std::pair<const uint8_t *, const uint8_t *> & p) const {
        const uint8_t * start = p.second;
        if (*start == 0) {
            return { nullptr, nullptr };
        }
        const uint8_t *d = start + 1;
        const uint8_t *d_end = d + *start;
        return { d, d_end };
    }

private:

    // computes the total number of bytes needed to hold all of the
    // strings in the input vector, along with the length prefix of
    // each string, including a terminating null byte
    //
    // if any input string has a length greater than 255, an exception
    // will be thrown, because it is impossible to represent that
    // length with a uint8_t
    //
    static size_t total_length(const std::vector<std::string> &vec_of_strings) {

        size_t length = 0;
        for (const std::string & s : vec_of_strings) {
            if (s.length() > 255 || s.length() == 0) {
                throw std::runtime_error{"bad input string length"};
            }
            length += (s.length() + 1);
        }
        length += 1;    // room for terminating null byte
        return length;
    }

    // computes the total number of bytes needed to hold all of the
    // strings (in the first element of the pairs) in the input
    // vector, along with the length prefix of each string, including
    // a terminating null byte.
    //
    // If any input string has a length greater than 255, an exception
    // will be thrown, because it is impossible to represent that
    // length with a uint8_t.
    //
    // This function is needed whenever the input strings are
    // associated with data elements, as in a packed_string_map.
    //
    template <typename D>
    static size_t total_length(const std::vector<std::pair<std::string,D>> &vec_of_strings) {

        size_t length = 0;
        for (const std::pair<std::string,D> & p : vec_of_strings) {
            const std::string &s = p.first;
            if (s.length() > 255 || s.length() == 0) {
                throw std::runtime_error{"bad input string length"};
            }
            length += (s.length() + 1);
        }
        length += 1;    // room for terminating null byte
        return length;
    }

};

// stores an ordered sequence of zero or more character strings
// contiguously, along with an ordered sequence of data elements
// associated with each string.  This class is more compact than an
// unordered_map, and when the number of strings is small, has
// comparable lookup times.  It is also trivially serializable.
//
template <typename T>
class packed_strings_map {
    packed_strings strings;
    std::vector<T> data;

public:

    packed_strings_map(const std::vector<std::string> &input,
                       const std::vector<T> &d) :
        strings{input},
        data{d}
    { }

    packed_strings_map(const std::vector<std::pair<std::string, T>> &input) :
        strings{input}
    {
        data.reserve(input.size());
        for (const auto & p : input) {
            data.push_back(p.second);
        }
    }

    const T *find_value(const char *str, size_t str_len) {
        ssize_t index = strings.find(str, str_len);
        if (index < 0) {
            return nullptr;
        }
        return &data[index];
    }

};



#endif // PACKED_STRINGS_HPP
