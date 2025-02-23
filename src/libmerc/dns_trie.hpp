// dns_trie.hpp
//

#ifndef DNS_TRIE_HPP
#define DNS_TRIE_HPP

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

/// implements a trie container with an insert/find interface,
/// suitable for associating arbitrary data with DNS subdomains or
/// other hierarchical namespaces.  It supports longest-prefix
/// matching; the \ref find operation returns the value of the longest
/// subdomain that matches the search input.  The subdomains entered
/// into the trie with \ref insert need not be prefix-free.  For
/// example, if the trie contains `abc.def.example.com` and
/// `example.com`, then searching for `def.example.com` would find the
/// longest prefix match of `example.com`.
///
template <typename T>
class dns_trie {
public:

    /// initializes an (empty) dns_trie
    ///
    /// implementation note: the nodes vector is initiallized to hold
    /// a single empty node, which serves as the root of the trie
    ///
    dns_trie() : nodes{{no_node_value}} { }

    /// inserts a vector of labels \param subdomain into the trie, and
    /// associates the subdomain with the \param value provided.  If
    /// the subdomain is already present in the trie, then the old
    /// value will be overwritten with the new one.
    ///
    void insert(const std::vector<std::string> &subdomain, T value);

    /// searches for the longest match for the vector of labels \param
    /// subdomain in the trie, and returns either a pointer to the
    /// value associated with the longest match, or `nullptr` if no
    /// such match exists.
    ///
    const T * find(const std::vector<std::string> &subdomain) const;

    /// performs unit tests for \ref class dns_trie and returns `true`
    /// if all pass, and `false` otherwise.  If \param f is
    /// non-`NULL`, then verbose output is written to that \ref FILE
    /// *.
    ///
    static bool unit_test(FILE *f=nullptr);

private:

    using node_index = size_t;
    using node_value = ssize_t;
    static constexpr node_value no_node_value = -1;

    std::vector<node_value> nodes;
    std::vector<T> values;
    std::unordered_map<std::string, node_index> transitions;

    // returns the search string consisting of \param label with a
    // prefix-free encoding of \param node_number, which represents
    // the edge associated with \param label that is directed from
    // node \param node_number
    //
    static std::string search_string(const std::string &label, node_index ni);

    // implementation notes: this class provides a C++ Standard
    // Library type container interface for a trie data structure
    // intended for use with hierarchical names, such as DNS names. It
    // supports longest-prefix matching; the `find` operation returns
    // the value of the longest subdomain that matches the search
    // input.  It aims to provide low memory overhead, to which end it
    // minimizes the data stored in each node of the trie.  The actual
    // values are stored in the `values` vector, and the information
    // about node transitions is stored in the `transitions`
    // unordered_map.  Each node is identified by a node_index, which
    // is an unsigned integer.  Each node contains only a node_value,
    // which is a singed integer; if it is non-negative, than that
    // node is associated with the value at that index in the `values`
    // vector.  All of the information about how the nodes are
    // connected is contained in the `transitions` structure, whose
    // key is a string formed by combining a label and a node_index,
    // and whose value is the node_index that is connected to the
    // first node_index by an edge associated with the label.  The
    // label and node_number are combined by appending a suffix-free
    // representation of the node_number to the label, to ensure
    // uniqueness of such strings across distinct node_numbers.

};

template<typename T>
inline void dns_trie<T>::insert(const std::vector<std::string> &subdomain, T value) {
    node_index n = 0;
    for (const auto & s : subdomain) {
        assert(n < nodes.size());
        auto result = transitions.find(search_string(s,n));
        if (result != transitions.end()) {
            n = result->second;
        } else {
            nodes.push_back(no_node_value);
            node_index ni = nodes.size()-1;
            transitions.emplace(search_string(s, n), ni);
            n = ni;
        }
    }
    if (nodes[n] > no_node_value) {
        values[nodes[n]] = value;
    } else {
        values.push_back(value);
        nodes[n] = values.size()-1;
    }
}

template <typename T>
inline const T * dns_trie<T>::find(const std::vector<std::string> &subdomain) const {
    node_value longest_so_far = -1;
    node_index n = 0;
    for (const auto & s : subdomain) {
        assert(n < nodes.size());
        auto result = transitions.find(search_string(s,n));
        if (result != transitions.end()) {
            n = result->second;
            if (nodes[n] >= 0) {
                longest_so_far = nodes[n];
            }
        }
    }
    if (longest_so_far >= 0) {
        return &values[longest_so_far];
    }
    return nullptr;
}

template <typename T>
inline std::string dns_trie<T>::search_string(const std::string &label, node_index ni) {
    std::string result{label};

    // append a prefix-free encoding of ni to the string label, to
    // ensure that no two combinations of label and node_number
    // are equal if their node_numbers are distinct
    //
    // we essentially use a reversed variable-length quantity
    // (VLQ), in which each byte of encoded value contains seven
    // bits of node_index, and uses the most significant bit of
    // the byte to indicate whether it is the first byte or not.
    //
    result += (uint8_t)(ni & 0b11111111);
    ni >>= 7;
    size_t i = 1;
    while(ni > 0) {
        result += (uint8_t)(ni & 0b01111111);
        ni >>= 7;
        i++;
    }
    return result;
}

template <>
inline bool dns_trie<std::string>::unit_test(FILE *f) {

    // construct a trie and then verify that searching for the inputs
    // obtains correct results
    //
    std::vector<std::vector<std::string>>  inputs {
        { "com", "google", "www"},
        { "com", "google" },
        { "com", "facebook", "www"},
        { "net", "example"},
        { "a", "b", "c", "d"},
        { "a", "b"},
    };
    std::vector<std::string> outputs {
        "GOOG-WWW",
        "GOOG",
        "META-WWW",
        "NIL",
        "ABCD",
        "AB",
    };
    assert(inputs.size() == outputs.size());

    dns_trie<std::string> t;

    // insert 128 garbage entires into the trie, just to exercise the suffix-free encoding
    //
    for (char c=0; c < 128; c++) {
        t.insert(std::vector{std::string{c}},"BOGUS");
    }

    // insert all of the test inputs
    //
    for (size_t i=0; i<inputs.size(); i++) {
        t.insert(inputs[i], outputs[i]);
    }

    // verify that the test inputs can be found and give the expected results
    //
    for (size_t i=0; i<inputs.size(); i++) {
        const std::string *result = t.find(inputs[i]);
        if (result == nullptr || *result != outputs[i]) {
            if (f) {
                fprintf(f, "input: ");
                for (const auto & s : inputs[i]) {
                    fprintf(f, "%s ", s.c_str());
                }
                fprintf(stderr, "result: %s\texpected: %s\n", result ? result->c_str() : "nullptr", outputs[i].c_str());
            }
            return false;
        }
    }

    // verify that search terms that do not appear in the trie
    // actually fail
    //
    std::vector<std::vector<std::string>> searches_that_will_fail {
        { "notavalidinput", },
        { "com", "googleeeee" },
        { "com", },
    };
    for (const auto & s : searches_that_will_fail) {
        const std::string *result = t.find(s);
        if (result != nullptr) {
            if (f) {
                fprintf(f, "input: ");
                for (const auto & label : s) {
                    fprintf(f, "%s ", label.c_str());
                }
                fprintf(f, "result: %s\texpected: %s\n", result ? result->c_str() : "nullptr", "nullptr");
            }
            return false;
        }
    }

    // enter a new value and verify that it appears correctly
    //
    std::vector<std::string> modified{ "com", "google", "www"};
    t.insert(modified, "goog");
    const std::string *result = t.find(modified);
    if (result == nullptr || *result != "goog") {
        if (f) {
            fprintf(f, "input: ");
            for (const auto & label : modified) {
                fprintf(f, "%s ", label.c_str());
            }
            fprintf(f, "result: %s\texpected: %s\n", result ? result->c_str() : "nullptr", "goog");
        }
        return false;
    }

    return true;
}

#endif // DNS_TRIE_HPP
