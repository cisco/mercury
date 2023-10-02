// dns_trie.hpp
//


#ifndef DNS_TRIE_HPP
#define DNS_TRIE_HPP

#include <string>
#include <unordered_map>
#include <iostream>
#include <memory>
#include <cmath>
#include <cstdio>
#include <cstring>
#include "libmerc/datum.h"
#include "libmerc/watchlist.hpp"

#include "markov.hpp"

// class dns_trie implements a trie whose edges are DNS labels and
// whose nodes hold prevalence counters, so that the probabilities
// associated with DNS names can be estimated.
//
// Each node holds two counters: the prevalence count N for names that
// end at that node, and the prevalence count S for all names that end
// on a child of that node.
//
// For example, a dns_trie constructed from this data
//
//         Name          Count
//     a.example.com      10
//     b.example.com      20
//     c.example.com      30
//       example.com      10
//           foo.com      30
//
// ... would look like this, where a node is represented as (N,C):
//
//      (0,100) -----> (0,100) --+-----------> (10,60) --+------> (10,10)
//               com             |  example              |  a
//                               |                       |
//                               +-----------> (30,30)   +------> (20,20)
//                                    foo                |  b
//                                                       |
//                                                       +------> (30,30)
//                                                          c
//
// An exact match between a dns name and a trie returns the node that
// can be found by following the labels down the trie; if there is no
// such node, null is returned.
//
// A longest match between a dns name and a trie follows labels down
// the trie as far as possible, then returns the node after the last
// matched label.  If no labels match, then null is returned.
//
class dns_trie {

public:

    // class dns_trie::node represents a node of the dns_trie
    //
    class node {

        std::unordered_map<std::string, node *> edges;
        size_t subtree_count = 0;    // count of all names that include this node
        size_t node_count = 0;       // count of names with exact-match ending at this node

    public:

        node(size_t cnt=0) : subtree_count{cnt} {
            // fprintf(stderr, "%s: constructing node with count=%zu\n", __func__, cnt);
        }

        node * add_edge(const char *name, size_t len, size_t cnt=0) {

            std::string s{name, len};
            auto it = edges.find(s);
            if (it == edges.end()) {
                node *tmp = new node{cnt};
                edges.emplace(s, tmp);
                return tmp;
            }
            return it->second;
        }

        // increment total subtree_count for this node
        //
        void increment_subtree_count(size_t cnt) {
            subtree_count += cnt;
        }

        void increment_node_count(size_t cnt) {
            node_count += cnt;
        }

        size_t get_subtree_count() const { return subtree_count; }

        size_t get_node_count() const { return node_count; }

        bool is_leaf() const { return edges.size() == 0; }

        // compute the L1 norm of the distribution
        //
        double get_uniformity() const {
            //fprintf(stderr, "computing l1 distance from uniform\n");

            size_t num_edges = 0;
            size_t total_edge_count = 0;
            for (const auto & e : edges) {
                ++num_edges;
                total_edge_count += e.second->get_subtree_count();
            }
            double u = 1.0 / num_edges;  // uniform distribution
            double sum_abs = 0.0;
            for (const auto & e : edges) {
                // fprintf(stderr, "%s\t%zu\n", e.first.c_str(), e.second->get_subtree_count());
                sum_abs += fabs(u - ((double)e.second->get_subtree_count() / total_edge_count));
            }
            //fprintf(stderr, "l1: %e\n", sum_abs);
            return sum_abs;
        }

        node * get_node(const uint8_t *name, size_t len) {
            std::string s{(const char *)name, len};
            //fprintf(stderr, "looking for edge %s\n", name);
            auto it = edges.find(s);
            if (it == edges.end()) {
                return nullptr;
            }
            return it->second;
        }

        template <typename F>
        void postorder_traverse(F visit, const std::string &s, size_t root_prob_count) {
            for (const auto & e : edges) {
                if (e.second) {
                    std::string tmp{s};
                    tmp.append(e.first);
                    tmp += '.';
                    e.second->postorder_traverse(visit, tmp, root_prob_count);
                }
                visit(e, s, root_prob_count);
            }
        }

        template <typename F>
        void preorder_traverse(F visit, const std::string &s, size_t root_prob_count) {
            for (const auto & e : edges) {
                visit(e, s, root_prob_count);
                if (e.second) {
                    std::string tmp{s};
                    tmp.append(e.first);
                    tmp += '.';
                    e.second->preorder_traverse(visit, tmp, root_prob_count);
                }
            }
        }

        void fprint_stats(FILE *f, const std::string &s, size_t root_prob_count) const {
            for (const auto & e : edges) {
                char indent_string[] = "                                                                                    ";
                fprintf(f, "%s%s%.*s\t%f\t%zu\n",
                        s.c_str(),
                        e.first.c_str(),
                        (int)(strlen(indent_string)-(int)e.first.length()-s.length()),
                        indent_string,
                        // markov.log_prob_per_char(e.first),
                        markov.test_random(e.first),
                        e.second->get_subtree_count());
                if (e.second) {
                    std::string tmp{s};
                    tmp.append(e.first);
                    tmp += '.';
                    e.second->fprint_stats(f, tmp, root_prob_count);
                }
            }
        }

    };

private:

    node root;

    static inline markov_model<dns_char_set> markov{fopen("markov-model.dat", "r")};

public:

    // dns_trie(std::istream &input) constructs a dns_trie from the set
    // of DNS names in the file input, which must have the same format as
    // the mozilla public suffix list
    //
    dns_trie(std::istream &input, bool verbose=false) {
        std::string line;
        while (std::getline(input, line)) {
            if (line.length() == 0 || line[0] == '/') {
                continue;
            }
            if (verbose) { fprintf(stderr, "dns_trie: adding %s\n", line.c_str()); }
            add(line);
        }
    }

    dns_trie() { }

    void add(const std::string &name, size_t count=0) {

        datum dns_name = get_datum(name);
        dns_string d{dns_name};
        if (d.is_valid()) {

            node *n = &root;
            n->increment_subtree_count(count);

            const std::vector<dns_label_string> & label_vector = d.get_value();
            auto l = label_vector.end();
            while (l-- != label_vector.begin()) {
                n = n->add_edge((const char *)l->begin(), l->length(), 0);
                n->increment_subtree_count(count);
                if (l == label_vector.begin()) {
                    n->increment_node_count(count);
                }
            }

        } else {
            fprintf(stderr, "warning: could not parse dns name (%s)\n", name.c_str());
        }

    }

    std::string longest_prefix_match(const std::string &name) {
        std::string tmp;
        node *n = &root;
        datum dns_name = get_datum(name);
        //        fprintf(stderr, "parsing dns_name '%s'\n", name.c_str());
        dns_string d{dns_name};
        if (d.is_valid()) {
            const std::vector<dns_label_string> & label_vector = d.get_value();
            for (auto l = label_vector.end(); l-- != label_vector.begin(); ) {
                n = n->get_node(l->begin(), l->length());
                if (n == nullptr) {
                    break;
                }
                //fprintf(stderr, "tmp: %s\n", tmp.c_str());
                tmp = std::string{(char *)l->begin(), (long unsigned int)l->length()} + '.' + tmp;
            }
        } else {
            fprintf(stderr, "warning: could not parse dns name (%s)\n", name.c_str());
        }
        return tmp;
    }

    node * longest_prefix_match_node(const std::string &name) {
        std::string tmp;
        node *n = &root;
        datum dns_name = get_datum(name);
        //        fprintf(stderr, "parsing dns_name '%s'\n", name.c_str());
        dns_string d{dns_name};
        if (d.is_valid()) {
            const std::vector<dns_label_string> & label_vector = d.get_value();
            for (auto l = label_vector.end(); l-- != label_vector.begin(); ) {
                n = n->get_node(l->begin(), l->length());
                if (n == nullptr) {
                    break;
                }
                //fprintf(stderr, "tmp: %s\n", tmp.c_str());
                tmp = std::string{(char *)l->begin(), (long unsigned int)l->length()} + '.' + tmp;
            }
        } else {
            fprintf(stderr, "warning: could not parse dns name (%s)\n", name.c_str());
        }
        return n;
    }

    std::string longest_prefix_match_plus_one(const std::string &name) {
        std::string tmp;
        node *n = &root;
        datum dns_name = get_datum(name);
        //        fprintf(stderr, "parsing dns_name '%s'\n", name.c_str());
        dns_string d{dns_name};
        if (d.is_valid()) {
            const std::vector<dns_label_string> & label_vector = d.get_value();
            for (auto l = label_vector.end(); l-- != label_vector.begin(); ) {
                n = n->get_node(l->begin(), l->length());
                if (n == nullptr) {
                    tmp = std::string{(char *)l->begin(), (long unsigned int)l->length()} + '.' + tmp;
                    break;
                }
                //fprintf(stderr, "tmp: %s\n", tmp.c_str());
                tmp = std::string{(char *)l->begin(), (long unsigned int)l->length()} + '.' + tmp;
            }
        } else {
            fprintf(stderr, "warning: could not parse dns name (%s)\n", name.c_str());
        }
        return tmp;
    }

    float probability(const std::string &s) { // TODO: should be const
        node *n = longest_prefix_match_node(s);
        return (float) n->get_node_count() / root.get_subtree_count();
    }

    void fprint(FILE *f, bool leaf_only=true) {

        auto print_node = [f, leaf_only](std::pair<std::string, dns_trie::node *> e, const std::string &s, size_t ) {
            char indent_string[] = "                                                                            ";
            if (leaf_only == false || e.second->is_leaf()) {
                fprintf(f, "%s%s%.*s%zu\n",
                        s.c_str(),
                        e.first.c_str(),
                        (int)(strlen(indent_string)-(int)e.first.length()-s.length()),
                        indent_string,
                        e.second->get_subtree_count());
            }
            // fprintf(f, "%s%s%.*s%zu\t%f\t%f\t%u\t%zu\t%zu\t%f\n",
            //         s.c_str(),
            //         e.first.c_str(),
            //         (int)(strlen(indent_string)-(int)e.first.length()-s.length()),
            //         indent_string,
            //         e.second->get_subtree_count(),
            //         e.second->get_uniformity(),
            //         prob_dynamic_name(e.first),
            //         e.second->is_leaf(),
            //         e.second->prob_count(),
            //         root_prob_count,
            //         (float)e.second->prob_count() / root_prob_count);
        };
        root.preorder_traverse(print_node, "", root.get_subtree_count());
    }

    void fprint_stats(FILE *f) const {
        root.fprint_stats(f, "", root.get_subtree_count());
    }

    dns_trie::node &get_root() { return root; }

};


#endif // DNS_TRIE_HPP
