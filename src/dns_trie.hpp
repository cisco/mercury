// dns_trie.hpp
//


#ifndef DNS_TRIE_HPP
#define DNS_TRIE_HPP

#include <string>
#include <unordered_map>
#include <algorithm>
#include <iostream>
#include <memory>
#include <cmath>
#include <cstdio>
#include <cstring>
#include "libmerc/datum.h"
#include "libmerc/watchlist.hpp"

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

class node_counts {
    size_t subtree_count = 0;    // count of all names that include this node
    size_t node_count = 0;       // count of names with exact-match ending at this node

public:

    node_counts(size_t s=0, size_t n=0) : subtree_count{s}, node_count{n} { }


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

};

template <typename N>
class dns_trie {

public:

    // class dns_trie::node represents a node of the dns_trie
    //
    class node {

        std::unordered_map<std::string, node *> edges;
        N value;
        // size_t subtree_count = 0;    // count of all names that include this node
        // size_t node_count = 0;       // count of names with exact-match ending at this node

    public:

        N& get_value() { return value; }

        const N& get_value() const { return value; }

        //
        // TODO: constructor should accept a type N
        //

        // node(size_t cnt=0) : subtree_count{cnt} {
        node(size_t cnt=0) : value{cnt} {
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

        bool remove_edge(const char *name, size_t len) {
            std::string s{name, len};
            auto it = edges.find(s);
            if (it == edges.end()) {
                return false;
            }
            edges.erase(it);
            return true;
        }

        void remove_subtree() {
            // fprintf(stdout, "%s\n", __func__);

            // recursively visit entire subtree and delete the
            // children nodes
            //
            for (auto it = edges.begin(); it != edges.end(); it++) {
                fprintf(stdout, "%s: %s\n", __func__, it->first.c_str());
                if (it->second != nullptr) {
                    it->second->remove_subtree();
                    delete it->second;
                }
            }
            edges.clear();
        }

        bool is_leaf() const { return edges.size() == 0; }

        // compute the L1 norm of the distribution
        //
        double get_uniformity() const {

            //fprintf(stderr, "computing l1 distance from uniform\n");

            size_t num_edges = 0;
            size_t total_edge_count = 0;
            for (const auto & e : edges) {
                ++num_edges;
                total_edge_count += e.second->get_value().get_subtree_count();
            }
            double u = 1.0 / num_edges;  // uniform distribution
            double sum_abs = 0.0;
            for (const auto & e : edges) {
                // fprintf(stderr, "%s\t%zu\n", e.first.c_str(), e.second->get_subtree_count());
                sum_abs += fabs(u - ((double)e.second->get_value().get_subtree_count() / total_edge_count));
            }
            //fprintf(stderr, "l1: %e\n", sum_abs);
            return sum_abs;
        }

        // get_node(name, len) returns a pointer to the child node
        // connected by the edge with the label containing the `len`
        // bytes starting at `name`, if that child exists; otherwise,
        // `nullptr` is returned
        //
        node * get_node(const uint8_t *name, size_t len) {
            std::string s{(const char *)name, len};
            //fprintf(stderr, "looking for edge %s\n", name);
            auto it = edges.find(s);
            if (it == edges.end()) {
                return nullptr;
            }
            return it->second;
        }

        // performs a postorder traversal of the trie, and applies the
        // function `visit` to each node
        //
        template <typename F, typename T>
        T postorder_traverse(F visit, const std::string &s, size_t root_prob_count) {
            T t;
            for (const auto & e : edges) {
                if (e.second) {
                    std::string tmp{s};
                    tmp.append(e.first);
                    tmp += '.';
                    t += e.second->template postorder_traverse<F, T>(visit, tmp, root_prob_count);
                }
                t += visit(e, s, root_prob_count);
            }
            return t;
        }

        // performs a preorder traversal of the trie, and applies the
        // function `visit` to each node
        //
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

        static bool compare_edges(const std::pair<std::string, node *> &a, const std::pair<std::string, node *> &b) {
            return a.first < b.first;
        }

        // performs a preorder traversal of the trie, and applies the
        // function `visit` to each node
        //
        template <typename F, typename ... A>
        void preorder_traversal(F visit, const std::string &s, A ... args) {

            // create an alphabetically-sorted copy of the edge list
            //
            std::vector<std::pair<std::string, node *>> sorted_edges{edges.begin(), edges.end()};
            std::sort(sorted_edges.begin(), sorted_edges.end(), compare_edges);

            // visit each edge in succession
            //
            for (const auto & e : sorted_edges) {
                visit(e, s, args ...);
                if (e.second) {
                    std::string tmp{e.first};
                    if (s != "") {
                        tmp += '.';
                        tmp.append(s);
                    }
                    // std::string tmp{s};
                    // tmp.append(e.first);
                    // tmp += '.';
                    e.second->preorder_traversal(visit, tmp, args ...);
                }
            }
        }

        // performs a postorder traversal of the trie, and applies the
        // function `visit` to each node
        //
        template <typename F, typename ... A>
        void postorder_traversal(F visit, const std::string &s, A ... args) {

            // create an alphabetically-sorted copy of the edge list
            //
            std::vector<std::pair<std::string, node *>> sorted_edges{edges.begin(), edges.end()};
            std::sort(sorted_edges.begin(), sorted_edges.end(), compare_edges);

            // visit each edge in succession
            //
            for (const auto & e : sorted_edges) {
                if (e.second) {
                    std::string tmp{e.first};
                    if (s != "") {
                        tmp += '.';
                        tmp.append(s);
                    }
                    // std::string tmp{s};
                    // tmp.append(e.first);
                    // tmp += '.';
                    e.second->postorder_traversal(visit, tmp, args ...);
                }
                visit(e, s, args ...);
            }
        }

    };

private:

    node root;

public:

    // dns_trie(std::istream &input) constructs a dns_trie from the set
    // of DNS names in the file input, which must have the same format as
    // the mozilla public suffix list
    //
    // TODO: implement punycode, wildcards, and negation
    //
    dns_trie(std::istream &input, bool verbose=false) {
        std::string line;
        while (std::getline(input, line)) {
            if (line.length() == 0 || line[0] == '/' || line[0] == '#') {
                continue;  // ignore empty line or comment
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
            n->get_value().increment_subtree_count(count);

            const std::vector<datum> & label_vector = d.get_value();
            auto l = label_vector.end();
            while (l-- != label_vector.begin()) {
                n = n->add_edge((const char *)l->begin(), l->length(), 0);
                n->get_value().increment_subtree_count(count);
                if (l == label_vector.begin()) {
                    n->get_value().increment_node_count(count);
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
            const std::vector<datum> & label_vector = d.get_value();
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
            const std::vector<datum> & label_vector = d.get_value();
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
            const std::vector<datum> & label_vector = d.get_value();
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
        if (n != nullptr) {
            return (float) n->get_value().get_node_count() / root.get_value().get_subtree_count();
        }
        return 0.0;   // no match found
    }

    float probability_subtree(const std::string &s) { // TODO: should be const
        node *n = longest_prefix_match_node(s);
        if (n != nullptr) {
            return (float) n->get_subtree_count() / root.get_subtree_count();
        }
        return 0.0;   // no match found
    }

    size_t subtree_count(const std::string &s) {      // TODO: should be const
        node *n = longest_prefix_match_node(s);
        if (n != nullptr) {
            return n->get_value().get_subtree_count();
        }
        return 0;     // no match found
    }

    struct node_stats {
        size_t leaf_count = 0;
        size_t node_count = 0;

        node_stats operator+=(const node_stats &rhs) {
            leaf_count += rhs.leaf_count;
            node_count += rhs.node_count;
            // fprintf(stderr, "%s: leaves: %zu\tnodes: %zu\n", __func__, leaf_count, node_count);
            return *this;
        }
    };
    node_stats count_leaves_and_nodes() {
        auto count = [](std::pair<std::string, dns_trie::node *> e, const std::string &, size_t ) -> node_stats {
            node_stats tmp;
            if (e.second->is_leaf()) {
                ++tmp.leaf_count;
            }
            ++tmp.node_count;
            // fprintf(stderr, "%s: leaves: %zu\tnodes: %zu\n", __func__, tmp.leaf_count, tmp.node_count);
            return tmp;
        };
        return root.template postorder_traverse<decltype(count), node_stats>(count, "", root.get_value().get_subtree_count());
    }

    void fprint(FILE *f, bool leaf_only=true) {

        auto print_node = [f, leaf_only](std::pair<std::string, dns_trie::node *> e, const std::string &s, size_t ) {
            if (leaf_only == false || e.second->is_leaf()) {
                char indent_string[] = "                                                                            ";
                fprintf(f, "%s%s%.*s%zu\n",
                        s.c_str(),
                        e.first.c_str(),
                        (int)(strlen(indent_string)-(int)e.first.length()-s.length()),
                        indent_string,
                        e.second->get_value().get_subtree_count());
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
        root.preorder_traverse(print_node, "", root.get_value().get_subtree_count());
    }

    // void fprint_stats(FILE *f, bool leaf_only=true) {
    //
    //     auto print_node_stats = [f, leaf_only](std::pair<std::string, dns_trie::node *> e, const std::string &s, size_t ) {
    //         char indent_string[] = "                                                                                    ";
    //         fprintf(f, "%s%s%.*s\t%f\t%zu\n",
    //                 s.c_str(),
    //                 e.first.c_str(),
    //                 (int)(strlen(indent_string)-(int)e.first.length()-s.length()),
    //                 indent_string,
    //                 // markov.log_prob_per_char(e.first),
    //                 markov.test_random(e.first),
    //                 e.second->get_subtree_count());
    //     };
    //     root.preorder_traverse(print_node_stats, "", root.get_subtree_count());
    //         //        root.fprint_stats(f, "", root.get_subtree_count());
    // }

    void fprint_uniformity(FILE *f, bool leaf_only=true, float threshold=1.0) {

        auto print_uniformity = [f, leaf_only, threshold](std::pair<std::string, dns_trie::node *> e, const std::string &s, size_t ) {
            // if (e.second->is_leaf()) {
            //     return;  // uniformity is not defined for leaves, only interior nodes
            // }

            char indent_string[] = "                                                                                    ";
            fprintf(f, "%s%s%.*s\t%c\t%f\t%zu\n",
                    s.c_str(),
                    e.first.c_str(),
                    (int)(strlen(indent_string)-(int)e.first.length()-s.length()),
                    indent_string,
                    e.second->get_uniformity() >= threshold ? 'P' : ' ',
                    e.second->get_uniformity(),
                    e.second->get_value().get_subtree_count());

        };
        root.preorder_traverse(print_uniformity, "", root.get_value().get_subtree_count());
            //        root.fprint_stats(f, "", root.get_subtree_count());
    }

    // void fprint_uniform_nodes(FILE *f, float threshold) {
    //
    //     auto print_uniform_nodes = [f, threshold](std::pair<std::string, dns_trie::node *> e, const std::string &s, size_t ) {
    //         if (e.second->is_leaf()) {
    //             return;  // uniformity is not defined for leaves, only interior nodes
    //         }
    //         if (e.second->get_uniformity() >= threshold) {
    //             char indent_string[] = "                                                                                    ";
    //             fprintf(f, "%s%s%.*s\t%f\t%zu\n",
    //                     s.c_str(),
    //                     e.first.c_str(),
    //                     (int)(strlen(indent_string)-(int)e.first.length()-s.length()),
    //                     indent_string,
    //                     e.second->get_uniformity(),
    //                     e.second->get_subtree_count());
    //
    //             auto print_child = [f, indent_string](std::pair<std::string, dns_trie::node *> c, const std::string &, size_t ) {
    //                 fprintf(f, "%s%.*s\t%f\t%zu\n",
    //                         c.first.c_str(),
    //                         (int)(strlen(indent_string)-(int)c.first.length()),
    //                         indent_string,
    //                         c.second->get_uniformity(),
    //                         c.second->get_subtree_count());
    //             };
    //             e.second->preorder_traverse(print_child, "", 0);
    //         }
    //     };
    //     root.preorder_traverse(print_uniform_nodes, "", root.get_subtree_count());
    // }

    dns_trie::node &get_root() { return root; }

};

class binary_classifier {
    dns_trie<node_counts> a;
    dns_trie<node_counts> b;
    size_t total_count = 0;
    dns_trie<node_counts>::node_stats trie_stats;

    // count_all_names(h, n) returns the count of names that appear in
    // either h or n; that is, it finds the cardinality of the union
    // of sets of names in h and n.
    //
    // static size_t find_total_count(dns_trie &h, dns_trie &n) {
    //     size_t count = 0;
    //     auto count_unique_leaves = [count, h, n](std::pair<std::string, dns_trie::node *> e, const std::string &s) {
    //         // fprintf(f, "e: %s\ts: %s\n", e.first.c_str(), s.c_str());
    //         std::string tmp{e.first};
    //         if (s != "") {
    //             tmp += '.';
    //             tmp.append(s);
    //         }
    //     };
    //     h.get_root().preorder_traversal(count_unique_leaves, "");
    //     return 0; // TODO: make this real
    // }

public:

    binary_classifier(const dns_trie<node_counts> &hypothesis, const dns_trie<node_counts> &null) :
        a{hypothesis},
        b{null},
        total_count{a.get_root().get_value().get_subtree_count() + b.get_root().get_value().get_subtree_count()},
        trie_stats{a.count_leaves_and_nodes() += b.count_leaves_and_nodes()}
    {

        // smoothing
        //
        //
        // total_count += trie_stats.node_count
    }

    // [[maybe_unused]] static double divergence(double p, double q) {
    //     if (p == 0.0) {
    //         return 0.0;
    //     }
    //     return - p * (log(q) - log(p)); // note: could divide by log(2.0)
    // }

    void compare(FILE *f) {
        auto print_node = [f,this](std::pair<std::string, dns_trie<node_counts>::node *> e, const std::string &s) {
            // fprintf(f, "e: %s\ts: %s\n", e.first.c_str(), s.c_str());
            std::string tmp{e.first};
            if (s != "") {
                tmp += '.';
                tmp.append(s);
            }
            char c = 'N'; // H = hypothesis, N = null
            float pa = (float) a.subtree_count(tmp) / total_count;
            float pb = (float) b.subtree_count(tmp) / total_count;

            // smoothing
            if (pb == 0.0) {
                //fprintf(f, "smoothing %e to %e\n", pb, (
                pb = 0.1 / total_count; // TODO: better smoothing
            }

            if (pa >= pb) {
                c = 'H';
            }
            // fprintf(f, "%c\t%e\t%e\t%e\t%s\n", c, pa, pb, divergence(pa, pb), tmp.c_str());
            // fprintf(f, "%c\t%e\t%e\t%s\n", c, pa, pb, tmp.c_str());
            fprintf(f, "%c\t%zu\t%zu\t%s\n", c, a.subtree_count(tmp), b.subtree_count(tmp), tmp.c_str());
            if (!e.second->is_leaf()) {
                return;  // skip interior nodes
            }
            if (s == "") {
                return;  // skip the empty string
            }
        };
        a.get_root().preorder_traversal(print_node, "");
        b.get_root().preorder_traversal(print_node, "");
    }

    void prune(FILE *f) {
        auto prune_node = [f,this](std::pair<std::string, dns_trie<node_counts>::node *> e, const std::string &s) {
            // fprintf(f, "e: %s\ts: %s\n", e.first.c_str(), s.c_str());
            std::string tmp{e.first};
            if (s != "") {
                tmp += '.';
                tmp.append(s);
            }

            //fprintf(stdout, "prune: %s\t%zu\n", tmp.c_str(), b.subtree_count(tmp));
            if (b.subtree_count(tmp) == 0) {
                e.second->remove_subtree();
            }

        };
        a.get_root().postorder_traversal(prune_node, "");
        b.get_root().preorder_traversal(prune_node, "");
    }

    // TODO: implement a member function that prunes a and b so as to
    // remove subtrees that are not needed to distinguish between them

};

class binary_classifier2 {
    dns_trie<double> a;
    size_t total_count = 0;

public:

    binary_classifier2(const dns_trie<node_counts> &, const dns_trie<node_counts> &) {

        // smoothing
        //
        //
        // total_count += trie_stats.node_count
    }

};

#endif // DNS_TRIE_HPP
