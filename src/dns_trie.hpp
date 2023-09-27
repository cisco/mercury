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

class dns_trie {

public:

    class node {

        std::unordered_map<std::string, node *> edges;
        size_t count = 0;
        size_t leaf_count = 0;   // count of names with exact-match ending at this edge

    public:

        node(size_t cnt=0) : count{cnt} {
            // fprintf(stderr, "%s: constructing node with count=%zu\n", __func__, cnt);
        }

        node * add_edge(const char *name, size_t len, size_t cnt=0) {

            // fprintf(stderr, "%s: adding %.*s\t%zu\n", __func__, (int)len, name, cnt);

            std::string s{name, len};
            auto it = edges.find(s);
            if (it == edges.end()) {
                node *tmp = new node{cnt};
                edges.emplace(s, tmp);
                return tmp;
            }
            return it->second;
        }

        // increment total count for this node
        //
        void increment(size_t cnt) {
            count += cnt;
            leaf_count += cnt;
        }

        size_t get_count() const { return count; }

        bool is_leaf() const { return edges.size() == 0; }

        // compute the L1 norm of the distribution
        //
        double get_uniformity() const {
            //fprintf(stderr, "computing l1 distance from uniform\n");

            size_t num_edges = 0;
            size_t total_edge_count = 0;
            for (const auto & e : edges) {
                ++num_edges;
                total_edge_count += e.second->get_count();
            }
            double u = 1.0 / num_edges;  // uniform distribution
            double sum_abs = 0.0;
            for (const auto & e : edges) {
                // fprintf(stderr, "%s\t%zu\n", e.first.c_str(), e.second->get_count());
                sum_abs += fabs(u - ((double)e.second->get_count() / total_edge_count));
            }
            //fprintf(stderr, "l1: %e\n", sum_abs);
            return sum_abs;
        }

        node * visit_edge(const char *name, size_t len) {
            std::string s{name, len};
            //fprintf(stderr, "looking for edge %s\n", name);
            auto it = edges.find(s);
            if (it == edges.end()) {
                return nullptr;
            }
            return it->second;
        }

        void fprint(FILE *f, const std::string &s, size_t root_prob_count) const {
            for (const auto & e : edges) {
                char indent_string[] = "                                                                            ";
                if (e.second->is_leaf()) {
                    fprintf(f, "%s%s%.*s%zu\n",
                            s.c_str(),
                            e.first.c_str(),
                            (int)(strlen(indent_string)-(int)e.first.length()-s.length()),
                            indent_string,
                            e.second->get_count());
                }
                // fprintf(f, "%s%s%.*s%zu\t%f\t%f\t%u\t%zu\t%zu\t%f\n",
                //         s.c_str(),
                //         e.first.c_str(),
                //         (int)(strlen(indent_string)-(int)e.first.length()-s.length()),
                //         indent_string,
                //         e.second->get_count(),
                //         e.second->get_uniformity(),
                //         prob_dynamic_name(e.first),
                //         e.second->is_leaf(),
                //         e.second->prob_count(),
                //         root_prob_count,
                //         (float)e.second->prob_count() / root_prob_count);
                if (e.second) {
                    std::string tmp{s};
                    tmp.append(e.first);
                    tmp += '.';
                    e.second->fprint(f, tmp, root_prob_count);
                }
            }
        }

        template <typename F>
        void postorder_traverse(F visit, const std::string &s, size_t root_prob_count) const {
            for (const auto & e : edges) {
                if (e.second) {
                    std::string tmp{s};
                    tmp.append(e.first);
                    tmp += '.';
                    e.second->postorder_traverse(visit, tmp, root_prob_count);
                }
                visit(e, s);
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
                        e.second->get_count());
                if (e.second) {
                    std::string tmp{s};
                    tmp.append(e.first);
                    tmp += '.';
                    e.second->fprint_stats(f, tmp, root_prob_count);
                }
            }
        }

        template <typename F>
        void visit_edges(F &lambda, const std::string &s="") const {
            for (const auto & e : edges) {
                lambda(e.first, e.second, s);
                if (e.second) {
                    std::string tmp{s};
                    tmp.append(e.first);
                    tmp += '.';
                    e.second->visit_edges(lambda, tmp);
                }
            }
        }

        size_t prob_count() const {
            if (this->is_leaf()) {
                return count;
            }
            return leaf_count;  // TODO: better name for this variable
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
    dns_trie(std::istream &input) {
        std::string line;
        while (std::getline(input, line)) {
            if (line.length() == 0 || line[0] == '/') {
                continue;
            }
            //fprintf(stderr, "line: %s\n", line.c_str());
            add(line);
        }
    }

    dns_trie() { }

    // void add(const std::string &name) {
    //
    //     int indentation = 0;
    //     node *n = &root;
    //     const char *c = name.c_str();
    //     while (c != nullptr) {
    //         label l{&c};
    //         // fprintf(stderr, "label: %.*s\t", (int)l.size(), l.value());
    //         // fprintf(stderr, "indentation: %d\n", indentation);
    //         indentation += l.size() + 1;
    //         n = n->add_edge(l.value(), l.size(), indentation);
    //     }
    // }

    void add(const std::string &name) {

        node *n = &root;
        datum dns_name = get_datum(name);
        dns_string d{dns_name};

        if (d.is_valid()) {

            const std::vector<dns_label_string> & label_vector = d.get_value();
            for (auto l = label_vector.end(); l-- != label_vector.begin(); ) {
                //              fprintf(stdout, "%s\n", l->get_string().c_str());;
                n = n->add_edge((const char *)l->begin(), l->length());
            }
        } else {
            fprintf(stderr, "warning: could not parse dns name (%s)\n", name.c_str());
        }

    }

    void add(const std::string &name, size_t count) {

        // fprintf(stderr, "%s: adding %s\t%zu\n", __func__, name.c_str(), count);

        node *n = &root;
        n->increment(count);
        // fprintf(stderr, "parsing dns_name '%s' with length %zu\n", name.c_str(), name.length());
        datum dns_name = get_datum(name);
        // fprintf(stderr, "dns_name.is_not_empty(): %u\n", dns_name.is_not_empty());
        dns_string d{dns_name};
        // fprintf(stderr, "d.is_valid(): %u\n", d.is_valid());

        if (d.is_valid()) {

            const std::vector<dns_label_string> & label_vector = d.get_value();
            for (auto l = label_vector.end(); l-- != label_vector.begin(); ) {
                //              fprintf(stdout, "%s\n", l->get_string().c_str());;
                n = n->add_edge((const char *)l->begin(), l->length(), 0);
                n->increment(count);
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
                n = n->visit_edge((const char *)l->begin(), l->length());
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
                n = n->visit_edge((const char *)l->begin(), l->length());
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
                n = n->visit_edge((const char *)l->begin(), l->length());
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

    float probabiliy(std::string &s) { // TODO: should be const
        node *n = longest_prefix_match_node(s);
        return (float) n->prob_count() / root.prob_count();
    }

    void fprint(FILE *f) const {
        root.fprint(f, "", root.prob_count());
    }

    void fprint_stats(FILE *f) const {
        root.fprint_stats(f, "", root.prob_count());
    }

    template <typename F>
    void visit_edges(F &lambda) const {
         root.visit_edges(lambda);
    }

    dns_trie::node &get_root() { return root; }

};


#endif // DNS_TRIE_HPP
