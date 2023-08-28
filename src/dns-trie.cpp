// dns-trie.cpp

#include <string>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <memory>
#include <cmath>

#include "fpdb_reader.hpp"
#include "markov.hpp"

#include "options.h"

#include <vector>

static float digits(const std::string &d) {
    size_t count = 0;
    for (const auto & c : d) {
        if (c >= '0' && c <= '9') {
            ++count;
        }
    }
    return (float) count / d.length();
}

[[maybe_unused]] static float hex_digits(const std::string &d) {
    size_t count = 0;
    for (const auto & c : d) {
        if ((c >= 'a' && c <= 'f') ||( c >= '0' && c <= '9')) {
            ++count;
        }
    }
    return (float) count / d.length();
}

// static float base36(const std::string &d) {
//     size_t count = 0;
//     for (const auto & c : d) {
//         if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
//             ++count;
//         }
//     }
//     return (float) count / d.length();
// }

static float uuid(const std::string &d) {
    size_t count = 0;
    for (const auto & c : d) {
        if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || (c >= '0' && c <= '9') || c == '-') {
            ++count;
        }
    }
    return (float) count / d.length();
}

[[maybe_unused]] static float prob_dynamic_name(const std::string &d) {
    if (digits(d) == 1.0) {
        return 1.0;
    }
    if (d.length() >= 8) {
        return uuid(d);
    }
    return 0.0;
}

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
                fprintf(f, "%s%s%.*s%zu\n",
                        s.c_str(),
                        e.first.c_str(),
                        (int)(strlen(indent_string)-(int)e.first.length()-s.length()),
                        indent_string,
                        e.second->get_count());
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

    // template <typename F>
    // void visit_edges(F &lambda) const {
    //     root.visit_edges(lambda);
    // }

    dns_trie::node &get_root() { return root; }

};

void test() {
    dns_trie t;

    t.add("www.amazon.com");
    t.add("www.cisco.com");
    t.add("abc.net");

    t.fprint(stdout);
}

struct dns_classifier {
    std::vector<std::string> process;
    std::vector<dns_trie> trie;

    // TODO: add compare() function

    // compute KL divergence between processes
};

class configuration {
    std::unordered_map<const char *, const char *> value;
public:

    static constexpr const char *no_argument = "";
    static constexpr const char *FALSE = nullptr;
    static constexpr const char *TRUE = "";

    configuration(const std::unordered_map<const char *, const char *> &v) : value{v} {
    }

    const char *operator[](const char *option) {
        const auto &it = value.find(option);
        if (it == value.end()) {
            return nullptr;
        }
        return it->second;
    }

    void process_argv(int argc, char *argv[]) {
        for (int i=1; i<argc; i++) {
            printf("%s\n", argv[i]);
        }
    }

};

std::string process_dns_name(const std::string &s, fingerprint_type fp_type, bool detail=false) {

    if (s.length() == 0) {
        return "missing.invalid";
    }

    // process dns name
    //
    std::string name{s};
    std::transform(name.begin(), name.end(), name.begin(),
                   [](char c){ return std::tolower(c); });

    datum tmp  = get_datum(name);
    if (ipv4_address_string{tmp}.is_valid()) {
        if (not detail) {
            return "address.invalid";
        }
        // std::replace(name.begin(), name.end(), ':', '-');
        // name += ".address.invalid";
        std::transform(name.begin(), name.end(), name.begin(),
                       [](char c){
                           if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' || c == '_')) {
                               return c;
                           }
                           return '-';
                       });

        name += ".address.invalid";
        //fprintf(stderr, "ipv4 address: %s\n", name.c_str());
        return name;
    }
    tmp = get_datum(name);
    if (ipv6_address_string{tmp}.is_valid()) {
        if (not detail) {
            return "address.invalid";
        }
        // std::replace(name.begin(), name.end(), ':', '-');
        std::transform(name.begin(), name.end(), name.begin(),
                       [](char c){
                           if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' || c == '_')) {
                               return c;
                           }
                           return '-';
                       });
        name += ".address.invalid";
        //fprintf(stderr, "ipv6 address: %s\n", name.c_str());
        return name;
    }
    tmp = get_datum(name);
    if (fp_type == fingerprint_type_tls) {
        auto pos = name.rfind(":");
        if (pos != std::string::npos) {
            // fprintf(stderr, "replacing %s with ", name.c_str());
            name = name.substr(0, pos);  // trim away :PORT
            // fprintf(stderr, "%s\n", name.c_str());
        }
    }
    if (!dns_string{tmp}.is_valid()) {
        if (not detail) {
            return "other.invalid";
        }
        //std::replace(name.begin(), name.end(), ':', '-');
        std::transform(name.begin(), name.end(), name.begin(),
                       [](char c){
                           if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' || c == '_')) {
                               return c;
                           }
                           return '-';
                       });
        name += ".other.invalid";
    }
    return name;
}

fingerprint_type get_fingerprint_type(const std::string &s) {

    if (s.rfind("tls/", 0) == 0) {
        return fingerprint_type_tls;
    }
    if (s.rfind("quic/", 0) == 0) {
        return fingerprint_type_quic;
    }
    if (s.rfind("http/", 0) == 0) {
        return fingerprint_type_http;
    }

    return fingerprint_type_unknown;
}


// dns name lookup
//
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
int dns_lookup(const char *hostname, int port) {
    int err;
    struct addrinfo hints = {}, *addrs;
    char port_str[16] = {};
    sprintf(port_str, "%d", port);

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    err = getaddrinfo(hostname, port_str, NULL, &addrs);
    if (err != 0) {
        fprintf(stderr, "%s: %s\n", hostname, gai_strerror(err));
        return -1;
    }
    for (struct addrinfo *a = addrs; a != NULL; a = a->ai_next) {
        fprintf(stderr, "hostname:       %s\n", hostname);
        fprintf(stderr, "canonical name: %s\n", a->ai_canonname);
        // int              ai_flags;
        // int              ai_family;
        // int              ai_socktype;
        // int              ai_protocol;
        // socklen_t        ai_addrlen;
        // struct sockaddr *ai_addr;
        fprintf(stderr, "flags:         %d\n", a->ai_flags);
        fprintf(stderr, "family:        %d\n", a->ai_family);
        fprintf(stderr, "socktype:      %d\n", a->ai_socktype);
        fprintf(stderr, "protocol:      %d\n", a->ai_protocol);
        fprintf(stderr, "addrlen:       %u\n", a->ai_addrlen);
        // fprintf(stderr, "addr:          %d\n", a->ai_flags);
    }
    freeaddrinfo(addrs);
    return err;
}

#include <regex>
#include <optional>

class name_filter {
    std::regex rgx;

public:

    name_filter(const std::string &s) : rgx{s} { }

    bool matches(const std::string &s) { return std::regex_search(s, rgx); }
};

#include <iostream>

using namespace mercury_option;

int main(int argc, char *argv[]) {

    std::ios::sync_with_stdio(false);  // for performance

    // configuration config({
    //         {"--find-public-suffix", configuration::FALSE},
    //         {"--public-suffix", "public_suffix_list.dat"},
    //         {"--asdf", configuration::FALSE}
    //     });
    //
    // config.process_argv(argc, argv);

    class option_processor opt({
        { argument::none,       "--help",               "print help message"       },
        { argument::none,       "--trie",               "create dns name trie"     },
        { argument::none,       "--dump",               "dump printout of trie"    },
        { argument::none,       "--json",               "input is json"            },
        { argument::none,       "--find-public-suffix", "report the public suffix" },
        { argument::required,   "--public-suffix-list", "public suffix list file"  },
        { argument::required,   "--test-data",          "file with names to test"  },
        { argument::required,   "--fpdb",               "fingerprint_db.json file" },
        { argument::required,   "--dns-lookup",         "look up dns name"         },
        { argument::required,   "--filter",             "filter (regex|uuid)"      },
    });
    const char summary[] =
        "usage:\n"
        "   dns-trie [OPTIONS]\n"
        "\n"
        "OPTIONS\n"
        ;
    if (!opt.process_argv(argc, argv)) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    auto [ psl_is_set, psl_filename ] = opt.get_value("--public-suffix-list");
    auto [ test_data_is_set, test_data ] = opt.get_value("--test-data");
    auto [ fpdb_is_set, fpdb ]        = opt.get_value("--fpdb");
    auto [ lookup_set, lookup ]       = opt.get_value("--dns-lookup");
    bool find_psl                     = opt.is_set("--find-public-suffix");
    bool dump                         = opt.is_set("--dump");
    bool json_input                   = opt.is_set("--json");
    bool help                         = opt.is_set("--help");
    std::optional<std::string> filter_string = opt.get("--filter");

    if (help) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_SUCCESS;
    }

    if (lookup_set) {
        fprintf(stderr, "%s: %d\n", lookup.c_str(), dns_lookup(lookup.c_str(), 0));
        return 0;
    }

    std::unique_ptr<dns_trie> psl;
    if (find_psl) {

        std::string tmp_filename{"public_suffix_list.dat"};
        if (psl_is_set) {
            tmp_filename = psl_filename;
        }
        std::ifstream psl_file{tmp_filename};
        psl = std::make_unique<dns_trie>(psl_file);

        // std::string line;
        // while (std::getline(std::cin, line)) {
        //     if (line.length() == 0) {
        //         continue; // ignore empty line
        //     }
        //     fprintf(stdout, "name:               %s\n", line.c_str());
        //     fprintf(stdout, "public suffix:      %s\n", psl->longest_prefix_match(line).c_str());
        //     fprintf(stdout, "top private suffix: %s\n", psl->longest_prefix_match_plus_one(line).c_str());
        // }

    }
    // std::ifstream tmpfile{"public_suffix_list.dat"} ;
    // dns_trie psl2{tmpfile};
    //
    // std::string vic{"vic.gov.au"};
    // fprintf(stdout, "public suffix:  %s\n", psl2.longest_prefix_match(vic).c_str());
    // return 0;

    if (fpdb_is_set) {

        std::ifstream fpdb_file{fpdb};
        resources fingerprint_db(fpdb_file, resources::verbosity::verbose);

        std::unordered_map<std::string, dns_classifier> fp_and_classifier;

        dns_trie benign_tls;
        dns_trie benign_http;
        dns_trie benign_quic;
        dns_trie malware_tls;
        dns_trie malware_http;
        dns_trie malware_quic;

        const std::unordered_map<std::string, std::vector<process_info>> & fp_and_process_info = fingerprint_db.get_fpdb();
        for (const auto & fp_data : fp_and_process_info) {
            fingerprint_type fp_type = get_fingerprint_type(fp_data.first);
            //fprintf(stderr, "%s: %d\n", fp_data.first.c_str(), fp_type);

            dns_classifier c;
            // std::vector<dns_trie> t;
            // std::vector<std::string> p;
            for (const auto & pi : fp_data.second) {
                //pi.print(stderr);

                if (false) {
                if (pi.malware == true) {
                    for (auto &x : pi.hostname_sni) {
                        switch(fp_type) {
                        case fingerprint_type_tls:
                            malware_tls.add(process_dns_name(x.first, fp_type, true), x.second);
                            break;
                        case fingerprint_type_http:
                            malware_http.add(process_dns_name(x.first, fp_type, true), x.second);
                            break;
                        case fingerprint_type_quic:
                            malware_http.add(process_dns_name(x.first, fp_type, true), x.second);
                            break;
                        default:
                            ;
                        }
                    }
                } else { // pi.malware == false
                    for (auto &x : pi.hostname_sni) {
                        switch(fp_type) {
                        case fingerprint_type_tls:
                            benign_tls.add(process_dns_name(x.first, fp_type, true), x.second);
                            break;
                        case fingerprint_type_http:
                            benign_http.add(process_dns_name(x.first, fp_type, true), x.second);
                            break;
                        case fingerprint_type_quic:
                            benign_http.add(process_dns_name(x.first, fp_type, true), x.second);
                            break;
                        default:
                            ;
                        }
                    }
                }

                continue;   // skip the vector-of-tries processing for now
                } // false

                // fprintf(stdout, "-----------------------------------------------------------------\n");
                // fprintf(stdout, "process: %s\n", pi.name.c_str());
                c.process.emplace_back(pi.name);

                c.trie.emplace_back();
                dns_trie &t_back = c.trie.back();
                for (auto &x : pi.hostname_sni) {
                    //fprintf(stderr, "%s\":%" PRIu64 "\n", x.first.c_str(), x.second);
                    t_back.add(process_dns_name(x.first, fp_type, true), x.second);
                }

                fp_and_classifier[fp_data.first] = c;

                //t_back.fprint(stdout);
            }
            // fprintf(stdout, "==================================================================\n");
        }

        //  malware_tls.fprint(stdout);

        static constexpr auto lambda = [](const std::string &label, const dns_trie::node *node, const std::string &s) {
            if (node->is_leaf() == false) {
                return;
            }
            char indent_string[] = "                                                                            ";
            fprintf(stdout, "%s%s%.*s\t%zu\n",
                    s.c_str(),
                    label.c_str(),
                    (int)(strlen(indent_string)-(int)label.length()-s.length()),
                    indent_string,
                    node->get_count());
        };

        for (auto & fp_c : fp_and_classifier) {
            fprintf(stdout, "str_repr: %s\n", fp_c.first.c_str());
            size_t num_procs = fp_c.second.process.size();
            for (size_t i=0; i<num_procs; i++) {
                fprintf(stdout, "process: %s\n", fp_c.second.process[i].c_str());
                //fp_c.second.trie[i].fprint(stdout);
                fp_c.second.trie[i].fprint_stats(stdout);
                //fp_c.second.trie[i].get_root().visit_edges(lambda);
            }
        }

        // early return
        //
        return 0;
    }

    if (json_input) {
        dns_trie t;

        std::string line;
        while (std::getline(std::cin, line)) {
            if (line.length() == 0) {
                continue; // ignore empty line
            }
            //fprintf(stdout, "line: '%s'\n", line.c_str());

            rapidjson::Document json;
            json.Parse(line.c_str());

            for (auto &y : json.GetObject()) {
                if (y.name.IsString() && y.value.IsUint64()) {
                    fprintf(stderr, "\t\t%s: %lu\n", y.name.GetString(), y.value.GetUint64());
                    // json[y.name.GetString()] = y.value.GetUint64();

                    if (psl) {
                        std::string n = y.name.GetString();
                        // fprintf(stdout, "name:               %s\n", n.c_str());
                        // fprintf(stdout, "public suffix:      %s\n", psl->longest_prefix_match(n).c_str());
                        // fprintf(stdout, "top private suffix: %s\n", psl->longest_prefix_match_plus_one(n).c_str());
                        t.add(psl->longest_prefix_match_plus_one(n).c_str(), y.value.GetUint64());
                    } else {
                        t.add(y.name.GetString(), y.value.GetUint64());
                    }
                }
            }

        }

        if (dump) {
            t.fprint(stdout);
        }

        if (test_data_is_set) {
            std::string line;
            std::ifstream test_data_file{test_data};
            while (std::getline(test_data_file, line)) {
                if (line.length() == 0) {
                    continue; // ignore empty line
                }
                fprintf(stdout, "name:                   %s\n", line.c_str());
                fprintf(stdout, "longest match:          %s\n", t.longest_prefix_match(line).c_str());
                dns_trie::node *n = t.longest_prefix_match_node(line);
                if (n) {
                    fprintf(stdout, "count:                  %zu\n", n->get_count());
                    fprintf(stdout, "leaf:                   %u\n", n->is_leaf());
                }
                // fprintf(stdout, "longest match plus one: %s\n", t.longest_prefix_match_plus_one(line).c_str());
            }
        }


    } else {

        std::optional<name_filter> filter;

        if (filter_string) {
            if (filter_string == "uuid") {
                filter = name_filter{"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"};
            } else {
                filter = name_filter{*filter_string};
            }
            // filter = name_filter{"[0-9]{8}"};
        }

        dns_trie t;

        std::string line;
        while (std::getline(std::cin, line)) {
            if (line.length() == 0) {
                continue; // ignore empty line
            }

            if (filter) {
                if (!filter->matches(line)) {
                    continue;  // ignore this string
                }
            }
            // fprintf(stdout, "line: '%s'\n", line.c_str());
            t.add(line, 1);
        }

        if (dump) {
            t.fprint(stdout);
        }

        if (test_data_is_set) {
            std::string line;
            std::ifstream test_data_file{test_data};
            while (std::getline(test_data_file, line)) {
                if (line.length() == 0) {
                    continue; // ignore empty line
                }
                fprintf(stdout, "name:                   %s\n", line.c_str());
                fprintf(stdout, "longest match:          %s\n", t.longest_prefix_match(line).c_str());
                fprintf(stdout, "longest match plus one: %s\n", t.longest_prefix_match_plus_one(line).c_str());
            }
        }

    }

    return 0;
}
