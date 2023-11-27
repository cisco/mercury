// dns-trie.cpp

#include "dns_trie.hpp"

#include <fstream>

#include "fpdb_reader.hpp"

#include "options.h"

#include <vector>

// #include "markov.h"
// markov_model<dns_char_set> markov{fopen("markov-model.dat", "r")};

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
    (void)hints;  // prevent compiler complaining

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

void testcase() {

    // create a trie using the examples from the working draft writeup
    //
    dns_trie t;
    t.add("foo.net", 10);
    t.add("example.com", 10);
    t.add("a.example.com", 15);
    t.add("b.example.com", 15);
    t.add("c.example.com", 20);
    t.add("foo.example.com", 30);

    t.fprint(stdout);

    fputc('\n', stdout);

    auto print_node = [](std::pair<std::string, dns_trie::node *> e, const std::string &s, size_t root_prob_count) {
        char indent_string[] = "                                                                            ";
        if (true || e.second->is_leaf()) {
            fprintf(stdout, "%s%s%.*s%f\n",
                    s.c_str(),
                    e.first.c_str(),
                    (int)(strlen(indent_string)-(int)e.first.length()-s.length()),
                    indent_string,
                    (float)e.second->get_subtree_count() / root_prob_count);
        }
        return 0;
    };
    // auto print_node2 = [](std::pair<std::string, dns_trie::node *> e, const std::string &s, size_t root_prob_count) {
    //     (void)root_prob_count;  // ignore parameter
    //     char indent_string[] = "                                                                            ";
    //     if (true || e.second->is_leaf()) {
    //         fprintf(stdout, "%s%s%.*s%zu\t%zu\n",
    //                 s.c_str(),
    //                 e.first.c_str(),
    //                 (int)(strlen(indent_string)-(int)e.first.length()-s.length()),
    //                 indent_string,
    //                 e.second->get_subtree_count(),
    //                 e.second->get_node_count());
    //     }
    // };
    fprintf(stdout, "preorder traversal:\n");
    t.get_root().preorder_traverse(print_node, "", 100);
    fputc('\n', stdout);

    fprintf(stdout, "postorder traversal:\n");
    t.get_root().postorder_traverse<decltype(print_node), size_t>(print_node, "", 100);
    fputc('\n', stdout);

    for (auto &s : {
            "foo.net", "example.com", "a.example.com", "b.example.com", "c.example.com", "foo.example.com"
        }) {
        printf("%s:\t%f\n", s, t.probability(s));
    }

    t.fprint_uniformity(stdout);
    fputc('\n', stdout);

    dns_trie::node_stats ns = t.count_leaves_and_nodes();
    fprintf(stderr, "leaves: %zu\tnodes: %zu\n", ns.leaf_count, ns.node_count);
    fputc('\n', stdout);

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

// dns_trie
//
// creates, reports on, and manipulates dns_tries
//
//
// input options:
//     file containing dns names
//     FPDB json
//
// filtering:
//     regex
//     uuid
//     not-matching
//
// remove uniform nodes
// remove nodes below the private suffix
// create a classifier from two dns_tries (malware/benign)
//
// reporting:
//     preorder traversal
//     postorder traversal
//     report leaves
//     report all nodes
//     uniformity of non-leaf nodes
//
//
//
int main(int argc, char *argv[]) {

    if (false) {
        //
        // what's the minimum size?  about 72 bytes each
        //
        fprintf(stdout, "sizeof(dns_trie::node): %zu\n", sizeof(dns_trie::node));
        fprintf(stdout, "sizeof(dns_trie):       %zu\n", sizeof(dns_trie));
    }

    // testcase();
    // return 0;

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
        { argument::none,       "--leaf",               "only output leaf info"    },
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
    bool leaf                         = opt.is_set("--leaf");
    (void)leaf; // compiler silencer
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
        // dns_trie benign_http;
        // dns_trie benign_quic;
        dns_trie malware_tls;
        // dns_trie malware_http;
        // dns_trie malware_quic;

        const std::unordered_map<std::string, std::vector<process_info>> & fp_and_process_info = fingerprint_db.get_fpdb();
        for (const auto & fp_data : fp_and_process_info) {
            fingerprint_type fp_type = get_fingerprint_type(fp_data.first);
            //fprintf(stderr, "%s: %d\n", fp_data.first.c_str(), fp_type);

            dns_classifier c;
            // std::vector<dns_trie> t;
            // std::vector<std::string> p;
            for (const auto & pi : fp_data.second) {
                //pi.print(stderr);

                if (true) {
                    if (pi.malware == true) {
                        for (auto &x : pi.hostname_sni) {
                            switch(fp_type) {
                            case fingerprint_type_tls:
                                malware_tls.add(process_dns_name(x.first, fp_type, true), x.second);
                                break;
                            // case fingerprint_type_http:
                            //     malware_http.add(process_dns_name(x.first, fp_type, true), x.second);
                            //     break;
                            // case fingerprint_type_quic:
                            //     malware_http.add(process_dns_name(x.first, fp_type, true), x.second);
                            //     break;
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
                            // case fingerprint_type_http:
                            //     benign_http.add(process_dns_name(x.first, fp_type, true), x.second);
                            //     break;
                            // case fingerprint_type_quic:
                            //     benign_http.add(process_dns_name(x.first, fp_type, true), x.second);
                            //     break;
                            default:
                                ;
                            }
                        }
                    }

                    continue;   // skip the vector-of-tries processing for now
                }

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

        // benign_tls.fprint_uniformity(stdout);
        // malware_tls.fprint_uniformity(stdout);
        // benign_tls.fprint_uniformity(stdout);
        // benign_tls.fprint(stdout);

        // dns_trie::node_stats malware_stats = malware_tls.count_leaves_and_nodes();
        // fprintf(stderr, "malware: leaves: %zu\tnodes: %zu\n", malware_stats.leaf_count, malware_stats.node_count);
        // dns_trie::node_stats benign_stats = benign_tls.count_leaves_and_nodes();
        // fprintf(stderr, "benign: leaves:  %zu\tnodes: %zu\n", benign_stats.leaf_count, benign_stats.node_count);

        // fprintf(stderr, "malware count: %zu\n", malware_tls.get_root().get_subtree_count());
        // fprintf(stderr, "benign count:  %zu\n", benign_tls.get_root().get_subtree_count());

        // return 0;

        binary_classifier malware_classifier{malware_tls, benign_tls};

        malware_classifier.prune(stdout);
        malware_classifier.compare(stdout);

        return 0;

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
                    node->get_subtree_count());
        };
        (void)lambda; // prevent compiler complaining

        for (auto & fp_c : fp_and_classifier) {
            fprintf(stdout, "str_repr: %s\n", fp_c.first.c_str());
            size_t num_procs = fp_c.second.process.size();
            for (size_t i=0; i<num_procs; i++) {
                fprintf(stdout, "process: %s\n", fp_c.second.process[i].c_str());
                //fp_c.second.trie[i].fprint(stdout);
                fp_c.second.trie[i].fprint_uniformity(stdout);
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
            //t.fprint(stdout, leaf);
            //dns_trie::node_stats ns = t.count_leaves_and_nodes();
            //fprintf(stderr, "leaves: %zu\tnodes: %zu\n", ns.leaf_count, ns.node_count);
            t.fprint_uniformity(stdout);
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
                    fprintf(stdout, "count:                  %zu\n", n->get_subtree_count());
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
            if (line.length() == 0 || line[0] == '/' || line[0] == '#') {
                continue; // ignore empty line or comment
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
            // t.fprint(stdout, leaf);
            // dns_trie::node_stats ns = t.count_leaves_and_nodes();
            // fprintf(stderr, "leaves: %zu\tnodes: %zu\n", ns.leaf_count, ns.node_count);
            t.fprint_uniformity(stdout);
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
