//
// oidc.cc - ASN.1 Object IDentifier Compiler
//

#include <string>
#include <vector>
#include <list>
#include <iostream>
#include <sstream>
#include <iterator>
#include <regex>
#include <unordered_map>
#include <map>
#include <set>
#include <algorithm>


void oid_print(std::vector<uint32_t> oid, const char *label) {

    if (label) {
        printf("%s: ", label);
    }
    bool first = true;
    printf("{");
    for (const int& i : oid) {
        if (!first) {
            printf(",");
        } else {
            first = false;
        }
        printf(" %d", i);
    }
    printf(" }\n");
}

struct char_pair { char first; char second; };

inline struct char_pair raw_to_hex(unsigned char x) {
    char hex[]= "0123456789abcdef";

    struct char_pair result = { hex[x >> 4], hex[x & 0x0f] };
    return result;
}

inline uint8_t hex_to_raw(const char *hex) {

    int value = 0;
    if(*hex >= '0' && *hex <= '9') {
        value = (*hex - '0');
    } else if (*hex >= 'A' && *hex <= 'F') {
        value = (10 + (*hex - 'A'));
    } else if (*hex >= 'a' && *hex <= 'f') {
        value = (10 + (*hex - 'a'));
    }
    value = value << 4;
    hex++;
    if(*hex >= '0' && *hex <= '9') {
        value |= (*hex - '0');
    } else if (*hex >= 'A' && *hex <= 'F') {
        value |= (10 + (*hex - 'A'));
    } else if (*hex >= 'a' && *hex <= 'f') {
        value |= (10 + (*hex - 'a'));
    }

    return value;
}

std::string raw_to_hex_string(std::vector<uint8_t> v) {
    std::string s;
    for (const auto &x: v) {
        char_pair p = raw_to_hex(x);
        s.push_back(p.first);
        s.push_back(p.second);
    }
    return s;
}

std::string raw_to_hex_array(std::vector<uint8_t> v) {
    std::string s;
    s.push_back('{');
    bool comma = false;
    for (const auto &x: v) {
        if (comma) {
            s.push_back(',');
        } else {
            comma = true;
        }
        s.push_back('0');
        s.push_back('x');
        char_pair p = raw_to_hex(x);
        s.push_back(p.first);
        s.push_back(p.second);
    }
    s.push_back('}');
    return s;
}

std::vector<uint8_t> oid_to_raw_string(std::vector<uint32_t> oid) {
    std::vector<uint8_t> raw;

    raw.push_back(40 * oid[0] + oid[1]);
    for (size_t i = 2; i < oid.size(); i++) {
        uint32_t tmp = oid[i];

        std::vector<uint8_t> v;
        if (tmp == 0) {
            v.push_back(0);
        } else {
            while (tmp > 0) {
                uint32_t div = tmp/128;
                uint32_t rem = tmp - div * 128;
                v.push_back(rem);
                tmp = div;
            }
        }

        if (v.size() > 1) {
            for (size_t j=v.size()-1; j>0; j--) {
                raw.push_back(0x80 | v[j]);
            }
        }
        raw.push_back(v[0]);

    }

    // printf("raw: ");
    // for (const auto &x: raw) {
    //     printf("%02x", x);
    // }
    return raw;
}

std::string oid_to_hex_string(const std::vector<uint32_t> &oid) {
    return raw_to_hex_string(oid_to_raw_string(oid));
}

std::string oid_to_hex_array(const std::vector<uint32_t> &oid) {
    return raw_to_hex_array(oid_to_raw_string(oid));
}

std::vector<uint32_t> hex_string_to_oid(std::string s) {
    std::vector<uint32_t> v;

    if (s.size() & 1) {
        return v;
    }
    const char *c = s.c_str();

    uint32_t component = hex_to_raw(c);
    uint32_t div = component / 40;
    uint32_t rem = component - (div * 40);
    if (div > 2 || rem > 39) {
        return v; // error: invalid input
    }
    v.push_back(div);
    v.push_back(rem);

    c += 2;
    component = 0;
    for (unsigned int i=2; i<s.size(); i += 2) {
        uint8_t tmp = hex_to_raw(c);
        if (tmp & 0x80) {
            component = component * 128 + (tmp & 0x7f);
        } else {
            component = component * 128 + tmp;
            v.push_back(component);
            component = 0;
        }
        c += 2;

    }

    return v;
}

void output_oid(std::vector<uint32_t> oid, const char *delimiter) {

    if (oid.size() < 1) {
        return;    // nothing to output
    }
    unsigned int i = 0;
    for (   ; i < oid.size() - 1; i++) {
        std::cout << oid[i] << delimiter;
    }
    std::cout << oid[i] << '\n';
}


enum token_type {
  token_unknown,
  token_str,
  token_num,
  token_lbrace,
  token_rbrace,
  token_assignment,
  token_comment
};

enum token_type type(const std::string &t) {
    using namespace std;

    regex str("[a-zA-Z_][a-zA-Z_\\-\\(\\)0-9]*");
    regex num("[0-9]+");

    if (t == "{") {
        return token_lbrace;
    } else if (t == "}") {
        return token_rbrace;
    } else if (t == "::=") {
        return token_assignment;
    } else if (t == "--") {
        return token_comment;
    } else if (regex_match(t, str)) {
        return token_str;
    } else if (regex_match(t, num)) {
        return token_num;
    }
    return token_unknown;
}


enum assignment_type {
    type_oid = 0,
    type_other = 1
};

struct oid_assignment {
    std::string name;
    enum assignment_type type;
    std::vector<uint32_t> asn_notation;
};

struct oid_set {
    std::unordered_map<std::string, std::vector<uint32_t>> oid_dict;
    std::unordered_map<std::string, std::vector<uint32_t>> nonterminal_oid_dict;
    std::unordered_map<std::string, std::string> keyword_dict;
    std::unordered_map<std::string, std::string> synonym;
    std::multiset<std::string> keywords;

    void dump_oid_dict_sorted();
    void dump_oid_enum_dict_sorted();
    void verify_oid_dict();
    std::vector<uint32_t> get_vector_from_keyword(const std::string &keyword) {
        auto x = oid_dict.find(keyword);
        if (x != oid_dict.end()) {
            return x->second;
        }
        auto syn = synonym.find(keyword);
        if (syn != synonym.end()) {
            return oid_dict[syn->second];
        }
        std::cerr << "error: unknown OID keyword '" << keyword << "'\n";
        throw "parse error";
    }

    void add_oid(const std::string &name,
                 const std::vector<uint32_t> &v,
                 enum assignment_type type) {

        // if 'v' is already in use as an OID, don't add anything to
        // the OID set, but instead create a synonym
        //
        std::string oid_hex_string = oid_to_hex_string(v);
        if (keyword_dict.find(oid_hex_string) != keyword_dict.end()) {
            std::cerr << "note: OID ";
            bool not_first = 0;
            for (auto &c : v) {
                if (not_first) {
                    std::cerr << '.';
                } else {
                    not_first = 1;
                }
                std::cerr << c;
            }
            std::cerr << " is already in the OID set with keyword " << name;
            if (keyword_dict[oid_hex_string] != name) {
                std::cerr << " creating synonym for " << keyword_dict[oid_hex_string];
                synonym[name] = keyword_dict[oid_hex_string];
            }
            std::cerr << std::endl;

            return;
        }

        // if 'name' is already in use as a keyword, then append a
        // distinct number
        //
        auto count = keywords.count(name);
        std::string k(name);
        keywords.insert(name);
        if (count != 0) {
            std::cerr << "note: keyword " << name << " is already in use, appending [" << count << "]" << std::endl;
            k.append("[").append(std::to_string(count)).append("]");
        }
        // cout << "assignment: " << name << "\t" << type << endl;
        oid_dict[k] = v;
        if (type == type_other) {
            std::cerr << "assigning synonym " << name << "\n";
        }
        keyword_dict[oid_to_hex_string(v)] = k;
    }

    void remove_nonterminals() {
        for (std::pair <std::string, std::vector<uint32_t>> x : oid_dict) {
            std::vector<uint32_t> v = x.second;
            //std::cout << s << std::endl;
            while (1) {
                v.erase(v.end() - 1);
                if (v.empty()) {
                    break;
                }
                std::string oid_hex_string = oid_to_hex_string(v);
                const auto &o = keyword_dict.find(oid_hex_string);
                if (o != keyword_dict.end()) {
                    //std::cout << "found in dict" << std::endl;
                    //nonterminal_oid_dict.insert(o);
                    keyword_dict.erase(o);
                }

                // for (auto &c : v) {
                //    std::cout << c << ' ';
                //}
                //std::cout << '\n';
            }
        }

    }
};

struct oid_set oid_set;

void parse_asn1_line(std::list<std::string> &tokens) {
    using namespace std;

    regex str("[a-zA-Z][a-zA-Z\\-\\(\\)0-9]*");
    regex num("[0-9]+");
    regex str_with_num("(\\([0-9]*\\))");

    /*
     * examples of lines:
     *
     *    id-at OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) ds(5) 4 }
     *    id-at-name AttributeType ::= { id-at 41 }
     *
     *    string OBJECT IDENTIFIER ::= { string+ number+ }
     *    string string ::= { string+ number+ }
     */

#if 0

    for (auto t: tokens) {
        cout << "token\t" << t << "\t";
        if (regex_match(t, str)) {
            cout << "is a string";
        }
        if (regex_match(t, num)) {
            cout << "is a number";
        }
        if (t == "{") {
           cout << "is a left brace";
        } else if (t == "}") {
           cout << "is a right brace";
        } else if (t == "::=") {
            cout << "is an assignment operator";
        } else if (t == "--") {
            cout << "is a comment";
        }
        if (type(t) == token_unknown) {
            cout << "UNKNOWN TOKEN";
        }
        cout << "\n";
    }
#endif

    struct oid_assignment assignment;
    std::list<std::string>::const_iterator t = tokens.begin();
    if (type(*t) == token_comment) {
        return;
    }
    if (type(*t) == token_str) {
        assignment.name = *t;
    } else {
        cout << "error: expected string, got '" << *t << "'\n";
        throw "parse error";
    }
    ++t;

    string category_name;
    if (type(*t) == token_str) {
        if (*t == "OBJECT") {
            ++t;
            if (type(*t) == token_str && *t == "IDENTIFIER") {
                assignment.type = type_oid;
            }
        } else {
            assignment.type = type_other;
            category_name = *t;
        }
    } else if (type(*t) == token_assignment) {

        ++t;
        if (type(*t) == token_str && *t == "OBJECT")  {
            ++t;
            if (type(*t) == token_str && *t == "IDENTIFIER") {
                assignment.type = type_oid;
            } else {
                throw "parse error";
            }
        } else {
            return;
        }

        cout << assignment.name << " is a synonym for OBJECT IDENTIFIER\n";
        return;

    } else {
        cout << "error: expected OBJECT IDENTIFIER or ::=, got '" << *t << "'\n";
        throw "parse error";
    }
    ++t;

    if (type(*t) != token_assignment) {
        cout << "error: expected '::=', got '" << *t << "'\n";
        throw "parse error";
    }
    ++t;

    if (type(*t) != token_lbrace) {
        cout << "error: expected '{', got '" << *t << "'\n";
        throw "parse error";
    }
    ++t;

    while (type(*t) != token_rbrace) {

        // cout << "got token " << *t << endl;
        if (type(*t) == token_str) {
            smatch string_match;

            if (regex_search(*t, string_match, str_with_num)) {
                string s = string_match.str(1);
                // cout << "got str_with_num " << s << endl;
                uint32_t component =  stoi(s.substr(1, s.size() - 2));
                // cout << "component " << component << endl;
                assignment.asn_notation.push_back(component);

            } else {

                std::vector<uint32_t> x = oid_set.get_vector_from_keyword(*t);
                for (uint32_t &component: x) {
                    assignment.asn_notation.push_back(component);
                }
            }

        } else if (type(*t) == token_num) {
            assignment.asn_notation.push_back(stoi(*t));
        }

        ++t;
    }

    oid_set.add_oid(assignment.name, assignment.asn_notation, assignment.type);
}

int paren_balance(const char *s) {
    int balance = 0;
    while (*s != 0 && *s != '\n') {
        //        std::cout << *s;
        switch(*s) {
        case '{':
            balance++;
            break;
        case '}':
            balance--;
            break;
        default:
            break;
        }
        s++;
    }
    // std::cout << "balance: " << balance << "\n";
    return balance;
}

void parse_asn1_file(const char *filename) {
    using namespace std;
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    stream = fopen(filename, "r");
    if (stream == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    size_t balance = 0;
    list<string> statement;
    while ((nread = getline(&line, &len, stream)) != -1) {
        // printf("got line of length %zu:\n", nread);
        // fwrite(line, nread, 1, stdout);

        string word;
        istringstream iss(line, istringstream::in);
        //while( iss >> word ) {
        //    cout << word << endl;
        //}
        list<string> tokens{istream_iterator<string>{iss},
                istream_iterator<string>{}};
        balance += paren_balance(line);
        statement.splice(statement.end(), tokens);

        if (balance == 0 && statement.size() > 0) {
            // cout << "parsing balanced line\n";
            // for (auto x: statement) {
            //    cout << x << endl;
            // }
            parse_asn1_line(statement);
            statement.clear();
        } else {
            // cout << "line is unbalanced (" << balance << ")\n";
        }
    }

    fclose(stream);

}

void oid_set::dump_oid_dict_sorted() {
    using namespace std;

    struct pair_cmp {
        inline bool operator() (const pair<string, vector<uint32_t>> &s1, const pair<string, vector<uint32_t>> &s2) {
            return (s1.second < s2.second);
        }
    };
    vector<pair<string, vector<uint32_t>>> ordered_dict(oid_dict.begin(), oid_dict.end());
    sort(ordered_dict.begin(), ordered_dict.end(), pair_cmp());

    cout << "std::unordered_map<std::string, std::string> oid_dict = {\n";
    for (pair <string, vector<uint32_t>> x : ordered_dict) {
        cout << "\t{ " << oid_to_hex_array(x.second) << ", \"" <<  x.first << "\" },\n";
    }
    cout << "};\n";
}

void oid_set::dump_oid_enum_dict_sorted() {
    using namespace std;

    struct pair_cmp {
        inline bool operator() (const pair<string, vector<uint32_t>> &s1, const pair<string, vector<uint32_t>> &s2) {
            return (s1.second < s2.second);
        }
    };
    vector<pair<string, vector<uint32_t>>> ordered_dict(oid_dict.begin(), oid_dict.end());
    sort(ordered_dict.begin(), ordered_dict.end(), pair_cmp());

    cout << "std::unordered_map<std::string, std::string> oid_dict = {\n";
    for (pair <string, vector<uint32_t>> x : ordered_dict) {
        cout << "\t{ " << oid_to_hex_array(x.second) << ", \"" <<  x.first << "\" },\n";
    }
    cout << "};\n";

    cout << "enum oid {\n";
    unsigned int oid_num = 0;
    cout << "\t" << "unknown" << " = " <<  oid_num++ << ",\n";
    for (pair <string, vector<uint32_t>> x : ordered_dict) {
        std::string tmp_string(x.first);
        std::replace(tmp_string.begin(), tmp_string.end(), '-', '_');
        std::replace(tmp_string.begin(), tmp_string.end(), '[', '_');
        std::replace(tmp_string.begin(), tmp_string.end(), ']', '_');
        cout << "\t" << tmp_string << " = " <<  oid_num << ",\n";

        //const auto &syn = synonym.find(x.first);
        //if (syn != synonym.end()) {
        //    std::cerr << syn->second << " is a synonym for " << x.first << std::endl;
        //    std::string tmp_string2(syn->second);
        //    std::replace(tmp_string2.begin(), tmp_string2.end(), '-', '_');
        //    std::replace(tmp_string2.begin(), tmp_string2.end(), '[', '_');
        //    std::replace(tmp_string2.begin(), tmp_string2.end(), ']', '_');
        //    cout << "\t" << tmp_string2 << " = " <<  oid_num << ",\n";
        //}

        oid_num++;
    }
    cout << "};\n";

    cout << "std::unordered_map<std::string, enum oid> oid_to_enum = {\n";
    for (pair <string, vector<uint32_t>> x : ordered_dict) {
        std::string tmp_string(x.first);
        std::replace(tmp_string.begin(), tmp_string.end(), '-', '_');
        std::replace(tmp_string.begin(), tmp_string.end(), '[', '_');
        std::replace(tmp_string.begin(), tmp_string.end(), ']', '_');
        cout << "\t{ " << oid_to_hex_array(x.second) << ", " <<  tmp_string << " },\n";
    }
    cout << "};\n";
}

void oid_set::verify_oid_dict() {
    using namespace std;

    struct pair_cmp {
        inline bool operator() (const pair<string, vector<uint32_t>> &s1, const pair<string, vector<uint32_t>> &s2) {
            return (s1.second < s2.second);
        }
    };
    vector<pair<string, vector<uint32_t>>> ordered_dict(oid_dict.begin(), oid_dict.end());
    sort(ordered_dict.begin(), ordered_dict.end(), pair_cmp());

    for (pair <string, vector<uint32_t>> x : ordered_dict) {
        string s = oid_to_hex_string(x.second);
        vector<uint32_t> v = hex_string_to_oid(s);
        if (v != x.second) {

            cout << "error with oid " << oid_to_hex_string(x.second) << "\n";

            auto iv = v.begin();
            auto ix = x.second.begin();

            while (iv != v.end() || ix != x.second.end()) {
                if (iv != v.end()) {
                    cout << "v: " << *iv;
                    if (*iv != *ix) {
                        cout << "\t***";
                    }
                    cout << endl;
                    iv++;
                }
                if (ix != x.second.end()) {
                    cout << "x: " << *ix << endl;
                    ix++;
                }
            }
        }
    }

}

int main(int argc, char *argv[]) {
    using namespace std;

#if 0
    auto unknown_oids =
        {
         "2a8648ce3d030107",
         "2b81040022",
         "2b0e03021d",
         "2a864886f70d01010b",
         "2a864886f70d01090f",
         "2a864886f70d010914",
         "2b0601040182371402",
         "2b0601040182371501",
         "2b0601040182371502",
         "2b0601040182371507",
         "2b060104018237150a",
         "2b0601040182373c020101",
         "2b0601040182373c020102",
         "2b0601040182373c020103",
         "2b060104018237540101",
         "2b06010401d04701028245",
         "2b06010401d679020402",
         "2b06010505070101",
         "2b06010505070103",
         "550409",
         "55040c",
         "55040f",
         "550411",
         "55042a",
         "550461",
         "551d01",
         "551d07",
         "551d0a",
         "551d10",
         "551d11",
         "551d12",
         "551d13",
         "551d1e",
         "551d1f",
         "551d20",
         "551d23",
         "6086480186f8420101",
         "6086480186f8420103",
         "6086480186f8420104",
         "6086480186f842010c",
         "6086480186f842010d"
    };
    for (auto &hexstring : unknown_oids) {
        cout << hexstring << '\t';
        auto v = hex_string_to_oid(hexstring);
        const char *delimeter = ".";
        output_oid(v, delimeter);
    }
#endif /* 0 */

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file> [<file2> ... ]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    for (int i=1; i<argc; i++) {
        // cerr << "reading file " << argv[i] << endl;
        parse_asn1_file(argv[i]);
    }

#if 0
    cout << "dictionary dump:" << endl;
    for (pair <string, vector<uint32_t>> x : oid_dict) {
        cout << x.first << " = { ";
        for (auto c: x.second) {
            cout << c << " ";
        }
        cout << "}\t";
        cout << oid_to_hex_string(x.second) << endl;
    }
    cout << endl;

    for (pair <string, vector<uint32_t>> x : oid_dict) {
        cout << oid_to_hex_string(x.second) << "\t\t" << x.first << endl;
    }
#endif

    oid_set.remove_nonterminals();
    oid_set.dump_oid_enum_dict_sorted();
    // oid_set.verify_oid_dict();

    //    for (auto &x : oid_set.keyword_dict) {
    //        cout << x.first << "\t" << x.second << endl;
    //    }
    return 0;
}
