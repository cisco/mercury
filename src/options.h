/*
 * options.h
 */

#ifndef OPTIONS_H
#define OPTIONS_H

#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

/*
 * example use of class option_processor
 *
 *    class option_processor opt({{ argument::required,   "--one",     "first argument" },
 *                                { argument::none,       "--two",     "second argument" },
 *                                { argument::positional, "position1", "first positional" },
 *                                { argument::positional, "position2", "second positional" },
 *                                { argument::optional,   "--three",   "third argument" }});
 *
 */

/*
 * TODO: detect ambiguous situations, such as argument::optional that
 * appear before positional parameters
 */


enum class argument {
    required,
    optional,
    none,
    positional
};

class option {
    std::string name;
    argument arg;
    std::string documentation;
    std::string value;
    bool value_is_set;

public:
    option(argument opt_arg, const std::string &opt_name, std::string opt_doc) : name{opt_name}, arg{opt_arg}, documentation{opt_doc}, value{}, value_is_set{false} { }

    bool matches(const char *option_name) const {
        return name.compare(option_name) == 0;
    }

    bool arg_type(argument a) const { return (a == arg); }

    const char *get_name() const { return name.c_str(); }

    const char *get_doc() const { return documentation.c_str(); }

    std::pair<bool, std::string> get_value() const {
        return {value_is_set, value};
    }

    void set_value(const char *v) {
        value = v;
        value_is_set = true;
    }

    void set_value() {
        value_is_set = true;
    }

    bool is_set() { return value_is_set; }

    const char *get_type_string() {
        if (arg_type(argument::required)) {
            return "<arg>";
        }
        if (arg_type(argument::optional)) {
            return "[<arg>]";
        }
        if (arg_type(argument::none) || arg_type(argument::positional)) {
            return "";
        }
        return "";
    }

};

class option_processor {
    std::vector<option> option_vector;

public:
    option_processor(const std::vector<option> &opts) : option_vector{opts} {
        // TBD: verify that there are no duplicated option names
    }

    bool set_positional_parameter(const char *arg) {
        for (option &o : option_vector) {
            if (o.arg_type(argument::positional) && !o.is_set()) {
                o.set_value(arg);
                return true;
            }
        }
        return false;
    }

    option *find_option_by_name(const char *arg) {
        for (option &o : option_vector) {
            if (o.matches(arg)) {
                return &o;
            }
        }
        return nullptr;
    }

    bool string_matches_option_name(const char *arg) {
        for (option &o : option_vector) {
            if (o.matches(arg)) {
                return true;
            }
        }
        return false;
    }

    bool process_argv(int argc, char *argv[]) {
        if (argc <= 1) {
            return false;  // no options
        }
        argv = &argv[1];  argc--;  // skip program name

        option *last_option = nullptr;
        for (int i=0; i<argc; i++) {
            if (last_option) {
                if (last_option->arg_type(argument::required)) {
                    last_option->set_value(argv[i]);
                    last_option = nullptr;

                } else if (last_option->arg_type(argument::optional)) {
                    if (!string_matches_option_name(argv[i])) {
                        last_option->set_value(argv[i]);
                        last_option = nullptr;
                    }
                }

            } else {
                last_option = find_option_by_name(argv[i]);
                if (last_option == nullptr) {
                    if (!set_positional_parameter(argv[i])) {
                        fprintf(stderr, "error: \"%s\" does not match any option name or positional parameter\n", argv[i]);
                        return false;
                    }
                }
                if (last_option && (last_option->arg_type(argument::none) || last_option->arg_type(argument::optional))) {
                    last_option->set_value();
                    last_option = nullptr;
                }
            }
        }
        if (last_option && last_option->arg_type(argument::required)) {
            fprintf(stderr, "error: option \"%s\" requires an argument\n", last_option->get_name());
            return false;
        }
        return true;
    }

    // parse_c_string(s) parses a null-terminated C character string s
    // into an argv[] style vector of null-terminated C character
    // strings
    std::vector<char *> parse_c_string(char *s) {
        char delimiter = ' ';
        std::vector<char *> v;
        v.push_back(nullptr);  // placeholder for argv[] compatibility

        while (*s == delimiter) {
            s++;  // consume leading whitespace
        }
        char *prev_string = s;
        while (*s != '\0') {
            if (prev_string == nullptr) {
                prev_string = s;
            }
            if (*s == delimiter) {
                *s = '\0';
                v.push_back(prev_string);
                prev_string = nullptr;
                s++;
                while (*s == delimiter) {
                    s++;  // consume whitespace
                }
            } else {
                s++;
            }
        }
        if (s != prev_string && prev_string != nullptr) {
            v.push_back(prev_string);
        }
        return v;
    }

    bool process_c_string(char *s) {
        std::vector<char *> v = parse_c_string(s);
        int argc = v.size();
        char **argv = &v[0];
        return process_argv(argc, argv);
    }

    void usage(FILE *f, const char *progname, const char *summary) {
        fprintf(f, "%s %s", progname, summary);
        const char *whitespace = "                  ";
        for (option &o : option_vector) {
            int white_len = strlen(whitespace) - strlen(o.get_name()) - strlen(o.get_type_string());
            white_len = white_len > 0 ? white_len : 0;
            fprintf(f, "   %s %s %.*s%s\n", o.get_name(), o.get_type_string(), white_len, whitespace, o.get_doc());
        }
        fputc('\n', f);
    }

    void print_values(FILE *f) {
        fprintf(f, "option values\n");
        for (option &o : option_vector) {
            std::pair<bool, std::string> v = o.get_value();
            if (v.first) {
                fprintf(f, "\t%s", o.get_name());
                if (o.arg_type(argument::required)
                    || o.arg_type(argument::positional)
                    || (o.arg_type(argument::optional) && v.second != "")) {
                    fprintf(f, "\t%s", v.second.c_str());
                }
                fputc('\n', f);
            }
        }
    }

    std::pair<bool, std::string> get_value(const char *name) {
        for (option &o : option_vector) {
            if (o.matches(name)) {
                return o.get_value();
            }
        }
        return { false, "" }; // error: option name not found
    }

    bool is_set(const char *name) {
        for (option &o : option_vector) {
            if (o.matches(name)) {
                return o.is_set();
            }
        }
        return false;  // error: option name not found
    }

};

#endif // OPTIONS_H
