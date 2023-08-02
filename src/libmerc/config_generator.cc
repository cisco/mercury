#include <map>
#include <functional>
#include <algorithm>
#include <numeric>

#include "global_config.h"
#include "../options.h"

static inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
                                                            return !std::isspace(ch);
                                                        }));
}

// trim from end (in place)
static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
                                                   return !std::isspace(ch);
                                               }).base(), s.end());
}

// trim from both ends (in place)
static inline void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}

static std::vector<libmerc_option> config_mapper = {
    {"analysis", "-a", "--analysis", SETTER_FUNCTION(){ c.do_analysis = s.empty() ? true : s.compare("1") == 0; }},
    {"select", "-s", "--select",     SETTER_FUNCTION(){ c.packet_filter_cfg = (c.temp_proto_str.assign(s)).data(); }},
    {"dns-json", "", "",             SETTER_FUNCTION(){ c.dns_json_output = s.empty() ? true : s.compare("1") == 0; }},
    {"certs-json", "", "",           SETTER_FUNCTION(){ c.certs_json_output = s.empty() ? true : s.compare("1") == 0; }},
    {"metadata", "", "",             SETTER_FUNCTION(){ c.metadata_output = s.empty() ? true : s.compare("1") == 0; }},
    {"stats", "", "",                SETTER_FUNCTION(){ c.do_stats = s.empty() ? true : s.compare("1") == 0; }},
    {"report_os", "", "",            SETTER_FUNCTION(){ c.report_os = s.empty() ? true : s.compare("1") == 0; }},
    {"nonselected-tcp-data", "", "", SETTER_FUNCTION(){ c.output_tcp_initial_data = s.empty() ? true : s.compare("1") == 0; }},
    {"nonselected-udp-data", "", "", SETTER_FUNCTION(){ c.output_udp_initial_data = s.empty() ? true : s.compare("1") == 0; }},
    {"tcp-reassembly", "", "",       SETTER_FUNCTION(){ c.tcp_reassembly = s.empty() ? true : s.compare("1") == 0;}},
    {"fp_proc_threshold", "", "",    SETTER_FUNCTION(){ c.fp_proc_threshold = std::stof(s); }},
    {"proc_dst_threshold", "", "",   SETTER_FUNCTION(){ c.proc_dst_threshold = std::stof(s); }},
    {"max_stats_entries", "", "",    SETTER_FUNCTION(){ c.max_stats_entries = std::stoull(s); }}
};

struct config_token
{
    std::string key_;
    std::string value_;

    config_token() {}
    config_token(const std::string& key) : key_{key} { trim(key_);}
    config_token(const std::string& key, const std::string& value) : key_{key}, value_{value} { trim(key_); trim(value_); }

    static config_token parse(const std::string& in, const char& assignment) {
        auto indx = in.find(assignment);
        if(indx == std::string::npos) {
            return config_token(in);
        }

        return config_token(in.substr(0, indx), in.substr(indx + 1));
    }
};

std::string create_config_from_arguments(char** argv, int& argc) {
    std::vector<mercury_option::option> option_list;
    std::vector<std::string> processed_options;
    std::string result;
    for(libmerc_option op : config_mapper) {
        if(op.get_long_option_name().length() > 0)
            option_list.push_back({mercury_option::argument::optional, op.get_long_option_name(), ""});
        if(op.get_short_option_name().length() > 0)
            option_list.push_back({mercury_option::argument::optional, op.get_short_option_name(), ""});
    }

    mercury_option::option_processor proc(option_list);

    proc.process_argv(argc, argv, false);

    for(auto i = config_mapper.begin(); i != config_mapper.end(); i++) {
        const char* tmp_long_name = i->get_long_option_name().c_str();
        auto res = proc.get_value(tmp_long_name);
        if(res.first) {
            result += ";" + i->get_long_option_name() + "=" + res.second;
            processed_options.push_back(i->get_long_option_name());
            processed_options.push_back(res.second);
            continue;
        }
        const char* tmp_short_name = i->get_short_option_name().c_str();
        res = proc.get_value(tmp_short_name);
        if(res.first) {
            result += ";" + i->get_short_option_name() + "=" + res.second;
            processed_options.push_back(i->get_short_option_name());
            processed_options.push_back(res.second);
        }
    }

    int new_argc = 0;
    for(int i = 0; i < argc; i++) {
        bool found = false;
        for(auto op : processed_options) {
            if(strcmp(argv[i], op.c_str()) == 0) {
                found = true;
                break;
            }
        }
        if(!found)
            argv[new_argc++] = argv[i];
    }
    argc = new_argc;

    return result;
}

std::vector<config_token> parse_tokens(std::string config, const char& delim, const char& assignment) {
    std::vector<config_token> tokens;
    size_t indx = config.find(delim);
    while(indx != std::string::npos) {
        if(config.empty())
            break;

        std::string data = config.substr(0, indx);
        trim(data);

        if(data.empty() == false) {
            tokens.push_back(config_token::parse(data, assignment));
        }

        config = config.substr(indx + 1);
        indx = config.find(delim);
    }

    if(config.empty() == false) {
        tokens.push_back(config_token::parse(config, assignment));
    }
    return tokens;
}

bool config_contains_delims(const std::string& config, const char& delim) {
    return config.find(delim) != std::string::npos;
}

void parse_additional_options(std::vector<libmerc_option> options, std::string config, global_config& lc, const char& delim, const char& assignment) {
    options.insert(options.end(), config_mapper.begin(), config_mapper.end());

    std::vector<config_token> tokens = parse_tokens(config, delim, assignment);

    for(const auto& token : tokens) {
        bool setter_invoked = false;
        for(libmerc_option op : options) {
            if(op.perform_option_check(token.key_)) {
                setter_invoked = true; 
                op.perform_setter(token.value_, lc);
            }
        }
        /* If the option keyword is not recognized/missing,
         * by default treat it as protocol string and attempt parsing
         */
        if (!setter_invoked) {
            lc.set_protocols(token.key_);
        }
    }
}
