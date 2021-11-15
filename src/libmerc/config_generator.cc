#include <map>
#include <functional>
#include <algorithm> 
#include <numeric>

#include "config_generator.h"
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
    {"resources", "", "",            SETTER_FUNCTION(){ strcpy(c.resources, s.c_str()); }},
    {"select", "-s", "--select",     SETTER_FUNCTION(){ strcpy(c.packet_filter_cfg, s.c_str()); }},
    {"dns-json", "", "",             SETTER_FUNCTION(){ c.dns_json_output = s.empty() ? true : s.compare("1") == 0; }},
    {"certs-json", "", "",           SETTER_FUNCTION(){ c.certs_json_output = s.empty() ? true : s.compare("1") == 0; }},
    {"metadata", "", "",             SETTER_FUNCTION(){ c.metadata_output = s.empty() ? true : s.compare("1") == 0; }},
    {"stats", "", "",                SETTER_FUNCTION(){ c.do_stats = s.empty() ? true : s.compare("1") == 0; }},
    {"report_os", "", "",            SETTER_FUNCTION(){ c.report_os = s.empty() ? true : s.compare("1") == 0; }},
    {"nonselected-tcp-data", "", "", SETTER_FUNCTION(){ c.output_tcp_initial_data = s.empty() ? true : s.compare("1") == 0; }},
    {"nonselected-udp-data", "", "", SETTER_FUNCTION(){ c.output_udp_initial_data = s.empty() ? true : s.compare("1") == 0; }},
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

    static config_token parse(const std::string& in, const char& assignment)
    {
        auto indx = in.find(assignment);
        if(indx == std::string::npos)
        {
            return config_token(in);
        }

        return config_token(in.substr(0, indx), in.substr(indx + 1));
    }
};

libmerc_config create_config(std::string config, const char& delim, const char& assignment)
{
    libmerc_config result;

    reconfigure_libmerc_config(result, config, delim, assignment);

    return result;
}

libmerc_config create_config_from_arguments(char** argv, int argc)
{
    std::vector<mercury_option::option> option_list;
    libmerc_config result;

    for(libmerc_option op : config_mapper)
    {
        option_list.push_back({mercury_option::argument::optional, op.get_long_option_name(), ""});
        option_list.push_back({mercury_option::argument::optional, op.get_short_option_name(), ""});
    }

    mercury_option::option_processor proc(option_list);

    proc.process_argv(argc, argv, false);
    
    for(auto i = config_mapper.begin(); i != config_mapper.end(); i++)
    {
        auto res = proc.get_value(i->get_long_option_name().c_str());
        if(res.first)
        {
            i->perform_setter(res.second, result);
            continue;
        }
        res = proc.get_value(i->get_short_option_name().c_str());
        if(res.first)
        {
            i->perform_setter(res.second, result);
        }
    }

    return result;
}

std::vector<config_token> parse_tokens(std::string config, const char& delim, const char& assignment)
{
    std::vector<config_token> tokens;
    size_t indx = config.find(delim);
    while(indx != std::string::npos)
    {
        if(config.empty())
            break;
            
        std::string data = config.substr(0, indx);
        trim(data);
        
        if(data.empty() == false)
        {
            tokens.push_back(config_token::parse(data, assignment));
        }
        
        config = config.substr(indx + 1);
        indx = config.find(delim);
    }

    if(config.empty() == false)
    {
        tokens.push_back(config_token::parse(config, assignment));
    }
    return tokens;
}

bool reconfigure_libmerc_config(libmerc_config& result, std::string config, const char& delim, const char& assignment)
{
    std::vector<config_token> tokens = parse_tokens(config, delim, assignment);

    for(const auto& token : tokens)
    {
        for(libmerc_option op : config_mapper)
        {
            if(op.perform_option_check(token.key_))
                op.perform_setter(token.value_, result);
        }
    }

    return true;
}

libmerc_config create_config_from_lines(std::vector<std::string> lines, const char& assignment)
{
    libmerc_config result;
    for(const auto& line : lines)
    {
        reconfigure_libmerc_config(result, line, assignment);
    }
    return result;
}

bool config_contains_delims(const std::string& config, const char& delim)
{
    return config.find(delim) != std::string::npos;
}

void parse_additional_options(std::vector<libmerc_option> options, std::string config, libmerc_config& lc, const char& delim, const char& assignment)
{
    options.insert(options.end(), config_mapper.begin(), config_mapper.end());

    std::vector<config_token> tokens = parse_tokens(config, delim, assignment);

    for(const auto& token : tokens)
    {
        for(libmerc_option op : options)
        {
            if(op.perform_option_check(token.key_))
                op.perform_setter(token.value_, lc);
        }
    }
}

void dump_config(FILE* f, const libmerc_config& c)
{
    fprintf(f, "dns_json_output = %s\n", c.dns_json_output ? "true" : "false");
    fprintf(f, "certs_json_output = %s\n", c.certs_json_output ? "true" : "false");
    fprintf(f, "metadata_output = %s\n", c.metadata_output ? "true" : "false");
    fprintf(f, "do_analysis = %s\n", c.do_analysis ? "true" : "false");
    fprintf(f, "do_stats = %s\n", c.do_stats ? "true" : "false");
    fprintf(f, "report_os = %s\n", c.report_os ? "true" : "false");
    fprintf(f, "output_tcp_initial_data = %s\n", c.output_tcp_initial_data ? "true" : "false");
    fprintf(f, "output_udp_initial_data = %s\n", c.output_udp_initial_data ? "true" : "false");
    fprintf(f, "resources = %s\n", c.resources);
    fprintf(f, "enc_key = %s\n", c.enc_key);
    fprintf(f, "key_type = %d\n", c.key_type);
    fprintf(f, "packet_filter_cfg = %s\n", c.packet_filter_cfg);
    fprintf(f, "fp_proc_threshold = %f\n", c.fp_proc_threshold);
    fprintf(f, "proc_dst_threshold = %f\n", c.proc_dst_threshold);
    fprintf(f, "max_stats_entries = %ld\n", c.max_stats_entries);
}