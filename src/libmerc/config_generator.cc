#include <map>
#include <functional>
#include <algorithm> 
#include <numeric>

#include "config_generator.h"
#include "../options.h"

#define SETTER_FUNCTION []([[maybe_unused]] const std::string& s, libmerc_config& c)

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

class libmerc_option
{
private:
    std::string _opt_name;
    std::string _opt_short_name;
    std::string _opt_long_name;
    std::function<void(const std::string&, libmerc_config&)> _setter;

public:

    libmerc_option(const std::string& opt_name, const std::string& opt_short_name, const std::string& opt_long_name, std::function<void(const std::string&, libmerc_config&)> setter) :
    _opt_name(opt_name), _opt_short_name(opt_short_name), _opt_long_name(opt_long_name), _setter(setter)
    {

    }

    bool perform_option_check(const std::string& input)
    {
        return input.compare(_opt_name) == 0 || input.compare(_opt_short_name) == 0 || input.compare(_opt_long_name) == 0;
    }

    void perform_setter(const std::string& value, libmerc_config& config)
    {
        _setter(value, config);
    }

    const std::string& get_option_name()
    {
        return _opt_name;
    }

    const std::string& get_long_option_name()
    {
        return _opt_long_name;
    }

    const std::string& get_short_option_name()
    {
        return _opt_short_name;
    }
};

static std::vector<libmerc_option> config_mapper = {
    {"analysis", "-a", "--analysis", SETTER_FUNCTION { c.do_analysis = true; }},
    {"resources", "", "",            SETTER_FUNCTION { c.resources = strdup(s.c_str()); }},
    {"select", "-s", "--select",     SETTER_FUNCTION{ c.packet_filter_cfg = strdup(s.c_str()); }},
    {"dns-json", "", "",             SETTER_FUNCTION{ c.dns_json_output = true; }},
    {"certs-json", "", "",           SETTER_FUNCTION{c.certs_json_output = true; }},
    {"metadata", "", "",             SETTER_FUNCTION{c.metadata_output = true; }},
    {"stats", "", "",                SETTER_FUNCTION{c.do_stats = true; }},
    {"report_os", "", "",            SETTER_FUNCTION{c.report_os = true; }},
    {"nonselected-tcp-data", "", "", SETTER_FUNCTION{c.output_tcp_initial_data = true; }},
    {"nonselected-udp-data", "", "", SETTER_FUNCTION{c.output_udp_initial_data = true; }},
    {"enc_key", "", "",              SETTER_FUNCTION{c.enc_key = (uint8_t*)strdup(s.c_str()); }},
    {"key_type", "", "",             SETTER_FUNCTION{c.key_type = (enc_key_type)atoi(s.c_str()); }},
    {"fp_proc_threshold", "", "",    SETTER_FUNCTION{c.fp_proc_threshold = std::stof(s); }},
    {"proc_dst_threshold", "", "",   SETTER_FUNCTION{c.proc_dst_threshold = std::stof(s); }},
    {"max_stats_entries", "", "",    SETTER_FUNCTION{c.max_stats_entries = std::stoull(s); }}
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

    for(const auto& token : tokens)
    {
        for(libmerc_option op : config_mapper)
        {
            if(op.perform_option_check(token.key_))
                op.perform_setter(token.value_, result);
        }
    }

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

bool reconfigure_libmerc_config(libmerc_config& config, std::string line, const char& assignment)
{
    auto token = config_token::parse(line, assignment);
    for(libmerc_option op : config_mapper)
        {
            if(op.perform_option_check(token.key_))
            {
                op.perform_setter(token.value_, config);
                return true;
            }
        }
    return false;
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