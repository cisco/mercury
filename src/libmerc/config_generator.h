#ifndef CONFIG_GENERATOR_H
#define CONFIG_GENERATOR_H

#include "libmerc.h"
#include <string>
#include <vector>
#include <functional>

#define SETTER_FUNCTION(context) [context]([[maybe_unused]] const std::string& s, [[maybe_unused]] libmerc_config& c)

#define DEFAULT_DELIM ';'
#define DEFAULT_ASSIGN '='

class libmerc_option {

private:
    std::string _opt_name;
    std::string _opt_short_name;
    std::string _opt_long_name;
    std::function<void(const std::string&, libmerc_config&)> _setter;

public:

    libmerc_option(const std::string& opt_name, const std::string& opt_short_name, const std::string& opt_long_name, std::function<void(const std::string&, libmerc_config&)> setter) :
        _opt_name(opt_name), _opt_short_name(opt_short_name), _opt_long_name(opt_long_name), _setter(setter) {

    }

    bool perform_option_check(const std::string& input) {
        return input.compare(_opt_name) == 0 || input.compare(_opt_short_name) == 0 || input.compare(_opt_long_name) == 0;
    }

    void perform_setter(const std::string& value, libmerc_config& config) {
        _setter(value, config);
    }

    const std::string& get_option_name() {
        return _opt_name;
    }

    const std::string& get_long_option_name() {
        return _opt_long_name;
    }

    const std::string& get_short_option_name() {
        return _opt_short_name;
    }
};

std::string create_config_from_arguments(char** argv, int& argc);

bool config_contains_delims(const std::string& config, const char& delim = DEFAULT_DELIM);

void parse_additional_options(std::vector<libmerc_option> options, std::string config, libmerc_config& lc, const char& delim = DEFAULT_DELIM, const char& assignment = DEFAULT_ASSIGN);

#endif
