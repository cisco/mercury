#ifndef CONFIG_GENERATOR_H
#define CONFIG_GENERATOR_H

#include "libmerc.h"
#include <string>
#include <vector>

libmerc_config create_config(std::string config, const char& delim = ';', const char& assignment = '=');

libmerc_config create_config_from_arguments(char** argv, int argc);

bool reconfigure_libmerc_config(libmerc_config& config, std::string line, const char& delim = ';', const char& assignment = '=');

libmerc_config create_config_from_lines(std::vector<std::string> lines, const char& assignment = '=');

bool config_contains_delims(const std::string& config, const char& delim = ';');

void dump_config(FILE* f, const libmerc_config& c);

#endif