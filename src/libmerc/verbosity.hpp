// verbosity.hpp
//
// Copyright (c) 2023 Cisco Systems, Inc. License at
// https://github.com/cisco/mercury/blob/master/LICENSE

#ifndef VERBOSITY_HPP
#define VERBOSITY_HPP

// enum class verbosity_level defines increasing levels of output that
// can be applied to tls_connection and tls_scanner
//
enum class verbosity_level {
    no_output = 0,
    summary   = 1,
    errors    = 2,
    warnings  = 3,
    notes     = 4,
};

static inline bool operator>=(verbosity_level lhs, verbosity_level rhs) { return static_cast<unsigned>(lhs) >= static_cast<unsigned>(rhs); }

verbosity_level verbosity_from_string(const std::string &s) {
    if (s == "none")     { return verbosity_level::no_output; }
    if (s == "summary")  { return verbosity_level::summary; }
    if (s == "errors")   { return verbosity_level::errors; }
    if (s == "warnings") { return verbosity_level::warnings; }
    if (s == "notes")    { return verbosity_level::notes; }
    fprintf(stderr, "error: unknown verbosity level '%s'\n", s.c_str());
    return verbosity_level::no_output;
}

#endif // VERBOSITY_HPP
