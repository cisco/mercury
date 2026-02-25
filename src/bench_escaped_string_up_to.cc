/*
 * bench_escaped_string_up_to.cc
 *
 * Copyright (c) 2026 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>

#include "libmerc/bench.h"
#include "libmerc/lex.h"

namespace {

volatile size_t sink = 0;

static std::vector<uint8_t> make_telnet_buffer(size_t size, bool include_delim) {
    std::vector<uint8_t> buf;
    buf.reserve(size + 4);
    for (size_t i = 0; i < size; ++i) {
        buf.push_back('a');
        if (i % 31 == 0) {
            buf.push_back(0xff);
            buf.push_back(0xff); // escaped IAC
        }
    }
    if (include_delim) {
        buf.push_back(0xff); // delimiter IAC
    }
    return buf;
}

static std::vector<uint8_t> make_escaped_buffer(size_t size, bool include_delim) {
    std::vector<uint8_t> buf;
    buf.reserve(size + 4);
    for (size_t i = 0; i < size; ++i) {
        buf.push_back('b');
        if (i % 23 == 0) {
            buf.push_back('\\');
            buf.push_back('"');
        }
    }
    if (include_delim) {
        buf.push_back('"');
    }
    return buf;
}

template <uint8_t delim, uint8_t escape>
static void run_case(const char *label, const std::vector<uint8_t> &buf, size_t iterations) {
    benchmark::mean_and_standard_deviation s;
    for (size_t i = 0; i < iterations; ++i) {
        datum d{buf.data(), buf.data() + buf.size()};
        tsc_clock cc;
        escaped_string_up_to<delim, escape> parsed{d};
        s += cc.elapsed_tick();
        sink += parsed.length();
        sink += d.length();
    }
    if (benchmark::is_valid) {
        std::printf("%s: mean cycles %f\n", label, s.mean());
    } else {
        std::printf("%s: tsc_clock not valid\n", label);
    }
}

} // namespace

int main(int argc, char **argv) {
    size_t iterations = 100000;
    if (argc > 1) {
        iterations = static_cast<size_t>(std::strtoull(argv[1], nullptr, 10));
        if (iterations == 0) {
            iterations = 100000;
        }
    }

    const size_t size = 4096;
    auto telnet_with_delim = make_telnet_buffer(size, true);
    auto telnet_no_delim = make_telnet_buffer(size, false);
    auto escaped_with_delim = make_escaped_buffer(size, true);
    auto escaped_no_delim = make_escaped_buffer(size, false);

    run_case<0xff, 0xff>("telnet_with_delim", telnet_with_delim, iterations);
    run_case<0xff, 0xff>("telnet_no_delim", telnet_no_delim, iterations);
    run_case<'\"', '\\'>("escaped_with_delim", escaped_with_delim, iterations);
    run_case<'\"', '\\'>("escaped_no_delim", escaped_no_delim, iterations);

    return sink == 0 ? 0 : 0;
}
