// proxy_context.hpp
//

#ifndef PROXY_CONTEXT_HPP
#define PROXY_CONTEXT_HPP

#include "datum.h"
#include "util_obj.h"

struct proxy_ctx {
    enum class proxy_proto : uint8_t {
        http =  0,
        socks4 = 1,
        socks5 = 2,
        none = 3
    };

    static constexpr const char* const proxy_proto_str [] {
        "http",
        "socks4",
        "socks5",
        "none"
    };

    proxy_proto protocol = proxy_proto::none;
    datum domain;
    struct ip_address ip;
    uint16_t port = 0;

    proxy_ctx() : ip{0} {}
};

#endif // PROXY_CONTEXT_HPP