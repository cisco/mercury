#ifndef GLOBAL_CONFIG_H
#define GLOBAL_CONFIG_H

#include "libmerc.h"
#include "config_generator.h"
#include <map>  
#include <string>
#include <algorithm>

struct global_config : public libmerc_config
{
    global_config() : libmerc_config() {};
    global_config(const libmerc_config& c) : libmerc_config(c) {}

    std::map<std::string, bool> protocols{
            { "all",         false },
            { "none",        false },
            { "dhcp",        false },
            { "dns",         false },
            { "dtls",        false },
            { "http",        false },
            { "ssh",         false },
            { "tcp",         false },
            { "tcp.message", false },
            { "tls",         false },
            { "wireguard",   false },
            { "quic",        false },
            { "smtp",        false },
            { "tls.client_hello", false},
            { "tls.server_hello", false},
            { "http.request", false},
            { "http.response", false},
        };

    bool set_protocols(const std::string& data)
    {
        std::string s = data.empty() ? "all" : data;
        std::string delim{","};
        size_t pos = 0;
        std::string token;
        while ((pos = s.find(delim)) != std::string::npos) {
            token = s.substr(0, pos);
            token.erase(std::remove_if(token.begin(), token.end(), isspace), token.end());
            s.erase(0, pos + delim.length());

            auto pair = protocols.find(token);
            if (pair != protocols.end()) {
                pair->second = true;
            } else {
                printf_err(log_err, "unrecognized filter command \"%s\"\n", token.c_str());
                return false;
            }
        }
        token = s.substr(0, pos);
        s.erase(std::remove_if(s.begin(), s.end(), isspace), s.end());
        auto pair = protocols.find(token);
        if (pair != protocols.end()) {
            pair->second = true;
        } else {
            printf_err(log_err, "unrecognized filter command \"%s\"\n", token.c_str());
            return false;
        }
        return true;
    }
    
};

#endif