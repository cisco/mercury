#ifndef GLOBAL_CONFIG_H
#define GLOBAL_CONFIG_H

#include "libmerc.h"
#include "config_generator.h"
#include <map>  
#include <string>
#include <algorithm>

// the preprocessor directive STATIC_CFG_SELECT can be used as a
// compile-time option to select the default protocols that mercury
// will process, if an empty select string is provided to the
// global_config constructor.
//
// The STATIC_CFG_SELECT define must hold either nullptr or a quoted
// string that contains one of mercury's selector strings, and it can
// be passed to the compiler using the -D flag.  For example,
//
//    make OPTFLAGS=-DSTATIC_CFG_SELECT='\"tls.client_hello\"'
//
// will ensure that only tls client hello messages are selected, and
// all other packet types are ignored
//
#ifndef STATIC_CFG_SELECT
#define STATIC_CFG_SELECT nullptr
#endif

struct global_config;
static void setup_extended_fields(global_config* lc, const std::string& config);

struct global_config : public libmerc_config {

private:
    std::string resource_file;

    static constexpr const char *static_selector_string = STATIC_CFG_SELECT;

public:
    // extended configs
    std::string temp_proto_str;
    bool tcp_reassembly = false;          /* reassemble tcp segments      */
    size_t tls_fingerprint_format = 0;    // default fingerprint format

    void set_tls_fingerprint_format(size_t format) { tls_fingerprint_format = format; }

    global_config() : libmerc_config(), tcp_reassembly{false} {};
    global_config(const libmerc_config& c) : libmerc_config(c), tcp_reassembly{false} {
        if (c.resources) {
           resource_file = c.resources;
        }

        if (c.packet_filter_cfg && config_contains_delims(c.packet_filter_cfg)) {
            setup_extended_fields(this, std::string(c.packet_filter_cfg));
        } else {
            set_protocols(c.packet_filter_cfg ? c.packet_filter_cfg : "");
        }
    }

    const char* get_resource_file() {
        return resource_file.empty() ? resources : resource_file.c_str();
    }

    void set_resource_file(const std::string& res) {
        resource_file = res;
    }

    std::map<std::string, bool> protocols {
            { "all",                    false },
            { "none",                   false },
            { "arp",                    false },
            { "bittorrent",             false },
            { "cdp",                    false },
            { "dhcp",                   false },
            { "dnp3",                   false },
            { "dns",                    false },
            { "dtls",                   false },
            { "gre",                    false },
            { "http",                   false },
            { "http.request",           false },
            { "http.response",          false },
            { "icmp",                   false },
            { "iec",                    false },
            { "lldp",                   false },
            { "mdns",                   false },
            { "nbns",                   false },
            { "nbds",                   false },
            { "nbss",                   false },
            { "ospf",                   false },
            { "quic",                   false },
            { "sctp",                   false },
            { "smb",                    false },
            { "smtp",                   false },
            { "ssdp",                   false },
            { "ssh",                    false },
            { "stun",                   false },
            { "tcp",                    false },
            { "tcp.message",            false },
            { "tcp.syn_ack",            false },
            { "tls",                    false },
            { "tls.client_hello",       false },
            { "tls.server_hello",       false },
            { "tls.server_certificate", false},
            { "wireguard",              false },
            { "openvpn_tcp",            false },
            { "mysql",                  false },
        };

    bool set_protocols(const std::string& data) {

        std::string s = data.empty() ? (static_selector_string ? static_selector_string : "all") : data ;
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

    bool set_fingerprint_format(const std::string &s) {
        if (s == "tls") {
            tls_fingerprint_format = 0;
        } else if (s == "tls/1") {
            tls_fingerprint_format = 1;
        } else {
            printf_err(log_warning, "warning: unknown fingerprint format: %s; using default instead\n", s.c_str());
            return false;
        }
        return true;
    }
};

static void setup_extended_fields(global_config* lc, const std::string& config) {

    std::vector<libmerc_option> options = {
        {"select", "-s", "--select", SETTER_FUNCTION(&lc){ lc->set_protocols(s); }},
        {"resources", "", "", SETTER_FUNCTION(&lc){ lc->set_resource_file(s); }},
        {"format", "", "", SETTER_FUNCTION(&lc){ lc->set_fingerprint_format(s); }},
        {"tcp-reassembly", "", "", SETTER_FUNCTION(&lc){ lc->tcp_reassembly = true; }}
    };

    parse_additional_options(options, config, *lc);
}

#endif
