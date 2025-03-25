#ifndef GLOBAL_CONFIG_H
#define GLOBAL_CONFIG_H

#include "libmerc.h"
#include "config_generator.h"
#include <map>
#include <string>
#include <algorithm>
#include <unordered_map> 
#include <sstream>

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

class fingerprint_format {
    static constexpr const char* protocol_delim = ",";
    static constexpr const char* format_delim = "/";

public:
    size_t tls_fingerprint_format;
    size_t quic_fingerprint_format;

    fingerprint_format() :
        tls_fingerprint_format{0},
        quic_fingerprint_format{0} { }

    void set_tls_fingerprint_format(size_t format_version) {
        tls_fingerprint_format = format_version;
    }

    void set_quic_fingerprint_format(size_t format_version) {
        quic_fingerprint_format = format_version;
    }

    bool get_protocol_and_set_fp_format(std::string &format_str) {
        std::string protocol;
        std::string format_version;

        size_t pos = 0;

        pos = format_str.find(fingerprint_format::format_delim);

        if (pos != std::string::npos) {
            protocol = format_str.substr(0, pos);
            format_version = format_str.substr(pos+1);
        } else {
            protocol = format_str;
        }

        if (protocol == "tls") {
            if (format_version == "") {
                tls_fingerprint_format = 0;
            } else if (format_version == "1") {
                tls_fingerprint_format = 1;
            } else if (format_version == "2") {
                tls_fingerprint_format = 2;
            } else {
                printf_err(log_warning, "warning: unknown fingerprint format: %s; using default instead\n", format_str.c_str());
                return false;
            }
        } else if (protocol == "quic") {
            if (format_version == "") {
                quic_fingerprint_format = 0;
            } else if (format_version == "1") {
                quic_fingerprint_format = 1;
            } else {
                printf_err(log_warning, "warning: unknown fingerprint format: %s; using default instead\n", format_str.c_str());
                return false;
            }
        } else {
            printf_err(log_warning, "warning: unknown fingerprint format: %s; using default instead\n", format_str.c_str());
            return false;
        }
        return true;
    }

    bool set_fingerprint_format(const std::string &format_string) {
        if (!format_string.empty()) {
            std::string token;
            size_t start_pos = 0;
            size_t current_pos = 0;
            while ((current_pos = format_string.find(fingerprint_format::protocol_delim, start_pos)) != std::string::npos) {
                token = format_string.substr(start_pos, current_pos);
                token.erase(std::remove_if(token.begin(), token.end(), isspace), token.end());
                start_pos = current_pos + 1;

                if (!get_protocol_and_set_fp_format(token)) {
                    return false;
                }
            }

            if (start_pos < format_string.length()) {
                token = format_string.substr(start_pos);
                if (!get_protocol_and_set_fp_format(token)) {
                    return false;
                }
            }
        }
        return true;
    }
};

struct global_config : public libmerc_config {

private:
    std::string resource_file;

    static constexpr const char *static_selector_string = STATIC_CFG_SELECT;

public:
    // extended configs
    std::string temp_proto_str;
    std::string crypto_assess_policy;
    bool reassembly = false;              /* reassemble protocol segments      */
    bool stats_blocking = false;          /* stats mode: lossless but blocking */
    fingerprint_format fp_format;    // default fingerprint format

    global_config() : libmerc_config(), reassembly{false} {};
    global_config(const libmerc_config& c) : libmerc_config(c), reassembly{false} {
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
            { "ldap",                   false },
            { "ipsec",                  false },
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
            { "tftp",                   false },
            { "tls",                    false },
            { "tls.client_hello",       false },
            { "tls.server_hello",       false },
            { "tls.server_certificate", false},
            { "wireguard",              false },
            { "openvpn_tcp",            false },
            { "mysql",                  false },
            { "tofsee",                 false },
            { "socks",                  false },
            { "ftp",                    false},
            { "ftp.response",           false},
            { "ftp.request",            false}
        };

    std::unordered_map<std::string, bool> raw_features {
            { "all",                    false },
            { "none",                   false },
            { "bittorrent",             false },
            { "smb",                    false },
            { "ssdp",                   false },
            { "stun",                   false },
            { "tls",                    false },
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

    bool set_raw_features (const std::string& protocols) {
        std::string s = protocols.empty() ? "none" : protocols ;
        std::istringstream raw_features_selector(s);
        std::string token;
        char delim = ',';

        while (std::getline(raw_features_selector, token, delim)) {
            token.erase(std::remove_if(token.begin(), token.end(), isspace), token.end());
            auto pair = raw_features.find(token);
            if (pair != raw_features.end()) {
                pair->second = true;
            } else {
                printf_err(log_err, "unrecognized filter command \"%s\"\n", token.c_str());
                return false;
            }
        }
        return true;
    }

    bool set_crypto_assess (const std::string& policy) {
        crypto_assess_policy = policy; // policy.empty() ? "default" : policy ;
        return true;
    }

};

static void setup_extended_fields(global_config* lc, const std::string& config) {

    std::vector<libmerc_option> options = {
        {"select", "-s", "--select", SETTER_FUNCTION(&lc){ lc->set_protocols(s); }},
        {"resources", "", "", SETTER_FUNCTION(&lc){ lc->set_resource_file(s); }},
        {"format", "", "", SETTER_FUNCTION(&lc){ lc->fp_format.set_fingerprint_format(s); }},
        {"tcp-reassembly", "", "", SETTER_FUNCTION(&lc){ lc->reassembly = true; }},
        {"reassembly", "", "", SETTER_FUNCTION(&lc){ lc->reassembly = true; }},
        {"stats-blocking", "", "", SETTER_FUNCTION(&lc){ lc->stats_blocking = true; }},
        {"raw-features", "", "", SETTER_FUNCTION(&lc){ lc->set_raw_features(s); }},
        {"crypto-assess", "", "", SETTER_FUNCTION(&lc){ lc->set_crypto_assess(s); }},
    };

    parse_additional_options(options, config, *lc);
}

#endif
