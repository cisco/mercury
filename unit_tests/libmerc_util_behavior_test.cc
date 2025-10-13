#include "catch.hpp"
#include "libmerc_driver_helper.hpp"

#include <fstream>
#include <string>
#include <cstdlib>
#include <sstream>
#include <filesystem>
#include <unordered_map>
#include "libmerc/rapidjson/document.h"
#include "libmerc/rapidjson/error/en.h"

// Helper function to count protocol occurrences in L7 JSON output
struct protocol_counts {
    std::unordered_map<std::string, int> protocol_map;
    int total_lines = 0;

    // Helper methods for backward compatibility
    int get_count(const std::string& protocol) const {
        auto it = protocol_map.find(protocol);
        return (it != protocol_map.end()) ? it->second : 0;
    }
};

protocol_counts count_protocols_in_l7_output(const std::string& l7_output_file) {
    protocol_counts counts;
    std::ifstream file(l7_output_file);
    std::string line;

    while (std::getline(file, line)) {
        if (line.empty()) continue;
        counts.total_lines++;

        rapidjson::Document doc;
        doc.Parse(line.c_str());

        if (!doc.HasParseError() && doc.IsObject()) {
            // Check if protocols array exists
            if (doc.HasMember("protocols") && doc["protocols"].IsArray()) {
                const rapidjson::Value& protocols = doc["protocols"];

                // Iterate through protocols array
                for (rapidjson::SizeType i = 0; i < protocols.Size(); i++) {
                    if (protocols[i].IsString()) {
                        std::string protocol_name = protocols[i].GetString();
                        counts.protocol_map[protocol_name]++;
                    }
                }
            }
        }
    }

    return counts;
}

// Helper function to test a specific PCAP file
void test_pcap_file(const std::string& pcap_filename, int expected_total_lines,
                   const std::unordered_map<std::string, int>& expected_protocols = {}) {
    const std::string libmerc_util_path = "../src/libmerc_util";
    const std::string libmerc_so_path = "./debug-libs/libmerc_multiprotocol.so";
    const std::string pcap_file = "pcaps/" + pcap_filename;
    const std::string resources_file = "xtra/resources/resources-mp.tgz";
    const std::string l7_output_file = "test_l7_output_" + pcap_filename + ".json";

    // Check prerequisites
    REQUIRE(std::filesystem::exists(libmerc_util_path));
    REQUIRE(std::filesystem::exists(libmerc_so_path));
    REQUIRE(std::filesystem::exists(pcap_file));

    // Build and execute command
    std::stringstream cmd;
    cmd << libmerc_util_path
        << " --libmerc " << libmerc_so_path
        << " --read " << pcap_file
        << " --resources " << resources_file
        << " --fdc"
        << " --l7-output " << l7_output_file;

    INFO("Testing PCAP: " << pcap_filename);
    int result = std::system(cmd.str().c_str());
    REQUIRE(result == 0);

    // Analyze results
    if (std::filesystem::exists(l7_output_file)) {
        protocol_counts counts = count_protocols_in_l7_output(l7_output_file);

        INFO("Results for " << pcap_filename << ":");
        INFO("  Total L7 JSON lines: " << counts.total_lines);

        // Log all detected protocols
        for (const auto& [protocol, count] : counts.protocol_map) {
            INFO("  " << protocol << ": " << count << " records");
        }

        REQUIRE(counts.total_lines == expected_total_lines);

        // Check expected protocol counts if specified
        for (const auto& [protocol, expected_count] : expected_protocols) {
            REQUIRE(counts.get_count(protocol) == expected_count);
        }

        // Cleanup
        std::filesystem::remove(l7_output_file);
    } else {
        INFO("No L7 output generated for " << pcap_filename);
    }
}

// Test case for emix.pcap (merged traffic) with expected protocol counts
TEST_CASE("emix.pcap") {
    std::unordered_map<std::string, int> expected_protocols = {
        {"bittorrent", 2},
        {"bittorrent_dht", 5},
        {"bittorrent_lsd", 9},
        {"dhcp", 11},
        {"dnp3", 15},
        {"dns", 240},
        {"esp", 6},
        {"ftp", 58},
        {"http", 10},
        {"iec60870_5_104", 42},
        {"ike", 30},
        {"ldap", 25},
        {"mdns", 6},
        {"mysql", 4},
        {"nbds", 43},
        {"nbns", 160},
        {"nbss", 2},
        {"openvpn", 16},
        {"smb1", 150},
        {"smb2", 412},
        {"socks4", 1},
        {"socks5", 4},
        {"socks5_req_resp", 5},
        {"ssdp", 34},
        {"ssh", 2},
        {"stun", 4},
        {"tacacs", 12},
        {"tftp", 17},
        {"vnc", 2},
        {"tls", 5},
        {"quic", 4}
    };

    test_pcap_file("emix.pcap", 1336, expected_protocols);
}
