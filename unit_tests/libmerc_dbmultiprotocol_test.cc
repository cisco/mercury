#include "libmerc_fixture.h"
#include <iostream>

int sig_close_flag = false;


TEST_CASE_METHOD(LibmercTestFixture, "test http with recources-mp")
{
    auto destination_check_callback = [](const analysis_context *ac)
    {
        CHECK(analysis_context_get_fingerprint_type(ac) == 3);
    }; 
    
    auto http_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter(fingerprint_type_http,destination_check_callback));

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{{.do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"http"}},
                     "capture2.pcap"},
         397},
        {test_config{{.resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"http"}},
                     "capture2.pcap"},
         0},
        {test_config{{.do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"http"}},
                     "http_request.capture2.pcap"},
         397},
        {test_config{{.resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"http"}},
                     "multi_packet_http_request.pcap"},
         0},
         {test_config{{.do_analysis{true},
                       .resources{resources_mp_path},
                       .packet_filter_cfg{(char *)"http"}},
                     "multi_packet_http_request.pcap"},
         1}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        http_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test quic with recources-mp")
{
    
    auto quic_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{{.do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"quic"}},
                     "capture2.pcap"},
         2},
        {test_config{{.do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"quic"}},
                     "quic-crypto-packets.pcap"},
         0 /*684 - corret answear*/},
        {test_config{{.do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"quic"}},
                     "http_request.capture2.pcap"},
         0},
         {test_config{{.resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"quic"}},
                     "quic_init.capture2.pcap"},
         2},
         {test_config{{.resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"quic"}},
                     "mdns_capture.pcap"},
         0}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        quic_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test smtp with recources-mp")
{
    
    auto smtp_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{{.do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"smtp"}},
                     "capture2.pcap"},
         0},
        {test_config{{.dns_json_output{true},
                      .do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"smtp"}},
                     "capture2.pcap"},
         0},
        {test_config{{.do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"smtp"}},
                     "top_100_fingerprints.pcap"},
         0}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        smtp_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test dns and mdns with recources-mp")
{
    auto dns_output_check = [&]() {
        bool dns_output_provided = strstr(m_output, "base64") ? false : true;
        /* to not provide thousands of CHECKs, do one only in case of failure */
        if(!(m_mpp->global_vars.dns_json_output ? dns_output_provided : !dns_output_provided))
            CHECK(false);
    };

    auto dns_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter(fingerprint_type::fingerprint_type_unknown, dns_output_check));

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{{.do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"dns"}},
                     "capture2.pcap"},
         22568},
        {test_config{{.dns_json_output{true},
                      .do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"dns"}},
                     "capture2.pcap"},
         22568},
        {test_config{{.do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"dns"}},
                     "mdns_capture.pcap"},
         3141},
        {test_config{{.do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"dns"}},
                     "dns_packet.capture2.pcap"},
         22568},
        {test_config{{.do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"dns"}},
                     "top_100_fingerprints.pcap"},
         0}
        };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        dns_check(count, config.m_lc);
    }
}
