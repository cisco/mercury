#include "libmerc_fixture.h"

int sig_close_flag = false;


TEST_CASE_METHOD(LibmercMultiprotocolTestFixture, "test http with recources-mp")
{
       auto destination_check_callback = [](const analysis_context *ac)
    {
       // CHECK(ac->fp.type == 3);
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
                      .packet_filter_cfg{"http"}},
                     "capture2.pcap"},
         397},
        {test_config{{.do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{"http"}},
                     "capture2.pcap"},
         397},
        {test_config{{.do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{"http"}},
                     "http_request.capture2.pcap"},
         397},
        {test_config{{.resources{resources_mp_path},
                      .packet_filter_cfg{"http"}},
                     "multi_packet_http_request.pcap"},
         1},
         {test_config{{.resources{resources_mp_path},
                      .packet_filter_cfg{"http"}},
                     "multi_packet_http_request.pcap"},
         1}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        http_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercMultiprotocolTestFixture, "test quic with recources-mp")
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
                      .packet_filter_cfg{"quic"}},
                     "capture2.pcap"},
         3},
        {test_config{{.do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{"quic"}},
                     "quic-crypto-packets.pcap"},
         684},
        {test_config{{.do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{"quic"}},
                     "http_request.capture2.pcap"},
         0},
         {test_config{{.resources{resources_mp_path},
                      .packet_filter_cfg{"quic"}},
                     "quic_init.capture2.pcap"},
         1},
         {test_config{{.resources{resources_mp_path},
                      .packet_filter_cfg{"quic"}},
                     "mdns_capture.pcap"},
         0}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        quic_check(count, config.m_lc);
    }
}