#include "libmerc_fixture.h"

int sig_close_flag = false;

TEST_CASE_METHOD(LibmercTestFixture, "proccesing null packet")
{
    initialize();
   // check_global_configuraton();
    mercury_packet_processor_get_analysis_context(m_mpp, nullptr, 0, &m_time);
    CHECK_FALSE(m_mpp->analysis.result.is_valid());
    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test tcp filtering")
{
    
    auto tcp_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{{.do_analysis{true},
                      .resources{default_resources_path},
                      .packet_filter_cfg{(char *)"tcp"}},
                     "capture2.pcap"},
         12618}, 
        {test_config{{.packet_filter_cfg{(char *)"tcp"}},
                     "capture2.pcap"},
         12618},
        {test_config{{.do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"tcp"}},
                     "bad_tcp.pcap"},
         0},
        {test_config{{.resources{default_resources_path},
                      .packet_filter_cfg{(char *)"tcp"}},
                     "bad_tcp.pcap"},
         0}};

    // TODO: add for tcp_only.pcap 

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        tcp_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test tls filtering")
{
    auto tls_check = [&](int expected_count, const struct libmerc_config &config, fingerprint_type fp_t, std::function<void(const analysis_context *)> callback, fingerprint_type fp_t2 = fingerprint_type_unknown)
    {
        initialize(config);

        if (fp_t2 != fingerprint_type_unknown)
            CHECK(expected_count == counter(fp_t, fp_t2));
        else
            CHECK(expected_count == counter(fp_t, callback));

        deinitialize();
    };

    auto destination_check_callback = [](const analysis_context *ac)
    {
        CHECK(analysis_context_get_fingerprint_type(ac) == 1);
        CHECK(strcmp(ac->destination.dst_ip_str, "13.89.178.27") == 0);
        CHECK(ac->destination.dst_port == htons(443));
        CHECK(ac->result.is_valid());
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{{.do_analysis{true},
                      .resources{default_resources_path},
                      .packet_filter_cfg{(char *)"tls.client_hello"}},
                     "tls_client_hello_test_packet.pcap",
                     fingerprint_type_tls,
                     destination_check_callback},
         1},
        {test_config{{.do_analysis{true},
                      .packet_filter_cfg{(char *)"tls.client_hello"}},
                     "capture2.pcap",
                     fingerprint_type_tls},
         4301},
        {test_config{{.do_analysis{true},
                      .resources{default_resources_path},
                      .packet_filter_cfg{(char *)"tls"}},
                     "capture2.pcap",
                     fingerprint_type_tls},
         10829}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        if (strcmp(config.m_lc.packet_filter_cfg, "tls") == 0)
        {
            tls_check(count, config.m_lc, config.fp_t, config.callback, fingerprint_type_tls_server /*additional fp to check*/);
        }
        else
        {
            tls_check(count, config.m_lc, config.fp_t, config.callback);
        }
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test http filtering")
{
    auto http_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter(fingerprint_type_http));

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{{.do_analysis{true},
                      .resources{default_resources_path},
                      .packet_filter_cfg{(char *)"http"}},
                     "capture2.pcap"},
         397},
        {test_config{{.resources{default_resources_path},
                      .packet_filter_cfg{(char *)"http"}},
                     "capture2.pcap"},
         397},
        {test_config{{.do_analysis{true},
                      .resources{default_resources_path},
                      .packet_filter_cfg{(char *)"http"}},
                     "http_request.capture2.pcap"},
         397},
        {test_config{{.resources{default_resources_path},
                      .packet_filter_cfg{(char *)"http"}},
                     "multi_packet_http_request.pcap"},
         1},
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

TEST_CASE_METHOD(LibmercTestFixture, "test quic filtering")
{
    
    auto http_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{{.do_analysis{true},
                      .resources{default_resources_path},
                      .packet_filter_cfg{(char *)"quic"}},
                     "capture2.pcap"},
         2},
        {test_config{{.do_analysis{true},
                      .resources{default_resources_path},
                      .packet_filter_cfg{(char *)"quic"}},
                     "quic-crypto-packets.pcap"},
         684},
        {test_config{{.do_analysis{true},
                      .resources{default_resources_path},
                      .packet_filter_cfg{(char *)"quic"}},
                     "http_request.capture2.pcap"},
         0},
         {test_config{{.resources{default_resources_path},
                      .packet_filter_cfg{(char *)"quic"}},
                     "quic_init.capture2.pcap"},
         2},
         {test_config{{.resources{default_resources_path},
                      .packet_filter_cfg{(char *)"quic"}},
                     "mdns_capture.pcap"},
         0}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        http_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test dhcp filtering")
{
    auto dhcp_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{{.do_analysis{true},
                      .resources{default_resources_path},
                      .packet_filter_cfg{(char *)"dhcp"}},
                     "capture2.pcap"},//43000+
         123},
        {test_config{{.packet_filter_cfg{(char *)"dhcp"}},
                     "capture2.pcap"},
         123},
        {test_config{{.do_analysis{true},
                      .resources{resources_mp_path},
                      .packet_filter_cfg{(char *)"dhcp"}},
                     "mdns_capture.pcap"},
         0}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        dhcp_check(count, config.m_lc);
    }
}
