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
    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path, .packet_filter_cfg = (char *)"tcp"},
             .m_pc{"capture2.pcap"}},
         155},
        {test_config{
             .m_lc{.resources = resources_minimal_path, .packet_filter_cfg = (char *)"tcp"},
             .m_pc{"capture2.pcap"}},
         155},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path, .packet_filter_cfg = (char *)"tcp"},
             .m_pc{"bad_tcp.pcap"}},
         0},
        {test_config{
             .m_lc{.resources = resources_minimal_path, .packet_filter_cfg = (char *)"tcp"},
             .m_pc{"bad_tcp.pcap"}},
         0}};

    // TODO: add for tcp_only.pcap

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        run_count_test(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test tls filtering")
{
    auto destination_check_callback = [](const analysis_context *ac)
    {
        CHECK(analysis_context_get_fingerprint_type(ac) == 1);
        CHECK(strcmp(ac->destination.dst_ip_str, "13.89.178.27") == 0);
        CHECK(ac->destination.dst_port == hton<uint16_t>(443));
        CHECK(ac->result.is_valid());
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"tls.client_hello"},
             .m_pc{"tls_client_hello_test_packet.pcap"},
             .fp_t = fingerprint_type_tls,
             .callback{destination_check_callback}},
         1},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"tls.client_hello"},
             .m_pc{"capture2.pcap"},
             .fp_t = fingerprint_type_tls},
         17},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"tls"},
             .m_pc{"capture2.pcap"},
             .fp_t = fingerprint_type_tls},
         60}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        if (strcmp(config.m_lc.packet_filter_cfg, "tls") == 0)
        {
            run_count_test(count, config.m_lc, config.fp_t, fingerprint_type_tls_server /*additional fp to check*/);
        }
        else
        {
            run_count_test(count, config.m_lc, config.fp_t, config.callback);
        }
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test http filtering")
{
    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"http"},
             .m_pc{"capture2.pcap"}},
         127},
        {test_config{
             .m_lc{.resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"http"},
             .m_pc{"capture2.pcap"}},
         127},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"http"},
             .m_pc{"http_request.capture2.pcap"}},
         109},
        {test_config{
             .m_lc{.resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"http"},
             .m_pc{"multi_packet_http_request.pcap"}},
         1},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"http"},
             .m_pc{"multi_packet_http_request.pcap"}},
         1}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        run_count_test(count, config.m_lc, fingerprint_type_http);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test quic filtering")
{
    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"capture2.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"quic-crypto-packets.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"http_request.capture2.pcap"}},
         0},
        {test_config{
             .m_lc{.resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"quic_init.capture2.pcap"}},
         0},
        {test_config{
             .m_lc{.resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"mdns_capture.pcap"}},
         0}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        run_count_test(count, config.m_lc, fingerprint_type_quic);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test dhcp filtering")
{
    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"dhcp"},
             .m_pc{"capture2.pcap"}},//43000+
         279
        },
         {test_config{
             .m_lc{.resources = resources_minimal_path, .packet_filter_cfg = (char *)"dhcp"},
             .m_pc{"capture2.pcap"}},
         279
         },
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"dhcp"},
             .m_pc{"mdns_capture.pcap"}},
         0
        }
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        run_count_test(count, config.m_lc);
    }
}
