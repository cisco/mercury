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
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"http"},
             .m_pc{"capture2.pcap"}},
         127},
        {test_config{
             .m_lc{.resources = resources_mp_path,
                .packet_filter_cfg = (char *)"http"},
             .m_pc{"capture2.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"http"},
             .m_pc{"http_request.capture2.pcap"}},
         109},
        {test_config{
             .m_lc{.resources = resources_mp_path,
                .packet_filter_cfg = (char *)"http"},
             .m_pc{"multi_packet_http_request.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"http"},
             .m_pc{"multi_packet_http_request.pcap"}},
         1}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        http_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test http with recources-mp and linktype raw")
{
    auto destination_check_callback = [](const analysis_context *ac)
    {
        CHECK(analysis_context_get_fingerprint_type(ac) == 3);
    }; 
    
    auto http_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter(fingerprint_type_http,destination_check_callback, LINKTYPE_RAW));

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"http"},
             .m_pc{"http_rawip.pcap"}},
         9}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        http_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test quic with recources-mp")
{
    
    auto destination_check_callback = [](const analysis_context *ac)
    {
        CHECK(analysis_context_get_fingerprint_type(ac) == 12);
    };

    auto quic_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter(fingerprint_type_quic,destination_check_callback));

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"capture2.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"quic-crypto-packets.pcap"}},
         670},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"http_request.capture2.pcap"}},
         0},
        {test_config{
             .m_lc{.resources = resources_mp_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"quic_init.capture2.pcap"}},
        0},
        {test_config{
             .m_lc{.resources = resources_mp_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"mdns_capture.pcap"}},
        0}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        quic_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test quic with recources-mp and eth linktype")
{
    
    auto destination_check_callback = [](const analysis_context *ac)
    {
        CHECK(analysis_context_get_fingerprint_type(ac) == 12);
    };

    auto quic_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter(fingerprint_type_quic,destination_check_callback, LINKTYPE_ETHERNET));

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"quic-crypto-packets.pcap"}},
         670}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        quic_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test quic with recources-mp and ppp linktype")
{
    
    auto destination_check_callback = [](const analysis_context *ac)
    {
        CHECK(analysis_context_get_fingerprint_type(ac) == 12);
    };

    auto quic_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter(fingerprint_type_quic,destination_check_callback, LINKTYPE_PPP));

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"quic-crypto-packets.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"quic_ppp.pcap"}},
         1} 
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
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"smtp"},
             .m_pc{"capture2.pcap"}},
         1},
        {test_config{
             .m_lc{.dns_json_output = true, .do_analysis = true,
                .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"smtp"},
             .m_pc{"capture2.pcap"}},
         1},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"smtp"},
             .m_pc{"top_100_fingerprints.pcap"}},
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
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"dns"},
             .m_pc{"capture2.pcap"}},
         785},
        {test_config{
             .m_lc{.dns_json_output = true, .do_analysis = true,
                .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"dns"},
             .m_pc{"capture2.pcap"}},
         785},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"mdns"},
             .m_pc{"mdns_capture.pcap"}},
         3141},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"dns"},
             .m_pc{"dns_packet.capture2.pcap"}},
         785},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"dns"},
             .m_pc{"top_100_fingerprints.pcap"}},
         0}
        };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        dns_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test smb with recources-mp")
{

    auto smb_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"smb"},
             .m_pc{"smb.pcap"}},
         391},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"smb"},
             .m_pc{"top_100_fingerprints.pcap"}},
         0}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        smb_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test iec with recources-mp")
{

    auto iec_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"iec"},
             .m_pc{"iec.pcap"}},
         42},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"iec"},
             .m_pc{"top_100_fingerprints.pcap"}},
         0}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        iec_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test dnp3 with recources-mp")
{

    auto dnp3_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"dnp3"},
             .m_pc{"dnp3.pcap"}},
         15},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"dnp3"},
             .m_pc{"top_100_fingerprints.pcap"}},
         0}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        dnp3_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test nbss with recources-mp")
{

    auto nbss_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"nbss"},
             .m_pc{"top_100_fingerprints.pcap"}},
         0}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        nbss_check(count, config.m_lc);
    }
}

