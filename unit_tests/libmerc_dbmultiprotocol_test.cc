#include "libmerc_fixture.h"
#include <iostream>

int sig_close_flag = false;


TEST_CASE_METHOD(LibmercTestFixture, "test http with resources-mp")
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

TEST_CASE_METHOD(LibmercTestFixture, "test http with resources-mp and linktype raw")
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

TEST_CASE_METHOD(LibmercTestFixture, "test quic with resources-mp")
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
        0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"quic_v2.pcap"}},
         11},
         {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"quic;reassembly"},
             .m_pc{"quic_fragmented.pcap"}},
         2}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        quic_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test SGT encapsulated TLS - analysis with resources-mp")
{

    auto destination_check_callback = [](const analysis_context *ac)
    {
        CHECK(analysis_context_get_fingerprint_type(ac) == fingerprint_type_tls);
    };

    auto tls_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter(fingerprint_type_tls,destination_check_callback));

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"tls.client_hello"},
             .m_pc{"tls_sgt.pcap"}},
         58}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        tls_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test SGT encapsulated TLS - write_json with resources-mp")
{

    auto tls_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"tls.client_hello"},
             .m_pc{"tls_sgt.pcap"}},
         58}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        tls_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test quic with resources-mp and eth linktype")
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

TEST_CASE_METHOD(LibmercTestFixture, "test quic with resources-mp and ppp linktype")
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

TEST_CASE_METHOD(LibmercTestFixture, "test smtp with resources-mp")
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

TEST_CASE_METHOD(LibmercTestFixture, "test dns and mdns with resources-mp")
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

TEST_CASE_METHOD(LibmercTestFixture, "test smb with resources-mp")
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

TEST_CASE_METHOD(LibmercTestFixture, "test iec with resources-mp")
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

TEST_CASE_METHOD(LibmercTestFixture, "test dnp3 with resources-mp")
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

TEST_CASE_METHOD(LibmercTestFixture, "test decrypted quic with resources-mp")
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
             .m_pc{"quic_decry.pcap"}},
         1}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        quic_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test attributes with resources-mp")
{

    auto destination_check_callback = [](size_t attr_count, size_t expected_attr_count)
    {
        CHECK((attr_count == expected_attr_count));
    };

    auto attr_check = [&](size_t expected_attrs_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(counter(expected_attrs_count,destination_check_callback));

        deinitialize();
    };

    std::vector<std::pair<test_config, size_t>> test_set_up{
        // {test_config{
        //      .m_lc{.do_analysis = true, .resources = resources_mp_path,
        //         .packet_filter_cfg = (char *)"all"},
        //      .m_pc{"surfshark.pcap"}},
        //  3      // encrypted_dns, evasive_vpn, external_proxy as attributes
        // },
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"all"},
             .m_pc{"malware_tls.pcap"}},
         2      // encrypted_channel, malware as attributes
        }
    };

    for (auto &[config, attrs] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        attr_check(attrs, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test nbss with resources-mp")
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

TEST_CASE_METHOD(LibmercTestFixture, "test openvpn tcp with resources-mp")
{

    auto openvpn_check = [&](int count, const struct libmerc_config &config, fingerprint_type fp_t, fingerprint_type fp_t2)
    {
        initialize(config);

        CHECK(count == counter(fp_t, fp_t2));

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"openvpn_tcp"},
             .m_pc{"openvpn_tcp_multi.pcap"},
             .fp_t = fingerprint_type_openvpn},
         2},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"openvpn_tcp"},
             .m_pc{"openvpn_tcp_single.pcap"},
             .fp_t = fingerprint_type_openvpn},
         1}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        openvpn_check(count, config.m_lc, config.fp_t, fingerprint_type_unknown);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test bittorrent with resources-mp")
{

    auto bittorrent_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"bittorrent"},
             .m_pc{"top_100_fingerprints.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"bittorrent"},
             .m_pc{"bittorrent.pcap"}},
         16},
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        bittorrent_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "mysql with resources-mp")
{

    auto mysql_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"mysql"},
             .m_pc{"top_100_fingerprints.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"mysql"},
             .m_pc{"mysql.pcap"}},
         4},
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        mysql_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "socks with resources-mp")
{

    auto socks_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"socks"},
             .m_pc{"top_100_fingerprints.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"socks"},
             .m_pc{"socks4_5.pcap"}},
         10},
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        socks_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "geneve encapsulated IPv4 and Ethernet with resources-mp")
{

    auto tls_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"tls.client_hello"},
             .m_pc{"geneve.pcap"}},
         42},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"tls.server_hello"},
             .m_pc{"geneve.pcap"}},
         43},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"tcp"},
             .m_pc{"geneve.pcap"}},
         43},
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        tls_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test stun with resources-mp")
{

    auto stun_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"stun"},
             .m_pc{"stun.pcap"}},
         4},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"stun"},
             .m_pc{"stun_classic.pcap"}},
         2},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_mp_path,
                .packet_filter_cfg = (char *)"stun"},
             .m_pc{"top_100_fingerprints.pcap"}},
         0}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        stun_check(count, config.m_lc);
    }
}
