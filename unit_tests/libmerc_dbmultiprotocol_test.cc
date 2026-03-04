#include "libmerc_fixture.h"
#include <iostream>

int sig_close_flag = false;

SCENARIO("test packet_processor_get_analysis_context with http encapsulated in PPPOE") {
    GIVEN("mercury packet processor") {
        libmerc_config config = create_config();
        mercury_context mc = initialize_mercury(config);
        mercury_packet_processor mpp = mercury_packet_processor_construct(mc);

        struct timespec time;
        time.tv_sec = time.tv_nsec = 0;  // set to January 1st, 1970 (the Epoch)

        WHEN("get analysis context") {
            mercury_packet_processor_get_analysis_context(mpp, http_request_pppoe, http_request_pppoe_len, &time);
            THEN("a valid result  exist") {
                REQUIRE(mpp->analysis.result.is_valid());
                mercury_packet_processor_destruct(mpp);
            }
        }
        mercury_finalize(mc);
    }
}

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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"http"},
             .m_pc{"capture2.pcap"}},
         127},
        {test_config{
             .m_lc{.resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"http"},
             .m_pc{"capture2.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"http"},
             .m_pc{"http_request.capture2.pcap"}},
         109},
        {test_config{
             .m_lc{.resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"http"},
             .m_pc{"multi_packet_http_request.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"capture2.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"quic-crypto-packets.pcap"}},
         670},
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
        0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"quic_v2.pcap"}},
         5},
         {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"quic;reassembly"},
             .m_pc{"quic_fragmented.pcap"}},
         2},
         {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
               .packet_filter_cfg = (char *)"quic;reassembly"},
            .m_pc{"quic_reordered_frames.pcap"}},
         4}
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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

TEST_CASE_METHOD(LibmercTestFixture, "test tls select strings producing different output line counts")
{
    auto tls_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);
        CHECK(expected_count == counter());
        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.resources = resources_minimal_path,
                   .packet_filter_cfg = (char *)"tls.client_hello"},
             .m_pc{"capture2.pcap"}},
         17},
        {test_config{
             .m_lc{.resources = resources_minimal_path,
                   .packet_filter_cfg = (char *)"tls.client_hello,tls.server_hello"},
             .m_pc{"capture2.pcap"}},
         60} // this number is different because tls.server_hello is selected in addition to tls.client_hello
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"quic"},
             .m_pc{"quic-crypto-packets.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"smtp"},
             .m_pc{"capture2.pcap"}},
         1},
        {test_config{
             .m_lc{.dns_json_output = true, .do_analysis = true,
                .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"smtp"},
             .m_pc{"smtp.pcap"}},
         4},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"dns"},
             .m_pc{"capture2.pcap"}},
         785},
        {test_config{
             .m_lc{.dns_json_output = true, .do_analysis = true,
                .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"dns"},
             .m_pc{"capture2.pcap"}},
         785},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"mdns"},
             .m_pc{"mdns_capture.pcap"}},
         3141},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"dns"},
             .m_pc{"dns_packet.capture2.pcap"}},
         785},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"smb"},
             .m_pc{"smb.pcap"}},
         391},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"iec"},
             .m_pc{"iec.pcap"}},
         42},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"dnp3"},
             .m_pc{"dnp3.pcap"}},
         15},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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

TEST_CASE_METHOD(LibmercTestFixture, "test ftp with resources-mp")
{

    auto ftp_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.metadata_output=true, .do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"ftp"},
             .m_pc{"ftp.pcap"}},

         58},
         {test_config{
             .m_lc{.resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"ftp"},
             .m_pc{"ftp2.pcap"}},

         23},

        {test_config{
             .m_lc{.metadata_output=true, .do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"ftp"},
             .m_pc{"top_100_fingerprints.pcap"}},
         0}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        ftp_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test redis with resources-mp")
{

    auto redis_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.metadata_output=true, .do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"redis"},
             .m_pc{"redis.pcap"}},

         9},
        {test_config{
             .m_lc{.metadata_output=true, .do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"redis"},
             .m_pc{"top_100_fingerprints.pcap"}},
         0}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        redis_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test imap with resources-mp")
{

    auto imap_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.metadata_output=true, .do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"imap"},
             .m_pc{"imap.pcap"}},

         53},
         {test_config{
             .m_lc{.metadata_output=true, .do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"imap"},
             .m_pc{"imap2.pcap"}},

         5},

        {test_config{
             .m_lc{.metadata_output=true, .do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"imap"},
             .m_pc{"top_100_fingerprints.pcap"}},
         0}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        imap_check(count, config.m_lc);
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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
        fprintf(stderr, "attr_count: %zu, expected_attr_count: %zu\n", attr_count, expected_attr_count);
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
        //      .m_lc{.do_analysis = true, .resources = resources_minimal_path,
        //         .packet_filter_cfg = (char *)"all"},
        //      .m_pc{"surfshark.pcap"}},
        //  3      // encrypted_dns, evasive_vpn, external_proxy as attributes
        // },
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all"},
             .m_pc{"malware_tls.pcap"}},
         2      // encrypted_channel, malware as attributes
        },
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all;network-behavioral-detections"},
             .m_pc{"residential_proxy.pcap"}},
         1      // residential_proxy as attributes
        }
    };

    for (auto &[config, attrs] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        attr_check(attrs, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test ipv6 pcap for domain_faking")
{

    auto attr_check = [&](std::string &expected_attr, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(check_attr(expected_attr));

        deinitialize();
    };

    std::vector<std::pair<test_config, std::string>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all"},
             .m_pc{"ipv6-domain-faking.pcap"}},
            "domain_faking"      // domain_faking attribute in modified ipv6 curl pcap
        }
    };

    for (auto &[config, expected_attr] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        attr_check(expected_attr, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test faketls attribute with resources-mp")
{
    auto attr_check = [&](std::string &expected_attr, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(check_attr(expected_attr));

        deinitialize();
    };

    std::vector<std::pair<test_config, std::string>> test_set_up{
        {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all"},
            .m_pc{"faketls_potatovpn.pcap"}},
            "faketls"    // check if faketls attribute is present in the attributes array
        }
    };

    for (auto &[config, expected_attr] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        attr_check(expected_attr, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test domain_faking attribute with resources-mp")
{
    auto attr_check = [&](std::string &expected_attr, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(check_attr(expected_attr));

        deinitialize();
    };

    std::vector<std::pair<test_config, std::string>> test_set_up{
        {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all"},
            .m_pc{"faketls_potatovpn.pcap"}},
            "domain_faking"    // check if domain_faking attribute is present in the attributes array
        }
    };

    for (auto &[config, expected_attr] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        attr_check(expected_attr, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test exposed_creds attribute")
{
    auto attr_check = [&](std::string &expected_attr, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(check_attr(expected_attr));

        deinitialize();
    };

    std::vector<std::pair<test_config, std::string>> test_set_up{
        {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all;exposed-creds"
            },
            .m_pc{"http_auth.pcap"}},
            "exposed_credentials_plaintext"    // check if exposed_credentials_plaintext attribute is present in the attributes array
        },
        {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all;exposed-creds"
            },
            .m_pc{"http_auth_bearer.pcap"}},
            "exposed_credentials_token"
        },
        {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all;exposed-creds"
            },
            .m_pc{"http_auth_digest.pcap"}},
            "exposed_credentials_derived"
        },
        {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all;exposed-creds"
            },
            .m_pc{"ftp_exposed_creds.pcap"}},
            "exposed_credentials_plaintext"
        },
        {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all;exposed-creds"
            },
            .m_pc{"redis_exposed_creds.pcap"}},
            "exposed_credentials_plaintext"
        },
        {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all;exposed-creds"
            },
            .m_pc{"ldap_exposed_creds.pcap"}},
            "exposed_credentials_plaintext"
        },
        {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all;exposed-creds"
            },
            .m_pc{"ldap_exposed_creds_derived.pcap"}},
            "exposed_credentials_derived"
        },
        {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all;exposed-creds"
            },
            .m_pc{"snmp_exposed_creds.pcap"}},
            "exposed_credentials_plaintext"
        },
        {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all;exposed-creds"
            },
            .m_pc{"snmp_exposed_creds_derived.pcap"}},
            "exposed_credentials_derived"
        }
    };

    for (auto &[config, expected_attr] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        attr_check(expected_attr, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test exposed_creds with write_json and analysis off")
{
    set_pcap("http_auth.pcap");

    libmerc_config config{
        .do_analysis = false,
        .resources = resources_minimal_path,
        .packet_filter_cfg = (char *)"all;exposed-creds"
    };

    initialize(config);

    bool saw_json_output = false;
    while (1) {
        if (read_next_data_packet()) {
            break;
        }

        size_t json_size = mercury_packet_processor_write_json(
            m_mpp,
            m_output,
            4096,
            (unsigned char *)m_data_packet.first,
            m_data_packet.second - m_data_packet.first,
            &m_time
        );

        if (json_size > 0) {
            saw_json_output = true;
        }
        if (saw_json_output) {
            break;
        }
    }

    CHECK(saw_json_output);
    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test exposed_creds with analyze_ip_packet and analysis off")
{
    set_pcap("http_auth.pcap");

    libmerc_config config{
        .do_analysis = false,
        .resources = resources_minimal_path,
        .packet_filter_cfg = (char *)"all;exposed-creds"
    };

    initialize(config);

    int packet_count = 0;
    while (1) {
        if (read_next_data_packet()) {
            break;
        }

        mercury_packet_processor_get_analysis_context(
            m_mpp,
            (unsigned char *)m_data_packet.first,
            m_data_packet.second - m_data_packet.first,
            &m_time
        );
        packet_count++;
    }

    CHECK(packet_count > 0);
    deinitialize();
}


TEST_CASE_METHOD(LibmercTestFixture, "test crypto_assessment attributes")
{
    auto attr_check = [&](std::string &expected_attr, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(check_attr(expected_attr));

        deinitialize();
    };

    std::vector<std::pair<test_config, std::string>> test_set_up{
        {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all;crypto-assess=default"
            },
            .m_pc{"tlsv1_3.pcap"}},
            "cnsa_2_0_non_conformant"    // check if cnsa_2_0_non_conformant attribute is present in the attributes array
        },
        {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all;crypto-assess=default"
            },
            .m_pc{"tls_cnsa2_psk_mode_psk_ke.pcap"}},
            "cnsa_2_0_non_conformant"    // psk_key_exchange_modes includes psk_ke
        },
        {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all;crypto-assess=default"
            },
            .m_pc{"tls_cnsa2_psk_short_binder.pcap"}},
            "cnsa_2_0_non_conformant"    // pre_shared_key binder length < 256 bits
        },
        {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all;crypto-assess=default"
            },
            .m_pc{"tls_cnsa2_psk_mlkem1024_missing.pcap"}},
            "cnsa_2_0_non_conformant"    // psk_dhe_ke without MLKEM1024 key_share
        },
        {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all;crypto-assess=default"
            },
            .m_pc{"nist_nc.pcap"}},
            "nist_sp_800_52_2_non_conformant"    // check if nist_sp_800_52_2_non_conformant attribute is present in the attributes array
        }
    };

    for (auto &[config, expected_attr] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        attr_check(expected_attr, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test crypto_assessment quantum_safe compliance")
{
    auto attr_not_present_check = [&](std::string &attr_to_be_absent, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK_FALSE(check_attr(attr_to_be_absent));  // attribute should NOT be present

        deinitialize();
    };

    std::vector<std::pair<test_config, std::string>> test_set_up{
        {test_config{
            .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"all;crypto-assess=quantum_safe"
            },
            .m_pc{"secp384r1mlkem1024_clienthello.pcap"}},
            "cnsa_2_0_non_conformant"    // should NOT be present since secp384r1mlkem1024 is quantum-safe
        }
    };

    for (auto &[config, attr_to_be_absent] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        attr_not_present_check(attr_to_be_absent, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test crypto_assessment skipped on truncated tls")
{
    set_pcap("tls_cnsa2_psk_mode_psk_ke_truncated.pcap");

    libmerc_config config{
        .do_analysis = true,
        .resources = resources_minimal_path,
        .packet_filter_cfg = (char *)"all;crypto-assess=default"
    };

    initialize(config);

    std::string non_pqc_attr = "cnsa_2_0_non_conformant";
    CHECK_FALSE(check_attr(non_pqc_attr));

    deinitialize();
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"openvpn_tcp"},
             .m_pc{"openvpn_tcp_multi.pcap"},
             .fp_t = fingerprint_type_openvpn},
         2},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"bittorrent"},
             .m_pc{"top_100_fingerprints.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"mysql"},
             .m_pc{"top_100_fingerprints.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"socks"},
             .m_pc{"top_100_fingerprints.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"tls"},
             .m_pc{"geneve.pcap"}},
         43},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"tls,geneve"},
             .m_pc{"geneve.pcap"}},
         85},
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
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"stun"},
             .m_pc{"stun.pcap"}},
         4},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"stun"},
             .m_pc{"stun_classic.pcap"}},
         2},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
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

TEST_CASE_METHOD(LibmercTestFixture, "test ssh fingerprinting and reassembly")
{

    auto ssh_check = [&](int count, const struct libmerc_config &config, fingerprint_type fp_t, fingerprint_type fp_t2)
    {
        initialize(config);

        CHECK(count == counter(fp_t, fp_t2));

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"ssh;reassembly"},
             .m_pc{"ssh_frag.pcap"},
             .fp_t = fingerprint_type_ssh},
         2},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"ssh"},
             .m_pc{"ssh_frag.pcap"},
             .fp_t = fingerprint_type_ssh_init},
         2},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"ssh"},
             .m_pc{"ssh_frag.pcap"},
             .fp_t = fingerprint_type_ssh_kex},
         2}
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        ssh_check(count, config.m_lc, config.fp_t, fingerprint_type_unknown);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "GRE encapsulation with resources-mp")
{

    auto gre_check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"icmp"},
             .m_pc{"gre.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"gre,icmp"},
             .m_pc{"gre.pcap"}},
         1},
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        gre_check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "IP encapsulation  with resources-mp")
{

    auto check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path},
             .m_pc{"ip_encapsulation.pcap"}},
         2},
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "VXLAN  with resources-mp")
{

    auto check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"icmp"},
             .m_pc{"vxlan.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"vxlan,icmp"},
             .m_pc{"vxlan.pcap"}},
         8},
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "double VLAN tagged PPPoE with resources-mp")
{

    auto check = [&](int expected_count, const struct libmerc_config &config)
    {
        initialize(config);

        CHECK(expected_count == counter());

        deinitialize();
    };

    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"http"},
             .m_pc{"pppoe_double_vlan_tagging.pcap"}},
         6},
    };

    for (auto &[config, count] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        check(count, config.m_lc);
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test raw-features write_json output for tls")
{
    // Expected "features":"<value>" substring in the JSON output for
    // tls_client_hello_test_packet.pcap when raw-features=tls is enabled.
    const std::string expected_features_kv =
        R"("features":"[\"0303\",)"
        R"(\"130113021303c02cc02bc024c023c00ac009cca9c030c02fc028c027c014c013cca8)"
        R"(009d009c003d003c0035002fc008c012000a\",)"
        R"([[\"ff01\",\"00\"],)"
        R"([\"0000\",\"002100001e73656c662e6576656e74732e646174612e6d6963726f736f66742e636f6d\"],)"
        R"([\"0017\",\"\"],)"
        R"([\"000d\",\"001604030804040105030203080508050501080606010201\"],)"
        R"([\"0005\",\"0100000000\"],)"
        R"([\"0012\",\"\"],)"
        R"([\"0010\",\"000c02683208687474702f312e31\"],)"
        R"([\"000b\",\"0100\"],)"
        R"([\"0033\",\"0024001d0020b56ffcdd5474896e64a03e82f3390a61f08a0512cf4ea76857a6fc54a4c4c704\"],)"
        R"([\"002d\",\"0101\"],)"
        R"([\"002b\",\"080304030303020301\"],)"
        R"([\"000a\",\"0008001d001700180019\"],)"
        R"([\"0015\",\")"
        R"(00000000000000000000000000000000)"
        R"(00000000000000000000000000000000)"
        R"(00000000000000000000000000000000)"
        R"(00000000000000000000000000000000)"
        R"(00000000000000000000000000000000)"
        R"(00000000000000000000000000000000)"
        R"(00000000000000000000000000000000)"
        R"(00000000000000000000000000000000)"
        R"(00000000000000000000000000000000)"
        R"(00000000000000000000000000000000)"
        R"(00000000000000000000000000000000)"
        R"(000000000000000000000000000000)"
        R"(\"]]]")";

    auto check = [&](int expect_features, const struct libmerc_config &config)
    {
        initialize(config);

        std::string json = get_first_json();
        REQUIRE(json.size() > 0);

        if (expect_features) {
            CHECK(json.find(expected_features_kv) != std::string::npos);
        } else {
            CHECK(json.find("\"features\"") == std::string::npos);
        }

        deinitialize();
    };

    // expect_features: 1 = features key-value must be present, 0 = features key must be absent
    // sequence: enable → disable → re-enable (verifies reinit correctness)
    std::vector<std::pair<test_config, int>> test_set_up{
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"tls.client_hello;raw-features=tls"},
             .m_pc{"tls_client_hello_test_packet.pcap"}},
         1},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"tls.client_hello"},
             .m_pc{"tls_client_hello_test_packet.pcap"}},
         0},
        {test_config{
             .m_lc{.do_analysis = true, .resources = resources_minimal_path,
                .packet_filter_cfg = (char *)"tls.client_hello;raw-features=tls"},
             .m_pc{"tls_client_hello_test_packet.pcap"}},
         1},
    };

    for (auto &[config, expect_features] : test_set_up)
    {
        set_pcap(config.m_pc.c_str());
        check(expect_features, config.m_lc);
    }
}
