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

TEST_CASE_METHOD(LibmercTestFixture, "test http")
{
    auto destination_check_callback = [](const analysis_context *ac)
    {
        CHECK(analysis_context_get_fingerprint_type(ac) == fingerprint_type_http);
    };

    libmerc_config config{.packet_filter_cfg = (char *)"http"};
    initialize(config);

    set_pcap("capture2.pcap");
    CHECK(0 == counter(fingerprint_type_http, destination_check_callback));

    set_pcap("multi_packet_http_request.pcap");
    CHECK(0 == counter(fingerprint_type_http, destination_check_callback));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test http with analysis")
{
    auto destination_check_callback = [](const analysis_context *ac)
    {
        CHECK(analysis_context_get_fingerprint_type(ac) == fingerprint_type_http);
    };

    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"http"};
    initialize(config);

    set_pcap("capture2.pcap");
    CHECK(127 == counter(fingerprint_type_http, destination_check_callback));

    set_pcap("http_request.capture2.pcap");
    CHECK(109 == counter(fingerprint_type_http, destination_check_callback));

    set_pcap("multi_packet_http_request.pcap");
    CHECK(1 == counter(fingerprint_type_http, destination_check_callback));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test http with analysis and linktype raw")
{
    auto destination_check_callback = [](const analysis_context *ac)
    {
        CHECK(analysis_context_get_fingerprint_type(ac) == fingerprint_type_http);
    };

    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"http"};
    initialize(config);
    set_pcap("http_rawip.pcap");
    CHECK(9 == counter(fingerprint_type_http, destination_check_callback, LINKTYPE_RAW));
    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test quic")
{
    auto destination_check_callback = [](const analysis_context *ac)
    {
        CHECK(analysis_context_get_fingerprint_type(ac) == fingerprint_type_quic);
    };

    libmerc_config config{.packet_filter_cfg = (char *)"quic"};
    initialize(config);

    set_pcap("quic_init.capture2.pcap");
    CHECK(0 == counter(fingerprint_type_quic, destination_check_callback));

    set_pcap("mdns_capture.pcap");
    CHECK(0 == counter(fingerprint_type_quic, destination_check_callback));

    set_pcap("capture2.pcap");
    CHECK(0 == counter(fingerprint_type_quic, destination_check_callback));

    set_pcap("http_request.capture2.pcap");
    CHECK(0 == counter(fingerprint_type_quic, destination_check_callback));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test quic with analysis")
{
    auto destination_check_callback = [](const analysis_context *ac)
    {
        CHECK(analysis_context_get_fingerprint_type(ac) == fingerprint_type_quic);
    };

    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"quic"};
    initialize(config);

    set_pcap("quic-crypto-packets.pcap");
    CHECK(670 == counter(fingerprint_type_quic, destination_check_callback));

    set_pcap("quic_v2.pcap");
    CHECK(5 == counter(fingerprint_type_quic, destination_check_callback));

    set_pcap("quic_decry.pcap");
    CHECK(1 == counter(fingerprint_type_quic, destination_check_callback));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test quic with analysis and reassembly")
{
    auto destination_check_callback = [](const analysis_context *ac)
    {
        CHECK(analysis_context_get_fingerprint_type(ac) == fingerprint_type_quic);
    };

    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"quic;reassembly"};
    initialize(config);

    set_pcap("quic_fragmented.pcap");
    CHECK(2 == counter(fingerprint_type_quic, destination_check_callback));

    set_pcap("quic_reordered_frames.pcap");
    CHECK(4 == counter(fingerprint_type_quic, destination_check_callback));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test SGT encapsulated TLS with analysis")
{
    auto destination_check_callback = [](const analysis_context *ac)
    {
        CHECK(analysis_context_get_fingerprint_type(ac) == fingerprint_type_tls);
    };

    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"tls.client_hello"};
    initialize(config);

    // Test with fingerprint type checking
    set_pcap("tls_sgt.pcap");
    CHECK(58 == counter(fingerprint_type_tls, destination_check_callback));

    // Test basic JSON output counting with a fresh packet processor
    set_pcap("tls_sgt.pcap");
    CHECK(58 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test tls select strings producing different output line counts")
{
    {
        libmerc_config config{.resources = resources_minimal_path,
                              .packet_filter_cfg = (char *)"tls.client_hello"};
        initialize(config);
        set_pcap("capture2.pcap");
        CHECK(17 == counter());
        deinitialize();
    }
    {
        libmerc_config config{.resources = resources_minimal_path,
                              .packet_filter_cfg = (char *)"tls.client_hello,tls.server_hello"};
        initialize(config);
        set_pcap("capture2.pcap");
        CHECK(60 == counter()); // this number is different because tls.server_hello is selected in addition to tls.client_hello
        deinitialize();
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test quic with analysis and various linktypes")
{
    auto destination_check_callback = [](const analysis_context *ac)
    {
        CHECK(analysis_context_get_fingerprint_type(ac) == fingerprint_type_quic);
    };

    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"quic"};
    initialize(config);

    // Test with LINKTYPE_ETHERNET
    set_pcap("quic-crypto-packets.pcap");
    CHECK(670 == counter(fingerprint_type_quic, destination_check_callback, LINKTYPE_ETHERNET));

    // Test with LINKTYPE_PPP
    set_pcap("quic_ppp.pcap");
    CHECK(1 == counter(fingerprint_type_quic, destination_check_callback, LINKTYPE_PPP));
    set_pcap("quic-crypto-packets.pcap");
    CHECK(0 == counter(fingerprint_type_quic, destination_check_callback, LINKTYPE_PPP));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test smtp")
{
    libmerc_config config{.packet_filter_cfg = (char *)"smtp"};
    initialize(config);

    set_pcap("capture2.pcap");
    CHECK(1 == counter());

    set_pcap("top_100_fingerprints.pcap");
    CHECK(0 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test smtp with dns json output")
{
    libmerc_config config{.dns_json_output = true,
                          .do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"smtp"};
    initialize(config);

    set_pcap("smtp.pcap");
    CHECK(4 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test dns with analysis")
{
    auto dns_output_check = [&]() {
        bool dns_output_provided = strstr(m_output, "base64") ? false : true;
        /* to not provide thousands of CHECKs, do one only in case of failure */
        if(!(m_mpp->global_vars.dns_json_output ? dns_output_provided : !dns_output_provided))
            CHECK(false);
    };

    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"dns"};
    initialize(config);

    set_pcap("capture2.pcap");
    CHECK(785 == counter(fingerprint_type_unknown, dns_output_check));

    set_pcap("dns_packet.capture2.pcap");
    CHECK(785 == counter(fingerprint_type_unknown, dns_output_check));

    set_pcap("top_100_fingerprints.pcap");
    CHECK(0 == counter(fingerprint_type_unknown, dns_output_check));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test dns with analysis and json output")
{
    auto dns_output_check = [&]() {
        bool dns_output_provided = strstr(m_output, "base64") ? false : true;
        /* to not provide thousands of CHECKs, do one only in case of failure */
        if(!(m_mpp->global_vars.dns_json_output ? dns_output_provided : !dns_output_provided))
            CHECK(false);
    };

    libmerc_config config{.dns_json_output = true,
                          .do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"dns"};
    initialize(config);

    set_pcap("capture2.pcap");
    CHECK(785 == counter(fingerprint_type_unknown, dns_output_check));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test mdns with analysis")
{
    auto dns_output_check = [&]() {
        bool dns_output_provided = strstr(m_output, "base64") ? false : true;
        /* to not provide thousands of CHECKs, do one only in case of failure */
        if(!(m_mpp->global_vars.dns_json_output ? dns_output_provided : !dns_output_provided))
            CHECK(false);
    };

    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"mdns"};
    initialize(config);

    set_pcap("mdns_capture.pcap");
    CHECK(3141 == counter(fingerprint_type_unknown, dns_output_check));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test smb with analysis")
{
    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"smb"};
    initialize(config);

    set_pcap("smb.pcap");
    CHECK(391 == counter());

    set_pcap("top_100_fingerprints.pcap");
    CHECK(0 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test iec with analysis")
{
    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"iec"};
    initialize(config);

    set_pcap("iec.pcap");
    CHECK(42 == counter());

    set_pcap("top_100_fingerprints.pcap");
    CHECK(0 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test dnp3 with analysis")
{
    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"dnp3"};
    initialize(config);

    set_pcap("dnp3.pcap");
    CHECK(15 == counter());

    set_pcap("top_100_fingerprints.pcap");
    CHECK(0 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test ftp")
{
    libmerc_config config{.packet_filter_cfg = (char *)"ftp"};
    initialize(config);

    set_pcap("ftp2.pcap");
    CHECK(23 == counter());

    set_pcap("ftp.pcap");
    CHECK(58 == counter());

    set_pcap("top_100_fingerprints.pcap");
    CHECK(0 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test redis")
{
    libmerc_config config{.packet_filter_cfg = (char *)"redis"};
    initialize(config);

    set_pcap("redis.pcap");
    CHECK(9 == counter());

    set_pcap("top_100_fingerprints.pcap");
    CHECK(0 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test imap")
{
    libmerc_config config{.packet_filter_cfg = (char *)"imap"};
    initialize(config);

    set_pcap("imap.pcap");
    CHECK(53 == counter());

    set_pcap("imap2.pcap");
    CHECK(5 == counter());

    set_pcap("top_100_fingerprints.pcap");
    CHECK(0 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test attribute detection with analysis")
{
    auto attribute_check_callback = [](size_t attr_count, size_t expected_attr_count)
    {
        fprintf(stderr, "attr_count: %zu, expected_attr_count: %zu\n", attr_count, expected_attr_count);
        CHECK((attr_count == expected_attr_count));
    };

    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"all"};
    initialize(config);

    // encrypted_channel, malware as attributes
    set_pcap("malware_tls.pcap");
    CHECK(counter(2, attribute_check_callback));

    // domain_faking attribute in modified ipv6 curl pcap
    set_pcap("ipv6-domain-faking.pcap");
    { std::string attr = "domain_faking"; CHECK(check_attr(attr)); }

    // check if faketls attribute is present in the attributes array
    set_pcap("faketls_potatovpn.pcap");
    { std::string attr = "faketls"; CHECK(check_attr(attr)); }

    // check if domain_faking attribute is present in the attributes array
    set_pcap("faketls_potatovpn.pcap");
    { std::string attr = "domain_faking"; CHECK(check_attr(attr)); }

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test network behavioral detection attributes")
{
    auto check_callback = [](size_t attr_count, size_t expected_attr_count)
    {
        fprintf(stderr, "attr_count: %zu, expected_attr_count: %zu\n", attr_count, expected_attr_count);
        CHECK((attr_count == expected_attr_count));
    };

    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"all;network-behavioral-detections"};
    initialize(config);

    // residential_proxy as attributes
    set_pcap("residential_proxy.pcap");
    CHECK(counter(1, check_callback));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test exposed_creds attribute")
{
    libmerc_config config{.packet_filter_cfg = (char *)"all;exposed-creds"};
    initialize(config);

    set_pcap("http_auth.pcap");
    { std::string attr = "exposed_credentials_plaintext"; CHECK(check_attr(attr)); }

    set_pcap("http_auth_bearer.pcap");
    { std::string attr = "exposed_credentials_token"; CHECK(check_attr(attr)); }

    set_pcap("http_auth_digest.pcap");
    { std::string attr = "exposed_credentials_derived"; CHECK(check_attr(attr)); }

    set_pcap("ftp_exposed_creds.pcap");
    { std::string attr = "exposed_credentials_plaintext"; CHECK(check_attr(attr)); }

    set_pcap("redis_exposed_creds.pcap");
    { std::string attr = "exposed_credentials_plaintext"; CHECK(check_attr(attr)); }

    set_pcap("ldap_exposed_creds.pcap");
    { std::string attr = "exposed_credentials_plaintext"; CHECK(check_attr(attr)); }

    set_pcap("ldap_exposed_creds_derived.pcap");
    { std::string attr = "exposed_credentials_derived"; CHECK(check_attr(attr)); }

    set_pcap("snmp_exposed_creds.pcap");
    { std::string attr = "exposed_credentials_plaintext"; CHECK(check_attr(attr)); }

    set_pcap("snmp_exposed_creds_derived.pcap");
    { std::string attr = "exposed_credentials_derived"; CHECK(check_attr(attr)); }

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test exposed_creds with write_json and analysis off")
{
    set_pcap("http_auth.pcap");

    libmerc_config config{.do_analysis = false,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"all;exposed-creds"};

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

    libmerc_config config{.do_analysis = false,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"all;exposed-creds"};

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

TEST_CASE_METHOD(LibmercTestFixture, "analysis_context getters require completed analysis")
{
    libmerc_config config{.do_analysis = false,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"http"};
    initialize(config);
    set_pcap("http_auth.pcap");

    bool saw_http_fingerprint = false;
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

        if (json_size > 0 && m_mpp->analysis.fp.get_type() == fingerprint_type_http) {
            saw_http_fingerprint = true;
            break;
        }
    }

    CHECK(saw_http_fingerprint);
    CHECK_FALSE(m_mpp->analysis.analysis_done);
    CHECK(fingerprint_type_unknown == analysis_context_get_fingerprint_type(&m_mpp->analysis));
    CHECK(nullptr == analysis_context_get_fingerprint_string(&m_mpp->analysis));
    CHECK(nullptr == analysis_context_get_server_name(&m_mpp->analysis));
    CHECK(nullptr == analysis_context_get_user_agent(&m_mpp->analysis));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "server ssh skips analysis but still fingerprints")
{
    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"ssh.server"};
    initialize(config);
    set_pcap("ssh_direction_asym.pcap");

    bool saw_server_ssh = false;
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

        if (json_size > 0 && m_mpp->analysis.fp.get_type() == fingerprint_type_ssh_init_server) {
            saw_server_ssh = true;
            break;
        }
    }

    CHECK(saw_server_ssh);
    CHECK_FALSE(m_mpp->analysis.analysis_done);
    CHECK(fingerprint_type_unknown == analysis_context_get_fingerprint_type(&m_mpp->analysis));
    CHECK(nullptr == analysis_context_get_fingerprint_string(&m_mpp->analysis));
    CHECK(nullptr == analysis_context_get_user_agent(&m_mpp->analysis));

    deinitialize();
}


TEST_CASE_METHOD(LibmercTestFixture, "test crypto_assessment attributes")
{
    libmerc_config config{.packet_filter_cfg = (char *)"all;crypto-assess=default"};
    initialize(config);

    set_pcap("tlsv1_3.pcap");
    { std::string attr = "cnsa_2_0_non_conformant"; CHECK(check_attr(attr)); }

    // psk_key_exchange_modes includes psk_ke
    set_pcap("tls_cnsa2_psk_mode_psk_ke.pcap");
    { std::string attr = "cnsa_2_0_non_conformant"; CHECK(check_attr(attr)); }

    // pre_shared_key binder length < 256 bits
    set_pcap("tls_cnsa2_psk_short_binder.pcap");
    { std::string attr = "cnsa_2_0_non_conformant"; CHECK(check_attr(attr)); }

    // psk_dhe_ke without MLKEM1024 key_share
    set_pcap("tls_cnsa2_psk_mlkem1024_missing.pcap");
    { std::string attr = "cnsa_2_0_non_conformant"; CHECK(check_attr(attr)); }

    set_pcap("nist_nc.pcap");
    { std::string attr = "nist_sp_800_52_2_non_conformant"; CHECK(check_attr(attr)); }

    // Truncated TLS should NOT produce crypto assessment attributes
    set_pcap("tls_cnsa2_psk_mode_psk_ke_truncated.pcap");
    { std::string attr = "cnsa_2_0_non_conformant"; CHECK_FALSE(check_attr(attr)); }

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test crypto_assessment quantum_safe compliance")
{
    libmerc_config config{.packet_filter_cfg = (char *)"all;crypto-assess=quantum_safe"};
    initialize(config);

    // should NOT be present since secp384r1mlkem1024 is quantum-safe
    set_pcap("secp384r1mlkem1024_clienthello.pcap");
    { std::string attr = "cnsa_2_0_non_conformant"; CHECK_FALSE(check_attr(attr)); }

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test nbss")
{
    libmerc_config config{.packet_filter_cfg = (char *)"nbss"};
    initialize(config);

    set_pcap("top_100_fingerprints.pcap");
    CHECK(0 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test openvpn tcp")
{
    libmerc_config config{.packet_filter_cfg = (char *)"openvpn_tcp"};
    initialize(config);

    set_pcap("openvpn_tcp_multi.pcap");
    CHECK(2 == counter(fingerprint_type_openvpn));

    set_pcap("openvpn_tcp_single.pcap");
    CHECK(1 == counter(fingerprint_type_openvpn));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test bittorrent")
{
    libmerc_config config{.packet_filter_cfg = (char *)"bittorrent"};
    initialize(config);

    set_pcap("top_100_fingerprints.pcap");
    CHECK(0 == counter());

    set_pcap("bittorrent.pcap");
    CHECK(16 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test mysql")
{
    libmerc_config config{.packet_filter_cfg = (char *)"mysql"};
    initialize(config);

    set_pcap("top_100_fingerprints.pcap");
    CHECK(0 == counter());

    set_pcap("mysql.pcap");
    CHECK(4 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test socks")
{
    libmerc_config config{.packet_filter_cfg = (char *)"socks"};
    initialize(config);

    set_pcap("top_100_fingerprints.pcap");
    CHECK(0 == counter());

    set_pcap("socks4_5.pcap");
    CHECK(10 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "geneve encapsulated IPv4 and Ethernet")
{
    {
        libmerc_config config{.packet_filter_cfg = (char *)"tls"};
        initialize(config);
        set_pcap("geneve.pcap");
        CHECK(43 == counter());
        deinitialize();
    }
    {
        libmerc_config config{.packet_filter_cfg = (char *)"tls,geneve"};
        initialize(config);
        set_pcap("geneve.pcap");
        CHECK(85 == counter());
        deinitialize();
    }
}

TEST_CASE_METHOD(LibmercTestFixture, "test stun with analysis")
{
    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"stun"};
    initialize(config);

    set_pcap("stun.pcap");
    CHECK(4 == counter());

    set_pcap("stun_classic.pcap");
    CHECK(2 == counter());

    set_pcap("top_100_fingerprints.pcap");
    CHECK(0 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test ssh fingerprinting with reassembly")
{
    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"ssh;reassembly"};
    initialize(config);

    set_pcap("ssh_frag.pcap");
    CHECK(1 == counter(fingerprint_type_ssh));
    set_pcap("ssh_frag.pcap");
    CHECK(1 == counter(fingerprint_type_ssh_server));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test ssh direction selector 'ssh'")
{
    libmerc_config config{.resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"ssh"};
    initialize(config);

    set_pcap("ssh_direction_asym.pcap");
    CHECK(1 == counter(fingerprint_type_ssh_init));
    set_pcap("ssh_direction_asym.pcap");
    CHECK(1 == counter(fingerprint_type_ssh_init_server));
    set_pcap("ssh_direction_asym.pcap");
    CHECK(1 == counter(fingerprint_type_ssh_kex));
    set_pcap("ssh_direction_asym.pcap");
    CHECK(0 == counter(fingerprint_type_ssh_kex_server));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test ssh direction selector 'ssh.client'")
{
    libmerc_config config{.resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"ssh.client"};
    initialize(config);

    set_pcap("ssh_direction_asym.pcap");
    CHECK(1 == counter(fingerprint_type_ssh_init));
    set_pcap("ssh_direction_asym.pcap");
    CHECK(1 == counter(fingerprint_type_ssh_kex));
    set_pcap("ssh_direction_asym.pcap");
    CHECK(0 == counter(fingerprint_type_ssh_init_server));
    set_pcap("ssh_direction_asym.pcap");
    CHECK(0 == counter(fingerprint_type_ssh_kex_server));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test ssh direction selector 'ssh.server'")
{
    libmerc_config config{.resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"ssh.server"};
    initialize(config);

    set_pcap("ssh_direction_asym.pcap");
    CHECK(0 == counter(fingerprint_type_ssh_init));
    set_pcap("ssh_direction_asym.pcap");
    CHECK(0 == counter(fingerprint_type_ssh_kex));
    set_pcap("ssh_direction_asym.pcap");
    CHECK(1 == counter(fingerprint_type_ssh_init_server));
    set_pcap("ssh_direction_asym.pcap");
    CHECK(0 == counter(fingerprint_type_ssh_kex_server));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test ssh direction selector 'ssh.client,ssh.server'")
{
    libmerc_config config{.resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"ssh.client,ssh.server"};
    initialize(config);

    set_pcap("ssh_direction_asym.pcap");
    CHECK(1 == counter(fingerprint_type_ssh_init));
    set_pcap("ssh_direction_asym.pcap");
    CHECK(1 == counter(fingerprint_type_ssh_init_server));
    set_pcap("ssh_direction_asym.pcap");
    CHECK(1 == counter(fingerprint_type_ssh_kex));
    set_pcap("ssh_direction_asym.pcap");
    CHECK(0 == counter(fingerprint_type_ssh_kex_server));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test ssh_init fingerprinting")
{
    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"ssh"};
    initialize(config);

    set_pcap("ssh_frag.pcap");
    CHECK(1 == counter(fingerprint_type_ssh_init));
    set_pcap("ssh_frag.pcap");
    CHECK(1 == counter(fingerprint_type_ssh_init_server));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test ssh_kex fingerprinting")
{
    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"ssh"};
    initialize(config);

    set_pcap("ssh_frag.pcap");
    CHECK(1 == counter(fingerprint_type_ssh_kex));
    set_pcap("ssh_frag.pcap");
    CHECK(1 == counter(fingerprint_type_ssh_kex_server));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "GRE encapsulation without gre filter")
{
    libmerc_config config{.packet_filter_cfg = (char *)"icmp"};
    initialize(config);

    set_pcap("gre.pcap");
    CHECK(0 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "GRE encapsulation with gre filter")
{
    libmerc_config config{.packet_filter_cfg = (char *)"gre,icmp"};
    initialize(config);

    set_pcap("gre.pcap");
    CHECK(1 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "IP encapsulation")
{
    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path};
    initialize(config);

    set_pcap("ip_encapsulation.pcap");
    CHECK(2 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "VXLAN without vxlan filter")
{
    libmerc_config config{.packet_filter_cfg = (char *)"icmp"};
    initialize(config);

    set_pcap("vxlan.pcap");
    CHECK(0 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "VXLAN with vxlan filter")
{
    libmerc_config config{.packet_filter_cfg = (char *)"vxlan,icmp"};
    initialize(config);

    set_pcap("vxlan.pcap");
    CHECK(8 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "double VLAN tagged PPPoE")
{
    libmerc_config config{.packet_filter_cfg = (char *)"http"};
    initialize(config);

    set_pcap("pppoe_double_vlan_tagging.pcap");
    CHECK(6 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test raw-features write_json output for tls")
{
    // Stable prefix of the "features" value in JSON output for
    // tls_client_hello_test_packet.pcap when raw-features=tls is enabled.
    // Only a short prefix is matched to avoid brittleness if the full
    // serialization changes; the key goal is verifying presence/absence
    // across reinit cycles.
    const std::string expected_features_prefix =
        R"("features":"[\"0303\",)";

    // sequence: enable → disable → re-enable (verifies reinit correctness)

    // 1. raw-features enabled — features key must be present
    set_pcap("tls_client_hello_test_packet.pcap");
    {
        libmerc_config config{.do_analysis = true,
                              .resources = resources_minimal_path,
                              .packet_filter_cfg = (char *)"tls.client_hello;raw-features=tls"};
        initialize(config);
        std::string json = get_first_json();
        REQUIRE(json.size() > 0);
        CHECK(json.find(expected_features_prefix) != std::string::npos);
        deinitialize();
    }

    // 2. raw-features disabled — features key must be absent
    set_pcap("tls_client_hello_test_packet.pcap");
    {
        libmerc_config config{.do_analysis = true,
                              .resources = resources_minimal_path,
                              .packet_filter_cfg = (char *)"tls.client_hello"};
        initialize(config);
        std::string json = get_first_json();
        REQUIRE(json.size() > 0);
        CHECK(json.find("\"features\"") == std::string::npos);
        deinitialize();
    }

    // 3. raw-features re-enabled — features key must be present again
    set_pcap("tls_client_hello_test_packet.pcap");
    {
        libmerc_config config{.do_analysis = true,
                              .resources = resources_minimal_path,
                              .packet_filter_cfg = (char *)"tls.client_hello;raw-features=tls"};
        initialize(config);
        std::string json = get_first_json();
        REQUIRE(json.size() > 0);
        CHECK(json.find(expected_features_prefix) != std::string::npos);
        deinitialize();
    }
}
