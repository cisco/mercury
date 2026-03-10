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

TEST_CASE_METHOD(LibmercTestFixture, "test tcp with analysis")
{
    // TODO: add for tcp_only.pcap
    libmerc_config config{.do_analysis = true, .resources = resources_minimal_path,
        .packet_filter_cfg = (char *)"tcp"};
    initialize(config);

    set_pcap("capture2.pcap");
    CHECK(155 == counter());

    set_pcap("bad_tcp.pcap");
    CHECK(0 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test tcp")
{
    libmerc_config config{.packet_filter_cfg = (char *)"tcp"};
    initialize(config);

    set_pcap("capture2.pcap");
    CHECK(155 == counter());

    set_pcap("bad_tcp.pcap");
    CHECK(0 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test tls client_hello filtering with analysis")
{
    auto destination_check_callback = [](const analysis_context *ac)
    {
        CHECK(analysis_context_get_fingerprint_type(ac) == 1);
        CHECK(strcmp(ac->destination.dst_ip_str, "13.89.178.27") == 0);
        CHECK(ac->destination.dst_port == hton<uint16_t>(443));
        CHECK(ac->result.is_valid());
    };

    libmerc_config config{.do_analysis = true, .resources = resources_minimal_path,
        .packet_filter_cfg = (char *)"tls.client_hello"};
    initialize(config);

    set_pcap("tls_client_hello_test_packet.pcap");
    CHECK(1 == counter(fingerprint_type_tls, destination_check_callback));

    set_pcap("capture2.pcap");
    CHECK(17 == counter(fingerprint_type_tls));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test tls filtering with analysis")
{
    libmerc_config config{.do_analysis = true, .resources = resources_minimal_path,
        .packet_filter_cfg = (char *)"tls"};
    initialize(config);

    set_pcap("capture2.pcap");
    CHECK(60 == counter(fingerprint_type_tls, fingerprint_type_tls_server));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test http filtering with analysis")
{
    libmerc_config config{.do_analysis = true, .resources = resources_minimal_path,
        .packet_filter_cfg = (char *)"http"};
    initialize(config);

    set_pcap("capture2.pcap");
    CHECK(127 == counter(fingerprint_type_http));

    set_pcap("http_request.capture2.pcap");
    CHECK(109 == counter(fingerprint_type_http));

    set_pcap("multi_packet_http_request.pcap");
    CHECK(1 == counter(fingerprint_type_http));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test http filtering")
{
    libmerc_config config{.packet_filter_cfg = (char *)"http"};
    initialize(config);

    set_pcap("capture2.pcap");
    CHECK(127 == counter(fingerprint_type_http));

    set_pcap("multi_packet_http_request.pcap");
    CHECK(1 == counter(fingerprint_type_http));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test quic filtering with analysis")
{
    libmerc_config config{.do_analysis = true,
         .resources = resources_minimal_path,
        .packet_filter_cfg = (char *)"quic"};
    initialize(config);

    set_pcap("capture2.pcap");
    CHECK(0 == counter(fingerprint_type_quic));

    set_pcap("quic-crypto-packets.pcap");
    CHECK(0 == counter(fingerprint_type_quic));

    set_pcap("http_request.capture2.pcap");
    CHECK(0 == counter(fingerprint_type_quic));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test quic filtering")
{
    libmerc_config config{.packet_filter_cfg = (char *)"quic"};
    initialize(config);

    set_pcap("quic_init.capture2.pcap");
    CHECK(0 == counter(fingerprint_type_quic));

    set_pcap("mdns_capture.pcap");
    CHECK(0 == counter(fingerprint_type_quic));

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test dhcp filtering with analysis")
{
    libmerc_config config{.do_analysis = true,
                          .resources = resources_minimal_path,
                          .packet_filter_cfg = (char *)"dhcp"};
    initialize(config);

    set_pcap("capture2.pcap");
    CHECK(279 == counter());

    set_pcap("mdns_capture.pcap");
    CHECK(0 == counter());

    deinitialize();
}

TEST_CASE_METHOD(LibmercTestFixture, "test dhcp filtering")
{
    libmerc_config config{.packet_filter_cfg = (char *)"dhcp"};
    initialize(config);

    set_pcap("capture2.pcap");
    CHECK(279 == counter());

    deinitialize();
}
