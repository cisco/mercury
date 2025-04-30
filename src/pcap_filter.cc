// pcap_filter.cc
//
// a pcap file filter
//
// compile as:
//
//   g++ -Wall -Wno-deprecated-declarations -Wno-narrowing pcap_filter.cc pcap_file_io.c libmerc/tls.cc libmerc/http.cc libmerc/match.cc libmerc/asn1.cc libmerc/asn1/oid.cc libmerc/config_generator.cc libmerc/addr.cc libmerc/smb2.cc -lcrypto -lssl -o pcap_filter -std=c++17 -DSSLNEW

#include "pcap_file_io.h"
#include "libmerc/eth.h"
#include "libmerc/ip.h"
#include "libmerc/tcpip.h"
#include "libmerc/udp.h"

#include "libmerc/dns.h"
#include "libmerc/quic.h"
#include "libmerc/tls.h"
#include "libmerc/http.h"
#include "pcap.h"
#include "options.h"

using namespace mercury_option;

datum get_udp_data(struct datum eth_pkt);

datum get_tcp_data(struct datum eth_pkt);

class ascii : public datum {

public:

    ascii(datum d, size_t min_run_length, size_t max_run_length) {
        const uint8_t *start = d.data;
        if (d.length() < (ssize_t)max_run_length) {
            return;
        }
        size_t i=0;
        for ( ; i<min_run_length; i++) {
            if (!::isupper(*d.data)) {
                return;
            }
            d.data++;
        }
        for ( ; i<max_run_length; i++) {
            if (!isprint(*d.data) or *d.data==' ') {
                break;
            }
            d.data++;
        }
        this->data = start;
        this->data_end = d.data;
    }

};

int main(int argc, char *argv[]) {

    const char summary[] = "usage: %s --input <infile> --output <outfile>\n\n";

    class option_processor opt({{ argument::required, "--input",       "input file" },
                                { argument::required, "--output",      "output file" },
                                { argument::none,     "--ascii",       "report initial ASCII bytes" },
                                { argument::none,     "--json",        "output JSON representation"},
                                { argument::none,     "--nonmatching", "output non-matching packets"}});

    if (!opt.process_argv(argc, argv)) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    auto [ input_file_is_set, input_file ] = opt.get_value("--input");
    auto [ output_file_is_set, output_file ] = opt.get_value("--output");
    bool json_output  = opt.is_set("--json");
    bool nonmatching  = opt.is_set("--nonmatching");
    bool expected_value = !nonmatching;
    bool report_ascii = opt.is_set("--ascii");

    if (!input_file_is_set || !output_file_is_set) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    quic_crypto_engine quic_crypto{}; // initialize quic_crypto_engine for quic decryption

    size_t i=0, total=0, transport=0;
    try {

        // create input and output pcap files
        //
        pcap::file_reader pcap(input_file.c_str());
        struct pcap_file dns_out(("dns." + output_file + ".pcap").c_str(), io_direction_writer);
        struct pcap_file bad_dns_out(("bad_dns." + output_file + ".pcap").c_str(), io_direction_writer);
        struct pcap_file quic_out(("quic." + output_file + ".pcap").c_str(), io_direction_writer);
        struct pcap_file tls_out(("tls.client_hello." + output_file + ".pcap").c_str(), io_direction_writer);
        struct pcap_file http_out(("http.request." + output_file + ".pcap").c_str(), io_direction_writer);

        packet<65536> pkt;
        while (true) {
            datum pkt_data = pkt.get_next(pcap);
            if (!pkt_data.is_not_empty()) {
                break;
            }

            datum pkt_data_copy = pkt_data; // temporary copy

            datum udp_data = get_udp_data(pkt_data);
            if (udp_data.is_not_empty()) {

                if (report_ascii) {
                    ascii ascii_prefix{udp_data, 3, 8};
                    if (ascii_prefix.is_not_empty()) {
                        fprintf(stdout, "udp\t");
                        ascii_prefix.fprint(stdout); fputc('\n', stdout);
                    }
                }

                datum udp_data_copy = udp_data;
                dns_packet dns{udp_data_copy};
                if (dns.is_not_empty() == expected_value) {
                    pkt.write(dns_out);

                    // verify that this PDU matches the appropriate bitmask
                    if (dns_packet::matcher.matches(udp_data.data, udp_data.length()) == false) {
                        fprintf(stderr, "warning: valid dns_packet does not match bitmask\t");
                        udp_data.fprint_hex(stderr, 16);
                        fputc('\n', stderr);
                        std::array<uint8_t, 8> x = dns_packet::matcher.nonmatching(udp_data.data, udp_data.length());
                        fprintf(stderr, "nonmatching:                                    \t");
                        for (const auto &c : x) { fprintf(stderr, "%02x", c); }
                        fputc('\n', stderr);
                        pkt.write(bad_dns_out);
                    }

                    ++i;
                }

                udp_data_copy = udp_data;
                quic_init quic{udp_data_copy, quic_crypto};
                if (quic.is_not_empty() == expected_value) {
                    if (json_output) {

                        // output json representation of alleged quic initial packet
                        //
                        char output_buffer[8192];
                        struct buffer_stream buf{output_buffer, sizeof(output_buffer)};
                        json_object o{&buf};
                        quic.write_json(o);
                        o.close();
                        buf.write_line(stdout);
                    }

                    pkt.write(quic_out);

                    // verify that this PDU matches the appropriate bitmask
                    if (quic_initial_packet::matcher.matches(udp_data.data, udp_data.length()) == false) {
                        fprintf(stderr, "warning: valid quic_initial_packet does not match bitmask\t");
                        udp_data.fprint_hex(stderr, 16);
                        fputc('\n', stderr);
                    }

                }
                ++transport;
            }

            datum tcp_data = get_tcp_data(pkt_data_copy);
            if (tcp_data.is_not_empty()) {

                if (report_ascii) {
                    ascii ascii_prefix{tcp_data, 3, 8};
                    if (ascii_prefix.is_not_empty()) {
                        fprintf(stdout, "tcp\t");
                        ascii_prefix.fprint(stdout); fputc('\n', stdout);
                    }
                }

                datum tcp_data_copy = tcp_data;
                struct tls_record rec{tcp_data_copy};
                if (rec.type() == tls_content_type::handshake) {
                    struct tls_handshake handshake;
                    handshake.parse(rec.fragment);
                     if (handshake.type() == handshake_type::client_hello) {
                        tls_client_hello client_hello;
                        client_hello.parse(handshake.body);
                        if (client_hello.is_not_empty() == expected_value) {
                            pkt.write(tls_out);

                            // verify that this PDU matches the appropriate bitmask
                            if (tls_client_hello::matcher.matches(tcp_data.data, tcp_data.length()) == false) {
                                fprintf(stderr, "warning: valid tls_client_hello does not match bitmask\t");
                                tcp_data.fprint_hex(stderr, 16);
                                fputc('\n', stderr);
                            }
                        }
                    }
                }

                tcp_data_copy = tcp_data;
                http_request request{tcp_data_copy};
                if (request.is_not_empty() == expected_value) {
                    pkt.write(http_out);

                    // verify that this PDU matches the appropriate bitmask
                    if (http_request::matcher.matches(tcp_data.data, tcp_data.length()) == false) {
                        fprintf(stderr, "warning: valid http_request does not match bitmask\t");
                        tcp_data.fprint_hex(stderr, 16);
                        fputc('\n', stderr);
                    }
                }

            }

            ++total;
        }
    }
    catch (std::exception &e) {
        fprintf(stderr, "error processing pcap_file %s (%s)\n", input_file.c_str(), e.what());
        exit(EXIT_FAILURE);
    }

    // fprintf(stdout, "output packet count:    %zu\n", i);
    // fprintf(stdout, "transport packet count: %zu\n", transport);
    fprintf(stdout, "total packet count:     %zu\n", total);
    return 0;
}

datum get_udp_data(struct datum eth_pkt) {

    // TODO: handle GRE, IPinIP, etc.

    eth ethernet{eth_pkt};
    uint16_t ethertype = ethernet.get_ethertype();
    switch(ethertype) {
    case ETH_TYPE_IP:
    case ETH_TYPE_IPV6:
        {
            key k;
            ip ip_pkt{eth_pkt, k};
            ip::protocol protocol = ip_pkt.transport_protocol();
            if (protocol == ip::protocol::udp) {
                class udp udp_pkt{eth_pkt};
                //udp_pkt.set_key(k);
                return eth_pkt;
            }
        }
        break;
    default:
        ;   // ignore other ethertypes
    }

    return {nullptr, nullptr};
}

datum get_tcp_data(struct datum eth_pkt) {

    // TODO: handle GRE, IPinIP, etc.

    eth ethernet{eth_pkt};
    uint16_t ethertype = ethernet.get_ethertype();
    switch(ethertype) {
    case ETH_TYPE_IP:
    case ETH_TYPE_IPV6:
        {
            key k;
            ip ip_pkt{eth_pkt, k};

            ip::protocol protocol = ip_pkt.transport_protocol();
            if (protocol == ip::protocol::tcp) {
                tcp_packet tcp{eth_pkt};
                //tcp.set_key(k);
                return eth_pkt;
            }
        }
        break;
    default:
        ;   // ignore other ethertypes
    }

    return {nullptr, nullptr};
}

