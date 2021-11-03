// pcap_filter.cc
//
// a pcap file filter
//
// compile as:
//
//   g++ -Wall -Wno-narrowing pcap_filter.cc pcap_file_io.c -o pcap_filter -std=c++17

#include "pcap_file_io.h"
#include "libmerc/eth.h"
#include "libmerc/ip.h"
#include "libmerc/tcpip.h"
#include "libmerc/udp.h"
#include "libmerc/dns.h"
#include "libmerc/quic.h"
#include "libmerc/tls.h"
#include "libmerc/http.h"
#include "options.h"

bool parse_as_dns(struct datum pkt_data);

datum get_udp_data(struct datum eth_pkt);

datum get_tcp_data(struct datum eth_pkt);

int main(int argc, char *argv[]) {

    const char summary[] = "usage: %s --input <infile> --output <output-file-suffix>\n"
                           "\n"
                           "   <pdu> = all | dns | quic | tls_client_hello | http_request\n"
                           "\n";

    class option_processor opt({{ argument::required, "--input",       "input file" },
                                { argument::required, "--output",      "output file suffix" },
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

    if (!input_file_is_set || !output_file_is_set) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    size_t i=0, total=0, transport=0;
    try {

        // create input and output pcap files
        //
        struct pcap_file pcap(input_file.c_str(), io_direction_reader);
        struct pcap_file dns_out(("dns_packet." + output_file).c_str(), io_direction_writer);
        struct pcap_file bad_dns_out(("bad_dns_packet." + output_file).c_str(), io_direction_writer);
        struct pcap_file quic_out(("quic_init." + output_file).c_str(), io_direction_writer);
        struct pcap_file tls_out(("tls_client_hello." + output_file).c_str(), io_direction_writer);
        struct pcap_file http_out(("http_request." + output_file).c_str(), io_direction_writer);
        //struct pcap_file smtp_out(("smtp." + output_file).c_str(), io_direction_writer);

        packet<65536> pkt;
        while (true) {
            datum pkt_data = pkt.get_next(pcap);
            if (!pkt_data.is_not_empty()) {
                break;
            }

            datum pkt_data_copy = pkt_data; // temporary copy

            datum udp_data = get_udp_data(pkt_data);
            if (udp_data.is_not_empty()) {

                datum udp_data_copy = udp_data;
                dns_packet dns{udp_data_copy};
                if (dns.is_not_empty() == expected_value) {
                    pkt.write(dns_out);

                    // verify that this PDU matches the appropriate bitmask
                    if (dns_packet::matcher.matches(udp_data.data, udp_data.length()) == false) {
                        fprintf(stderr, "warning: valid dns_packet does not match bitmask\t");
                        udp_data.fprint_hex(stderr, 16);
                        fputc('\n', stderr);

                        pkt.write(bad_dns_out);
                    }

                    ++i;
                }

                udp_data_copy = udp_data;
                quic_init quic{udp_data_copy};
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

                datum tcp_data_copy = tcp_data;
                struct tls_record rec;
                rec.parse(tcp_data_copy);
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
                http_request request;
                request.parse(tcp_data_copy);
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

bool parse_as_dns(struct datum pkt_data) {

    // TODO: handle GRE, IPinIP, etc.

    eth ethernet{pkt_data};
    uint16_t ethertype = ethernet.get_ethertype();
    switch(ethertype) {
    case ETH_TYPE_IP:
    case ETH_TYPE_IPV6:
        {
            ip ip_pkt;
            key k;
            set_ip_packet(ip_pkt, pkt_data, k);
            uint8_t protocol = std::visit(get_transport_protocol{}, ip_pkt);
            //fprintf(stdout, "packet.ip.protocol: %u\n", protocol);
            if (protocol == 17) {
                class udp udp_pkt{pkt_data};
                udp_pkt.set_key(k);
                struct dns_packet dns;
                dns.parse(pkt_data);
                if (dns.is_not_empty()) {
                    return true;
                }
            }
        }
        break;
    default:
        ;   // ignore other ethertypes
    }

    return false;
}

datum get_udp_data(struct datum eth_pkt) {

    // TODO: handle GRE, IPinIP, etc.

    eth ethernet{eth_pkt};
    uint16_t ethertype = ethernet.get_ethertype();
    switch(ethertype) {
    case ETH_TYPE_IP:
    case ETH_TYPE_IPV6:
        {
            ip ip_pkt;
            key k;
            set_ip_packet(ip_pkt, eth_pkt, k);
            uint8_t protocol = std::visit(get_transport_protocol{}, ip_pkt);
            if (protocol == 17) {
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
            ip ip_pkt;
            key k;
            set_ip_packet(ip_pkt, eth_pkt, k);
            uint8_t protocol = std::visit(get_transport_protocol{}, ip_pkt);
            if (protocol == 6) {
                tcp_packet tcp;
                tcp.parse(eth_pkt);
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

