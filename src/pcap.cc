// pcap.cc
//
// a pcap file reader based on pcap_file_io.h
//
// compile as:
//
//   g++ -Wall -Wno-narrowing pcap.cc pcap_file_io.c -o pcap -std=c++17

#include "pcap_file_io.h"
#include "libmerc/eth.h"
#include "libmerc/ip.h"
#include "libmerc/tcpip.h"
#include "libmerc/udp.h"
#include "pcap.h"

void dump_packet_info(struct datum &pkt_data);

int main(int argc, char *argv[]) {

    if (argc != 2) {
        fprintf(stderr, "error: no file argument provided\nusage: %s <pcap file name>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    char *pcap_file_name = argv[1];

    size_t i=0;
    try {
        //struct pcap_file pcap(pcap_file_name, io_direction_reader);
        pcap_file_reader pcap(pcap_file_name);
        // pcap pcap(pcap_file_name);
        printf("linktype: %s\n", pcap.get_linktype());
        packet<65536> pkt;
        while (true) {
            datum pkt_data = pkt.get_next(pcap);
            if (!pkt_data.is_not_empty()) {
                break;
            }
            //fprintf(stdout, "packet.caplen: %u\n", pkt.caplen());
            dump_packet_info(pkt_data);
            i++;
        }
    }
    catch (std::exception &e) {
        fprintf(stderr, "error processing pcap_file %s\n", pcap_file_name);
        fprintf(stderr, "%s\n", e.what());
        exit(EXIT_FAILURE);
    }
    catch (...) {
        fprintf(stderr, "unknown error processing pcap_file %s\n", pcap_file_name);
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "packet count: %zu\n", i);
    return 0;
}

void dump_packet_info(struct datum &pkt_data) {

    eth ethernet{pkt_data};
    uint16_t ethertype = ethernet.get_ethertype();
    switch(ethertype) {
    case ETH_TYPE_IP:
    case ETH_TYPE_IPV6:
        fprintf(stdout, "packet.ethertype: %u\n", ethertype);
        {
            key k;
            ip ip_pkt{pkt_data, k};
            ip::protocol protocol = ip_pkt.transport_protocol();
            fprintf(stdout, "packet.ip.protocol: %u\n", protocol);
            if (protocol == ip::protocol::tcp) {
                struct tcp_packet tcp_pkt{pkt_data};
                tcp_pkt.set_key(k);
                fprintf(stdout, "packet.ip.tcp.data.length: %zd\n", pkt_data.length());
                fprintf(stdout, "packet.ip.tcp.data:");
                pkt_data.fprint_hex(stdout);
                fputc('\n', stdout);
            } else if (protocol == ip::protocol::udp) {
                class udp udp_pkt{pkt_data};
                udp_pkt.set_key(k);
            }
        }
        break;
    default:
        fprintf(stdout, "unknown ethertype (%u)\n", ethertype);
    }
    fputs("packet.data: ", stdout);
    pkt_data.fprint_hex(stdout);
    fputc('\n', stdout);
    fputc('\n', stdout);
}

