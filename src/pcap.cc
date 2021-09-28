// pcap.cc
//
// pcap file reader
//
// compile as:
//
//   g++ -Wall -Wno-narrowing pcap.cc pcap_file_io.c -o pcap -std=c++17

#include "pcap_file_io.h"
#include "libmerc/datum.h"
#include "libmerc/eth.h"
#include "libmerc/ip.h"
#include "libmerc/tcpip.h"

int sig_close_flag;  // dummy variable, needed to compile with pcap_file_io.c

int main(int argc, char *argv[]) {

    struct pcap_file pcap;

    enum status s = pcap_file_open(&pcap, argv[1], io_direction_reader, 0);
    if (s != status_ok) {
        fprintf(stderr, "pcap_file_open returned %d\n", s);
    }
    fprintf(stderr, "pcap_file_read_packet returned %d\n", s);

    struct pcap_pkthdr pkthdr;
    uint8_t packet_data[65536];  // TODO: eliminate hardcoded value
    do {
        s = pcap_file_read_packet(&pcap, &pkthdr, packet_data);
        fprintf(stdout, "packet.caplen: %u\n", pkthdr.caplen);

        datum packet{packet_data, packet_data + pkthdr.caplen};
        eth ethernet{packet};
        uint16_t ethertype = ethernet.get_ethertype();
        switch(ethertype) {
        case ETH_TYPE_IP:
        case ETH_TYPE_IPV6:
            fprintf(stdout, "packet.ethertype: %u\n", ethertype);
            break;
        default: // unsupported ethertype
            fprintf(stderr, "unknown ethertype (%u)\n", ethertype);
            exit(EXIT_FAILURE);
        }
        ip ip_pkt;
        key k;
        set_ip_packet(ip_pkt, packet, k);

        struct tcp_packet tcp_pkt;
        tcp_pkt.parse(packet);
        tcp_pkt.set_key(k);

        packet.fprint_hex(stdout);
        fprintf(stdout, "\n");

    } while (s == status_ok);
    if (s != status_err_no_more_data) {
        fprintf(stderr, "pcap_file_read_packet returned %d\n", s);
    }

    return 0;
}
