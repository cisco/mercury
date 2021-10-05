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
#include "libmerc/udp.h"

// class packet holds a network data packet (in buffer[]) and an
// associated pcap_pkthdr structure, and can load packets from a pcap
// file successively (using get_next())
//
template <size_t N>
class packet {
    uint8_t buffer[N];
    struct pcap_pkthdr pkthdr;
public:

    // packet() initializes an empty (zero-length) packet
    //
    packet() : pkthdr{{0,0},0,0} {}

    // get_next(file) sets this packet to the next one read from the
    // packet capture file provided as an argument, and returns a
    // datum representing the entirety of the packet data
    //
    struct datum get_next(struct pcap_file &pcap) {
        enum status s = pcap_file_read_packet(&pcap, &pkthdr, buffer);
        if (s != status_ok) {
            return {nullptr, nullptr};
        }
        return datum{buffer, buffer + pkthdr.caplen};
    }

    // ts() returns the struct timeval associated with this packet
    //
    struct timeval ts() const { return pkthdr.ts; }

    // caplen() returns the capture length associated with this packet
    // (that is, the number of bytes of the packet that are actually
    // available)
    //
    uint32_t caplen() const { return pkthdr.caplen; }

    // len() returns the length of this packet (that is, the length
    // that the packet claims to have)
    //
    uint32_t len() const { return pkthdr.len; }

};

void dump_packet(struct datum &pkt_data);

int sig_close_flag;  // dummy variable, needed to compile with pcap_file_io.c

int main(int argc, char *argv[]) {

    if (argc != 2) {
        fprintf(stderr, "error: no file argument provided\nusage: %s <pcap file name>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    char *pcap_file_name = argv[1];

    size_t i=0;
    try {
        struct pcap_file pcap(pcap_file_name, io_direction_reader, 0);
        packet<65536> pkt;
        while (true) {
            datum pkt_data = pkt.get_next(pcap);
            if (!pkt_data.is_not_empty()) {
                break;
            }
            //fprintf(stdout, "packet.caplen: %u\n", pkt.caplen());
            //dump_packet(pkt_data);
            i++;
        }
    }
    catch (std::exception &e) {
        fprintf(stderr, "error processing processing pcap_file %s\n", pcap_file_name);
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

void dump_packet(struct datum &pkt_data) {

    eth ethernet{pkt_data};
    uint16_t ethertype = ethernet.get_ethertype();
    switch(ethertype) {
    case ETH_TYPE_IP:
    case ETH_TYPE_IPV6:
        fprintf(stdout, "packet.ethertype: %u\n", ethertype);
        {
            ip ip_pkt;
            key k;
            set_ip_packet(ip_pkt, pkt_data, k);
            uint8_t protocol = std::visit(get_transport_protocol{}, ip_pkt);
            fprintf(stdout, "packet.ip.protocol: %u\n", protocol);
            if (protocol == 6) {
                struct tcp_packet tcp_pkt;
                tcp_pkt.parse(pkt_data);
                tcp_pkt.set_key(k);
                fprintf(stdout, "packet.ip.tcp.data.length: %zd\n", pkt_data.length());
            } else if (protocol == 17) {
                struct udp_packet udp;
                udp.parse(pkt_data);
                udp.set_key(k);
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

