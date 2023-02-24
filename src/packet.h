// packet.h
//

#ifndef PACKET_H
#define PACKET_H

#include "pcap.h"

// pcap_pkthdr mimics the definition used in libpcap, for
// compatibility, while guarding against name collision with libpcap
//
#ifndef lib_pcap_pcap_h

struct pcap_pkthdr {
    struct timeval ts;   // timestamp
    uint32_t caplen;     // length of portion present
    uint32_t len;        // length this packet (off wire)
};

#endif // lib_pcap_pcap_h


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
    // packet capture file provided as an argument, and returns a pair
    // of pointers to the first and last bytes of the packet data
    // (including link layer headers, if present)
    //
#if 0
    std::pair<const uint8_t *, const uint8_t *> get_next(struct pcap_file &pcap) {
        enum status s = pcap.read_packet(&pkthdr, buffer);
        if (s != status_ok) {
            return {nullptr, nullptr};
        }
        return {buffer, buffer + pkthdr.caplen};
    }
#endif

    // same as above, but for a pcap_ng file
    //
    std::pair<const uint8_t *, const uint8_t *> get_next(pcap::ng::reader &pcap) {
        return pcap.read_packet();
    }

    // same as above, but for a pcap file
    //
    std::pair<const uint8_t *, const uint8_t *> get_next(pcap::reader &pcap) {
        return pcap.read_packet();
    }
    // same as above, but for a pcap_file_reader file
    //
    std::pair<const uint8_t *, const uint8_t *> get_next(pcap::file_reader &pcap) {
        return pcap.read_packet();
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

    void write(struct pcap_file &pcap) {
        pcap_file_write_packet_direct(&pcap, buffer, pkthdr.caplen, pkthdr.ts.tv_sec, pkthdr.ts.tv_usec);
    }
};

#endif // PACKET_H
