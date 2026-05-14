// arp.h
//
// address resolution protocol (RFC 826, STD 37)


#ifndef ARP_H
#define ARP_H

#include <stdio.h>
#include "datum.h"
#include "eth.h"
#include "ip_address.hpp"

class arp_packet {
#ifdef _WIN32
// TODO: REFACTOR to use encoded<>
#pragma pack(1)
#endif
    struct header {
        uint16_t hardware_type;
        uint16_t protocol_type;
        uint8_t hardware_addr_len;
        uint8_t protocol_addr_len;
        uint16_t opcode;

        void fprint(FILE *f) {
            fprintf(f, "arp {\n");
            fprintf(f, "\thwtype:    %u\n", ntoh(hardware_type));
            fprintf(f, "\tptype:     %u\n", ntoh(protocol_type));
            fprintf(f, "\thwaddrlen: %u\n", hardware_addr_len);
            fprintf(f, "\tpaddrlen:  %u\n", protocol_addr_len);
            fprintf(f, "\topcode:    %u\n", ntoh(opcode));
            fprintf(f, "}\n");
        }

        // expected_length() returns the expected length of the ARP
        // frame, excluding the header, in bytes
        //
        ssize_t expected_length() const {
            return 2*(hardware_addr_len + protocol_addr_len);
        }

        uint8_t hw_addr_len() const {
            return hardware_addr_len;
        }

        uint8_t proto_addr_len() const {
            return protocol_addr_len;
        }

        static constexpr std::array<const char *, 5> opcodes {
            (const char *)"RESERVED",        // 0
            (const char *)"REQUEST",         // 1
            (const char *)"REPLY",           // 2
            (const char *)"REQUEST REVERSE", // 3
            (const char *)"REPLY REVERSE"    // 4
        };

        const char *get_opcode() const {
            if (ntoh(opcode) < opcodes.size()) {
                return opcodes[ntoh(opcode)];
            }
            return "unknown";
        }

    }
#ifdef _WIN32
    ;
#pragma pack()
#else
    __attribute__((__packed__));
#endif



public:

    header *hdr;
    datum addresses;

    arp_packet(struct datum &p) : hdr{nullptr}, addresses{} {
        hdr = p.get_pointer<header>();
        if (hdr == nullptr) {
            return;
        }
        //hdr->fprint(stderr);
        if (hdr->expected_length() > p.length()) {
            fprintf(stderr, "ARP frame too short (need %zu, have %zd)\n", hdr->expected_length(), p.length());
        }
        addresses = p;
    }

    void write_json(json_object &o, bool metadata=false) {
        (void)metadata;  // ignore parameter

        json_object arp_obj{o, "arp"};
        if (hdr) {

            arp_obj.print_key_uint("hwtype", ntoh(hdr->hardware_type));
            arp_obj.print_key_uint("protocol", ntoh(hdr->protocol_type));
            arp_obj.print_key_uint("hw_addr_len", hdr->hw_addr_len());
            arp_obj.print_key_uint("proto_addr_len", hdr->proto_addr_len());
            arp_obj.print_key_string("opcode", hdr->get_opcode());

            // TODO: parse ipv4 or ipv6 addr based on
            // hdr->protocol_type and handle addr lengths
            // appropriately

            // TODO: report OUI for addresses

            if (hdr->hw_addr_len() == eth_addr::bytes_in_addr
                && hdr->proto_addr_len() == ipv4_addr::bytes_in_addr) {
                eth_addr sender_hw_addr{addresses};
                ipv4_addr sender_proto_addr;
                sender_proto_addr.parse(addresses);
                eth_addr target_hw_addr{addresses};
                ipv4_addr target_proto_addr;
                target_proto_addr.parse(addresses);
                if (addresses.is_not_null()) {
                    arp_obj.print_key_hex("sender_hw_addr", sender_hw_addr);
                    arp_obj.print_key_value("sender_proto_addr", sender_proto_addr);
                    arp_obj.print_key_hex("target_hw_addr", target_hw_addr);
                    arp_obj.print_key_value("target_proto_addr", target_proto_addr);
                }
            }

        }
        arp_obj.close();
    }

    bool is_valid() const { return hdr != nullptr; }
    bool is_not_empty() const { return hdr != nullptr; }
};

[[maybe_unused]] inline int arp_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<arp_packet>(data, size);
}

namespace arp {
#ifndef NDEBUG
    inline bool unit_test() {
        char buffer[1024];

        uint8_t arp_request[] = {
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0xc0, 0xa8, 0x01, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xc0, 0xa8, 0x01, 0x02
        };
        datum d1{arp_request, arp_request + sizeof(arp_request)};
        arp_packet pkt1{d1};
        if (!pkt1.is_valid()) return false;
        {
            buffer_stream buf{buffer, sizeof(buffer)};
            json_object json{&buf};
            pkt1.write_json(json);
            json.close();
            buf.write_char('\0');
            if (!strstr(buffer, "REQUEST")) return false;
        }

        uint8_t arp_reply[] = {
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0xc0, 0xa8, 0x01, 0x02,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0xc0, 0xa8, 0x01, 0x01
        };
        datum d2{arp_reply, arp_reply + sizeof(arp_reply)};
        arp_packet pkt2{d2};
        if (!pkt2.is_valid()) return false;

        uint8_t too_short[] = { 0x00, 0x01, 0x08, 0x00 };
        datum d3{too_short, too_short + sizeof(too_short)};
        arp_packet pkt3{d3};
        if (pkt3.is_valid()) return false;

        return true;
    }
#endif
} // namespace arp

#endif // ARP_H
