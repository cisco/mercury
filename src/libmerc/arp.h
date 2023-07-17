// arp.h
//
// address resolution protocol (RFC 826, STD 37)


#ifndef ARP_H
#define ARP_H

#include <stdio.h>
#include "datum.h"

class arp_packet {

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

    } __attribute__((__packed__));



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
                arp_obj.print_key_hex("sender_hw_addr", sender_hw_addr);

                ipv4_addr sender_proto_addr;
                sender_proto_addr.parse(addresses);
                arp_obj.print_key_value("sender_proto_addr", sender_proto_addr);

                eth_addr target_hw_addr{addresses};
                arp_obj.print_key_hex("target_hw_addr", target_hw_addr);

                ipv4_addr target_proto_addr;
                target_proto_addr.parse(addresses);
                arp_obj.print_key_value("target_proto_addr", target_proto_addr);
            }

        }
        arp_obj.close();
    }

    bool is_valid() const { return hdr != nullptr; }
    bool is_not_empty() const { return hdr != nullptr; }
};


#endif // ARP_H
