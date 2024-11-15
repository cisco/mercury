// icmp.h
//
// Parsing of ICMP and ICMPv6 packets
//

// TODO:
//
//    * implement Type 138 (Router Renumbering)
//    * implement Type 139 (ICMP Node Information Query)
//    * improve output readability
//    * generate type codes and strings tables from IANA CSV files

#ifndef ICMP_H
#define ICMP_H

#include "datum.h"
#include "protocol.h"
#include "json_object.h"


class icmp_echo {
    uint16_t identifier;
    uint16_t sequence_number;
    datum data;

public:
    icmp_echo() : identifier{0}, sequence_number{0} { }

    void parse(datum &d) {
        d.read_uint16(&identifier);
        d.read_uint16(&sequence_number);
        data = d;
    }

    void write_json(json_object &o) {
        struct json_object json{o, "echo"};
        json.print_key_uint("identifier", identifier);
        json.print_key_uint("sequence_number", sequence_number);
        json.print_key_hex("data", data);
        json.close();
    }

};

class icmp_destination_unreachable {
    datum original_datagram;

public:
    icmp_destination_unreachable() { }

    void parse(datum &d) {
        d.skip(4);  // unused field
        original_datagram = d;
    }

    void write_json(json_object &o) {
        struct json_object json{o, "destination_unreachable"};
        json.print_key_hex("original_datagram", original_datagram);
        json.close();
    }

};

// Packet Too Big (following RFC 4443)
//
//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |     Type      |     Code      |          Checksum             |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                             MTU                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                    As much of invoking packet                 |
//      +               as possible without the ICMPv6 packet           +
//      |               exceeding the minimum IPv6 MTU [IPv6]           |


class icmp_packet_too_big {
    uint32_t mtu;
    datum original_datagram;

public:
    icmp_packet_too_big() : mtu{0} { }

    void parse(datum &d) {
        d.read_uint32(&mtu);
        original_datagram = d;
    }

    void write_json(json_object &o) {
        struct json_object json{o, "packet_too_big"};
        json.print_key_uint("mtu", mtu);
        json.print_key_hex("original_datagram", original_datagram);
        json.close();
    }

};



//
//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |     Type      |     Code      |          Checksum             |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                         Message Body                          +
//      |                                                               |
//

class icmp_packet : public datum, public base_protocol {
    uint8_t type;
    uint8_t code;

public:
    icmp_packet(datum &d) : type{0}, code{0} {
        parse(d);
    }

    void parse(datum &d) {
        d.read_uint8(&type);
        d.read_uint8(&code);
        d.skip(2);               // ignore checksum
        data = d.data;           // TODO: create datum::operator=()
        data_end = d.data_end;
    }

    bool is_not_empty() const { return datum::is_not_empty(); }

    void write_json(json_object &o, bool metadata=false) const {
        (void)metadata; // ignore parameter for now

        if (data) {
            struct json_object json{o, "icmp"};
            json.print_key_uint("type", type);
            json.print_key_uint("code", code);

            // write out type-specific data (if we understand it)
            //
            datum tmp = *this; // copy data to preserve const
            if (type == 0 || type == 8 || type == 128 || type == 129) { // echo [reply]
                icmp_echo echo;
                echo.parse(tmp);
                echo.write_json(json);

            } else if (type == 1 || type == 3 || type == 11) { // destination_unreachable or time_exceeded
                icmp_destination_unreachable unreachable;
                unreachable.parse(tmp);
                unreachable.write_json(json);

            } else if (type == 2) { // packet_too_big
                icmp_packet_too_big too_big;
                too_big.parse(tmp);
                too_big.write_json(json);

            } else {
                json.print_key_hex("body", *this);
            }
            json.close();
        }
    }
};




#endif // ICMP_H
