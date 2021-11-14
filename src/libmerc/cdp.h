//
// cdp.h
//
// Cisco Discovery Protocol (CDP)


#ifndef CDP_H
#define CDP_H

#include "eth.h"
#include "datum.h"
#include "json_object.h"

struct cdp_tlv : public datum {
    uint16_t type;
    uint16_t length;

    cdp_tlv() :  datum{NULL, NULL}, type{0}, length{0} {}

    void parse(datum &d) {
        d.read_uint16(&type);
        d.read_uint16(&length);
        datum::parse(d, length - sizeof(type) - sizeof(length));
    }

    void write_json(json_object &o) const {
        if (type == 0x0002) {
            datum tmp = *this;
            uint32_t number_of_addrs;
            tmp.read_uint32(&number_of_addrs);
            // o.print_key_uint("num_addrs", number_of_addrs);

            json_array address_array{o, "addresses"};
            for (unsigned int i = 0; i < number_of_addrs; i++) {
                uint8_t pt;
                tmp.read_uint8(&pt);
                uint8_t pt_length;
                tmp.read_uint8(&pt_length);
                datum protocol;
                protocol.parse(tmp, pt_length);
                uint16_t addr_length;
                tmp.read_uint16(&addr_length);
                datum addr;
                addr.parse(tmp, addr_length);

                json_object a{address_array};
                // a.print_key_uint("pt", pt);
                // a.print_key_uint("pt_length", pt_length);
                // a.print_key_hex("protocol", protocol);
                // a.print_key_uint("addr_length", addr_length);
                if (protocol.is_not_empty()) {
                    if (protocol.data[0] == 0xcc && addr_length == 4) {
                        a.print_key_ipv4_addr("ipv4_addr", addr.data);

                    } else if (protocol.data[0] == 0xAA && addr_length == 16) {
                        a.print_key_ipv6_addr("ipv6_addr", addr.data);
                    }
                }
                //o.print_key_hex("remainder", tmp);
                a.close();
            }
            address_array.close();

        } else if (type == 0x0001) {
            o.print_key_json_string("device_id", *this);
        } else if (type == 0x0003) {
            o.print_key_json_string("interface", *this);
        } else if (type == 0x0004) {
            o.print_key_hex("capabilities", *this);
        } else if (type == 0x0005) {
            o.print_key_json_string("software_version", *this);
        } else if (type == 0x0006) {
            o.print_key_json_string("platform", *this);
        } else if (type == 0x0009) {
            o.print_key_json_string("vtp_domain", *this);
        } else if (type == 0x000a) {
            o.print_key_hex("native_vlan_tag", *this);
        } else if (type == 0x000b) {
            if (this->datum::length() == 1) {
                if (this->data[0] == 0x80) {
                    o.print_key_bool("full_duplex", true);
                } else {
                    o.print_key_bool("full_duplex", true);
                }
            }
            // error condition
        } else if (type == 0x0011) {
            datum tmp = *this;
            size_t mtu;
            tmp.read_uint(&mtu, tmp.length());
            o.print_key_uint("mtu", mtu);
        } else if (type == 0x0014) {
            o.print_key_json_string("sys_name_fqdn", *this);
        } else if (type == 0x0015) {
            o.print_key_hex("sys_mib_oid", *this);  // TBD: print as ASN.1 OID
        } else {
            o.print_key_uint("type", type);
            o.print_key_uint("length", length);
            o.print_key_hex("value", *this);
        }
    }
};

struct cdp {
    uint8_t version;
    uint8_t ttl;
    datum tlv_list;

    // CDP can be recognized by this 'magic' prefix, which appears immediately after
    // the 802 length field.  It consists of the Logical Link Control (LLC) fields
    // followed by the HDLC protocol type value.
    //
    static constexpr std::array<uint8_t, 8> prefix = {
        0xaa,              // LLC DSAP
        0xaa,              // LLC SSAP
        0x03,              // LLC Control Byte
        0x00, 0x00, 0x0c,  // SNAP Vendor Code
        0x20, 0x00         // HDLC Protocol Type
    };

    cdp(datum &d) {
        d.skip(8);                // LLC/SNAP/HDLC prefix
        d.read_uint8(&version);
        d.read_uint8(&ttl);
        d.skip(sizeof(uint16_t)); // checksum
        tlv_list = d;
    }

    void write_json(json_object &o) const {
        //o.print_key_hex("cdp", tlv_list);
        json_array a{o, "cdp"};
        datum tmp = tlv_list;
        while (tmp.is_not_empty()) {
            struct cdp_tlv tlv;
            tlv.parse(tmp);
            if (tlv.is_not_empty()) {
                json_object json_tlv{a};
                tlv.write_json(json_tlv);
                json_tlv.close();
            } else {
                break;
            }
            // o.print_key_hex("tmp", tmp);
        }
        a.close();
    }

    bool is_not_empty() { return tlv_list.is_not_empty(); }
};

#endif // CDP_H
