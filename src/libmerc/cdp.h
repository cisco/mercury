//
// cdp.h
//
// Cisco Discovery Protocol (CDP)


#ifndef CDP_H
#define CDP_H

#include "datum.h"
#include "json_object.h"
#include <array>
#include <cstdint>
#include <cstring>

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
            for (unsigned int i = 0; i < number_of_addrs && tmp.is_not_empty(); i++) {
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
                    if (protocol.data[0] == 0xcc) {
                        a.print_key_ipv4_addr("ipv4_addr", addr);

                    } else if (protocol.data[0] == 0xAA) {
                        a.print_key_ipv6_addr("ipv6_addr", addr);
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
                    o.print_key_bool("full_duplex", false);
                }
            }
            // error condition
        } else if (type == 0x0011) {
            datum tmp = *this;
            uint64_t mtu;
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

    void write_json(json_object &o, bool metadata=false) const {
        (void)metadata;  // ignore parameter

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

[[maybe_unused]] inline int cdp_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<cdp>(data, size);
}

// LCOV_EXCL_START
namespace cdp_unit_test {

#ifndef NDEBUG
    inline bool is_aligned_to(const void *ptr, size_t alignment) {
        return reinterpret_cast<std::uintptr_t>(ptr) % alignment == 0;
    }

    template <size_t StorageSize, size_t PacketSize>
    inline const uint8_t *copy_with_unaligned_field(std::array<uint8_t, StorageSize> &storage,
                                                    const std::array<uint8_t, PacketSize> &packet,
                                                    size_t field_offset,
                                                    size_t alignment) {
        if (alignment <= 1 || field_offset >= packet.size() || packet.size() + alignment > storage.size()) {
            return nullptr;
        }

        for (size_t offset = 1; offset <= alignment; offset++) {
            uint8_t *candidate = storage.data() + offset;
            if (!is_aligned_to(candidate + field_offset, alignment)) {
                storage.fill(0);
                for (size_t i = 0; i < packet.size(); i++) {
                    candidate[i] = packet[i];
                }
                return candidate;
            }
        }
        return nullptr;
    }

    inline bool ipv6_address_tlv_unit_test() {
        static constexpr size_t cdp_ipv6_address_offset = 25;
        static constexpr std::array<uint8_t, 41> cdp_ipv6_address_tlv = {
            0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00,
            0x02, 0xb4, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x1d,
            0x00, 0x00, 0x00, 0x01,
            0x01, 0x01, 0xaa, 0x00, 0x10,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        };
        std::array<uint8_t, cdp_ipv6_address_tlv.size() + alignof(uint16_t)> storage{};

        const uint8_t *payload = copy_with_unaligned_field(storage,
                                                           cdp_ipv6_address_tlv,
                                                           cdp_ipv6_address_offset,
                                                           alignof(uint16_t));
        if (payload == nullptr) {
            return false;
        }

        datum d{payload, payload + cdp_ipv6_address_tlv.size()};
        cdp pkt{d};
        if (!pkt.is_not_empty()) {
            return false;
        }

        char buffer[2048];
        buffer_stream buf{buffer, sizeof(buffer)};
        json_object json{&buf};
        pkt.write_json(json, false);
        json.close();
        buf.add_null();

        return strstr(buffer, "ipv6_addr") != nullptr;
    }

    inline bool malformed_address_tlv_unit_test() {
        static constexpr std::array<uint8_t, 25> cdp_truncated_address_tlv = {
            0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00,
            0x02, 0xb4, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x0d,
            0x00, 0x00, 0x00, 0x01,
            0x01, 0x01, 0xcc, 0x00, 0x04
        };

        datum d{cdp_truncated_address_tlv.data(),
                cdp_truncated_address_tlv.data() + cdp_truncated_address_tlv.size()};
        cdp pkt{d};
        if (!pkt.is_not_empty()) {
            return false;
        }

        char buffer[2048];
        buffer_stream buf{buffer, sizeof(buffer)};
        json_object json{&buf};
        pkt.write_json(json, false);
        json.close();
        buf.write_char('\0');
        return strstr(buffer, "malformed") != nullptr;
    }

    inline bool unit_test() {
        char buffer[2048];

        uint8_t frame[] = {
            0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00,
            0x02, 0xb4, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x0c, 's', 'w', 'i', 't', 'c', 'h', '0', '1',
            0x00, 0x05, 0x00, 0x08, 'v', '1', '.', '0',
            0x00, 0x06, 0x00, 0x0a, 'C', 'i', 's', 'c', 'o', '0',
            0x00, 0x0b, 0x00, 0x05, 0x01
        };
        datum d{frame, frame + sizeof(frame)};
        cdp pkt{d};
        if (!pkt.is_not_empty()) return false;

        buffer_stream buf{buffer, sizeof(buffer)};
        json_object json{&buf};
        pkt.write_json(json, false);
        json.close();
        buf.add_null();
        if (!strstr(buffer, "cdp")) return false;
        if (!strstr(buffer, "device_id")) return false;
        if (!strstr(buffer, "software_version")) return false;
        if (!strstr(buffer, "platform")) return false;

        uint8_t minimal[] = {
            0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00,
            0x02, 0x3c, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x06, 'r', '1'
        };
        datum d2{minimal, minimal + sizeof(minimal)};
        cdp pkt2{d2};
        if (!pkt2.is_not_empty()) return false;

        if (!ipv6_address_tlv_unit_test()) return false;

        return true;
    }
#endif

} // namespace cdp_unit_test

namespace cdp_packet_safety_unit_test {

#ifndef NDEBUG
    inline bool unit_test() {
        return cdp_unit_test::malformed_address_tlv_unit_test();
    }
#endif

} // namespace cdp_packet_safety_unit_test
// LCOV_EXCL_STOP

#endif // CDP_H
