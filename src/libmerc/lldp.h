// lldp.h
//
// link layer discovery protocol (IEEE 802.1AB)

#ifndef LLDP_H
#define LLDP_H

#include "datum.h"
#include "eth.h"


class chassis_id {
    uint8_t subtype;
    datum id;

    enum basis : uint8_t {
        reserved           = 0,
        chassis_component  = 1,  // rfc4133
        interface_alias    = 2,  // rfc2863
        port_component     = 3,  // rfc4133
        mac_address        = 4,  // ieee802
        network_address    = 5,  // AF byte then raw ipv4 or ipv6 addr
        interface_name     = 6,  // rfc2863
        locally_assigned   = 7,  // alphanumeric string
    };

public:

    chassis_id(datum &d) {
        d.read_uint8(&subtype);
        id = d;
    }

    bool is_valid() const { return id.is_not_empty(); }

    void write_json(json_object &o) const {
        if (is_valid()) {
            datum tmp = id;
            json_object cid{o, "chassis_id"};
            if (subtype == mac_address) {
                eth_addr addr{tmp};
                cid.print_key_value("mac_address", addr);
            }
            cid.close();
        }
    }
};

class port_id {
    uint8_t subtype;
    datum id;

public:
    port_id(datum &d) {
        d.read_uint8(&subtype);
        id = d;
    }

    bool is_valid() const { return id.is_not_empty(); }

    void write_json(json_object &o) const {
        if (is_valid()) {
            datum tmp = id;
            json_object pid{o, "port_id"};
            pid.print_key_json_string("xxx", tmp);
            pid.close();
        }
    }
};

class time_to_live {
    uint16_t value_;

public:
    time_to_live(datum &d) {
        d.read_uint16(&value_);
    }

    uint16_t value() const { return value_; }
};

class system_capabilities {
    uint16_t capabilities;
    uint16_t enabled_capabilities;
    bool valid = false;

    enum type : uint16_t {
        other               = 1,
        repeater            = 2,
        mac_bridge          = 4,
        wlan_access_point   = 8,
        router              = 16,
        telephone           = 32,
        docsis_cable_device = 64,
        station_only        = 128,
        c_vlan              = 256,
        s_vlan              = 512,
        two_port_mac_relay  = 1024
    };

    const char *capability_string(uint16_t t) {
        switch(t) {
        case other:               return "other";
        case repeater:            return "repeater";
        case mac_bridge:          return "mac_bridge";
        case wlan_access_point:   return "wlan_access_point";
        case router:              return "router";
        case telephone:           return "telephone";
        case docsis_cable_device: return "docsis_cable_device";
        case station_only:        return "station_only";
        case c_vlan:              return "c_vlan";
        case s_vlan:              return "s_vlan";
        case two_port_mac_relay:  return "two_port_mac_relay";
        default:
            ;
        }
        return "reserved";
    }

public:
    system_capabilities(datum &d) {
        d.read_uint16(&capabilities);
        d.read_uint16(&enabled_capabilities);
        if (d.is_not_null()) {
            valid = true;
        }
    }

    void write_json(json_object &o) {
        if (valid) {
            json_object sc{o, "system_capabilities"};
            json_array sca{sc, "capabilities"};
            for (uint16_t i=1; i > 0; i<<=1) {
                if (capabilities & i) {
                    sca.print_string(capability_string(i));
                }
            }
            sca.close();
            json_array eca{sc, "enabled_capabilities"};
            for (uint16_t i=1; i > 0; i<<=1) {
                if (enabled_capabilities & i) {
                    eca.print_string(capability_string(i));
                }
            }
            eca.close();
            sc.close();
        }
    }
};

class org_specific_tlv {
    uint64_t oui;
    uint8_t subtype;
    datum id;

public:
    org_specific_tlv(datum &d) {
        d.read_uint(&oui, 3);
        d.read_uint8(&subtype);
        id = d;
    }

    bool is_valid() const { return id.is_not_empty(); }

    void write_json(json_object &o) const {
        if (is_valid()) {
            datum tmp = id;
            json_object ost{o, "organizationally_specific_tlv"};
            ost.print_key_uint("oui", oui);
            ost.print_key_uint("subtype", subtype);
            ost.print_key_hex("substring", tmp);
            ost.close();
        }
    }
};


class lldp_tlv {
    uint8_t type;
    datum information_string;

    enum type : uint16_t {
        end_of_pdu       = 0,
        chassis_id       = 1,
        port_id          = 2,
        ttl              = 3,
        port_descr       = 4,
        sys_name         = 5,
        sys_descr        = 6,
        sys_cap          = 7,
        mgmt_addr        = 8,
        org_specific_tlv = 127,
    };

public:

    lldp_tlv(datum &d) {
        uint16_t type_and_length;
        d.read_uint16(&type_and_length);
        type = type_and_length >> 9;
        uint16_t length = type_and_length & 0x01ff;
        information_string.parse(d, length);
    }

    void write_json(json_array &a) const {
        datum tmp = information_string;
        json_object wrapper{a};
        if (type == type::chassis_id) {
            class chassis_id tlv{tmp};
            tlv.write_json(wrapper);

        } else if (type == type::port_id) {
            class port_id tlv{tmp};
            tlv.write_json(wrapper);

        } else if (type == type::ttl) {
            class time_to_live tlv{tmp};
            wrapper.print_key_uint("ttl", tlv.value());

        } else if (type == type::port_descr) {
            wrapper.print_key_json_string("port_description", information_string);

        } else if (type == type::sys_name) {
            wrapper.print_key_json_string("system_name", information_string);

        } else if (type == type::sys_descr) {
            wrapper.print_key_json_string("system_description", information_string);

        } else if (type == type::sys_cap) {
            system_capabilities tlv{tmp};
            tlv.write_json(wrapper);

        } else if (type == type::mgmt_addr) {
            wrapper.print_key_hex("management_address", information_string);  // TODO: expand

        } else if (type == type::org_specific_tlv) {
            class org_specific_tlv ost{tmp};
            ost.write_json(wrapper);

        } else if (type == type::end_of_pdu) {
            if (information_string.is_not_empty()) {
                json_object eop{wrapper, "end_of_pdu"};
                wrapper.print_key_hex("unexpected_data", information_string);
                eop.close();
            }

        } else {
            wrapper.print_key_uint("type_code", type);
            wrapper.print_key_hex("information_string", information_string);
        }
        wrapper.close();
    }

};

class lldp {
    datum tlv_sequence;

public:

    lldp(datum &d) : tlv_sequence{d} { }

    void write_json(json_object &o, bool metadata=false) const {
        (void)metadata;  // ignore parameter

        datum tmp = tlv_sequence;
        json_array lldp_obj{o, "lldp"};
        while (tmp.is_not_empty()) {
            lldp_tlv tlv(tmp);
            tlv.write_json(lldp_obj);
        }
        lldp_obj.close();
    }

    bool is_not_empty() { return true; }  // TODO: validate mandatory TLVs
};

[[maybe_unused]] inline int lldp_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<lldp>(data, size);
}

#endif // LLDP_H
