/*
 * dhcp.h
 */

#ifndef DHCP_H
#define DHCP_H

#include <stdint.h>
#include <stdlib.h>
#include "dhcp.h"
#include "json_object.h"
#include "oui.h"

/*
 * DHCP protocol processing
 */


/*
 *
 * Format of a DHCP message (from RFC 2131)
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
 *  +---------------+---------------+---------------+---------------+
 *  |                            xid (4)                            |
 *  +-------------------------------+-------------------------------+
 *  |           secs (2)            |           flags (2)           |
 *  +-------------------------------+-------------------------------+
 *  |                          ciaddr  (4)                          |
 *  +---------------------------------------------------------------+
 *  |                          yiaddr  (4)                          |
 *  +---------------------------------------------------------------+
 *  |                          siaddr  (4)                          |
 *  +---------------------------------------------------------------+
 *  |                          giaddr  (4)                          |
 *  +---------------------------------------------------------------+
 *  |                                                               |
 *  |                          chaddr  (16)                         |
 *  |                                                               |
 *  |                                                               |
 *  +---------------------------------------------------------------+
 *  |                                                               |
 *  |                          sname   (64)                         |
 *  +---------------------------------------------------------------+
 *  |                                                               |
 *  |                          file    (128)                        |
 *  +---------------------------------------------------------------+
 *  |                                                               |
 *  |                          options (variable)                   |
 *  +---------------------------------------------------------------+
 *
 *  DHCP Options Overview (from RFC 2132)
 *
 *  DHCP options have the same format as the BOOTP 'vendor extensions'
 *  defined in RFC 1497.  Options may be fixed length or variable
 *  length.  All options begin with a tag octet, which uniquely
 *  identifies the option.  Fixed-length options without data consist
 *  of only a tag octet.  Only options 0 and 255 are fixed length.
 *  All other options are variable-length with a length octet
 *  following the tag octet.  The value of the length octet does not
 *  include the two octets specifying the tag and length.  The length
 *  octet is followed by "length" octets of data.  Options containing
 *  NVT ASCII data SHOULD NOT include a trailing NULL; however, the
 *  receiver of such options MUST be prepared to delete trailing nulls
 *  if they exist.  The receiver MUST NOT require that a trailing null
 *  be included in the data.  In the case of some variable-length
 *  options the length field is a constant but must still be
 *  specified.
 *
 *  Pseudo-BNF for option format:
 *     option     := fixed-code | code length data
 *     fixed-code := 0x00 | 0xff
 *     code       := 0x01 | 0x02 | ... | 0xfe
 *     length     := 0x00 | 0x01 | ... | 0xff
 *     data       := [0x00 | 0x01 | ... | 0xff]^length
 *
 *  When used with BOOTP, the first four octets of the vendor
 *  information field have been assigned to the "magic cookie" (as
 *  suggested in RFC 951).  This field identifies the mode in which
 *  the succeeding data is to be interpreted.  The value of the magic
 *  cookie is the 4 octet dotted decimal 99.130.83.99 (or hexadecimal
 *  number 63.82.53.63) in network byte order.
 */

#define L_dhcp_fixed_header 236
#define L_dhcp_magic_cookie   4
#define L_dhcp_option_tag     1
#define L_dhcp_option_length  1

#define DHCP_OPT_PAD 0x00
#define DHCP_OPT_END 0xff
#define DHCP_OPT_MESSAGE_TYPE   0x35
#define DHCP_OPT_PARAMETER_LIST 0x37
#define DHCP_OPT_VENDOR_CLASS   0x7C

enum class dhcp_option_type : uint8_t {
	Pad = 0x0000,
	Subnet_Mask = 0x0001,
	Time_Offset = 0x0002,
	Router= 0x0003,
	Time_Server = 0x0004,
	Name_Server = 0x0005,
	Domain_Server = 0x0006,
	Log_Server = 0x0007,
	Quotes_Server = 0x0008,
	LPR_Server = 0x0009,
	Impress_Server = 0x000a,
	RLP_Server = 0x000b,
	Hostname = 0x000c,
	Boot_File_Size = 0x000d,
	Merit_Dump_File = 0x000e,
	Domain_Name = 0x000f,
	Swap_Server = 0x0010,
	Root_Path = 0x0011,
	Extension_File = 0x0012,
	Forward_On_Off = 0x0013,
	SrcRte_On_Off = 0x0014,
	Policy_Filter = 0x0015,
	Max_DG_Assembly = 0x0016,
	Default_IP_TTL = 0x0017,
	MTU_Timeout = 0x0018,
	MTU_Plateau = 0x0019,
	MTU_Interface = 0x001a,
	MTU_Subnet = 0x001b,
	Broadcast_Address = 0x001c,
	Mask_Discovery = 0x001d,
	Mask_Supplier = 0x001e,
	Router_Discovery = 0x001f,
	Router_Request = 0x0020,
	Static_Route = 0x0021,
	Trailers = 0x0022,
	ARP_Timeout = 0x0023,
	Ethernet = 0x0024,
	Default_TCP_TTL = 0x0025,
	Keepalive_Time = 0x0026,
	Keepalive_Data = 0x0027,
	NIS_Domain = 0x0028,
	NIS_Servers = 0x0029,
	NTP_Servers = 0x002a,
	Vendor_Specific = 0x002b,
	NETBIOS_Name_Srv = 0x002c,
	NETBIOS_Dist_Srv = 0x002d,
	NETBIOS_Node_Type = 0x002e,
	NETBIOS_Scope = 0x002f,
	X_Window_Font = 0x0030,
	X_Window_Manager = 0x0031,
	Address_Request = 0x0032,
	Address_Time = 0x0033,
	Overload = 0x0034,
	DHCP_Msg_Type = 0x0035,
	DHCP_Server_Id = 0x0036,
	Parameter_List = 0x0037,
	DHCP_Message = 0x0038,
	DHCP_Max_Msg_Size = 0x0039,
	Renewal_Time = 0x003a,
	Rebinding_Time = 0x003b,
	Class_Id = 0x003c,
	Client_Id = 0x003d,
	NetWare_IP_Domain = 0x003e,
	NetWare_IP_Option = 0x003f,
	NIS_Domain_Name_= 0x0040,
	NIS_Server_Addr = 0x0041,
	Server_Name = 0x0042,
	Bootfile_Name = 0x0043,
	Home_Agent_Addrs = 0x0044,
	SMTP_Server = 0x0045,
	POP3_Server = 0x0046,
	NNTP_Server = 0x0047,
	WWW_Server = 0x0048,
	Finger_Server = 0x0049,
	IRC_Server = 0x004a,
	StreetTalk_Server = 0x004b,
	STDA_Server = 0x004c,
	User_Class = 0x004d,
	Directory_Agent = 0x004e,
	Service_Scope = 0x004f,
	Rapid_Commit = 0x0050,
	Client_FQDN = 0x0051,
	Relay_Agent_Information = 0x0052,
	iSNS = 0x0053,
	NDS_Servers = 0x0055,
	NDS_Tree_Name = 0x0056,
	NDS_Context = 0x0057,
	BCMCS_Controller_Domain_Name_list = 0x0058,
	BCMCS_Controller_IPv4_address_option = 0x0059,
	Authentication = 0x005a,
	client_last_transaction_time_option = 0x005b,
	associated_ip_option = 0x005c,
	Client_System = 0x005d,
	Client_NDI = 0x005e,
	LDAP = 0x005f,
	UUID_GUID = 0x0061,
	User_Auth = 0x0062,
	GEOCONF_CIVIC = 0x0063,
	PCode = 0x0064,
	TCode = 0x0065,
	IPv6_Only_Preferred = 0x006c,
	OPTION_DHCP4O6_S46_SADDR = 0x006d,
	Netinfo_Address = 0x0070,
	Netinfo_Tag = 0x0071,
	DHCP_Captive_Portal = 0x0072,
	Auto_Config = 0x0074,
	Name_Service_Search = 0x0075,
	Subnet_Selection_Option = 0x0076,
	Domain_Search = 0x0077,
	SIP_Servers_DHCP_Option = 0x0078,
	Classless_Static_Route_Option = 0x0079,
	CCC = 0x007a,
	GeoConf_Option = 0x007b,
	V_I_Vendor_Class = 0x007c,
	V_I_Vendor_Specific_Information = 0x007d,
	PXE = 0x0080,
	Etherboot_signature_6_bytes = 0x0080,
	DOCSIS	= 0x0080,
	TFTP_Server_IP_address = 0x0080,
	PXE_2 = 0x0081,
	Kernel_options_Variable_length = 0x0081,
	Call_Server_IP_address = 0x0081,
	PXE_3 = 0x0082,
	Ethernet_interface_Variable = 0x0082,
	Discrimination_string = 0x0082,
	PXE_4 = 0x0083,
	Remote_statistics_server_IP_address = 0x0083,
	PXE_5 = 0x0084,
	IEEE_802_1Q_VLAN_ID = 0x0084,
	PXE_6 = 0x0085,
	IEEE_802_1Dp_Layer_2_Priority = 0x0085,
	PXE_7 = 0x0086,
	Diffserv_Code_Point = 0x0086,
	PXE_8 = 0x0087,
	HTTP_Proxy_for_phone_specific = 0x0087,
	OPTION_PANA_AGENT = 0x0088,
	OPTION_V4_LOST = 0x0089,
	OPTION_CAPWAP_AC_V4 = 0x008a,
	OPTION_IPv4_Address_MoS = 0x008b,
	OPTION_IPv4_FQDN_MoS = 0x008c,
	SIP_UA_Configuration_Service_Domains = 0x008d,
	OPTION_IPv4_Address_ANDSF = 0x008e,
	OPTION_V4_SZTP_REDIRECT = 0x008f,
	GeoLoc = 0x0090,
	FORCERENEW_NONCE_CAPABLE = 0x0091,
	RDNSS_Selection = 0x0092,
	TFTP_server_address = 0x0096,
	Etherboot = 0x0096,
	GRUB_configuration_path_name = 0x0096,
	status_code = 0x0097,
	base_time = 0x0098,
	start_time_of_state = 0x0099,
	query_start_time = 0x009a,
	query_end_time = 0x009b,
	dhcp_state = 0x009c,
	data_source = 0x009d,
	OPTION_V4_PCP_SERVER = 0x009e,
	OPTION_V4_PORTPARAMS = 0x009f,
	OPTION_MUD_URL_V4 = 0x00a1,
	Etherboot_2 = 0x00af,
	IP_Telephone = 0x00b0,
	Etherboot_3 = 0x00b1,
	PacketCable_and_CableHome = 0x00b1,
	PXELINUX_Magic = 0x00d0,
	Configuration_File = 0x00d1,
	Path_Prefix = 0x00d2,
	Reboot_Time = 0x00d3,
	OPTION_6RD = 0x00d4,
	OPTION_V4_ACCESS_DOMAIN = 0x00d5,
	Subnet_Allocation_Option = 0x00dc,
	Virtual_Subnet_Selection_Option = 0x00dd,
	End = 0x00ff
};

const char *hwtype_get_string(uint8_t hwtype) {
    switch(hwtype) {
    case 0: return "reserved";
    case 1: return "ethernet";
    case 255: return "identity_association";
    default:
        ;
    }
    return "Unknown";
}

// as per https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml#message-type-53
// retrieved on Oct. 2020
//
const char *msg_type_get_string(uint8_t msg_type) {
    switch(msg_type) {
    case 1: return "discover";
    case 2: return "offer";
    case 3: return "request";
    case 4: return "decline";
    case 5: return "ack";
    case 6: return "nack";
    case 7: return "release";
    case 8: return "inform";
    case 9: return "force_renew";
    case 10: return "lease_query";
    case 11: return "lease_unassigned";
    case 12: return "lease_unknown";
    case 13: return "lease_active";
    case 14: return "bulk_lease_query";
    case 15: return "lease_query_done";
    case 16: return "active_lease_query";
    case 17: return "lease_query_status";
    case 18: return "tls";
    default:
        ;
    }
    return "unknown";
}

struct dhcp_option : public datum {
    uint8_t tag;
    uint8_t length;

    dhcp_option() : datum{NULL, NULL}, tag{0}, length{0} {};

    void parse(struct datum &p) {
        p.read_uint8(&tag);
        if (tag == 0 || tag == 255) {
            return;
        }
        p.read_uint8(&length);
        datum::parse(p, length);
    }

    void write_json(struct json_object &json_opt) {

        switch((dhcp_option_type)tag) {
        case dhcp_option_type::DHCP_Msg_Type:
            {
                uint8_t msg_type = 0;
                datum::read_uint8(&msg_type);
                json_opt.print_key_string("msg_type", msg_type_get_string(msg_type));
            }
            break;
        case dhcp_option_type::Address_Request:
            if (datum::length() == 4) {
                json_opt.print_key_ipv4_addr("requested_address", this->data);
            } // TBD: IPv6
            break;
        case dhcp_option_type::Hostname:
            json_opt.print_key_json_string("hostname", *this);
            break;
        case dhcp_option_type::Class_Id:
            json_opt.print_key_json_string("vendor_class_id", *this);
            break;
        case dhcp_option_type::Client_Id:
            {
                struct json_object json_client_id{json_opt, "client_id"};
                uint8_t hwtype = 0;
                datum::read_uint8(&hwtype);
                json_client_id.print_key_string("hw_type", hwtype_get_string(hwtype));
                if (hwtype != 1 && hwtype != 255) {
                    json_client_id.print_key_uint("hw_type_code", hwtype);
                }
                if (hwtype == 1) { // Ethernet
                    json_client_id.print_key_hex("address", *this);
                    size_t oui = 0;
                    datum_read_uint(this, 3, &oui);
                    auto x = oui_dict.find(oui);
                    if (x != oui_dict.end()) {
                        json_client_id.print_key_string("oui", x->second);
                    }
                } else if (hwtype == 255) {
                    uint32_t iaid;
                    datum::read_uint32(&iaid);
                    json_client_id.print_key_uint("iaid", iaid);
                    uint16_t duid_type;
                    datum::read_uint16(&duid_type);
                    if (duid_type == 2) { // assigned by enterprise number
                        uint32_t en;
                        datum::read_uint32(&en);
                        json_client_id.print_key_uint("enterprise_number", en);
                        json_client_id.print_key_hex("identifier", *this);
                    }
                }
                json_client_id.close();
            }
            break;
        default:
            ;
        }
    }

    void write_json_complete(struct json_array &option_array) {
        struct json_object json_opt{option_array};

        switch((dhcp_option_type)tag) {
        case dhcp_option_type::Address_Time:
            {
                uint32_t addr_time = 0;
                datum::read_uint32(&addr_time);
                json_opt.print_key_uint("ip_address_lease_time", addr_time);
            }
            break;
        case dhcp_option_type::DHCP_Msg_Type:
            {
                uint8_t msg_type = 0;
                datum::read_uint8(&msg_type);
                json_opt.print_key_uint("msg_type", msg_type);
            }
            break;
        case dhcp_option_type::Hostname:
            json_opt.print_key_json_string("hostname", *this);
            break;
        case dhcp_option_type::Class_Id:
            json_opt.print_key_json_string("vendor_class_id", *this);
            break;
        case dhcp_option_type::Client_Id:
            {
                uint8_t hwtype = 0;
                datum::read_uint8(&hwtype);
                json_opt.print_key_uint("hwtype", hwtype);
                json_opt.print_key_hex("client_id", *this);
                size_t oui = 0;
                datum_read_uint(this, 3, &oui);
                auto x = oui_dict.find(oui);
                if (x != oui_dict.end()) {
                    json_opt.print_key_string("oui", x->second);
                }
            }
            break;
        case dhcp_option_type::End:
            {
                json_opt.print_key_string("end", "end");
            }
            break;
        case dhcp_option_type::Pad:
            {
                json_opt.print_key_string("pad", "pad");
            }
            break;
        default:
            json_opt.print_key_uint("tag", tag);
            json_opt.print_key_uint("length", length);
            json_opt.print_key_hex("value", *this);
        }

        json_opt.close();
    }
};


struct dhcp_discover {
    struct datum options;

    dhcp_discover() = default;

    void parse(struct datum &p) {
        p.skip(L_dhcp_fixed_header);
        p.skip(L_dhcp_magic_cookie);
        options = p;
    }

    bool is_not_empty() const { return options.is_not_empty(); }

    void write_json(struct json_object &o) {
        struct json_object json_dhcp{o, "dhcp"};
        struct datum tmp = options;
        while (tmp.is_not_empty()) {
            struct dhcp_option opt;
            opt.parse(tmp);
            opt.write_json(json_dhcp);
        }
        json_dhcp.close();
    }

    void write_json_complete(struct json_object &o) {
        struct json_object json_dhcp{o, "dhcp"};
        //json_dhcp.print_key_hex("options_hex", options);
        //json_dhcp.print_key_datum("options", options);

        struct json_array option_array{json_dhcp, "options"};
        struct datum tmp = options;
        while (tmp.is_not_empty()) {
            struct dhcp_option opt;
            opt.parse(tmp);
            opt.write_json_complete(option_array);
        }
        option_array.close();
        json_dhcp.close();
    }

    void operator()(struct buffer_stream &b) const {

        b.write_char('\"');
        struct datum tmp = options;
        while (tmp.is_not_empty()) {
            struct dhcp_option opt;
            opt.parse(tmp);
            if (opt.tag == DHCP_OPT_PARAMETER_LIST || opt.tag == DHCP_OPT_VENDOR_CLASS || opt.tag == DHCP_OPT_MESSAGE_TYPE) {
                // copy entire option into fingerprint string
                b.write_char('(');
                b.raw_as_hex(&opt.tag, sizeof(opt.tag));
                b.raw_as_hex(&opt.length, sizeof(opt.length));
                b.raw_as_hex(opt.data, opt.data_end - opt.data);
                b.write_char(')');

            } else if (opt.tag != DHCP_OPT_PAD) {
                // copy only option tag into fingerprint string
                b.write_char('(');
                b.raw_as_hex(&opt.tag, sizeof(opt.tag));
                b.write_char(')');
            }
        }
        b.write_char('\"');
    }

};

#endif /* DHCP_H */
