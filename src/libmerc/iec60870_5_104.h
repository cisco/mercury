/*
 * iec60870_5_104.h
 *
 * Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

/*
 * \file iec60870_5_104.h
 *
 * \brief interface file for IEC60870_5_104 code
 */
#ifndef IEC60870_5_104_H
#define IEC60870_5_104_H

#include <variant>

#include "json_object.h"
#include "util_obj.h"
#include "match.h"
#include "protocol.h"

/*
 * ASDU packet format:
 * When SQ = 0
 *         0  1  2  3  4  5  6  7
 *       +--+--+--+--+--+--+--+--+
 *       |    Type id            |
 *       +--+--+--+--+--+--+--+--+
 *       |0 | No.of.objects      |
 *       +--+--+--+--+--+--+--+--+
 *       |T |N |     COT         |
 *       +--+--+--+--+--+--+--+--+
 *       | Originator address    |
 *       +--+--+--+--+--+--+--+--+
 *       |                       |
 *       +    ASDU address       +
 *       |                       |
 *       +--+--+--+--+--+--+--+--+
 *       |  IOA   | Info element |
 *       +--+--+--+              +
 *       |  8/16/24 ...          |
         +        +--+--+--+--+--+
         |        | IOA    |     |
 *       +--+--+--+--+--+--+     +
 *       |Info element           |
 *       +                 +--+--+
 *       |        ...      | ... |
 *       +--+--+--+--+--+--+--+--+
 *       |        ...            |
 *
 *
 *
 * When SQ = 1
 *         0  1  2  3  4  5  6  7
 *       +--+--+--+--+--+--+--+--+
 *       |    Type id            |
 *       +--+--+--+--+--+--+--+--+
 *       |1 | No.of.objects      |
 *       +--+--+--+--+--+--+--+--+
 *       |T |N |     COT         |
 *       +--+--+--+--+--+--+--+--+
 *       | Originator address    |
 *       +--+--+--+--+--+--+--+--+
 *       |                       |
 *       +    ASDU address       +
 *       |                       |
 *       +--+--+--+--+--+--+--+--+
 *       |  IOA   | Info element |
 *       +--+--+--+              +
 *       |    8/16/24 ...        |
 *       +        +--+--+--+--+--+
 *       |        |Info element  |
 *       +--+--+--+              +
 *       |    8/16/24 ...        |
 *       +        +--+--+--+--+--+
 *       |        |   ....       |
 *       +--+--+--+
 *
 */
class asdu {
    const uint8_t apdu_length;

    encoded<uint8_t> type_id;
    encoded<uint8_t> second_byte;
    bool sq;
    uint8_t num_objects;
    encoded<uint8_t> third_byte;
    bool test;
    bool negative_confirm;
    uint8_t cot;
    encoded<uint8_t> originator_address;
    encoded<uint16_t> asdu_address;
    datum& inf_objs;
    bool valid;
    mutable bool function_indicator=false;

    const char * get_type_string() const {
        switch (type_id) {
        case 1:         return "M_SP_NA_1";
        case 2:         return "M_SP_TA_1";
        case 3:         return "M_DP_NA_1";
        case 4:         return "M_DP_TA_1";
        case 5:         return "M_ST_NA_1";
        case 6:         return "M_ST_TA_1";
        case 7:         return "M_BO_NA_1";
        case 8:         return "M_BO_TA_1";
        case 9:         return "M_ME_NA_1";
        case 10:        return "M_ME_TA_1";
        case 11:        return "M_ME_NB_1";
        case 12:        return "M_ME_TB_1";
        case 13:        return "M_ME_NC_1";
        case 14:        return "M_ME_TC_1";
        case 15:        return "M_IT_NA_1";
        case 16:        return "M_IT_TA_1";
        case 17:        return "M_EP_TA_1";
        case 18:        return "M_EP_TB_1";
        case 19:        return "M_EP_TC_1";
        case 20:        return "M_PS_NA_1";
        case 21:        return "M_ME_ND_1";
        case 30:        return "M_SP_TB_1";
        case 31:        return "M_DP_TB_1";
        case 32:        return "M_ST_TB_1";
        case 33:        return "M_BO_TB_1";
        case 34:        return "M_ME_TD_1";
        case 35:        return "M_ME_TE_1";
        case 36:        return "M_ME_TF_1";
        case 37:        return "M_IT_TB_1";
        case 38:        return "M_EP_TD_1";
        case 39:        return "M_EP_TE_1";
        case 40:        return "M_EP_TF_1";
        case 45:        return "C_SC_NA_1";
        case 46:        return "C_DC_NA_1";
        case 47:        return "C_RC_NA_1";
        case 48:        return "C_SE_NA_1";
        case 49:        return "C_SE_NB_1";
        case 50:        return "C_SE_NC_1";
        case 51:        return "C_BO_NA_1";
        case 58:        return "C_SC_TA_1";
        case 59:        return "C_DC_TA_1";
        case 60:        return "C_RC_TA_1";
        case 61:        return "C_SE_TA_1";
        case 62:        return "C_SE_TB_1";
        case 63:        return "C_SE_TC_1";
        case 64:        return "C_BO_TA_1";
        case 70:        return "M_EI_NA_1";
        case 100:       return "C_IC_NA_1";
        case 101:       return "C_CI_NA_1";
        case 102:       return "C_RD_NA_1";
        case 103:       return "C_CS_NA_1";
        case 104:       return "C_TS_NB_1";
        case 105:       return "C_RP_NC_1";
        case 106:       return "C_CD_NA_1";
        case 107:       return "C_TS_TA_1";
        case 110:       return "P_ME_NA_1";
        case 111:       return "P_ME_NB_1";
        case 112:       return "P_ME_NC_1";
        case 113:       return "P_AC_NA_1";
        case 120:       return "F_FR_NA_1";
        case 121:       return "F_SR_NA_1";
        case 122:       return "F_SC_NA_1";
        case 123:       return "F_LS_NA_1";
        case 124:       return "F_AF_NA_1";
        case 125:       return "F_SG_NA_1";
        case 126:       return "F_DR_TA_1";
        case 127:       return "F_SC_NB_1";
        default:        return nullptr;
        }
    }

    const char * get_cot_string () const {
        switch(cot) {
        case 1:     return "per/cyc";
        case 2:     return "back";
        case 3:     return "spont";
        case 4:     return "init";
        case 5:     return "req";
        case 6:     return "act";
        case 7:     return "actcon";
        case 8:     return "deact";
        case 9:     return "deactcon";
        case 10:    return "actterm";
        case 11:    return "retrem";
        case 12:    return "retloc";
        case 13:    return "file";
        case 20:    return "inrogen";
        case 21:    return "inro1";
        case 22:    return "inro2";
        case 23:    return "inro3";
        case 24:    return "inro4";
        case 25:    return "inro5";
        case 26:    return "inro6";
        case 27:    return "inro7";
        case 28:    return "inro8";
        case 29:    return "inro9";
        case 30:    return "inro10";
        case 31:    return "inro11";
        case 32:    return "inro12";
        case 33:    return "inro13";
        case 34:    return "inro14";
        case 35:    return "inro15";
        case 36:    return "inro16";
        case 37:    return "reqcogen";
        case 38:    return "reqco1";
        case 39:    return "reqco2";
        case 40:    return "reqco3";
        case 41:    return "reqco4";
        case 44:    return "uknown_type";
        case 45:    return "uknown_cause";
        case 46:    return "unknown_asdu_address";
        case 47:    return "unknown_object_address";
        default:    return nullptr;
        }
    }
        
public:
    asdu (struct datum &d, const uint8_t& _apdu_length) :
        apdu_length(_apdu_length),
        type_id(d),
        second_byte(d),
        sq(second_byte.bit<0>()),
        num_objects(second_byte.slice<1, 8>()),
        third_byte(d),
        test(third_byte.bit<0>()),
        negative_confirm(third_byte.bit<1>()),
        cot(third_byte.slice<2, 8>()),
        originator_address(d),
        asdu_address(d),
        inf_objs(d),
        valid(d.is_not_null() && num_objects) { }

    bool is_not_empty() { return valid; }

    void write_json(struct json_object &o) const {
        if (!valid) {
            return;
        }
        type_codes<asdu> code{*this};
        function_indicator=false;
        o.print_key_value("type_id", code);
        
        o.print_key_bool("sq", sq);
        o.print_key_uint8("number_of_objects", num_objects);
        o.print_key_bool("test_bit", test);
        o.print_key_bool("negative_confirm", negative_confirm);

        function_indicator=true;
        o.print_key_value("cot", code);

        o.print_key_uint8("originator_address", originator_address);
        o.print_key_uint16("asdu_address", asdu_address);

         // Information objects should have a minimum length of 3 bytes(IOA) + 1 bytes(info element)
        if (!num_objects or inf_objs.length() < 4) {
            return;
        }

        uint8_t info_elem_size;
        if (sq) {
            /*
             * The length of information object can be computed using APDU length
             * information object_length (bytes) = APDU_length – ADPU_control_fields (4 bytes)
             *                                     – ASDU_header (6 bytes) – IOA (3 bytes);
             *                                   = APDU_length – 13 bytes
             * Size of each info element = information object length/number_of_objects
             */
            info_elem_size = (apdu_length - 13) / num_objects;
            struct json_object info_obj{o, "information_object"};

            datum ioa;
            ioa.parse(inf_objs, 3);
            info_obj.print_key_hex("information_object_address", ioa);

            struct json_array info_elem{info_obj, "information_elements"};
            uint8_t cnt = 0;
            datum data;
            while (cnt < num_objects and inf_objs.is_not_empty()) {
                data.parse(inf_objs, info_elem_size);
                info_elem.print_hex(data);
                cnt++;
            }
            info_elem.close();
            info_obj.close();   
        } else {
            /*
             * information object_length (bytes) = (APDU_length – ADPU_control_fields (4 bytes)
             *                          – ASDU_header (6 bytes))/ number_of_objects – IOA (3 bytes)
             *                                   = APDU_length – 10 bytes) / number_of_objects - 3
             */
            info_elem_size = ((apdu_length - 10) / num_objects) - 3;
            struct json_array info_objs{o, "info_objs"};
            uint8_t cnt = 0;
            while (cnt < num_objects and inf_objs.is_not_empty()) {
                struct json_object info_obj(info_objs);
                datum ioa;
                ioa.parse(inf_objs, 3);
                info_obj.print_key_hex("information_object_address", ioa);

                datum info_elem;
                info_elem.parse(inf_objs, info_elem_size);
                info_obj.print_key_hex("information_element", info_elem);
                info_obj.close();
            }
            info_objs.close();
        }
    }

    uint8_t get_code() const {
        if(function_indicator)
            return cot;
        else
            return type_id.value();
    }

    const char* get_code_str() const {
        if(function_indicator)
            return get_cot_string();
        else
            return get_type_string();
    }
};

class sequence_number {
public:
    uint16_t seq_number;

    sequence_number (struct datum &d) {
        d.read_uint16(&seq_number);
        seq_number = seq_number >> 1;
    }
};

/*
 *  I-frame control fields:
 *        0 1 2 3 4 5 6 7
 *       +-+-+-+-+-+-+-+-+
 *       | Send seq no |0|
 *       +-+-+-+-+-+-+-+-+
 *       |   Send seq no |
 *       +-+-+-+-+-+-+-+-+
 *       |  Rcv  seq no|0|
 *       +-+-+-+-+-+-+-+-+
 *       |   Rcv  seq no |
 *       +-+-+-+-+-+-+-+-+
 */
        
class i_frame {
    sequence_number send_seq_number;
    sequence_number recv_seq_number;
    asdu asdu_obj;

public:
    i_frame (struct datum &d, const uint8_t& apdu_length) :
        send_seq_number(d),
        recv_seq_number(d),
        asdu_obj(d, apdu_length) { }

    bool is_not_empty() { return asdu_obj.is_not_empty(); }

    void write_json(struct json_object &o) const {
        struct json_object r{o, "i_frame"};
        r.print_key_uint("send_sequence_number", send_seq_number.seq_number);
        r.print_key_uint("receive_sequence_number", recv_seq_number.seq_number);
        asdu_obj.write_json(r);
        r.close();
    }
};

/*
 * S-Frame format:
 *        0 1 2 3 4 5 6 7
 *       +-+-+-+-+-+-+-+-+
 *       |           |0|1|
 *       +-+-+-+-+-+-+-+-+
 *       |               |
 *       +-+-+-+-+-+-+-+-+
 *       |  Rcv  seq no|0|
 *       +-+-+-+-+-+-+-+-+
 *       |   Rcv  seq no |
 *       +-+-+-+-+-+-+-+-+
 */
class s_frame {
    skip_bytes<2> reserved;
    sequence_number recv_seq_number;
    bool valid;

public:
    s_frame (struct datum &d) :
        reserved(d),
        recv_seq_number(d),
        valid(d.is_not_null()) { }

    bool is_not_empty() { return valid; }

    void write_json(struct json_object &o) const {
        struct json_object r{o, "s_frame"};
        r.print_key_uint("receive_sequence_number", recv_seq_number.seq_number);
        r.close();
    } 
};

/*
 * U-Frame format:
 *         0  1  2  3  4  5  6  7
 *       +--+--+--+--+--+--+--+--+
 *       |Test | STOP|START| 0| 1|
 *       +--+--+--+--+--+--+--+--+
 *       |                       |
 *       +--+--+--+--+--+--+--+--+
 *       |                    | 0|
 *       +--+--+--+--+--+--+--+--+
 *       |                       |
 *       +--+--+--+--+--+--+--+--+
 */

class u_frame {
    enum uframe_type {
        TEST_FRAME_ACTIVATION = 0x43,
        TEST_FRAME_CONFIRMATION = 0x83,
        STOP_DATA_TRANSFER_ACTIVATION = 0x13,
        STOP_DATA_TRANSFER_CONFIRMATION = 0x23,
        START_DATA_TRANSFER_ACTIVATION = 0x07,
        START_DATA_TRANSFER_CONFIRMATION = 0x0B
    };

    encoded<uint8_t> function;
    bool valid;

    const char * get_function_string() const {
        switch(function) {
        case TEST_FRAME_ACTIVATION:            return "test_frame_activation";
        case TEST_FRAME_CONFIRMATION:          return "test_frame_confirmation";
        case STOP_DATA_TRANSFER_ACTIVATION:    return "stop_data_transfer_activation";
        case STOP_DATA_TRANSFER_CONFIRMATION:  return "stop_data_transfer_confirmation";
        case START_DATA_TRANSFER_ACTIVATION:   return "start_data_transfer_activation";
        case START_DATA_TRANSFER_CONFIRMATION: return "start_data_transfer_confirmation";
        default:                               break;
        }
        return "unknown";
    }

public:
    u_frame (struct datum &d) : 
        function(d),
        valid(d.is_not_null()) { }

    bool is_not_empty() { return valid; }

    void write_json(struct json_object &o) const {
        struct json_object r{o, "u_frame"};
        r.print_key_string("u_frame_function", get_function_string());
        r.close();
    }            
};

struct write_iec_json {
    json_object &o;
public:
    write_iec_json(json_object &json) : o{json} { }

    template <typename T> void operator()(T &x) { x.write_json(o); }

    void operator()(std::monostate &) { }
};

class is_packet_empty {
    template <typename T>
    bool operator()(T &x) { return x.is_not_empty(); }

    bool operator()(std::monostate &) { return false; }
};

/*
 * IEC packet format 
 *         0 1 2 3 4 5 6 7
 *       +-+-+-+-+-+-+-+-+
 *       |start byte 0x68|
 *       +-+-+-+-+-+-+-+-+
 *       |   APDU length |
 *       +-+-+-+-+-+-+-+-+
 *       |   Ctrl Field1 |
 *       +-+-+-+-+-+-+-+-+
 *       |   Ctrl Field2 |
 *       +-+-+-+-+-+-+-+-+
 *       |   Ctrl Field3 |
 *       +-+-+-+-+-+-+-+-+
 *       |   Ctrl Field4 |
 *       +-+-+-+-+-+-+-+-+
 *       |               |
 *       +               +
 *       | Variable      |
 *         length  ASDU  
 *       |     ...       |
 *       +               +
 *       |               |
 *       +-+-+-+-+-+-+-+-+
 */

template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; }; // (1)
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;
 
class iec60870_5_104 : public base_protocol {
    literal<1> start_byte;
    encoded<uint8_t> apdu_length;
    std::variant<std::monostate, i_frame, s_frame, u_frame> packet;

    static constexpr uint8_t frame_type_mask = 0x03;
  
public:
    iec60870_5_104 (struct datum &d) : start_byte(d, {0x68}), apdu_length{d} {
        uint8_t tmp;
        d.lookahead_uint8(&tmp);
        tmp = tmp & frame_type_mask;
        switch (tmp) {
        case 0x0:
            packet.emplace<i_frame>(d, apdu_length);
            break;
        case 0x1:
            packet.emplace<s_frame>(d);
            break;
        case 0x3:
            packet.emplace<u_frame>(d);
            break;
        default:
            packet.emplace<std::monostate>();
        }
    }

    bool is_not_empty() {
        bool empty = std::visit(overloaded {
                    [](std::monostate &) -> bool {return false;},
                    [](i_frame &r) -> bool {return r.is_not_empty(); },
                    [](s_frame &r) -> bool {return r.is_not_empty(); },
                    [](u_frame &r) -> bool {return r.is_not_empty(); }
                    }, packet);
        return empty;
    }

    static constexpr mask_and_value<4> matcher {
        {0xff, 0x00, 0x00, 0x00},
        {0x68, 0x00, 0x00, 0x00}
    };

    /*
     * Length of IEC payload = 2 + apdu_length
     */
    static ssize_t get_payload_length(datum pkt) {
        encoded<uint16_t> len(pkt);
        return (len.slice<8, 16>() + 2);
    }

    void write_json(struct json_object &o, bool) {
        if  (this->is_not_empty()) {
            struct json_object iec{o, "iec60870_5_104"};
            iec.print_key_uint8("apdu_length", apdu_length);
            std::visit(write_iec_json{iec}, packet);
            iec.close();
        }
    }

    static int iec60870_5_104_fuzz_test(const uint8_t *data, size_t size);
};

[[maybe_unused]] inline static int iec60870_5_104_fuzz_test(const uint8_t *data, size_t size) {
    struct datum request_data{data, data+size};
    char buffer_1[8192];
    struct buffer_stream buf_json(buffer_1, sizeof(buffer_1));
    struct json_object record(&buf_json);

    iec60870_5_104 iec_msg{request_data};
    if (iec_msg.is_not_empty()) {
        iec_msg.write_json(record, true);
    }

    return 0;
}

#endif 
