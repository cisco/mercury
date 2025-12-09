// event.hpp

#ifndef EVENT_HPP
#define EVENT_HPP

#include "queue.h"
#include "dict.h"


/// an event_msg represents a observable event
///
typedef std::tuple<std::string, std::string, std::string, std::string> event_msg;

namespace std {

    /// specialize `std::hash` for `event_msg`, for use in
    /// `std::unordered_map` and friends
    ///
    template <>
    struct hash<event_msg> {
        size_t operator()(const event_msg & x) const {
            std::hash<std::string> hasher;
            return hasher(std::get<0>(x))
                ^ hasher(std::get<1>(x))
                ^ hasher(std::get<2>(x))
                ^ hasher(std::get<3>(x));
        }
    };

}

class event_string {
    const struct key &k;
    const struct analysis_context &analysis;
    std::string dest_context;
    event_msg event;

public:

    event_string(const struct key &k, const struct analysis_context &analysis) :
        k{k}, analysis{analysis} {  }

    event_msg construct_event_string_tofsee() {
        //
        // For tofsee initial pkt, src ip, src port and bot ip are important
        // replace dst ip and port with src ip and port
        // add bot ip as user agent string
        //
        char src_ip_str[MAX_ADDR_STR_LEN];
        k.sprintf_dst_addr(src_ip_str);
        char dst_ip_str[MAX_ADDR_STR_LEN];
        k.sprint_src_addr(dst_ip_str);
        char dst_port_str[MAX_PORT_STR_LEN];
        k.sprint_src_port(dst_port_str);

        dest_context.append("(");
        dest_context.append(analysis.destination.sn_str).append(")(");
        dest_context.append(dst_ip_str).append(")(");
        dest_context.append(dst_port_str).append(")");

        event = std::make_tuple(src_ip_str, analysis.fp.string(), analysis.destination.ua_str, dest_context);
        return event;
    }

    event_msg construct_event_string() {
        char src_ip_str[MAX_ADDR_STR_LEN];
        k.sprint_src_addr(src_ip_str);
        char dst_port_str[MAX_PORT_STR_LEN];
        k.sprint_dst_port(dst_port_str);

        dest_context.append("(");
        dest_context.append(analysis.destination.sn_str).append(")(");
        dest_context.append(analysis.destination.dst_ip_str).append(")(");
        dest_context.append(dst_port_str).append(")");

        event = std::make_tuple(src_ip_str, analysis.fp.string(), utf8_string::get_utf8_string(analysis.destination.ua_str), dest_context);
        return event;
    }

};

// class event_encoder provides methods to compress/decompress event string.
// Its member functions are not const because they may update the dict
// member.

class event_encoder {
    dict addr_dict;
    dict fp_dict;
    dict ua_dict;

public:

    event_encoder() : addr_dict{}, fp_dict{}, ua_dict{} {}

    bool compute_inverse_map() {
        return addr_dict.compute_inverse_map() &&
               fp_dict.compute_inverse_map() &&
               ua_dict.compute_inverse_map();
    }

    void get_inverse(event_msg &event) {
        const std::string &saddr = std::get<0>(event);
        const std::string &fngr = std::get<1>(event);
        const std::string &ua   = std::get<2>(event);

        size_t compressed_saddr_num = strtol(saddr.c_str(), NULL, 16);
        size_t compressed_fp_num = strtol(fngr.c_str(), NULL, 16);
        size_t compressed_ua_num = strtol(ua.c_str(), NULL, 16);

        std::get<0>(event) = addr_dict.get_inverse(compressed_saddr_num);
        std::get<1>(event) = fp_dict.get_inverse(compressed_fp_num);
        std::get<2>(event) = ua_dict.get_inverse(compressed_ua_num);
    }

    void compress_event_string(event_msg& event) {

        const std::string &addr = std::get<0>(event);
        const std::string &fngr = std::get<1>(event);
        const std::string &ua   = std::get<2>(event);

        // compress source address string
        char src_addr_buf[9];
        addr_dict.compress(addr, src_addr_buf);

        // compress fingerprint string
        char compressed_fp_buf[9];
        fp_dict.compress(fngr, compressed_fp_buf);

        char compressed_ua_buf[9];
        ua_dict.compress(ua, compressed_ua_buf);

        std::get<0>(event) = src_addr_buf;
        std::get<1>(event) = compressed_fp_buf;
        std::get<2>(event) = compressed_ua_buf;

    }

};


#endif // EVENT_HPP
