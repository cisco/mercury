// event.hpp

#ifndef EVENT_HPP
#define EVENT_HPP

#include "queue.hpp"

template <typename T_M>
class event_string
{
    const struct key &k;
    const struct analysis_context &analysis;
    std::string dest_context;
    event_msg event;
    T_M &message_pkt;

public:

    event_string(const struct key &k, const struct analysis_context &analysis, T_M &proto) :
        k{k}, analysis{analysis}, message_pkt{proto} {  }

    event_msg construct_event_string_proto( [[maybe_unused]] tofsee_initial_message &msg) {
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

    template <typename T>
    event_msg construct_event_string_proto([[maybe_unused]] T &msg) {
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

    event_msg construct_event_string() {
        return construct_event_string_proto(message_pkt);
    }
};


#endif // EVENT_HPP
