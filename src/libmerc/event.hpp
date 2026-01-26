// event.hpp

#ifndef EVENT_HPP
#define EVENT_HPP

#include "queue.h"
#include "dict.h"
#include "flow_key.h"  // for MAX_PORT_STR_LEN and MAX_ADDR_STR_LEN
#include "result.h"    // for MAX_USER_AGENT_LEN
#include <zlib.h>
#include <cstring>


/// an event_msg represents a observable event
///
typedef std::array<std::string, 4> event_msg;

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

namespace event_string {

    inline event_msg construct_event_string_tofsee(const struct key &k,
                                                   const struct analysis_context &analysis)
    {
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

        std::string dest_context;
        dest_context.append("(");
        dest_context.append(analysis.destination.sn_str).append(")(");
        dest_context.append(dst_ip_str).append(")(");
        dest_context.append(dst_port_str).append(")");

        return {src_ip_str, analysis.fp.string(), analysis.destination.ua_str, dest_context};
    }

    inline event_msg construct_event_string(const struct key &k,
                                            const struct analysis_context &analysis)
    {
        char src_ip_str[MAX_ADDR_STR_LEN];
        k.sprint_src_addr(src_ip_str);
        char dst_port_str[MAX_PORT_STR_LEN];
        k.sprint_dst_port(dst_port_str);

        std::string dest_context;
        dest_context.append("(");
        dest_context.append(analysis.destination.sn_str).append(")(");
        dest_context.append(analysis.destination.dst_ip_str).append(")(");
        dest_context.append(dst_port_str).append(")");

        return {src_ip_str, analysis.fp.string(), utf8_string::get_utf8_string(analysis.destination.ua_str), dest_context};
    }

    inline constexpr const char *cert_label_prefix = "cert_label:";

    inline event_msg construct_cert_label_event(const struct key &k,
                                                const std::string &common_name)
    {
        char src_ip_str[MAX_ADDR_STR_LEN];
        k.sprint_src_addr(src_ip_str);
        std::string label{cert_label_prefix};
        label.append(common_name);
        return {src_ip_str, "", "", label};
    }

    inline bool is_cert_label_event(const event_msg &event)
    {
        return event[3].rfind(cert_label_prefix, 0) == 0;
    }

    inline std::string get_cert_label_common_name(const event_msg &event)
    {
        size_t prefix_len = std::strlen(cert_label_prefix);
        if (event[3].size() <= prefix_len) {
            return {};
        }
        return event[3].substr(prefix_len);
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
        const std::string &saddr = event[0];
        const std::string &fngr  = event[1];
        const std::string &ua    = event[2];

        size_t compressed_saddr_num = strtol(saddr.c_str(), NULL, 16);
        size_t compressed_fp_num = strtol(fngr.c_str(), NULL, 16);
        size_t compressed_ua_num = strtol(ua.c_str(), NULL, 16);

        event[0] = addr_dict.get_inverse(compressed_saddr_num);
        event[1] = fp_dict.get_inverse(compressed_fp_num);
        event[2] = ua_dict.get_inverse(compressed_ua_num);
    }

    void compress_event_string(event_msg& event) {

        const std::string &addr = event[0];
        const std::string &fngr = event[1];
        const std::string &ua   = event[2];

        // compress source address string
        char src_addr_buf[9];
        addr_dict.compress(addr, src_addr_buf);

        // compress fingerprint string
        char compressed_fp_buf[9];
        fp_dict.compress(fngr, compressed_fp_buf);

        char compressed_ua_buf[9];
        ua_dict.compress(ua, compressed_ua_buf);

        event[0] = src_addr_buf;
        event[1] = compressed_fp_buf;
        event[2] = compressed_ua_buf;

    }

};

// class event_processor_gz coverts a sequence of sorted event
// strings into an alternative JSON representation
//
class event_processor_gz {
    event_msg prev_fingerprint;
    bool have_prev_fingerprint = false;
    bool first_loop = true;
    gzFile gzf;
    std::array<std::string, 4> v;
    std::string current_src_ip;
    bool cert_labels_open = false;
    bool fingerprints_open = false;

    void close_record() {
        int gz_ret = 1;
        if (fingerprints_open) {
            gz_ret = gzprintf(gzf, "}]}]}]}");
        } else if (cert_labels_open) {
            gz_ret = gzprintf(gzf, "}],\"fingerprints\":[]}");
        } else {
            gz_ret = gzprintf(gzf, ", \"fingerprints\":[]}");
        }
        if (gz_ret <= 0) {
            throw std::runtime_error("error in gzprintf");
        }
    }

    void write_record_header(const event_msg &event, const char *version,
                             const char *resource_version, const char *git_commit_id,
                             uint32_t git_count, const char *init_time) {
        int gz_ret = gzprintf(gzf, "{\"src_ip\":\"%s\", \"libmerc_init_time\" : \"%s\",\"libmerc_version\": \"%s\","
                                   " \"resource_version\" : \"%s\", \"build_number\" : \"%u\", \"git_commit_id\": \"%s\"",
                              event[0].c_str(), init_time, version, resource_version, git_count, git_commit_id);
        if (gz_ret <= 0) {
            throw std::runtime_error("error in gzprintf");
        }
    }

    void add_cert_label(const std::string &common_name, uint32_t count) {
        int gz_ret = 1;
        if (!cert_labels_open) {
            gz_ret = gzprintf(gzf, ", \"cert_labels\":[{\"common_name\":\"%s\",\"count\":%u", common_name.c_str(), count);
            cert_labels_open = true;
        } else {
            gz_ret = gzprintf(gzf, "},{\"common_name\":\"%s\",\"count\":%u", common_name.c_str(), count);
        }
        if (gz_ret <= 0) {
            throw std::runtime_error("error in gzprintf");
        }
    }

public:

    event_processor_gz(gzFile gzfile) : gzf{gzfile} {}

    void process_init() {
        first_loop = true;
        prev_fingerprint = event_msg{};  // re-initialize previous event
        have_prev_fingerprint = false;
        current_src_ip.clear();
        cert_labels_open = false;
        fingerprints_open = false;
    }

    void process_update(const event_msg &event, uint32_t count, const char *version,
                    const char *resource_version, const char *git_commit_id,
                    uint32_t git_count, const char *init_time) {

        bool is_cert_label = event_string::is_cert_label_event(event);
        bool new_src_ip = current_src_ip.empty() || current_src_ip != event[0];

        if (new_src_ip) {
            if (!first_loop) {
                close_record();
                int gz_ret = gzprintf(gzf, "\n");
                if (gz_ret <= 0) {
                    throw std::runtime_error("error in gzprintf");
                }
            }
            current_src_ip = event[0];
            cert_labels_open = false;
            fingerprints_open = false;
            have_prev_fingerprint = false;
            write_record_header(event, version, resource_version, git_commit_id, git_count, init_time);
            first_loop = false;
        }

        if (is_cert_label) {
            add_cert_label(event_string::get_cert_label_common_name(event), count);
            return;
        }

        bool cert_labels_closed = false;
        if (cert_labels_open && !fingerprints_open) {
            int gz_ret = gzprintf(gzf, "}],");
            if (gz_ret <= 0) {
                throw std::runtime_error("error in gzprintf");
            }
            cert_labels_open = false;
            cert_labels_closed = true;
        }

        //Format the optional parameter user-agent only if it is present
        //Extra 15 bytes is to account for additional data required for json
        char user_agent[MAX_USER_AGENT_LEN + 15]{"\0"};
        if(event[2][0] != '\0') {
            snprintf(user_agent, MAX_USER_AGENT_LEN - 1, "\"user_agent\":\"%s\", ", event[2].c_str());
        }

        if (!fingerprints_open) {
            const char *prefix = cert_labels_closed ? " \"fingerprints\":[{\"str_repr\":\"%s\", \"sessions\": [{%s\"dest_info\":[{\"dst\":\"%s\",\"count\":%u"
                                                    : ", \"fingerprints\":[{\"str_repr\":\"%s\", \"sessions\": [{%s\"dest_info\":[{\"dst\":\"%s\",\"count\":%u";
            int gz_ret = gzprintf(gzf, prefix,
                                  event[1].c_str(), user_agent, event[3].c_str(), count);
            if (gz_ret <= 0) {
                throw std::runtime_error("error in gzprintf");
            }
            fingerprints_open = true;
            prev_fingerprint = event;
            have_prev_fingerprint = true;
            return;
        }

        if (!have_prev_fingerprint) {
            prev_fingerprint = event;
            have_prev_fingerprint = true;
        }

        // find number of elements that match previous vector
        size_t num_matching = 0;
        for (num_matching=0; num_matching < v.size()-1; num_matching++) {
            if (prev_fingerprint[num_matching].compare(event[num_matching]) != 0) {
                break;
            }
        }
        // set mismatched previous values
        for (size_t i=num_matching; i < v.size()-1; i++) {
            prev_fingerprint[i] = event[i];
        }

        // output unique elements
        int gz_ret = 1;
        switch(num_matching) {
        case 1:
            gz_ret = gzprintf(gzf, "}]}]},{\"str_repr\":\"%s\", \"sessions\": [{%s\"dest_info\":[{\"dst\":\"%s\",\"count\":%u", event[1].c_str(), user_agent, event[3].c_str(), count);
            break;
        case 2:
            gz_ret = gzprintf(gzf, "}]},{%s\"dest_info\":[{\"dst\":\"%s\",\"count\":%u", user_agent, event[3].c_str(), count);
            break;
        case 3:
            gz_ret = gzprintf(gzf, "},{\"dst\":\"%s\",\"count\":%u", event[3].c_str(), count);
            break;
        default:
            ;
        }
        if (gz_ret <= 0) {
            throw std::runtime_error("error in gzprintf");
        }
    }

    void process_final() {
        if (!first_loop) {
            close_record();
            int gz_ret = gzprintf(gzf, "\n");
            if (gz_ret <= 0) {
                throw std::runtime_error("error in gzprintf");
            }
        }
    }

};


#endif // EVENT_HPP
