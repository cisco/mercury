// event.hpp

#ifndef EVENT_HPP
#define EVENT_HPP

#include "queue.h"
#include "dict.h"
#include "flow_key.h"  // for MAX_PORT_STR_LEN and MAX_ADDR_STR_LEN
#include "result.h"    // for MAX_USER_AGENT_LEN
#include "universal61_bytes.hpp"
#include <zlib.h>
#include <cstring>


/// an event_msg represents a observable event
///
enum class event_type : uint8_t {
    fingerprint = 0,
    cert_label  = 1,
    snmp_oid    = 2,
};

/// event_key contains the dictionary-compressed representation of an event.
///
/// Dictionary indices that do not fit in 32 bits are not accepted.
struct event_key {
    std::array<uint32_t, 4> fields{};
    event_type type{event_type::fingerprint};

    bool operator==(const event_key &r) const {
        return fields == r.fields && type == r.type;
    }
};

/// event_msg holds an observable network event with a 4-tuple of string
/// fields and an event type discriminator.
///
/// The interpretation of the 4 fields depends on the event_type:
///
/// **fingerprint events** (protocol fingerprints and destinations):
/// - `fields[0]`: Source IP address (e.g., "192.168.1.10")
/// - `fields[1]`: Fingerprint string (e.g., "tls/1/(0303)[...]")
/// - `fields[2]`: User-Agent or similar application identifier (may be empty)
/// - `fields[3]`: Destination context: "(server_name)(dst_ip)(dst_port)"
///
/// **cert_label events** (TLS certificate device labels):
/// - `fields[0]`: Source IP address (e.g., "192.168.1.10")
/// - `fields[1]`: Empty string (unused)
/// - `fields[2]`: Empty string (unused)
/// - `fields[3]`: Certificate subject common name (e.g., "device.local")
///
/// **snmp_oid events** (SNMP device identifiers):
/// - `fields[0]`: Source IP address (e.g., "192.168.1.10")
/// - `fields[1]`: Empty string (unused)
/// - `fields[2]`: Empty string (unused)
/// - `fields[3]`: SNMP OID string (e.g., "1.3.6.1.2.1.1.5.0")
///
/// The struct provides array-style access via operator[], comparison
/// operators for use in hash tables and sorting, and specialized
/// constructors for each event type.
///
/// \note Field [0] always contains the source IP address regardless of
///       event type. Fields [1] and [2] are unused (empty strings) for
///       cert_label and snmp_oid events.
///
struct event_msg {
    std::array<std::string, 4> fields;
    event_type type;

    event_msg() : fields{}, type{event_type::fingerprint} {}

    event_msg(const std::string &a,
              const std::string &b,
              const std::string &c,
              const std::string &d,
              event_type t = event_type::fingerprint) :
        fields{a, b, c, d},
        type{t} {}

    std::string &operator[](size_t idx) { return fields[idx]; }
    const std::string &operator[](size_t idx) const { return fields[idx]; }

    bool operator==(const event_msg &r) const {
        return fields == r.fields && type == r.type;
    }

    bool operator<(const event_msg &r) const {
        if (fields < r.fields) {
            return true;
        }
        if (r.fields < fields) {
            return false;
        }
        return static_cast<uint8_t>(type) < static_cast<uint8_t>(r.type);
    }
};

namespace universal61 {

/// \brief Stateful universal61 hash for event messages.
///
/// \details
/// The event type and all four fields are appended in order. Each field is
/// length-prefixed so distinct field tuples cannot share a byte concatenation.
///
struct event_msg_hasher {
    byte_hasher hasher;

    /// \brief Hash an event message using ordered, length-prefixed fields.
    ///
    /// \param event The event message to hash.
    /// \return The hash value converted to `std::size_t`.
    ///
    std::size_t operator()(const ::event_msg &event) const noexcept {
        byte_hash_state state = hasher.begin();
        state.append(static_cast<uint64_t>(event.type));
        for (const std::string &field : event.fields) {
            state.append_length(field.size());
            state.append_bytes(field);
        }
        return static_cast<std::size_t>(state.finish());
    }
};

/// Stateful universal61 hash for compressed event keys.
///
struct event_key_hasher {
    byte_hasher hasher;

    /// Hash an event key using its type and dictionary indices.
    ///
    /// \param key The compressed event key.
    /// \return The hash value converted to `std::size_t`.
    ///
    std::size_t operator()(const ::event_key &key) const noexcept {
        byte_hash_state state = hasher.begin();
        state.append(static_cast<uint64_t>(key.type));
        state.append_four(key.fields[0], key.fields[1],
                          key.fields[2], key.fields[3]);
        return static_cast<std::size_t>(state.finish());
    }
};

#ifndef NDEBUG
// LCOV_EXCL_START
/// \brief Test event-message hashing and field-boundary preservation.
///
/// \return True if all event-message hash checks pass.
///
inline bool event_msg_hasher_unit_test() {
    const event_msg_hasher hasher{
        byte_hasher{{
            0x0123456789abcdefULL,
            0x0f0e0d0c0b0a0908ULL,
        }}
    };
    const ::event_msg split_fields{
        "ab", "c", "", "", event_type::fingerprint};
    const ::event_msg joined_fields{
        "a", "bc", "", "", event_type::fingerprint};
    const ::event_msg shifted_fields{
        "ab", "", "c", "", event_type::fingerprint};
    const ::event_msg different_type{
        "ab", "c", "", "", event_type::cert_label};

    return hasher(split_fields) == 0x13c2139e56ab8d09ULL
        && hasher(joined_fields) == 0x04f02f35dcb67425ULL
        && hasher(different_type) == 0x07d85db31e93bdc5ULL
        && hasher(split_fields) != hasher(shifted_fields);
}
// LCOV_EXCL_STOP
#endif

} // namespace universal61

namespace std {

    /// specialize `std::hash` for `event_key`, for use in
    /// `std::unordered_map` and friends
    ///
    template <>
    struct hash<event_key> {
        size_t operator()(const event_key &x) const {
            return std::hash<uint32_t>{}(x.fields[0])
                ^ std::hash<uint32_t>{}(x.fields[1])
                ^ std::hash<uint32_t>{}(x.fields[2])
                ^ std::hash<uint32_t>{}(x.fields[3])
                ^ std::hash<uint8_t>{}(static_cast<uint8_t>(x.type));
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
        dest_context.append(utf8_string::get_utf8_string(analysis.destination.sn_str)).append(")(");
        dest_context.append(dst_ip_str).append(")(");
        dest_context.append(dst_port_str).append(")");

        return event_msg{src_ip_str, analysis.fp.string(), analysis.destination.ua_str, dest_context, event_type::fingerprint};
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
        dest_context.append(utf8_string::get_utf8_string(analysis.destination.sn_str)).append(")(");
        dest_context.append(analysis.destination.dst_ip_str).append(")(");
        dest_context.append(dst_port_str).append(")");

        return event_msg{src_ip_str, analysis.fp.string(), utf8_string::get_utf8_string(analysis.destination.ua_str), dest_context, event_type::fingerprint};
    }

    inline event_msg construct_cert_label_event(const struct key &k,
                                                const std::string &common_name)
    {
        char src_ip_str[MAX_ADDR_STR_LEN];
        k.sprint_src_addr(src_ip_str);
        return event_msg{src_ip_str, "", "", common_name, event_type::cert_label};
    }

    inline bool is_cert_label_event(const event_msg &event)
    {
        return event.type == event_type::cert_label;
    }

    inline std::string get_cert_label_common_name(const event_msg &event)
    {
        return event[3];
    }

    inline event_msg construct_snmp_oid_event(const struct key &k,
                                              const std::string &oid_string)
    {
        char src_ip_str[MAX_ADDR_STR_LEN];
        k.sprint_src_addr(src_ip_str);
        return event_msg{src_ip_str, "", "", oid_string, event_type::snmp_oid};
    }

    inline bool is_snmp_oid_event(const event_msg &event)
    {
        return event.type == event_type::snmp_oid;
    }

    inline std::string get_snmp_oid_string(const event_msg &event)
    {
        return event[3];
    }

};

/// class event_encoder provides methods to compress and decompress events.
/// Its member functions are not const because they may update the dict
/// member.
///
class event_encoder {
    dict addr_dict;
    dict fp_dict;
    dict ua_dict;
    dict ctx_dict;

    static bool compress_field(dict &dictionary,
                               const std::string &value,
                               uint32_t &index,
                               bool no_new_entries)
    {
        uint64_t wide_index;
        bool prohibit_new_entries = no_new_entries ||
                                    dictionary.count > std::numeric_limits<uint32_t>::max();
        if (dictionary.compress(value, wide_index, prohibit_new_entries) == false ||
            wide_index > std::numeric_limits<uint32_t>::max()) {
            return false;
        }
        index = static_cast<uint32_t>(wide_index);
        return true;
    }

public:
    event_encoder() = default;

    size_t dictionary_bytes() const {
        return addr_dict.memory_bytes() +
               fp_dict.memory_bytes() +
               ua_dict.memory_bytes() +
               ctx_dict.memory_bytes();
    }

    bool compute_inverse_map() {
        return addr_dict.compute_inverse_map() &&
               fp_dict.compute_inverse_map() &&
               ua_dict.compute_inverse_map() &&
               ctx_dict.compute_inverse_map();
    }

    void get_inverse(event_msg &event, const event_key &key) {
        event.type = key.type;
        event[0] = addr_dict.get_inverse(key.fields[0]);
        event[1] = fp_dict.get_inverse(key.fields[1]);
        event[2] = ua_dict.get_inverse(key.fields[2]);
        event[3] = ctx_dict.get_inverse(key.fields[3]);
    }

    /// compresses the event \p event into the compact \p key representation.
    /// If \p no_new_entries is true, this succeeds only when all dictionary
    /// values are already present.
    bool compress_event(event_key &key,
                        const event_msg &event,
                        bool no_new_entries=false)
    {
        if (compress_field(addr_dict, event[0], key.fields[0], no_new_entries) == false ||
            compress_field(fp_dict, event[1], key.fields[1], no_new_entries) == false ||
            compress_field(ua_dict, event[2], key.fields[2], no_new_entries) == false ||
            compress_field(ctx_dict, event[3], key.fields[3], no_new_entries) == false) {
            return false;
        }
        key.type = event.type;
        return true;
    }

    /// remove all dictionary entries, to reset this `event_encoder` to
    /// the initial state
    ///
    void clear() {
        addr_dict.clear();
        fp_dict.clear();
        ua_dict.clear();
        ctx_dict.clear();
    }

};

/// class event_processor_gz coverts a sequence of sorted event
/// strings into an alternative JSON representation
///
class event_processor_gz {
    event_msg prev_fingerprint;
    bool have_prev_fingerprint = false;
    bool first_loop = true;
    gzFile gzf;
    std::array<std::string, 4> v;
    std::string current_src_ip;
    bool device_info_open = false;
    bool cert_labels_open = false;
    bool snmp_labels_open = false;
    bool fingerprints_open = false;

    void close_record() {
        int gz_ret = 1;
        if (fingerprints_open) {
            gz_ret = gzprintf(gzf, "}]}]}]}");
        } else if (snmp_labels_open) {
            gz_ret = gzprintf(gzf, "}]}, \"fingerprints\":[]}");
        } else if (cert_labels_open) {
            gz_ret = gzprintf(gzf, "}]}, \"fingerprints\":[]}");
        } else if (device_info_open) {
            gz_ret = gzprintf(gzf, "}, \"fingerprints\":[]}");
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
        if (!device_info_open) {
            gz_ret = gzprintf(gzf, ", \"device_info\":{");
            if (gz_ret <= 0) {
                throw std::runtime_error("error in gzprintf");
            }
            device_info_open = true;
        }
        if (!cert_labels_open) {
            gz_ret = gzprintf(gzf, "\"cert_labels\":[{\"common_name\":\"%s\",\"count\":%u", common_name.c_str(), count);
            cert_labels_open = true;
        } else {
            gz_ret = gzprintf(gzf, "},{\"common_name\":\"%s\",\"count\":%u", common_name.c_str(), count);
        }
        if (gz_ret <= 0) {
            throw std::runtime_error("error in gzprintf");
        }
    }

    void add_snmp_oid(const std::string &oid, uint32_t count) {
        int gz_ret = 1;
        if (cert_labels_open) {
            gz_ret = gzprintf(gzf, "}],");
            if (gz_ret <= 0) {
                throw std::runtime_error("error in gzprintf");
            }
            cert_labels_open = false;
        }
        if (!device_info_open) {
            gz_ret = gzprintf(gzf, ", \"device_info\":{");
            if (gz_ret <= 0) {
                throw std::runtime_error("error in gzprintf");
            }
            device_info_open = true;
        }
        if (!snmp_labels_open) {
            gz_ret = gzprintf(gzf, "\"snmp_labels\":[{\"oid\":\"%s\",\"count\":%u", oid.c_str(), count);
            snmp_labels_open = true;
        } else {
            gz_ret = gzprintf(gzf, "},{\"oid\":\"%s\",\"count\":%u", oid.c_str(), count);
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
        snmp_labels_open = false;
        device_info_open = false;
        fingerprints_open = false;
    }

    void process_update(const event_msg &event, uint32_t count, const char *version,
                    const char *resource_version, const char *git_commit_id,
                    uint32_t git_count, const char *init_time) {

        bool is_cert_label = event_string::is_cert_label_event(event);
        bool is_snmp_oid = event_string::is_snmp_oid_event(event);
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
            snmp_labels_open = false;
            device_info_open = false;
            fingerprints_open = false;
            have_prev_fingerprint = false;
            write_record_header(event, version, resource_version, git_commit_id, git_count, init_time);
            first_loop = false;
        }

        if (is_cert_label) {
            add_cert_label(event_string::get_cert_label_common_name(event), count);
            return;
        }
        if (is_snmp_oid) {
            add_snmp_oid(event_string::get_snmp_oid_string(event), count);
            return;
        }

        bool cert_labels_closed = false;
        if (cert_labels_open && !fingerprints_open) {
            int gz_ret = gzprintf(gzf, "}]");
            if (gz_ret <= 0) {
                throw std::runtime_error("error in gzprintf");
            }
            cert_labels_open = false;
            cert_labels_closed = true;
        }
        bool snmp_oids_closed = false;
        if (snmp_labels_open && !fingerprints_open) {
            int gz_ret = gzprintf(gzf, "}]");
            if (gz_ret <= 0) {
                throw std::runtime_error("error in gzprintf");
            }
            snmp_labels_open = false;
            snmp_oids_closed = true;
        }
        if (device_info_open && !fingerprints_open && (cert_labels_closed || snmp_oids_closed)) {
            int gz_ret = gzprintf(gzf, "},");
            if (gz_ret <= 0) {
                throw std::runtime_error("error in gzprintf");
            }
            device_info_open = false;
        }

        // Format the optional parameter user-agent only if it is present. The
        // extra 17 bytes is to account for additional data required for json
        char user_agent[MAX_USER_AGENT_LEN + 17]{"\0"};
        if(event[2][0] != '\0') {
            snprintf(user_agent, sizeof(user_agent), "\"user_agent\":\"%s\", ", event[2].c_str());
        }

        if (!fingerprints_open) {
            const char *prefix = (cert_labels_closed || snmp_oids_closed)
                ? " \"fingerprints\":[{\"str_repr\":\"%s\", \"sessions\": [{%s\"dest_info\":[{\"dst\":\"%s\",\"count\":%u"
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
