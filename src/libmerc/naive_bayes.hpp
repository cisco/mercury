// naive_bayes.hpp

#ifndef NAIVE_BAYES_HPP
#define NAIVE_BAYES_HPP

#include <string>
#include <vector>
#include <unordered_map>

/// data type used in floating point computations
///
using floating_point_type = long double;


/// an instance of class update represents an update to a prior
/// probability
///
class update {
public:

    unsigned int index;          /// index of probability to update
    floating_point_type value;   /// value of update

    update(unsigned int i, floating_point_type v) : index{i}, value{v} {}

    bool operator==(const update &rhs) const {
        return index == rhs.index
            && value == rhs.value;
    }

    /// combines this update with another set of counts \param
    /// rhs_count, associated with the same data feature value
    ///
    void combine(size_t rhs_count, size_t total_count, floating_point_type base_prior, floating_point_type domain_weight) {

        floating_point_type old_count = expl((value / domain_weight) + base_prior) * total_count;
        size_t old_count_integral = (size_t)roundl(old_count);
        value = (log((floating_point_type)(rhs_count + old_count_integral) / total_count) - base_prior) * domain_weight;
    }

};

template <typename T>
class feature {
public:

    std::unordered_map<T, std::vector<class update>> updates;
    floating_point_type weight;

    feature(floating_point_type w=1.0) : updates{}, weight{w} { }

    // construct a naive bayes feature of type T
    //
    feature(const std::unordered_map<T,uint64_t> &info, size_t total_count, floating_point_type weight=1.0) {
        floating_point_type base_prior = log(0.1 / total_count);
        for (const auto &[feat, count] : info) {
            const auto x = updates.find(feat);
            class update u{ index, (log((floating_point_type)count / total_count) - base_prior ) * weight };
            if (x != updates.end()) {
                x->second.push_back(u);
            } else {
                updates[feat] = { u };
            }
        }
    }

    void add_updates_from_object(rapidjson::Value::ConstMemberIterator itr,
                                 size_t process_index,
                                 size_t total_count
                                 )
    {

        if (itr->value.IsObject() == false) {
            throw std::runtime_error{"json error: expected object, got other type"};
        }

        for (auto &y : itr->value.GetObject()) {
            if (y.value.IsUint64()) {
                if (strcmp(itr->name.GetString(), "classes_ip_as") == 0 && strcmp(y.name.GetString(), "unknown") == 0) {
                    //
                    //  map "unknown" values in classes_ip_as to zero
                    //
                    add_update(0, process_index, y.value.GetUint64(), total_count);
                } else {
                    add_update(convert(y.name.GetString()), process_index, y.value.GetUint64(), total_count);
                }
            } else {
                throw std::runtime_error{"expected uint64, got other type"};
            }
        }

    }

    void add_update(T feature_value,
                    size_t process_index,
                    size_t count,
                    size_t total_count
                    )
    {
        floating_point_type base_prior = log(0.1 / total_count);
        std::pair<T,size_t> value_and_count = { feature_value, count };
        const auto x = updates.find(value_and_count.first);
        class update u{ process_index, (log((floating_point_type)value_and_count.second / total_count) - base_prior) * weight };
        if (x != updates.end()) {
            x->second.push_back(u);
        } else {
            updates[value_and_count.first] = { u };
        }
    }

    /// convert a null-terminated string to type T.  This function is
    /// specialized for several different types
    ///
    static T convert(const char *s);

    // apply a naive bayes feature update to prob_vector
    //
    void update(std::vector<floating_point_type> &prob_vector, const T &value) const {
        auto u = updates.find(value);
        if (u != updates.end()) {
            for (const auto &x : u->second) {
                assert(x.index < prob_vector.size());
                prob_vector[x.index] += x.value;
            }
        }
    }

};

template <>
inline auto feature<std::string>::convert(const char *s) -> std::string {
    return std::string{s};
}

template <>
inline auto feature<uint16_t>::convert(const char *s) -> uint16_t {
    uint64_t tmp = 0;
    try {
        tmp = std::stoul(s);
    }
    catch (...) {
        printf_err(log_warning, "unexpected string \"%s\"", s);
    }
    if (tmp > std::numeric_limits<uint16_t>::max()) {
        printf_err(log_warning, "number %" PRIu64 " too high\n", tmp);
        tmp = 0;    // error: port numbers should 16-bit unsigned integers
    }
    return tmp;
}

template <>
inline auto feature<uint32_t>::convert(const char *s) -> uint32_t {
    uint64_t tmp = 0;
    try {
        tmp = std::stoul(s);
    }
    catch (...) {
        printf_err(log_warning, "unexpected string \"%s\"", s);
    }
    if (tmp > std::numeric_limits<uint32_t>::max()) {
        printf_err(log_warning, "number %" PRIu64 " too high\n", tmp);
        tmp = 0;    // error: port numbers should 16-bit unsigned integers
    }
    return tmp;
}

template <>
inline auto feature<uint64_t>::convert(const char *s) -> uint64_t {
    uint64_t tmp = 0;
    try {
        tmp = std::stoul(s);
    }
    catch (...) {
        printf_err(log_warning, "unexpected string \"%s\"", s);
    }
    return tmp;
}


/// represents an internet protocol address (IPv4 or IPv6)
///
class ip_addr_feature {
    std::unordered_map<uint32_t, std::vector<class update>> ipv4_updates;
    std::unordered_map<ipv6_array_t, std::vector<class update>> ipv6_updates;

public:

    floating_point_type weight;

    ip_addr_feature(floating_point_type w=1.0) : weight{w} { };

    void add_updates_from_object(rapidjson::Value::ConstMemberIterator itr,
                                 size_t process_index,
                                 size_t total_count
                                 )
    {

        if (itr->value.IsObject() == false) {
            throw std::runtime_error{"json error: expected object, got other type"};
        }

        for (auto &y : itr->value.GetObject()) {
            if (y.value.IsUint64()) {
                add_update(y.name.GetString(), process_index, y.value.GetUint64(), total_count);
            } else {
                throw std::runtime_error{"expected uint64, got other type"};
            }
        }

    }

    void add_update(const std::string &feature_value,
                    size_t process_index,
                    size_t count,
                    size_t total_count
                    )
    {
        floating_point_type base_prior = log(0.1 / total_count);
        class update u{ process_index, (log((floating_point_type)count / total_count) - base_prior) * weight };

        if (lookahead<ipv4_address_string> ipv4{datum{feature_value}}) {
            uint32_t addr = ipv4.value.get_value();
            auto update = ipv4_updates.find(addr);
            if (update != ipv4_updates.end()) {
                update->second.push_back(u);
            } else {
                ipv4_updates[addr] = { u };
            }
        } else if (lookahead<ipv6_address_string> ipv6{datum{feature_value}}) {
            ipv6_array_t addr = ipv6.value.get_value_array();
            auto update = ipv6_updates.find(addr);
            if (update != ipv6_updates.end()) {
                update->second.push_back(u);
            } else {
                ipv6_updates[addr] = { u };
            }
        }
    }

    // apply a naive bayes feature update to prob_vector
    //
    void update(std::vector<floating_point_type> &prob_vector, const std::string &dst_ip_str) const {
        if (lookahead<ipv4_address_string> ipv4{datum{dst_ip_str}}) {
            auto ip_ip_update = ipv4_updates.find(ipv4.value.get_value());
            if (ip_ip_update != ipv4_updates.end()) {
                for (const auto &x : ip_ip_update->second) {
                    prob_vector[x.index] += x.value;
                }
            }
        } else if (lookahead<ipv6_address_string> ipv6{datum{dst_ip_str}}) {
            auto ip_ip_update = ipv6_updates.find(ipv6.value.get_value_array());
            if (ip_ip_update != ipv6_updates.end()) {
                for (const auto &x : ip_ip_update->second) {
                    prob_vector[x.index] += x.value;
                }
            }
        } else {
            printf_err(log_err, "unknown type destination ip %s\n", dst_ip_str.c_str());
        }
    }

};


/// represents a model that assigns a probability update to a domain
/// name (or a TLS or QUIC server name, or an HTTP host name)
///
class domain_name_model {

    std::unordered_map<std::string, std::vector<class update>> hostname_domain_updates;
    std::unordered_map<std::string, std::vector<class update>> hostname_sni_updates;

public:

    floating_point_type domain_weight = 1.0;
    floating_point_type sni_weight = 1.0;

    domain_name_model(floating_point_type domain_wt=1.0,
                      floating_point_type sni_wt=1.0) :
        domain_weight{domain_wt},
        sni_weight{sni_wt}
    { }

    void add_snis_from_json_object(rapidjson::Value::ConstMemberIterator itr,
                                   size_t process_index,
                                   size_t total_count
                                   )
    {
        if (itr->value.IsObject()) {
            for (auto &y : itr->value.GetObject()) {
                if (y.value.IsUint64()) {
                    std::string normalized = server_identifier{y.name.GetString()}.get_normalized_domain_name(server_identifier::detail::on);
                    add_sni_update(process_index, normalized, y.value.GetUint64(), total_count, sni_weight);
                }
            }
        }
    }

    void add_domain_names_from_json_object(rapidjson::Value::ConstMemberIterator itr,
                                           size_t process_index,
                                           size_t total_count
                                           )
    {
        if (itr->value.IsObject()) {
            for (auto &y : itr->value.GetObject()) {
                if (y.value.IsUint64()) {
                    std::string normalized = server_identifier{y.name.GetString()}.get_normalized_domain_name(server_identifier::detail::on);
                    add_domain_update(process_index, normalized, y.value.GetUint64(), total_count, domain_weight);
                }
            }
        }
    }

    void add_domain_update(size_t index,
                           const std::string &hostname_domains,
                           size_t count,
                           size_t total_count,
                           floating_point_type domain_weight
                           ) {

        floating_point_type base_prior = log(0.1 / total_count);
        std::pair<std::string,size_t> domains_and_count{ hostname_domains, count };

        const auto x = hostname_domain_updates.find(domains_and_count.first);
        class update u{ index, (log((floating_point_type)domains_and_count.second / total_count) - base_prior) * domain_weight };
        if (x != hostname_domain_updates.end()) {

            // check for previous occurence of this index
            //
            class update *prev_update = nullptr;
            for (auto & upd : x->second) {
                if (upd.index == index) {
                    prev_update = &upd;
                }
            }
            if (prev_update) {
                prev_update->combine(count, total_count, base_prior, domain_weight);
            } else {
                x->second.push_back(u);
            }

        } else {
            hostname_domain_updates[domains_and_count.first] = { u };
        }

    }

    void add_sni_update(size_t index,
                        const std::string &hostname_sni,
                        size_t count,
                        size_t total_count,
                        floating_point_type sni_weight
                        ) {

        floating_point_type base_prior = log(0.1 / total_count);
        std::pair<std::string,size_t> sni_and_count{ hostname_sni, count };

        const auto x = hostname_sni_updates.find(sni_and_count.first);
        class update u{ index, (log((floating_point_type)sni_and_count.second / total_count) - base_prior) * sni_weight };
        if (x != hostname_sni_updates.end()) {

            // check for previous occurence of this index
            //
            class update *prev_update = nullptr;
            for (auto & upd : x->second) {
                if (upd.index == index) {
                    prev_update = &upd;
                }
            }
            if (prev_update) {
                prev_update->combine(count, total_count, base_prior, sni_weight);
            } else {
                x->second.push_back(u);
            }

        } else {
            hostname_sni_updates[sni_and_count.first] = { u };
        }

    }


    /// updates the probability vector \param process_score
    /// based on the feature \param server_name_str
    ///
    void update(std::vector<floating_point_type> &process_score,
                const std::string &server_name_str
                ) const
    {

        std::string domain = get_tld_domain_name(server_name_str.c_str());

        auto hostname_domain_update = hostname_domain_updates.find(domain);
        if (hostname_domain_update != hostname_domain_updates.end()) {
            for (const auto &x : hostname_domain_update->second) {
                assert(x.index < process_score.size());
                process_score[x.index] += x.value;
            }
        }

        auto hostname_sni_update = hostname_sni_updates.find(server_name_str);
        if (hostname_sni_update != hostname_sni_updates.end()) {
            for (const auto &x : hostname_sni_update->second) {
                assert(x.index < process_score.size());
                process_score[x.index] += x.value;
            }
        }
    }

    /// get_tld_domain_name() returns the string containing the top two
    /// domains of the input string; that is, given "s3.amazonaws.com",
    /// it returns "amazonaws.com".  If there is only one name, it is
    /// returned.
    ///
    static std::string get_tld_domain_name(const char* server_name) {

        const char *separator = NULL;
        const char *previous_separator = NULL;
        const char *c = server_name;
        while (*c) {
            if (*c == '.') {
                if (separator) {
                    previous_separator = separator;
                }
                separator = c;
            }
            c++;
        }
        if (previous_separator) {
            previous_separator++;  // increment past '.'
            return previous_separator;
        }
        return server_name;
    }

};


struct feature_weights {
    floating_point_type as     = std::numeric_limits<floating_point_type>::quiet_NaN();
    floating_point_type domain = std::numeric_limits<floating_point_type>::quiet_NaN();
    floating_point_type port   = std::numeric_limits<floating_point_type>::quiet_NaN();
    floating_point_type ip     = std::numeric_limits<floating_point_type>::quiet_NaN();
    floating_point_type sni    = std::numeric_limits<floating_point_type>::quiet_NaN();
    floating_point_type ua     = std::numeric_limits<floating_point_type>::quiet_NaN();

    static constexpr size_t num_weights = 6;  // number of weights we expect to read

    void read_from_object(rapidjson::Value &v) {

        if (v.IsObject() == false) {
            throw std::runtime_error{"json error: expected object, got other type"};
        }
        if (v.MemberCount() != num_weights) {
            throw std::runtime_error{"json error: wrong number of elements in feature_weights"};
        }

        for (auto &w : v.GetObject()) {
            if (!w.value.IsFloat()) {
                throw std::runtime_error{"expected float, got other type"};
            }
            if (strcmp(w.name.GetString(), "as") == 0)          { as = w.value.GetFloat(); }
            else if (strcmp(w.name.GetString(), "domain") == 0) { domain = w.value.GetFloat(); }
            else if (strcmp(w.name.GetString(), "port") == 0)   { port = w.value.GetFloat(); }
            else if (strcmp(w.name.GetString(), "ip") == 0)     { ip = w.value.GetFloat(); }
            else if (strcmp(w.name.GetString(), "sni") == 0)    { sni = w.value.GetFloat(); }
            else if (strcmp(w.name.GetString(), "ua") == 0)     { ua = w.value.GetFloat(); }
            else {
                printf_err(log_err, "unexpected feature weight \"%s\" \n", w.name.GetString());
            }
        }
    }

    bool is_initialized() const {
        return !std::isnan(as)
            || !std::isnan(domain)
            || !std::isnan(port)
            || !std::isnan(ip)
            || !std::isnan(sni)
            || !std::isnan(ua);
    }

};


/// implements a (possibly weighted) naive bayes classifier
///
class naive_bayes {

    static constexpr feature_weights default_weights {
        0.13924, // as_weight
        0.15590, // domain_weight
        0.00528, // port_weight
        0.56735, // ip_weight
        0.96941, // sni_weight
        1.0      // ua_weight
    };

    std::vector<floating_point_type> prior_prob;  // vector of prior probabilities

    domain_name_model domain_name;
    feature<uint16_t> dst_port_feature;
    ip_addr_feature dst_addr_feature;
    feature<uint32_t> asn_feature;
    feature<std::string> user_agent_feature;

public:

    // constructs a naive_bayes classifier by reading a JSON array
    //
    naive_bayes(const rapidjson::Value &process_info,
                size_t total_count,
                const feature_weights &w = default_weights
                ) :
        domain_name{w.domain, w.sni},
        dst_port_feature{w.port},
        dst_addr_feature{w.ip},
        asn_feature{w.as},
        user_agent_feature{w.ua}
    {

        size_t index = 0;   // zero-based index of process in probability vector

        if (total_count == 0) {
            printf_err(log_warning, "total_count==0 in naive_bayes\n");
        }

        for (auto &x : process_info.GetArray()) {

            // track which object members appear
            //
            bool got_dst_port_feature = false,
                got_dst_addr_feature = false,
                got_asn_feature = false,
                got_user_agent_feature = false,
                got_domain_names = false,
                got_snis = false;

            if (x.IsObject()) {

                // loop over the members of the object, processing
                // each according to its name
                //
                for (rapidjson::Value::ConstMemberIterator itr = x.MemberBegin(); itr != x.MemberEnd(); ++itr) {

                    const std::string & member_name = itr->name.GetString();
                    if (member_name == "classes_port_port") {
                        dst_port_feature.add_updates_from_object(itr, index, total_count);
                        got_dst_port_feature = true;

                    } else if (member_name == "classes_hostname_domains") {
                        domain_name.add_domain_names_from_json_object(itr, index, total_count);
                        got_domain_names = true;

                    } else if (member_name == "classes_hostname_sni") {
                        domain_name.add_snis_from_json_object(itr, index, total_count);
                        got_snis = true;

                    } else if (member_name == "classes_ip_as") {
                        asn_feature.add_updates_from_object(itr, index, total_count);
                        got_asn_feature = true;

                    } else if (member_name == "classes_user_agent") {
                        user_agent_feature.add_updates_from_object(itr, index, total_count);
                        got_user_agent_feature = true;

                    } else if (member_name == "classes_ip_ip") {
                        dst_addr_feature.add_updates_from_object(itr, index, total_count);
                        got_dst_addr_feature = true;

                    } else if (member_name == "process"
                               || member_name == "count"
                               || member_name == "sha256"
                               || member_name == "attributes"
                               || member_name == "os_info"
                               || member_name == "malware"
                               || member_name == "classes_port_applications"
                               || member_name == "classes_hostname_tld"
                               ) {

                        ; // silently ignore these schema elements

                    } else {
                        // printf_err(log_warning, "unknown member '%s' in json object\n", member_name.c_str());
                    }

                }

                if (got_dst_port_feature == false
                    || got_dst_addr_feature == false
                    || got_asn_feature == false
                    // || got_user_agent_feature == false  // NOTE: some protocols don't have this feature
                    || got_domain_names == false
                    || got_snis == false) {

                    // warn about missing members (but for now, don't throw an exception)
                    //
                    std::string missing_members{ "missing members in process_info[] object: "};
                    if (got_dst_port_feature == false)   { missing_members += "classes_port_port "; }
                    if (got_dst_addr_feature == false)   { missing_members += "classes_ip_ip "; }
                    if (got_asn_feature == false)        { missing_members += "classes_ip_as "; }
                    if (got_user_agent_feature == false) { missing_members += "classes_user_agent "; }
                    if (got_domain_names == false)       { missing_members += "classes_hostname_domains "; }
                    if (got_snis == false)               { missing_members += "classes_hostname_sni "; }
                    printf_err(log_warning, "%s\n", missing_members.c_str());

                    // throw std::runtime_error{missing_members};

                }

            }

            uint64_t count = 0;
            if (x.HasMember("count") && x["count"].IsUint64()) {
                count = x["count"].GetUint64();
            }
            if (count == 0) {
                throw std::runtime_error("error: process_fp_db_line() count 0");
                continue;
            }

            // construct vector of prior probabilities
            //
            add_class(count, total_count);

            index++;  // increment process index
        }

    }

    void add_class(size_t count, size_t total_count) {
        floating_point_type base_prior = log(0.1 / total_count);
        floating_point_type proc_prior = log(.1);
        floating_point_type prob_process_given_fp = (floating_point_type)count / total_count;
        floating_point_type score = log(prob_process_given_fp);
        prior_prob.push_back(fmax(score, proc_prior) + base_prior *
                             (asn_feature.weight + domain_name.domain_weight + dst_port_feature.weight + dst_addr_feature.weight + domain_name.sni_weight + user_agent_feature.weight));
    }

    std::vector<floating_point_type> classify(uint32_t asn_int,
                                              uint16_t dst_port,
                                              const std::string &server_name_str,
                                              const std::string &dst_ip_str,
                                              const char *user_agent
                                              ) const {

        std::vector<floating_point_type> process_score = prior_prob;  // working copy of probability vector

        asn_feature.update(process_score, asn_int);
        dst_port_feature.update(process_score, hton(dst_port));
        dst_addr_feature.update(process_score, dst_ip_str);
        if (user_agent != nullptr) {
            user_agent_feature.update(process_score, user_agent);
        }
        domain_name.update(process_score, server_name_str);

        return process_score;
    }

};


#endif // NAIVE_BAYES_HPP
