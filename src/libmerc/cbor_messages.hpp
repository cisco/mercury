// cbor_messages.hpp
//
// Non-owning feature classes for the CBOR metadata interface.
// Each class is used for both encoding (libmerc) and decoding (inspector).

#ifndef CBOR_MESSAGES_HPP
#define CBOR_MESSAGES_HPP

#include "cbor.hpp"
#include "exposed_creds.hpp"

/// Tags for exposed credentials.
enum class exposed_creds_tag : uint8_t {
    plaintext,
    token,      
    derived      
};

template<exposed_creds_tag Tag>
class exposed_creds_message {
    cbor::text_string protocol_;
    cbor::text_string auth_method_;
    cbor::text_string username_;
    datum cbor_span_;
    bool valid_ = false;

public:
    
    static constexpr const char* KEY =
        Tag == exposed_creds_tag::plaintext ? "exposed_credentials_plaintext" :
        Tag == exposed_creds_tag::token     ? "exposed_credentials_token" :
                                              "exposed_credentials_derived";

    /// Construct from raw data (encoding path).
    static exposed_creds_message construct(datum protocol,
                                            datum auth_method,
                                            datum username) {
        exposed_creds_message msg;
        msg.protocol_ = cbor::text_string::construct(protocol);
        msg.auth_method_ = cbor::text_string::construct(auth_method);
        msg.username_ = cbor::text_string::construct(username);
        msg.valid_ = true;
        return msg;
    }

    /// Decode from CBOR indefinite map (decoding path).
    /// d must point at the 0xBF opening byte.
    static exposed_creds_message decode(datum &d) {
        exposed_creds_message msg;
        const uint8_t* begin = d.data;
        cbor::map m{d};
        while (d.is_not_empty() && *d.data != 0xff) {
            cbor::text_string key = cbor::text_string::decode(d);
            datum k = key.value();
            if (k.match("protocol"))                   msg.protocol_ = cbor::text_string::decode(d);
            else if (k.match("authentication_method")) msg.auth_method_ = cbor::text_string::decode(d);
            else if (k.match("username"))              msg.username_ = cbor::text_string::decode(d);
            else cbor::skip_cbor_value(d);
        }
        m.close();
        msg.cbor_span_ = datum{begin, d.data};
        msg.valid_ = !d.is_null();
        return msg;
    }

    /// Templated write 
    template<typename Object, typename Array>
    void write(Object &parent) const {
        Object o{parent, KEY};
        if (protocol_.is_valid())
            o.print_key_string("protocol", protocol_.value());
        if (auth_method_.is_valid())
            o.print_key_string("authentication_method", auth_method_.value());
        if (username_.is_valid())
            o.print_key_string("username", username_.value());
        o.close();
    }

    bool is_valid() const { return valid_; }
    datum key() const { return datum{KEY}; }
    datum protocol() const { return protocol_.value(); }
    datum auth_method() const { return auth_method_.value(); }
    datum username() const { return username_.value(); }
    datum cbor_span() const { return cbor_span_; }
};

using exposed_creds_plaintext_message = exposed_creds_message<exposed_creds_tag::plaintext>;
using exposed_creds_token_message     = exposed_creds_message<exposed_creds_tag::token>;
using exposed_creds_derived_message   = exposed_creds_message<exposed_creds_tag::derived>;

#endif // CBOR_MESSAGES_HPP
