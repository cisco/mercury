// Exposed Credentials Assessor
//

#ifndef EXPOSED_CREDS_H
#define EXPOSED_CREDS_H

#include <cstdint>
#include <array>
#include "json_object.h"
#include "tls_parameters.hpp"
#include "tls_extensions.hpp"
#include "tls.h"
#include "dtls.h"
#include "ssh.h"
#include "http.h"
#include "http_auth.hpp"
#include "pkt_proc_util.h"

class exposed_creds_assessor {
public:
    static inline exposed_creds_type assess(const http_request &http_req);
    static inline exposed_creds_type assess(const tacacs::packet &tacacs_req);

    ~exposed_creds_assessor() {}
};


exposed_creds_type exposed_creds_assessor::assess(const http_request &req) {

    datum auth_hdr = req.get_header("authorization");
    if (auth_hdr.is_readable()) {

        scheme auth_scheme{authorization{auth_hdr}.get_scheme()};
        switch(auth_scheme.get_type()) {
            case scheme::type::basic:
                return exposed_creds_plaintext;
            case scheme::type::bearer:
                return exposed_creds_token;
            case scheme::type::digest:
                return exposed_creds_derived;
            default:
                return exposed_creds_none;
        }
    }

    return exposed_creds_none;
}

exposed_creds_type exposed_creds_assessor::assess(const tacacs::packet &pkt) {

    if (pkt.check_credential_exposure()) {
        return exposed_creds_plaintext;
    }

    return exposed_creds_none;
}

#endif // EXPOSED_CREDS_H