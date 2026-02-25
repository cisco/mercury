// Exposed Credentials Assessor
//

#ifndef EXPOSED_CREDS_H
#define EXPOSED_CREDS_H

#include "exposed_creds.hpp"

class exposed_creds_assessor {
public:
    template <typename T>
    static exposed_creds_type assess(const T &protocol) {
        return protocol.check_credential_exposure();
    }
};

#endif // EXPOSED_CREDS_H
