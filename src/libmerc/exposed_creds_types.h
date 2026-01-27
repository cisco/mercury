// Credential exposure type definitions

#ifndef EXPOSED_CREDS_TYPES_H
#define EXPOSED_CREDS_TYPES_H

enum exposed_creds_type {
    exposed_creds_none = 0,
    exposed_creds_plaintext = 1,
    exposed_creds_token = 2,
    exposed_creds_derived = 3
};

#endif  /* EXPOSED_CREDS_TYPES_H */