// exposed_creds.hpp
//
// Exposed credential type definitions
//

#ifndef EXPOSED_CREDS_HPP
#define EXPOSED_CREDS_HPP

/// indicates a type of exposed credential, or the absence of an exposed credential
///
enum class exposed_creds_type {
    none               = 0,      ///< No exposed credential
    plaintext_password = 1,      ///< Unencrypted password
    plaintext_token    = 2,      ///< Unencrypted token
    password_derived   = 3,      ///< Password subject to dictionary attack
};

#endif // EXPOSED_CREDS_HPP
