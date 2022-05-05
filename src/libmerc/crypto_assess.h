// TLS and X509/PKIX Crypto Security Assessment
//
// Based on NIST Special Publications 800-52 and 800-57

#ifndef CRYPTO_ASSESS_H
#define CRYPTO_ASSESS_H

#include <cstdint>
#include <array>
#include "tls_ciphersuites.h"

// requirement level, based on rfc2119 keywords
//
enum requirement_level {
    shall,       // an absolute requirement
    should,      // recommended, but not strictly required
    should_not,  // not recommended, but not strictly forbidden
    shall_not    // absolutely forbidden
};

// TLS protocol versions
//
enum tls_version_alt : uint16_t {
    ssl_2 = 0x0200,
    ssl_3 = 0x0300,
    v1_0  = 0x0301,
    v1_1  = 0x0302,
    v1_2  = 0x0303,
    v1_3  = 0x0304,
};

class nist_sp800_57 {

    // Servers that support government-only applications shall be configured
    // to use TLS 1.2 and should be configured to use TLS 1.3 as well. These
    // servers should not be configured to use TLS 1.1 and shall not use TLS
    // 1.0, SSL 3.0, or SSL 2.0. TLS versions 1.2 and 1.3 are represented by
    // major and minor number tuples (3, 3) and (3, 4), respectively, and may
    // appear in that format during configuration.

    static requirement_level version_requirements(tls_version_alt v) {
        switch(v) {
        case v1_3: return should;
        case v1_2: return shall;
        case v1_1: return should_not;
        case v1_0:
        case ssl_2:
        case ssl_3:
        default:
            ;
        }
        return shall_not;
    }

    // Servers that support citizen or business-facing applications (i.e.,
    // the client may not be part of a government IT system) 10 shall be
    // configured to negotiate TLS 1.2 and should be configured to negotiate
    // TLS 1.3. The use of TLS versions 1.1 and 1.0 is generally discouraged,
    // but these versions may be configured when necessary to enable
    // interaction with citizens and businesses.  See Appendix F for a
    // discussion on determining whether to support TLS 1.0 and TLS
    // 1.1. These servers shall not allow the use of SSL 2.0 or SSL 3.0.

    // Agencies shall support TLS 1.3 by January 1, 2024. After this date,
    // servers shall support TLS 1.3 for both government-only and citizen or
    // business-facing applications. In general, servers that support TLS 1.3
    // should be configured to use TLS 1.2 as well. However, TLS 1.2 may be
    // disabled on servers that support TLS 1.3 if it has been determined
    // that TLS 1.2 is not needed for interoperability.


    // TLS servers shall be configured with certificates issued by a CA that
    // publishes revocation information in Online Certificate Status Protocol
    // (OCSP) [63] responses. The CA may additionally publish revocation
    // information in a certificate revocation list (CRL) [19]. The source(s)
    // for the revocation information shall be included in the CA-issued
    // certificate in the appropriate extension to promote interoperability.


    // To comply with these guidelines, the TLS server certificate shall
    // be an X.509 version 3 certificate; both the public key contained in
    // the certificate and the signature shall provide at least 112 bits
    // of security. Prior to TLS 1.2, the server Certificate message
    // required that the signing algorithm for the certificate be the same
    // as the algorithm for the certificate key (see Section 7.4.2 of
    // [24]). If the server supports TLS versions prior to TLS 1.2, the
    // certificate should be signed with an algorithm consistent with the
    // public key:
    //
    // •Certificates containing RSA, ECDSA, or DSA public keys should be signed with those
    // same signature algorithms, respectively;
    // •Certificates containing Diffie-Hellman public keys should be signed with DSA; and
    // •Certificates containing ECDH public keys should be signed with ECDSA.

    // key must provide 112 bits of security

    // DSA, DH, MQV: L = 2048, N = 224
    // IFC/RSA:      k = 2048
    // ECC:          f = 224-255;

    size_t rsa_strength(size_t k) {
        if (k < 1024)  { return 0;   }  // less than 80 bits
        if (k < 2048)  { return 80;  }
        if (k < 3072)  { return 112; }
        if (k < 7680)  { return 128; }
        if (k < 15360) { return 192; }
        return 256;
    }

    size_t ffc_strength(size_t L) {
        return rsa_strength(L);
    }

    size_t ecc_strength(size_t f) {
        if (f < 160) { return 0; }
        if (f < 224) { return 80; }
        if (f < 256) { return 112; }
        if (f < 384) { return 128; }
        if (f < 512) { return 192; }
        return 256;
    }

    // X509 certificate profile
#if 0
    Version       2 // Version 3
    Serial Number N // Unique positive integerMust be unique

    Issuer Signature Algorithm
    Values by CA key type:
    sha256WithRSAEncryption {1 2 840 113549 1 1 11} // or strongerCA with RSA key
    id-RSASSA-PSS {1 2 840 113549 1 1 10 } // CA with RSA key
    ecdsa-with-SHA256 {1 2 840 10045 4 3 2} // or strongerCA with elliptic curve key
    id-dsa-with-sha256 {2 16 840 1 101 3 4 3 2}//, or strongerCA with DSA key
#endif
    // Issuer Distinguished Name (DN) // Unique X.500 issuing CA DN - A single value should be encoded in each Relative Distinguished Name (RDN). All
    // attributes that are of DirectoryString type
    // should be encoded as a PrintableString.

    //     Validity PeriodN/A3 years or lessDates through 2049 expressed in UTCTime
    // Subject Distinguished NameN/AUnique X.500 subject DN per agency
    // requirementsA single value should be encoded in each
    // RDN. All attributes that are of
    // DirectoryString type should be encoded as
    // a PrintableString. If present, the CN
    // attribute should be of the form:
    // Subject Public Key
    // InformationN/A
    // CN={host IP address | host DNS name}
    // Values by certificate type:
    // rsaEncryption {1 2 840 113549 1 1 1}
    // RSA signature certificate
    // 2048-bit RSA key modulus or other
    // approved lengths as defined in [45] and [5]
    // Parameters: NULL
    // ecPublicKey {1 2 840 10045 2 1}
    // ECDSA signature certificate or ECDH
    // certificate
    // Parameters: namedCurve OID for named
    // curve specified in SP 800-186. 15 The curve
    // should be P-256 or P-384
    // SubjectPublic Key: Uncompressed EC
    // Point.
    // id-dsa {1 2 840 10040 4 1}
    // DSA signature certificate
    // Parameters: p, q, g (2048-bit large prime,
    // i.e., p)
    // dhpublicnumber {1 2 840 10046 2 1}
    // DH certificate
    // Parameters: p, g, q (2048-bit large prime,
    // i.e., p)
    // N/ASame value as in Issuer Signature
    // Algorithm
    // Authority Key IdentifierNoOctet String
    // Subject Key IdentifierNoOctet String
    // Key UsageYes
    // Issuer’s Signature
    // Extensions
    // Same as subject key identifier in issuing
    // CA certificate
    // Prohibited: Issuer DN, Serial Number tuple
    // Same as in Public-Key Cryptography
    // Standards (PKCS) 10 request or calculated
    // by the issuing CA
    // Values by certificate type:
    // digitalSignature
    // RSA signature certificate, ECDSA
    // signature certificate, or DSA signature
    // certificate
    // 11NIST SP 800-52 REV. 2
    // Field
    // GUIDELINES FOR TLS IMPLEMENTATIONS
    // Critical
    // Extended Key Usage
    // No
    // ValueDescription
    // keyAgreementECDH certificate, DH certificate
    // id-kp-serverAuth {1 3 6 1 5 5 7 3 1}Required
    // id-kp-clientAuth {1 3 6 1 5 5 7 3 2}Optional
    // Prohibited: anyExtendedKeyUsage; all
    // others unless consistent with key usage
    // extension
    // Certificate PoliciesNoSubject Alternative Name
    // (SAN)NoDNS host name, or IP address if there is
    // no DNS name assigned. Other name
    // forms may be included, if appropriate.Required. Multiple SANs are permitted,
    // e.g., for load balanced environments.
    // Authority Information AccessNoid-ad-caIssuersRequired. Access method entry contains
    // HTTP URL for certificates issued to
    // issuing CA
    // id-ad-ocspRequired. Access method entry contains
    // HTTP URL for the issuing CA OCSP
    // responder
    // See commentsOptional. HTTP value in distributionPoint
    // field pointing to a full and complete CRL.
    // CRL Distribution Points
    // No
    // Optional
    // Prohibited: reasons and cRLIssuer fields,
    // and nameRelativetoCRLIssuer CHOICE
    // Signed Certificate
    // Timestamps ListNoSee commentsOptional. This extension contains a
    // sequence of Signed Certificate
    // Timestamps, which provide evidence that
    // the certificate has been submitted to
    // Certificate Transparency logs.
    // TLS featureNostatus_request(5)Optional. This extension (sometimes
    // referred to as the “must staple” extension)
    // may be present to indicate to clients that
    // the server supports OCSP stapling and will
    // provide a stapled OCSP response when one
    // is requested.

    // The acceptable cipher suites for a TLS client are the same as those
    // for a TLS server.
    //

    static constexpr std::array<uint16_t, 60> allowed_ciphersuites {

        // TLS version 1.2 includes authenticated encryption modes and support
        // for the SHA-256 and SHA-384 hash algorithms, which are not supported
        // in prior versions of TLS. These cipher suites are described in [61]
        // and [56]. TLS 1.2 servers that are configured with ECDSA certificates
        // may be configured to support the following cipher suites, which are
        // only supported by TLS 1.2:
        //
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
        TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
        TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
        TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,

        // TLS servers may be configured to support the following cipher
        // suites when ECDSA certificates are used with TLS versions 1.2, 1.1,
        // or 1.0:

        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,

        // TLS 1.2 servers that are configured with RSA certificates may be
        // configured to support the following cipher suites:

        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_DHE_RSA_WITH_AES_128_CCM,
        TLS_DHE_RSA_WITH_AES_256_CCM,
        TLS_DHE_RSA_WITH_AES_128_CCM_8,
        TLS_DHE_RSA_WITH_AES_256_CCM_8,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,

        // TLS servers may be configured to support the following cipher
        // suites when RSA certificates are used with TLS versions 1.2, 1.1,
        // or 1.0:

        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA,

        // TLS 1.2 servers that are configured with DSA certificates may be
        // configured to support the following cipher suites:

        TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
        TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,

        // TLS servers may be configured to support the following cipher
        // suites when DSA certificates are used with TLS versions 1.2, 1.1,
        // or 1.0:

        TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA,

        // TLS 1.2 servers that are configured with DSA-signed DH certificates
        // may be configured to support the following cipher suites:

        TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
        TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
        TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA256,

        // TLS servers may be configured to support the following cipher
        // suites when DSA-signed DH certificates are used with TLS versions
        // 1.2, 1.1, or 1.0:

        TLS_DH_DSS_WITH_AES_128_CBC_SHA,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA,

        // TLS 1.2 servers that are configured with RSA-signed DH certificates
        // may be configured to support the following cipher suites:

        TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
        TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
        TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA256,

        // TLS servers may be configured to support the following cipher
        // suites when RSA-signed DH certificates are used with TLS versions
        // 1.2, 1.1, or 1.0:

        TLS_DH_RSA_WITH_AES_128_CBC_SHA,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA,


        // TLS 1.2 servers that are configured with ECDSA-signed ECDH
        // certificates may be configured to support the following cipher
        // suites:

        TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,

        // TLS servers may be configured to support the following cipher
        // suites when ECDSA-signed ECDH certificates are used with TLS
        // versions 1.2, 1.1, or 1.0:

        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,

        // TLS 1.2 servers that are configured with RSA-signed ECDH
        // certificates may be configured to support the following cipher
        // suites:

        TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,

        // TLS servers may be configured to support the following cipher
        // suites when RSA-signed ECDH certificates are used with TLS versions
        // 1.2, 1.1, or 1.0:

        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,

        // TLS 1.3 servers may be configured to support the following cipher
        // suites, which may be used with either RSA or ECDSA server
        // certificates; DSA and DH certificates are not supported by TLS 1.3.

        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_AES_128_CCM_SHA256,
        TLS_AES_128_CCM_8_SHA256
    };


}; // class nist_sp800_57

#if 0
// The server shall support the use of the following TLS extensions.

Renegotiation Indication
Server Name Indication
Extended Master Secret
Signature Algorithms
Certificate Status Request extension

#endif

// more extension requirements ...


// The client shall be configured to use TLS 1.2 and should be
// configured to use TLS 1.3. The client may be configured to use TLS
// 1.1 and TLS 1.0 to facilitate communication with private sector
// servers. The client shall not be configured to use SSL 2.0 or SSL
// 3.0. Agencies shall support TLS 1.3 by January 1, 2024. After this
// date, clients shall be configured to use TLS 1.3.  In general,
// clients that support TLS 1.3 should be configured to use TLS 1.2 as
// well. However, TLS 1.2 may be disabled on clients that support TLS
// 1.3 if TLS 1.2 is not needed for interoperability.

#endif // CRYPTO_ASSESS_H
