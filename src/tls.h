#include "extractor.h"

struct tls_security_assessment {
    bool weak_version_offered;
    bool weak_ciphersuite_offered;
    bool weak_elliptic_curve_offered;
    bool weak_version_used;
    bool weak_ciphersuite_used;
    bool weak_elliptic_curve_used;
    bool weak_key_size_used;

    tls_security_assessment() :
        weak_version_offered{false},
        weak_ciphersuite_offered{false},
        weak_elliptic_curve_offered{false},
        weak_version_used{false},
        weak_ciphersuite_used{false},
        weak_elliptic_curve_used{false},
        weak_key_size_used{false}
    {  }

    void print(struct json_object &o, const char *key);
};

#define L_ExtensionType            2
#define L_ExtensionLength          2

/*
 * extension types used in normalization
 */
#define type_sni                0x0000
#define type_supported_groups   0x000a
#define type_supported_versions 0x002b

#define SNI_HDR_LEN 9

struct tls_extensions : public parser {

    tls_extensions(const uint8_t *data, const uint8_t *data_end) : parser{data, data_end} {}

    void print(struct json_object &o, const char *key) const;

    void print_server_name(struct json_object &o, const char *key) const;

    void print_session_ticket(struct json_object &o, const char *key) const;

    void fingerprint(struct buffer_stream &b) const;
};


struct tls_client_hello {
    struct parser protocol_version;
    struct parser random;
    struct parser ciphersuite_vector;
    struct parser session_id;
    struct parser compression_methods;
    struct tls_extensions extensions;

    tls_client_hello() : protocol_version{NULL, NULL}, random{NULL, NULL}, ciphersuite_vector{NULL, NULL}, session_id{NULL, NULL}, compression_methods{NULL, NULL}, extensions{NULL, NULL} {}

    void parse(struct parser &p);

    void fingerprint(json_object &o, const char *key) const;

    static void write_json(struct parser &data, struct json_object &record);

    void write_json(struct json_object &record) const;

    struct tls_security_assessment security_assesment();
};

struct tls_server_hello {
    struct parser protocol_version;
    struct parser random;
    struct parser ciphersuite_vector;
    struct parser extensions;

    tls_server_hello() : protocol_version{NULL, NULL}, random{NULL, NULL}, ciphersuite_vector{NULL, NULL}, extensions{NULL, NULL} {}

    void parse(struct parser &p);

    enum status parse_tls_server_hello(struct parser &p);
};
