// fingerprint.h
//

#ifndef FINGERPRINT_H
#define FINGERPRINT_H

#include "json_object.h"

class fingerprint {
    enum fingerprint_type type;
    static const size_t MAX_FP_STR_LEN = 4096;
    char fp_str[MAX_FP_STR_LEN];
    struct buffer_stream fp_buf;

public:

    fingerprint() : type{fingerprint_type_unknown},
                    fp_buf{fp_str, MAX_FP_STR_LEN} {}

    void init() {
        type = fingerprint_type_unknown;
        fp_buf = buffer_stream{fp_str, MAX_FP_STR_LEN};
    }

    const char *string() const {
        return fp_str;
    }

    // add - allows to add sections of fp
    // set - allows to add one/last section of fp
    //
    template <typename T>
    void set(T &msg, enum fingerprint_type fp_type) {
        msg.fingerprint(fp_buf);
        fp_buf.write_char('\0'); // null-terminate
        type = fp_type;
    }

    template <typename T>
    void add(T &msg) {
        msg.fingerprint(fp_buf);
    }

    bool is_null() const {
        return type == fingerprint_type_unknown;
    }

    enum fingerprint_type get_type() const { return type; }

    void write(struct json_object &record) {
        const char *name[] = {
            "unknown",
            "tls",
            "tls_server",
            "http",
            "http_server",
            "ssh",
            "ssh_kex",
            "tcp",
            "dhcp",
            "smtp_server",
            "dtls",
            "dtls_server",
            "quic",
        };
        if (type > (sizeof(name)/sizeof(const char *))) {
            type = fingerprint_type_unknown;  // error: unknown type
        }
        struct json_object fps{record, "fingerprints"};
        fps.print_key_string(name[type], fp_str);
        fps.close();
    }
};

#endif // FINGERPRINT_H
