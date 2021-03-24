// fingerprint.h
//

#ifndef FINGERPRINT_H
#define FINGERPRINT_H

#include "json_object.h"

#define MAX_FP_STR_LEN 4096

struct fingerprint {
    enum fingerprint_type type;
    char fp_str[MAX_FP_STR_LEN];

    fingerprint() : type{fingerprint_type_unknown} {}

    template <typename T>
    void set(T &msg, enum fingerprint_type fp_type) {
        struct buffer_stream fp_buf{fp_str, MAX_FP_STR_LEN};
        msg(fp_buf);
        fp_buf.write_char('\0'); // null-terminate
        type = fp_type;
    }

    enum fingerprint_type get_type() { return type; }

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
            "dhcp"
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
