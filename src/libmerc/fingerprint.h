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

    // to create a fingerprint, call these member functions in this
    // order:
    //
    //    init()
    //    set_type()
    //    add()       (one or more times)
    //    final()

    void set_type(fingerprint_type fp_type) {
        type = fp_type;
        fp_buf.puts(get_type_name(fp_type));
        fp_buf.write_char(':');
    }

    template <typename T>
    void add(T &msg) {
        msg.fingerprint(fp_buf);
    }

    void final() {
        fp_buf.write_char('\0'); // null-terminate
    }

    bool is_null() const {
        return type == fingerprint_type_unknown;
    }

    enum fingerprint_type get_type() const { return type; }

    static const char *get_type_name(fingerprint_type fp_type) {

        // note: the array name[] corresponds to the enumeration
        // values in fingerprint_type in libmerc.h; if you change one,
        // you *must* change the other, to keep them in sync
        //
        static const char *name[] = {
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
            "tcp_server",
        };
        if (fp_type > (sizeof(name)/sizeof(const char *))) {
            return name[0];  // error: unknown type
        }
        return name[fp_type];
    }

    void write(struct json_object &record) {
        struct json_object fps{record, "fingerprints"};
        fps.print_key_string(get_type_name(type), fp_str);
        fps.close();
    }
};

#endif // FINGERPRINT_H
