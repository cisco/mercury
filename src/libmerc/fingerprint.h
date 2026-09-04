// fingerprint.h
//

#ifndef FINGERPRINT_H
#define FINGERPRINT_H

#include <cctype>
#include <cassert>
#include <cstring>
#include <vector>
#include "json_object.h"
#include "libmerc.h"  // for fingerprint_type

class fingerprint {
public:
    static const size_t MAX_FP_STR_LEN = 8192;
private:
    enum fingerprint_type type;
    char fp_str[MAX_FP_STR_LEN];
    struct buffer_stream fp_buf;

public:

    fingerprint() : type{fingerprint_type_unknown},
                    fp_buf{fp_str, MAX_FP_STR_LEN} {}

    void init() {
        type = fingerprint_type_unknown;
        fp_str[0] = '\0';
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

    void set_type(fingerprint_type fp_type, size_t format_version=0) {
        type = fp_type;
        fp_buf.puts(get_type_name(fp_type));
        fp_buf.write_char('/');
        if (format_version) {
            fp_buf.write_uint8(format_version);
            fp_buf.write_char('/');
        }
    }

    template <typename T>
    void add(T &msg) {
        return msg.fingerprint(fp_buf);
    }

    template <typename T>
    void add(T &msg, size_t format_version) {
        msg.fingerprint(fp_buf, format_version);
    }

    // the function fingerprint_is_well_formed() checks the
    // fingerprint in fp_str and verifies that it consists of balanced
    // parenthesis and hex strings.  A fingerprint with no data section,
    // e.g., "smtp_server/", is accepted; discarding it is the producer's job.
    //
    bool fingerprint_is_well_formed() {
        std::vector<char> stack;
        const char *c = &fp_str[0];

        // loop over fingerprint type
        //
        while (*c != '\0' && *c != '/') {
            if (!(isalpha(*c) && islower(*c)) && (*c != '_')) {
                return false;  // ill-formed fingerprint type string
            }
            c++;
        }
        if (*c != '/') {
            return false;  // missing '/' after fingerprint type
        }
        c++;  // accept '/'

        //loop over version string if present
        if (*c != '(') {
            while (*c != '\0' && *c != '/') {
                if (!isdigit(*c)) {
                    return false;
                }
                c++;
            }
            if (*c == '/') {   // not present if there is no data section
                c++;
            }
        }

        // accept keyword "generic" and possibly trailing data as fingerprint string
        if (strncmp(c, "generic", 7) == 0) {
            return true;
        }

        // loop over balanced parens / tree data
        //
        while (*c != '\0') {
            switch (*c) {
            case '(':
            case '[':
                stack.push_back(*c);
                break;
            case ')':
                if (!stack.empty() && stack.back() == '(') {
                    stack.pop_back();
                } else {
                    return false; // error
                }
                break;
            case ']':
                if (!stack.empty() && stack.back() == '[') {
                    stack.pop_back();
                } else {
                    return false; // error
                }
                break;
            default:
                if (!isxdigit(*c) || isupper(*c)) {
                    return false;  // non hex digit in string
                }
            }
            c++;
        }
        if (stack.size() != 0) {
            return false;
        }
        return true;
    }

    void final() {
        if (fp_buf.is_truncated()) {
            //
            // If fp_buf has been truncated, then either the length of
            // a fingerprint exceeded that of the buffer, or the
            // protocol-parsing code determined that the message that
            // it was parsing did not contain a valid fingerprint, and
            // set the fp_buf truncation bit.  In either case, we want
            // to ignore this fingerprint, so we reset to fingerprint_type_unknown.
            //
            init();
            return;
        }
        fp_buf.add_null(); // null-terminate
        if (fp_buf.is_truncated()) {
            init();
            return;
        }
        assert(fingerprint_is_well_formed());
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
            "openvpn",
            "tofsee",
            "stun",
            "ssh_init",
            "ssh_server",
            "ssh_kex_server",
            "ssh_init_server"
        };
        if (fp_type > (sizeof(name)/sizeof(const char *)) - 1) {
            return name[0];  // error: unknown type
        }
        return name[fp_type];
    }

    void write(struct json_object &record) {
        struct json_object fps{record, "fingerprints"};
        fps.print_key_string(get_type_name(type), fp_str);
        fps.close();
    }

    static size_t max_length() { return MAX_FP_STR_LEN; }
};

// LCOV_EXCL_START
namespace fingerprint_unit_test {

#ifndef NDEBUG

    // a message that writes a well-formed fingerprint body
    //
    struct well_formed_message {
        void fingerprint(buffer_stream &b) const { b.puts("(0301)(002f)"); }
    };

    // a message that fills every payload byte using normal stream writes
    //
    struct max_length_message {
        void fingerprint(buffer_stream &b) const {
            b.write_char('(');
            while (b.doff < b.dlen - 2) {
                b.write_char('a');
            }
            b.write_char(')');
        }
    };

    // a message that writes a literal fingerprint body
    //
    struct literal_message {
        const char *body;
        void fingerprint(buffer_stream &b) const { b.puts(body); }
    };

    inline bool unit_test() {
        bool passed = true;

        {
            // final() accepts a fingerprint that leaves room for the
            // terminator.
            fingerprint fp;
            fp.init();
            fp.set_type(fingerprint_type_tls);
            well_formed_message msg;
            fp.add(msg);
            fp.final();

            passed &= !fp.is_null();
            passed &= fp.get_type() == fingerprint_type_tls;
            passed &= strcmp(fp.string(), "tls/(0301)(002f)") == 0;
        }

        {
            // final() terminates a maximum-length fingerprint without
            // dropping it.
            fingerprint fp;
            fp.init();
            fp.set_type(fingerprint_type_tls);
            max_length_message msg;
            fp.add(msg);
            fp.final();

            passed &= !fp.is_null();
            passed &= fp.get_type() == fingerprint_type_tls;
            passed &= strlen(fp.string()) == fingerprint::max_length() - 1;
        }

        {
            // final() keeps a fingerprint with no data section, and
            // does not read the bytes that the previous fingerprint
            // left in the same buffer
            fingerprint fp;
            fp.init();
            fp.set_type(fingerprint_type_tls);
            well_formed_message msg;
            fp.add(msg);
            fp.final();

            fp.init();
            fp.set_type(fingerprint_type_tls);
            literal_message empty{""};
            fp.add(empty);
            fp.final();

            passed &= strcmp(fp.string(), "tls/") == 0;

            // a closing delimiter with nothing open is rejected, and
            // does not read the empty stack; final() is not called
            // here, because it asserts well-formedness
            //
            fp.init();
            fp.set_type(fingerprint_type_tls);
            literal_message unbalanced_paren{"1/)"};
            fp.add(unbalanced_paren);
            passed &= !fp.fingerprint_is_well_formed();

            fp.init();
            fp.set_type(fingerprint_type_tls);
            literal_message unbalanced_bracket{"1/]"};
            fp.add(unbalanced_bracket);
            passed &= !fp.fingerprint_is_well_formed();
        }

        {
            // the "generic" keyword is accepted as the whole data
            // section, and is read no further than the terminator
            fingerprint fp;
            fp.init();
            fp.set_type(fingerprint_type_tls, 1);
            literal_message generic{"generic"};
            fp.add(generic);

            passed &= fp.fingerprint_is_well_formed();
            fp.final();
            passed &= strcmp(fp.string(), "tls/1/generic") == 0;

            // a buffer holding no type name and no '/' is rejected
            // instead of read past
            fp.init();
            passed &= !fp.fingerprint_is_well_formed();
        }

        return passed;
    }
#endif

} // namespace fingerprint_unit_test
// LCOV_EXCL_STOP

#endif // FINGERPRINT_H
