// cms.cpp
//
// Cryptographic Message Syntax (CMS) reader

#include <cstdio>
#include <stdexcept>
#include "pkcs8.hpp"
#include "pem.hpp"
#include "libmerc/x509.h"

bool compare(const datum &lhs, const datum &rhs, bool verbose=false) {
    bool match = true;
    ssize_t llen = lhs.data_end - lhs.data;
    ssize_t rlen = rhs.data_end - rhs.data;
    ssize_t min_len = llen < rlen ? llen : rlen;
    if (verbose) { fprintf(stderr, "lhs.length(): %zu\trhs.length(): %zu\t", lhs.length(), rhs.length()); }
    for (ssize_t i=0; i<min_len; i++) {
        if (verbose) { fprintf(stderr, "%02x\t%02x", lhs.data[i], rhs.data[i]); }
        if (lhs.data[i] != rhs.data[i]) {
            if (verbose) { fprintf(stderr, "***"); }
            match = false;
        }
        if (verbose) { fputc('\n', stderr); }
    }
    return match;
}

int main(int argc, char *argv[]) {

    assert(base64::unit_test());
    assert(rsa_private_key::unit_test());
    // assert(private_key_info::unit_test(true));

    if (argc < 2) {
        fprintf(stderr, "error: missing filename\n");
        return EXIT_FAILURE;
    }

    pem_file_reader pemfile(argv[1]);
    while (true) {

        data_buffer<2048> pembuf;
        pemfile.write(pembuf);
        pem_file_reader::pem_label label = pemfile.get_label();
        datum pemdata = pembuf.contents();
        if (pemdata.length() == 0) {
            break;  // no more entries in pemfile
        }

        bool hex_output = false;
        if (hex_output) {
            pemdata.fprint_hex(stdout);
            fputc('\n', stdout);
            continue;
        }

        bool c_array_output = false;
        if (c_array_output) {
            const char *label_string = pem_file_reader::pem_label_string[label];
            pemdata.fprint_c_array(stdout, label_string);
            fputc('\n', stdout);
            continue;
        }

        if (label == pem_file_reader::RSA_PRIVATE_KEY) {
            const char *label_string = pem_file_reader::pem_label_string[label];
            rsa_private_key priv{pemdata};

            char buffer[4096];
            buffer_stream buf(buffer, sizeof(buffer));
            json_object record{&buf};
            json_object o{record, label_string};
            priv.write_json(o);
            o.close();
            if (pemdata.length() != 0) {
                o.print_key_hex("trailing_data", pemdata);
            }
            record.close();
            buf.write_line(stdout);
        }

        if (label == pem_file_reader::PRIVATE_KEY) {
            const char *label_string = pem_file_reader::pem_label_string[label];
            private_key_info pkinfo{pemdata};

            char buffer[4096];
            buffer_stream buf(buffer, sizeof(buffer));
            json_object record{&buf};
            json_object o{record, label_string};
            // pkinfo.write_json(o);  // TODO
            o.close();
            record.close();
            buf.write_line(stdout);
        }

        if (label == pem_file_reader::CERTIFICATE) {
            // const char *label_string = pem_file_reader::pem_label_string[label];
            x509_cert cert{};
            cert.parse(pemdata.data, pemdata.length());
            cert.print_as_json(stdout);
        }
    }

    return 0;
}
