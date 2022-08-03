/*
 * x509_fuzz.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */


#ifndef X509_FUZZ_H
#define X509_FUZZ_H

#include "json_object.h"
#include "tls.h"
#include "x509.h"
#include "fingerprint.h"

namespace {

    [[maybe_unused]] int x509_cert_fuzz_test(const uint8_t *data, size_t size) {
        struct datum tmp_cert_list{data, data+size};
        char buffer[8192];
        struct buffer_stream buf(buffer, sizeof(buffer));

        while (tmp_cert_list.length() > 0) {

            /* get certificate length */
            uint64_t tmp_len;
            if (tmp_cert_list.read_uint(&tmp_len, L_CertificateLength) == false) {
                return -1;
            }

            if (tmp_len > (unsigned)tmp_cert_list.length()) {
                tmp_len = tmp_cert_list.length(); /* truncate */
            }

            if (tmp_len == 0) {
            return -1; /* don't bother printing out a partial cert if it has a length of zero */
            }

            struct json_object o{&buf};
            datum tmp_tmp_cert_list{tmp_cert_list.data, tmp_cert_list.data + tmp_len};

            struct json_object_asn1 cert{o, "cert"};
            struct x509_cert c;
            c.parse(tmp_cert_list.data, tmp_len);
            c.print_as_json(cert, {}, NULL);
            cert.close();
            
            //struct datum cert_parser{tmp_tmp_cert_list.data, tmp_tmp_cert_list.data + tmp_len};
                o.print_key_base64("base64", tmp_tmp_cert_list);
            
            o.close();

            /*
             * advance parser over certificate data
             */
            if (tmp_cert_list.skip(tmp_len) == false) {
                return -1;
            }
        }
        return 0;
    }

};

#endif /* X509_FUZZ_H */