/*
 * ssh.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef SMTP_H
#define SMTP_H

#include <stdint.h>
#include <stdlib.h>
#include "datum.h"
#include "json_object.h"
#include "fingerprint.h"



struct smtp_parameters : public datum {
    smtp_parameters() : datum{} {}

    void parse(struct datum &p) {
        unsigned char crlf[2] = { '\r', '\n' };

        data = p.data;
        while (datum_get_data_length(&p) > 0) {
            if (datum_match(&p, crlf, sizeof(crlf), NULL) == status_ok) {
                break;  /* at end of headers */
            }
            if (datum_skip_upto_delim(&p, crlf, sizeof(crlf)) == status_err) {
                break;
            }
        }
        data_end = p.data;
    }

    void print_parameters(struct json_array &a) const {
        unsigned char crlf[2] = { '\r', '\n' };

        if (this->is_not_readable()) {
            return;
        }
        struct datum p{this->data, this->data_end};

        while (datum_get_data_length(&p) > 0) {
            if (datum_match(&p, crlf, sizeof(crlf), NULL) == status_ok) {
                break;  /* at end of parameters */
            }

            struct datum param{p.data, NULL};
            if (datum_skip_upto_delim(&p, crlf, sizeof(crlf)) == status_err) {
                break;
            }
            param.data_end = p.data - 2;
            param.data += 4;

            a.print_json_string(param);
        }
    }
};


struct smtp_server {
    struct smtp_parameters parameters;

    smtp_server() : parameters{} { }

    void parse(struct datum &pkt) {
        parameters.parse(pkt);

        return;
    }

    void operator()(buffer_stream &) { }

    void write_json(json_object &record, bool) {
        if (this->is_not_empty()) {
            struct json_object smtp{record, "smtp"};
            struct json_object smtp_response{smtp, "response"};
            struct json_array params{smtp_response, "parameters"};

            parameters.print_parameters(params);

            params.close();
            smtp_response.close();
            smtp.close();
        }
    }

    void compute_fingerprint(struct fingerprint &fp) const { };

    bool is_not_empty() { return parameters.is_not_empty(); }
};


#endif // SMTP_H
