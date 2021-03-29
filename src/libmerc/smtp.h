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

    void fingerprint(struct buffer_stream &buf) const {
        unsigned char crlf[2] = { '\r', '\n' };
        unsigned char hello[2] = { '.' };

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

            if (datum_find_delim(&param, hello, sizeof(hello)) == (param.data_end - param.data)) {
                buf.write_char('(');
                buf.raw_as_hex(param.data, param.data_end - param.data);         // write {name, value}
                buf.write_char(')');
            }
        }
    }

    void print_parameters(struct json_array &a, int offset) const {
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
            param.data += offset;

            a.print_json_string(param);
        }
    }
};


class smtp_client {
    struct smtp_parameters parameters;

public:

    smtp_client() : parameters{} { }

    void parse(struct datum &pkt) {
        parameters.parse(pkt);

        return;
    }

    void operator()(buffer_stream &) const { }

    void write_json(json_object &record, bool) {
        if (this->is_not_empty()) {
            struct json_object smtp{record, "smtp"};
            struct json_object smtp_request{smtp, "request"};
            struct json_array params{smtp_request, "parameters"};

            parameters.print_parameters(params, 5);

            params.close();
            smtp_request.close();
            smtp.close();
        }
    }

    void compute_fingerprint(struct fingerprint) const { };

    bool is_not_empty() const { return parameters.is_not_empty(); }
};


class smtp_server {
    struct smtp_parameters parameters;

public:

    smtp_server() : parameters{} { }

    void parse(struct datum &pkt) {
        parameters.parse(pkt);

        return;
    }

    void operator()(buffer_stream &buf) const {
        if (is_not_empty() == false) {
            return;
        }
        buf.write_char('(');
        buf.write_char(')');
        //parameters.fingerprint(buf);
    }

    void write_json(json_object &record, bool) {
        if (this->is_not_empty()) {
            struct json_object smtp{record, "smtp"};
            struct json_object smtp_response{smtp, "response"};
            struct json_array params{smtp_response, "parameters"};

            parameters.print_parameters(params, 4);

            params.close();
            smtp_response.close();
            smtp.close();
        }
    }

    //void compute_fingerprint(struct fingerprint) const { }
    void compute_fingerprint(struct fingerprint &fp) const {
        fp.set(*this, fingerprint_type_smtp_server);
    }

    bool is_not_empty() const { return parameters.is_not_empty(); }
};


#endif // SMTP_H
