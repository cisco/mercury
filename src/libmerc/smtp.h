/*
 * smtp.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef SMTP_H
#define SMTP_H

#include <stdint.h>
#include <stdlib.h>
#include "match.h"
#include "protocol.h"
#include "datum.h"
#include "analysis.h"
#include "json_object.h"
#include "fingerprint.h"


/*
 * SMTP service extension parameters (from RFC 5321)
 *
 * In an effort that started in 1990, approximately a decade after RFC
 * 821 was completed, the protocol was modified with a "service
 * extensions" model that permits the client and server to agree to
 * utilize shared functionality beyond the original SMTP requirements.
 * The SMTP extension mechanism defines a means whereby an extended SMTP
 * client and server may recognize each other, and the server can inform
 * the client as to the service extensions that it supports.
 *
 * IANA maintains a list of these parameters here:
 *   https://www.iana.org/assignments/mail-parameters/mail-parameters.xhtml
 */

struct smtp_parameter {
    one_or_more_up_to_byte<'\r'> parameter;
    crlf delimiter;
    bool valid;
    
    smtp_parameter(struct datum &p) : 
        parameter(p),
        delimiter(p),
        valid(p.is_not_null()) { }

    void write_json(struct json_array &a, bool metadata) const {
        (void)metadata;
        a.print_json_string(parameter);
    }

    bool is_valid() const {
        return valid;
    }

    bool is_not_empty() const {
        return valid and parameter.is_not_empty();
    }
    
};
 
struct smtp_parameters {
    datum parameters;
    bool valid = true;

    smtp_parameters(struct datum &p) : parameters{p} {
        parse(p);
    }

    void parse(struct datum &p) {
        
        while (p.is_not_empty()) {
            smtp_parameter param{p};
            if (!param.is_valid()) {
                valid = false;
                break;
            }
        }
    }    
        
    void fingerprint(struct buffer_stream &buf) const {
        unsigned char crlf[2] = { '\r', '\n' };
        unsigned char domain[1] = { '.' };                    /* used to identify domain parameter */
        unsigned char hello[5] = { 'H', 'e', 'l', 'l', 'o' }; /* used to identify domain parameter */

        datum p{parameters};
        if (!valid) {
            return; 
        }
    
        while (p.length() > 0) {
            if (p.compare(crlf, sizeof(crlf)) == 0) {
                break;  /* at end of parameters */
            }

            struct datum param{p.data, NULL};
            if (p.skip_up_to_delim(crlf, sizeof(crlf)) == false) {
                break;
            }
            param.data_end = p.data - 2;

            if ((param.find_delim(domain, sizeof(domain)) == -1*(param.data_end - param.data)) &&
                (param.find_delim(hello, sizeof(hello)) == -1*(param.data_end - param.data))) {
                buf.write_char('(');
                buf.raw_as_hex(param.data, param.data_end - param.data);
                buf.write_char(')');
            }
        }
    }

    /*
     * Prints the list of SMTP parameters into json_array. If output_metadata == false, then
     *   only parameters related to domain names are printed.
     */
    void write_json(struct json_object &record, bool output_metadata) {
        (void)output_metadata;

        if (!valid) {
            return;
        }

        smtp_parameter param{parameters};
        if (param.is_not_empty()) {
            struct json_array a{record, "parameters"};
            param.write_json(a, output_metadata);

            while(parameters.is_not_empty()) {
                smtp_parameter param{parameters};
                param.write_json(a, output_metadata);
            }
            a.close();
        }
    }

    bool is_valid() const { return valid; }
};


/*
 *
 * SMTP initial client message (from RFC 5321)
 *
 * In any event, a
 * client MUST issue HELO or EHLO before starting a mail transaction.
 *
 * These commands, and a "250 OK" reply to one of them, confirm that
 * both the SMTP client and the SMTP server are in the initial state,
 * that is, there is no transaction in progress and all state tables and
 * buffers are cleared.
 *
 * Syntax:
 * ehlo           = "EHLO" SP ( Domain / address-literal ) CRLF
 * helo           = "HELO" SP Domain CRLF
 *
 * mercury's processing: identify the EHLO line and report this information
 *   in the parameters list, i.e., "smtp": {"request": {"parameters": []}}
 */

class smtp_client : public base_protocol {
    alpha_numeric command;
    optional<literal_byte<' '>>  sp;
    smtp_parameters parameters;

public:

    smtp_client(datum &pkt) : 
        command{pkt},
        sp{pkt},
        parameters{pkt} { }

    void fingerprint(buffer_stream &) const { }

    void write_json(json_object &record, bool metadata) {
        if (is_not_empty()) {
            struct json_object smtp{record, "smtp"};
            struct json_object smtp_request{smtp, "request"};
            smtp_request.print_key_json_string("command", command);
            parameters.write_json(smtp_request, metadata);
            smtp_request.close();
            smtp.close();
        }
    }

    void write_l7_metadata(cbor_object &o, bool) {
        cbor_array protocols{o, "protocols"};
        protocols.print_string("smtp");
        protocols.close();
    }

    bool is_not_empty() const { return parameters.is_valid(); }

    static constexpr mask_and_value<8> matcher{
        { 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 },
        { 0x45, 0x48, 0x4c, 0x4f, 0x20, 0x00, 0x00, 0x00 }
    };

};


/*
 *
 * SMTP server message (from RFC 5321)
 *
 * Normally, the response to EHLO will be a multiline reply.  Each line
 * of the response contains a keyword and, optionally, one or more
 * parameters.  Following the normal syntax for multiline replies, these
 * keywords follow the code (250) and a hyphen for all but the last
 * line, and the code and a space for the last line.  The syntax for a
 * positive response, using the ABNF notation and terminal symbols of
 * RFC 5234 [7], is:
 *
 * ehlo-ok-rsp    = ( "250" SP Domain [ SP ehlo-greet ] CRLF )
 *                  / ( "250-" Domain [ SP ehlo-greet ] CRLF
 *                  *( "250-" ehlo-line CRLF )
 *                  "250" SP ehlo-line CRLF )
 *
 * mercury's processing: identify the server's response to the client's
 *   EHLO line and report the server's response in the parameters list,
 *   i.e., "smtp_server": {"response": {"parameters": []}}. We also
 *   generate a fingerprint string that reports all non-domain parameters.
 */
class smtp_server : public base_protocol {
    alpha_numeric command;
    optional<literal_byte<' '>>  sp;
    smtp_parameters parameters;

public:

    smtp_server(datum &pkt) :
        command{pkt},
        sp{pkt},
        parameters{pkt} { }

    void fingerprint(buffer_stream &buf) const {
        if (is_not_empty() == false) {
            return;
        }
        parameters.fingerprint(buf);
    }

    void write_json(json_object &record, bool output_metadata) {
        if (is_not_empty()) {
            struct json_object smtp{record, "smtp"};
            struct json_object smtp_response{smtp, "response"};
            smtp_response.print_key_json_string("command", command);
            parameters.write_json(smtp_response, output_metadata);
            smtp_response.close();
            smtp.close();
        }
    }

    void write_l7_metadata(cbor_object &o, bool) {
        cbor_array protocols{o, "protocols"};
        protocols.print_string("smtp");
        protocols.close();
    }

    void compute_fingerprint(class fingerprint &fp) const {
        fp.set_type(fingerprint_type_smtp_server);
        fp.add(*this);
        fp.final();
    }

    bool is_not_empty() const { return parameters.is_valid(); }

    bool do_analysis(const struct key, struct analysis_context, classifier*) { return false; }

    static constexpr mask_and_value<8> matcher{
        { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 },
        { 0x32, 0x35, 0x30, 0x2d, 0x00, 0x00, 0x00, 0x00 }
    };

};

[[maybe_unused]] inline int smtp_client_packet_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<smtp_client>(data, size);
}

[[maybe_unused]] inline int smtp_server_packet_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<smtp_client>(data, size);
}

#endif // SMTP_H
