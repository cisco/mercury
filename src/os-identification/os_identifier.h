
#ifndef OS_IDENTIFIER_H
#define OS_IDENTIFIER_H

#include "../parser.h"

struct mercury_record {
    struct parser fp_type;
    struct parser fingerprint;
    struct parser src_ip;
    struct parser event_start;

    mercury_record() = default;

    mercury_record(struct parser &d) : fp_type{}, fingerprint{}, src_ip{}, event_start{} {
        parse(d);
    };

    void parse(struct parser &d) {
        uint8_t next_byte;
        if (d.accept('{')) return;
        if (d.accept_byte((const uint8_t *)"\"}", &next_byte)) return;
        struct parser key;
        if (next_byte == '\"') {
            key.parse_up_to_delim(d, '\"'); // "fingerprints"
            if (d.accept_byte((const uint8_t *)"\"", &next_byte)) return;
        }
        if (d.accept(':')) return;
        if (d.accept('{')) return;
        if (d.accept('\"')) return;
        fp_type.parse_up_to_delim(d, '\"');  // "tls"/"http"/"tcp"
        if (d.accept('\"')) return;

        if (d.accept(':')) return;
        if (d.accept('\"')) return;
        fingerprint.parse_up_to_delim(d, '\"');
        if (d.accept('\"')) return;
        if (d.accept('}')) return;

        if (parser_skip_upto_delim(&d, (const unsigned char *)"src_ip", sizeof("src_ip")-1)) return;
        if (d.accept('\"')) return;
        if (d.accept(':')) return;
        if (d.accept('\"')) return;
        src_ip.parse_up_to_delim(d, '\"');
        if (d.accept('\"')) return;

        if (parser_skip_upto_delim(&d, (const unsigned char *)"event_start", sizeof("event_start")-1)) return;
        if (d.accept('\"')) return;
        if (d.accept(':')) return;
        event_start.parse_up_to_delim(d, '}');
        if (d.accept('}')) return;
    }

    void write_json(FILE *output) {
        fprintf(output, "{\"fp_type\":\"%.*s\"", (int)fp_type.length(), fp_type.data);
        fprintf(output, ",\"fingerprint\":\"%.*s\"", (int)fingerprint.length(), fingerprint.data);
        fprintf(output, ",\"src_ip\":\"%.*s\"", (int)src_ip.length(), src_ip.data);
        fprintf(output, ",\"event_start\":%.*s}\n", (int)event_start.length(), event_start.data);
    }

};



#endif /* OS_IDENTIFIER_H */
