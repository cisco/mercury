// json_reader.cc
//
// driver/test program for JSON parsing
//
//  compile as: g++ -Wall json_reader.cc -o json_reader parser.c
//
// Copyright (c) 2021 Cisco Systems, Inc.  All rights reserved.  License at
// https://github.com/cisco/mercury/blob/master/LICENSE

#include <stdio.h>
#include "parser.h"

unsigned char jbuf[] = "{\"fingerprints\":{\"tls\":\"(0303)(00ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d003c0035002f000a)((0000)(000a00080006001700180019)(000b00020100)(000d000e000c050104010201050304030203)(3374)(00100030002e0268320568322d31360568322d31350568322d313408737064792f332e3106737064792f3308687474702f312e31)(000500050100000000)(0012))\"},\"tls\":{\"client\":{\"version\":\"0303\",\"random\":\"58ec0e8814ec73ee485e09e3cbb4c05779f1c4673ed534335cb9d027f2a7cbac\",\"session_id\":\"a8201677af1768be3750ed52790188168b0fa976e315434f638e81e9724803cd\",\"cipher_suites\":\"00ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d003c0035002f000a\",\"compression_methods\":\"00\",\"server_name\":\"static.criteo.net\",\"fingerprint\":\"(0303)(00ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d003c0035002f000a)((0000)(000a00080006001700180019)(000b00020100)(000d000e000c050104010201050304030203)(3374)(00100030002e0268320568322d31360568322d31350568322d313408737064792f332e3106737064792f3308687474702f312e31)(000500050100000000)(0012))\"}},\"src_ip\":\"10.41.32.146\",\"dst_ip\":\"74.119.117.74\",\"protocol\":6,\"src_port\":60034,\"dst_port\":443,\"event_start\":1491865224.241034}";

// struct mercury_record represents a mercury JSON output record.
// It can be constructed by parsing a string containing such a record,
// with these caveats:
//      * the order of the fields must match those used by mercury
//      * there must be no whitespace
// No JSON validation is performed, and in fact the parsing routine will
// accept all sorts of garbage.
//
// A future version may perform JSON validation.

struct mercury_record {
    struct parser tls_fingerprint;
    struct parser server_name;
    struct parser dst_ip;
    struct parser dst_port;
    //struct parser src_ip;
    // struct parser protocol;
    //struct parser src_port;
    //struct parser event_start;

    mercury_record() = default;

    mercury_record(struct parser &d) : tls_fingerprint{}, server_name{}, dst_ip{}, dst_port{} {
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
        key = {NULL, NULL};
        key.parse_up_to_delim(d, '\"');  // "tls"
        if (d.accept('\"')) return;

        if (d.accept(':')) return;
        if (d.accept('\"')) return;
        tls_fingerprint.parse_up_to_delim(d, '\"');
        if (d.accept('\"')) return;
        if (d.accept('}')) return;

        if (parser_skip_upto_delim(&d, (const unsigned char *)"server_name", sizeof("server_name")-1)) return;
        if (d.accept('\"')) return;
        if (d.accept(':')) return;
        if (d.accept('\"')) return;
        server_name.parse_up_to_delim(d, '\"');
        if (d.accept('\"')) return;

        if (parser_skip_upto_delim(&d, (const unsigned char *)"dst_ip", sizeof("dst_ip")-1)) return;
        if (d.accept('\"')) return;
        if (d.accept(':')) return;
        if (d.accept('\"')) return;
        dst_ip.parse_up_to_delim(d, '\"');
        if (d.accept('\"')) return;

        if (parser_skip_upto_delim(&d, (const unsigned char *)"dst_port", sizeof("dst_port")-1)) return;
        if (d.accept('\"')) return;
        if (d.accept(':')) return;
        dst_port.parse_up_to_delim(d, ',');
        if (d.accept('\"')) return;

    }

    void write_json(FILE *output) {

        fprintf(output, "{\"fingerprint\":\"%.*s\"", (int)tls_fingerprint.length(), tls_fingerprint.data);
        fprintf(output, ",\"server_name\":\"%.*s\"", (int)server_name.length(), server_name.data);
        fprintf(output, ",\"dst_ip\":\"%.*s\"", (int)dst_ip.length(), dst_ip.data);
        fprintf(output, ",\"dst_port\":%.*s}\n", (int)dst_port.length(), dst_port.data);

    }
};

int main(int argc, char *argv[]) {

    //fwrite(jbuf, 1, sizeof(jbuf), stdout);
    //fputc('\n', stdout);

    struct parser d{jbuf, jbuf + sizeof(jbuf)};
    struct mercury_record r{d};
    r.write_json(stdout);

    return 0;
}
