// json_reader.cc
//
// driver/test program for JSON parsing
//
//  compile as: g++ -Wall json_reader.cc -o json_reader parser.c

#include <stdio.h>
#include "parser.h"

unsigned char jbuf[] = "{\"fingerprints\":{\"tls\":\"(0303)(00ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d003c0035002f000a)((0000)(000a00080006001700180019)(000b00020100)(000d000e000c050104010201050304030203)(3374)(00100030002e0268320568322d31360568322d31350568322d313408737064792f332e3106737064792f3308687474702f312e31)(000500050100000000)(0012))\"},\"tls\":{\"client\":{\"version\":\"0303\",\"random\":\"58ec0e8814ec73ee485e09e3cbb4c05779f1c4673ed534335cb9d027f2a7cbac\",\"session_id\":\"a8201677af1768be3750ed52790188168b0fa976e315434f638e81e9724803cd\",\"cipher_suites\":\"00ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d003c0035002f000a\",\"compression_methods\":\"00\",\"server_name\":\"static.criteo.net\",\"fingerprint\":\"(0303)(00ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d003c0035002f000a)((0000)(000a00080006001700180019)(000b00020100)(000d000e000c050104010201050304030203)(3374)(00100030002e0268320568322d31360568322d31350568322d313408737064792f332e3106737064792f3308687474702f312e31)(000500050100000000)(0012))\"}},\"src_ip\":\"10.41.32.146\",\"dst_ip\":\"74.119.117.74\",\"protocol\":6,\"src_port\":60034,\"dst_port\":443,\"event_start\":1491865224.241034}";

struct mercury_record {
    struct parser tls_fingerprint;
    struct parser src_ip;
    struct parser dst_ip;
    struct parser protocol;
    struct parser src_port;
    struct parser dst_port;
    struct parser event_start;

    mercury_record() = default;

    void parse(struct parser &d) {

        uint8_t next_byte;
        if (d.accept_byte((const uint8_t *)"{", &next_byte)) return;
        if (d.accept_byte((const uint8_t *)"\"}", &next_byte)) return;
        struct parser key;
        if (next_byte == '\"') {
            key.parse_up_to_delim(d, '\"'); // "fingerprints"
            d.skip(1);
        }
        fprintf(stderr, "%.*s\n", (int)key.length(), key.data);
        if (d.accept_byte((const uint8_t *)":", &next_byte)) return;
        if (d.accept_byte((const uint8_t *)"{", &next_byte)) return;
        if (d.accept_byte((const uint8_t *)"\"", &next_byte)) return;
        key = {NULL, NULL};
        if (next_byte == '\"') {
            key.parse_up_to_delim(d, '\"');  // "tls"
            d.skip(1);
        }
        fprintf(stderr, "%.*s\n", (int)key.length(), key.data);

        if (d.accept_byte((const uint8_t *)":", &next_byte)) return;
        if (d.accept_byte((const uint8_t *)"\"", &next_byte)) return;
        if (next_byte == '\"') {
            tls_fingerprint.parse_up_to_delim(d, '\"');
            d.skip(1);
        }
        fprintf(stderr, "%.*s\n", (int)tls_fingerprint.length(), tls_fingerprint.data);

        // parser_skip_upto_delim(&d, (const unsigned char *)"src_ip", sizeof("src_ip"));
        // fprintf(stdout, "%.*s\n", (int)d.length(), d.data);
    }
};

int main(int argc, char *argv[]) {

    fwrite(jbuf, 1, sizeof(jbuf), stdout);
    fputc('\n', stdout);

    struct parser d{jbuf, jbuf + sizeof(jbuf)};

    struct mercury_record r;

    r.parse(d);

    return 0;
}
