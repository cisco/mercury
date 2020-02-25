/*
 * cert-analyze.cc
 *
 * analyze X509 certificates
 */

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <string>
#include <unordered_map>

#include "x509.h"
#include "base64.h"

void print_as_ascii_with_dots(const void *string, size_t len) {
    const char *s = (const char *)string;
    for (size_t i=0; i < len; i++) {
        if (isprint(s[i])) {
            printf("%c", s[i]);
        } else {
            printf(".");
        }
    }
    printf("\n");
}

void fprintf_parser_as_string(FILE *f, struct parser *p) {
    fprintf(f, "%.*s", (int) (p->data_end - p->data), p->data);
}


// set to 1 to include hashing
#define HAVE_MHASH 0
#if HAVE_MHASH

#include <mhash.h>
void sha256_hash(const void *buffer,
                 unsigned int len) {
    int i;
    MHASH td;
    unsigned char hash[32]; 

    hashid hash_type = MHASH_SHA1;
    td = mhash_init(hash_type);
    if (td == MHASH_FAILED) {
        return;
    }

    mhash(td, buffer, len);

    mhash_deinit(td, hash);

    printf("%s: ", mhash_get_hash_name(hash_type));
    for (i = 0; i < mhash_get_block_size(hash_type); i++) {
        printf("%.2x", hash[i]);
    }
    printf("\n");

}

#endif

// std::unordered_map<std::string, std::string> cert_dict;
//#include <thread>

void usage(const char *progname) {
    fprintf(stdout, "%s: --input <infile> [--prefix] [--prefix-as-hex]\n", progname);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    const char *infile = NULL;
    bool prefix = false;
    bool prefix_as_hex = false;
    //const char *outfile = NULL;

    // parse arguments
    while (1) {
        int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        enum arg_type {
             case_input,
             case_output,
             case_prefix,
             case_prefix_as_hex
        };
        static struct option long_options[] = {
             {"input",          required_argument, NULL,  case_input         },
             {"prefix",         no_argument,       NULL,  case_prefix        },
             {"prefix-as-hex",  no_argument,       NULL,  case_prefix_as_hex },
             {0,                0,                 0,     0                  }
        };

        int c = getopt_long(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;
        switch (c) {
        case case_input:
            if (!optarg) {
                fprintf(stderr, "error: option 'input' needs an argument\n");
                usage(argv[0]);
            }
            infile = optarg;
            break;
        case case_prefix_as_hex:
            if (optarg) {
                fprintf(stderr, "error: option 'prefix-as-hex' does not accept an argument\n");
                usage(argv[0]);
            }
            prefix_as_hex = true;
            break;
        case case_prefix:
            if (optarg) {
                fprintf(stderr, "error: option 'prefix' does not accept an argument\n");
                usage(argv[0]);
            }
            prefix = true;
            break;
        case case_output:
            printf("got output ");
            if (optarg)
                printf(" with arg %s", optarg);
            printf("\n");
            break;
        default:
            ;
        }
    }

    if (!infile) {
        fprintf(stderr, "error: no input file specified\n");
        usage(argv[0]);
    }
    stream = fopen(infile, "r");
    if (stream == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    unsigned int line_number = 0;
    while ((nread = getline(&line, &len, stream)) != -1) {
        line_number++;

        size_t offset=0;
        if (0) {
            // advance just past the comma
            int i;
            for (i=0; i<nread; i++) {
                if (line[i] == ',') {
                    break;
                }
            }
            offset = i+1;
        }
        char *b64_line = line + offset;

        uint8_t cert_buf[8192];
        int cert_len = base64::decode(cert_buf, sizeof(cert_buf), b64_line, nread-offset);
        if (cert_len <= 0) {
            fprintf(stderr, "error: base64 decoding failure on line %u\n", line_number);

        } else {

            //  sha256_hash(cert_buf, cert_len);

            try{

                if (prefix || prefix_as_hex) {
                    // parse certificate prefix, then print as JSON 
                    struct x509_cert_prefix p;
                    p.parse(cert_buf, cert_len);
                    if (prefix) {
                        p.print_as_json(stdout);
                    }
                    if (prefix_as_hex) {
                        p.print_as_json_hex(stdout);
                    }
                    // fprintf(stderr, "cert: %u\tprefix length: %zu\n", line_number, p.get_length());

                } else {
                    // parse certificate, then print as JSON
                    struct x509_cert c;
                    c.parse(cert_buf, cert_len);
                    c.print_as_json(stdout);

                }
            }
            catch (const char *msg) {
                fprintf(stdout, "error processing certificate at line %u (%s)\n", line_number, msg);
                //return EXIT_FAILURE;
            }
        }
        //        cert_dict[key] = cert;
    }

    // fprintf(stderr, "loaded %lu certs\n", cert_dict.size());

    free(line);
    fclose(stream);

    exit(EXIT_SUCCESS);

}
