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
#include <string>

#include "x509.h"
#include "base64.h"
#include "../rapidjson/document.h"


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

// file reading

struct file_reader {
    virtual ssize_t get_cert(uint8_t *outbuf, size_t outbuf_len) = 0;
    virtual ~file_reader() = default;
};


using namespace rapidjson;

struct json_file_reader : public file_reader {
    FILE *stream;
    char *line = NULL;
    unsigned int line_number = 0;

    json_file_reader(const char *infile) : stream{NULL}, line{NULL} {
        stream = fopen(infile, "r");
        if (stream == NULL) {
            fprintf(stderr, "error: could not open file %s (%s)\n", infile, strerror(errno));
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "opened JSON file\n");
    }
    ssize_t get_cert(uint8_t *outbuf, size_t outbuf_len) {
        line_number++;
        size_t len = 0;
        size_t cert_len = 0;
        ssize_t nread = getline(&line, &len, stream); // note: could skip zero-length lines
        if (nread == -1) {
            free(line);
            fprintf(stderr, "error: could not read JSON file\n");
            return 0;
        }

        //        fprintf(stdout, "%s\n", line);

        Document document;
        if (document.ParseInsitu(line).HasParseError()) {
            fprintf(stderr, "error parsing JSON\n");
            return -1;
        } else {
            Value::MemberIterator tls_iterator = document.FindMember("tls");
            if (tls_iterator == document.MemberEnd()) {
                fprintf(stderr, "warning: no \"tls\" object in JSON file\n");
               return 0; // no tls info
            }
            const Value &certs = document["tls"]["server_certs"];
            if (!certs.IsArray()) {
                fprintf(stderr, "warning: no \"tls\"[\"server_certs\"] object in JSON file\n");
                return 0; // no certificates
            }

            for (auto& c : certs.GetArray()) {
                // printf("%s ", c.GetString());

                std::string s = c.GetString();
                cert_len = base64::decode(outbuf, outbuf_len, s.c_str(), s.size());
                break; // just process first cert for now
            }

        }

        return cert_len;
    }


    ~json_file_reader() {
        fclose(stream);
    }
};

struct base64_file_reader : public file_reader {
    FILE *stream;
    char *line = NULL;
    unsigned int line_number = 0;

    base64_file_reader(const char *infile) : stream{NULL}, line{NULL} {
        stream = fopen(infile, "r");
        if (stream == NULL) {
            fprintf(stderr, "error: could not open file %s (%s)\n", infile, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    ssize_t get_cert(uint8_t *outbuf, size_t outbuf_len) {
        size_t len = 0;
        line_number++;
        ssize_t nread = getline(&line, &len, stream); // note: could skip zero-length lines
        if (nread == -1) {
            free(line);
            return 0;
        }
        ssize_t cert_len = base64::decode(outbuf, outbuf_len, line, nread);
#if 0
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
#endif
        if (cert_len < 0) {
            fprintf(stderr, "error: base64 decoding failure on line %u around character %zd\n", line_number, -cert_len);
            const char opening_line[] = "-----BEGIN CERTIFICATE-----";
            if ((size_t)nread >= sizeof(opening_line)-1 && strncmp(line, opening_line, sizeof(opening_line)-1) == 0) {
                fprintf(stderr, "input seems to be in PEM format; try --pem\n");
            }
        }
        free(line); // TBD: we shouldn't need to call this after every read, but valgrind says we do :-(
        return cert_len;
    }
    ~base64_file_reader() {
        fclose(stream);
    }
};

struct pem_file_reader : public file_reader {
    FILE *stream;
    char *line;
    size_t cert_number;

    pem_file_reader(const char *infile) : stream{NULL}, line{NULL}, cert_number{0} {
        stream = fopen(infile, "r");
        if (stream == NULL) {
            fprintf(stderr, "error: could not open file %s (%s)\n", infile, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    ssize_t get_cert(uint8_t *outbuf, size_t outbuf_len) {
        size_t len = 0;
        ssize_t nread = 0;
        const char opening_line[] = "-----BEGIN CERTIFICATE-----";
        const char closing_line[] = "-----END CERTIFICATE-----";

        cert_number++;

        // check for opening
        nread = getline(&line, &len, stream);
        if (nread == -1) {
            free(line); // TBD: we shouldn't need to call this after every read, but valgrind says we do :-(
            return 0;  // empty line; assue we are done with certificates
        }
        if ((size_t)nread >= sizeof(opening_line)-1 && strncmp(line, opening_line, sizeof(opening_line)-1) != 0) {
            const char *pem = "-----BEGIN";
            if ((size_t)nread >= sizeof(pem)-1 && strncmp(line, pem, sizeof(pem)-1) == 0) {
                fprintf(stderr, "error: PEM data does not contain a certificate (encapsulated text %zd)\n", cert_number);
            } else {
                fprintf(stderr, "error: not in PEM format, or missing opening line in certificate %zd\n", cert_number);
            }
            free(line); // TBD: we shouldn't need to call this after every read, but valgrind says we do :-(
            return -1; // missing opening line; not in PEM format
        }

        // marshall data
        char base64_buffer[8*8192];       // note: hardcoded length for now
        char *base64_buffer_end = base64_buffer + sizeof(base64_buffer);
        char *b_ptr = base64_buffer;
        while ((nread = getline(&line, &len, stream)) > 0 ) {
            if (nread == -1) {
                fprintf(stderr, "error: PEM format incomplete for certificate %zd\n", cert_number);
                free(line); // TBD: we shouldn't need to call this after every read, but valgrind says we do :-(
                return -1; // empty line; PEM format incomplete
            }
            ssize_t advance = 0;
            if (nread == 65) {
                advance = nread-1;
            } else {
                if ((size_t)nread >= sizeof(closing_line)-1 && strncmp(line, closing_line, sizeof(closing_line)-1) == 0) {
                    break;
                } else {
                    advance = nread;
                }
            }
            if (b_ptr + advance >= base64_buffer_end) {
                fprintf(stderr, "error: PEM certificiate %zd too long for buffer, or missing closing line\n", cert_number);
                return -1; // PEM certificate is too long for buffer, or missing closing line
            }
            memcpy(b_ptr, line, advance);
            b_ptr += advance;
        }
        ssize_t cert_len = base64::decode(outbuf, outbuf_len, base64_buffer, b_ptr - base64_buffer);
        free(line); // TBD: we shouldn't need to call this after every read, but valgrind says we do :-(
        return cert_len;
    }
    ~pem_file_reader() {
        fclose(stream);
    }
};


// std::unordered_map<std::string, std::string> cert_dict;
//#include <thread>

void usage(const char *progname) {
    fprintf(stdout, "%s: --input <infile> [--prefix] [--prefix-as-hex] [--pem] [--json] [--filter weak]\n", progname);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    const char *infile = NULL;
    const char *filter = NULL;
    bool prefix = false;
    bool prefix_as_hex = false;
    bool input_is_pem = false;
    bool input_is_json = false;
    //const char *outfile = NULL;

    // parse arguments
    while (1) {
        int option_index = 0;
        enum arg_type {
             case_input,
             case_output,
             case_prefix,
             case_prefix_as_hex,
             case_pem,
             case_json,
             case_filter
        };
        static struct option long_options[] = {
             {"input",          required_argument, NULL,  case_input         },
             {"prefix",         no_argument,       NULL,  case_prefix        },
             {"prefix-as-hex",  no_argument,       NULL,  case_prefix_as_hex },
             {"pem",            no_argument,       NULL,  case_pem           },
             {"json",           no_argument,       NULL,  case_json          },
             {"filter",         required_argument, NULL,  case_filter        },
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
        case case_pem:
            if (optarg) {
                fprintf(stderr, "error: option 'pem' does not accept an argument\n");
                usage(argv[0]);
            }
            input_is_pem = true;
            break;
        case case_json:
            if (optarg) {
                fprintf(stderr, "error: option 'json' does not accept an argument\n");
                usage(argv[0]);
            }
            input_is_json = true;
            break;
        case case_filter:
            if (!optarg) {
                fprintf(stderr, "error: option 'filter' requires an argument\n");
                usage(argv[0]);
            }
            filter=optarg;
            break;
        case case_output:
            break;
        default:
            ;
        }
    }

    if (!infile) {
        fprintf(stderr, "error: no input file specified\n");
        usage(argv[0]);
    }

    if ((prefix || prefix_as_hex) && filter) {
        fprintf(stderr, "warning: filter cannot be applied to certificate prefix\n");
    }

    struct file_reader *reader = NULL;
    if (input_is_pem) {
        reader = new pem_file_reader(infile);
    } else if (input_is_json) {
        reader = new json_file_reader(infile);
    } else {
        reader = new base64_file_reader(infile);
    }

    uint8_t cert_buf[8*8192];
    ssize_t cert_len = 1;
    while ((cert_len = reader->get_cert(cert_buf, sizeof(cert_buf))) > 0) {

        //  sha256_hash(cert_buf, cert_len);

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

            if ((filter == NULL) || c.is_not_currently_valid() || c.is_weak() || c.is_nonconformant()) {
                c.print_as_json(stdout);
            }
        }
    }

    delete reader;

    exit(EXIT_SUCCESS);

}
