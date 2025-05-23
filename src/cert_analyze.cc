/*
 * cert_analyze.cc
 *
 * analyze X509 certificates
 *
 * Copyright (c) 2021 Cisco Systems, Inc.  All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <string>
#include <unordered_map>
#include <string>
#include <list>
#include <regex>

#include "libmerc/x509.h"
#include "libmerc/base64.h"
#include "libmerc/rapidjson/document.h"
#include "libmerc/crypto_engine.h"

// certificate hashing

void fprint_sha1_hash(FILE *f, const void *buffer, unsigned int len) {

    class hasher h;
    uint8_t output_buffer[h.output_size];

    h.hash_buffer((uint8_t *)buffer, len, output_buffer, sizeof(output_buffer));

    for (size_t i = 0; i < sizeof(output_buffer); i++) {
        fprintf(f, "%.2x", output_buffer[i]);
    }
    fputc('\n', f);

}


// file reading

struct file_reader {
    virtual ssize_t get_cert(uint8_t *outbuf, size_t outbuf_len) = 0;
    virtual ~file_reader() = default;
    void get_cert_list(std::list<struct x509_cert> &list_of_certs, uint8_t *cb, size_t cb_len) {
        ssize_t cert_len = 1;
        while ((cert_len = get_cert(cb, cb_len)) > 0) {
            struct x509_cert c;
            c.parse(cb, cert_len);
            list_of_certs.push_back(c);
            cb += cert_len;
            cb_len -= cert_len;
        }
    }
};

struct der_file_reader : public file_reader {
    FILE *stream;
    bool done = false;

    der_file_reader(const char *infile) {
        if (infile == NULL) {
            stream = stdin;
        } else {
            stream = fopen(infile, "r");
            if (stream == NULL) {
                fprintf(stderr, "error: could not open file %s (%s)\n", infile, strerror(errno));
                exit(EXIT_FAILURE);
            }
        }
    }
    ssize_t get_cert(uint8_t *outbuf, size_t outbuf_len) {
        if (done) {
            return 0;
        }
        fseek(stream, 0, SEEK_END);
        size_t file_length = ftell(stream);
        fseek(stream, 0, SEEK_SET);

        if (file_length > outbuf_len) {
            fprintf(stderr, "error: certificate too large for buffer\n");
            return -1;
        }
        if (fread(outbuf, 1, file_length, stream) != file_length) {
            fprintf(stderr, "error: could not read entire certificate\n");
            return -1;
        }
        if (tlv::is_der_format(outbuf, file_length) != true) {
            fprintf(stderr, "error: input is not in DER format\n");
            return -1;
        }
        done = true;
        return file_length;
    }
    ~der_file_reader() {
        fclose(stream);
    };
};

using namespace rapidjson;

struct json_file_reader : public file_reader {
    FILE *stream;
    unsigned int line_number = 0;

    json_file_reader(const char *infile) : stream{NULL} {
        if (infile == NULL) {
            stream = stdin;
        } else {
            stream = fopen(infile, "r");
            if (stream == NULL) {
                fprintf(stderr, "error: could not open file %s (%s)\n", infile, strerror(errno));
                exit(EXIT_FAILURE);
            }
        }
    }
    ssize_t get_cert(uint8_t *outbuf, size_t outbuf_len) {
        line_number++;
        size_t len = 0;
        size_t cert_len = 0;
        char *line = NULL;

        while (1) {
            ssize_t nread = getline(&line, &len, stream); // note: could skip zero-length lines
            if (nread == -1) {
                free(line);
                line = NULL;
                return 0;
            }
            // fprintf(stdout, "line: %s", line);

            Document document;
            document.ParseInsitu(line);
            if (document.HasParseError()) {
                fprintf(stderr, "error parsing JSON\n");
                return -1;
            }
            if (document.HasMember("tls")) {
                const Value &tls_object = document["tls"];
                if (!tls_object.IsObject()) {
                    fprintf(stderr, "warning: no \"tls\" object in JSON line\n");

                } else if (tls_object.HasMember("server_certs")) {
                    //fprintf(stderr, "found server_certs\n");
                    const Value &server_certs_array = tls_object["server_certs"];
                    if (!server_certs_array.IsArray()) {
                        fprintf(stderr, "warning: no \"server_certs\" in \"tls\" object\n");
                    } else {
                        for (auto& c : server_certs_array.GetArray()) {
                            // fprintf(stderr, "%s ", c.GetString());
                            std::string s = c.GetString();
                            cert_len = base64::decode(outbuf, outbuf_len, s.c_str(), s.size());
                            break; // just process first cert for now // TODO: process all certs
                        }
                        free(line);
                        line = NULL;
                        return cert_len;
                    }
                }
            }
            //free(line);
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
        if (infile == NULL) {
            stream = stdin;
        } else {
            stream = fopen(infile, "r");
            if (stream == NULL) {
                fprintf(stderr, "error: could not open file %s (%s)\n", infile, strerror(errno));
                exit(EXIT_FAILURE);
            }
        }
    }
    ssize_t get_cert(uint8_t *outbuf, size_t outbuf_len) {
        size_t len = 0;
        line_number++;
        ssize_t nread = getline(&line, &len, stream); // note: could skip zero-length lines
        if (nread == -1) {
            free(line);
            line = NULL;
            return 0;
        }

        // trim LF from line
        //
        if (nread > 0) {
            if (line[nread-1] == '\n') {
                nread--;
            }
        }
        ssize_t cert_len = base64::decode(outbuf, outbuf_len, line, nread);
        if (cert_len < 0) {
            fprintf(stderr, "error: base64 decoding failure on line %u around character %zd\n", line_number, -cert_len);
            const char opening_line[] = "-----BEGIN CERTIFICATE-----";
            if ((size_t)nread >= sizeof(opening_line)-1 && strncmp(line, opening_line, sizeof(opening_line)-1) == 0) {
                fprintf(stderr, "input seems to be in PEM format; try --pem\n");
            }
            if (nread > 0 && line[0] == '{') {
                fprintf(stderr, "input may be in JSON format; try --json\n");
            }
        }
        free(line); // TBD: we shouldn't need to call this after every read, but valgrind says we do :-(
        line = NULL;
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
        if (infile == NULL) {
            stream = stdin;
        } else {
            stream = fopen(infile, "r");
            if (stream == NULL) {
                fprintf(stderr, "error: could not open file %s (%s)\n", infile, strerror(errno));
                exit(EXIT_FAILURE);
            }
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
            line = NULL;
            return 0;  // empty line; assume we are done with certificates
        }
        if ((size_t)nread >= sizeof(opening_line)-1 && strncmp(line, opening_line, sizeof(opening_line)-1) != 0) {
            const char *pem = "-----BEGIN";
            if ((size_t)nread >= sizeof(pem)-1 && strncmp(line, pem, sizeof(pem)-1) == 0) {
                fprintf(stderr, "error: PEM data does not contain a certificate (encapsulated text %zd)\n", cert_number);
            } else {
                fprintf(stderr, "error: not in PEM format, or missing opening line in certificate %zd\n", cert_number);
            }
            free(line); // TBD: we shouldn't need to call this after every read, but valgrind says we do :-(
            line = NULL;
            return -1; // missing opening line; not in PEM format
        }

        // marshall data
        char base64_buffer[64*8192];       // note: hardcoded length for now
        char *base64_buffer_end = base64_buffer + sizeof(base64_buffer);
        char *b_ptr = base64_buffer;
        bool is_closed = false;
        while ((nread = getline(&line, &len, stream)) > 0 ) {
            ssize_t advance = 0;
            if (nread == 65) {
                advance = nread-1;
            } else {
                if ((size_t)nread >= sizeof(closing_line)-1 && strncmp(line, closing_line, sizeof(closing_line)-1) == 0) {
                    is_closed = true;
                    break;
                } else {
                     if (line[nread-1] == '\n') {
                        advance = nread - 1;
                    } else {
                        advance = nread;
                    }
                }
            }
            if (b_ptr + advance >= base64_buffer_end) {
                fprintf(stderr, "error: PEM certificate %zd too long for buffer, or missing closing line\n", cert_number);
                return -1; // PEM certificate is too long for buffer, or missing closing line
            }
            memcpy(b_ptr, line, advance);
            b_ptr += advance;
        }
        ssize_t cert_len = base64::decode(outbuf, outbuf_len, base64_buffer, b_ptr - base64_buffer);
        if (nread <= 0 && !is_closed)
            fprintf(stderr, "error: PEM format incomplete for certificate %zd\n", cert_number);
        free(line); // TBD: we shouldn't need to call this after every read, but valgrind says we do :-(
        line = NULL;
        return cert_len;
    }
    ~pem_file_reader() {
        fclose(stream);
    }
};

struct der_file_writer {
    FILE *stream;

    der_file_writer(const char *outfile) {
        stream = fopen(outfile, "w");
        if (stream == NULL) {
            fprintf(stderr, "error: could not open file %s (%s)\n", outfile, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    ssize_t write_cert(const uint8_t *outbuf, size_t outbuf_len) {
        size_t bytes_written = fwrite(outbuf, 1, outbuf_len, stream);
        if (bytes_written == outbuf_len) {
            return bytes_written;
        }
        return -bytes_written; // indicate error with negative return value
    }
    ~der_file_writer() {
        fclose(stream);
    };
};

struct base64_file_writer {
    FILE *stream;

    base64_file_writer(const char *outfile) {
        stream = fopen(outfile, "a");
        if (stream == NULL) {
            fprintf(stderr, "error: could not open file %s (%s)\n", outfile, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    ssize_t write_cert(const uint8_t *outbuf, size_t outbuf_len) {
        std::string b64 = base64_encode(outbuf, outbuf_len);
        b64 += '\n';
        size_t bytes_written = fwrite(b64.c_str(), 1, b64.length(), stream);
        if (bytes_written == b64.length()) {
            return bytes_written;
        }
        return -bytes_written; // indicate error with negative return value
    }
    bool is_empty() {
        if (stream) {
            return ftell(stream) == 0;
        }
        return false;
    }
    ~base64_file_writer() {
        fclose(stream);
    };
};

[[maybe_unused]] static bool write_pem(FILE *f, const uint8_t *data, size_t length, const char *label="RSA PRIVATE KEY") {

    const char opening_line[] = "-----BEGIN ";
    const char closing_line[] = "-----END ";

    fprintf(f, "%s%s-----\n", opening_line, label);
    std::string b64 = base64_encode(data, length);
    const char *data_end = b64.data() + b64.length();
    for (char *c=b64.data(); c < data_end; c+=64) {
        int ll = (c + 64 < data_end) ? 64 : data_end - c;
        fprintf(f, "%.*s\n", ll, c);
    }
    fprintf(f, "%s%s-----\n", closing_line, label);

    return true;
}

// std::unordered_map<std::string, std::string> cert_dict;
//#include <thread>

[[noreturn]] void usage(const char *progname) {
    const char *help_message =
        "usage: %s: [--input <infile>] [INPUT OPTIONS] [OUTPUT OPTIONS]\n"
        "   --input <infile> reads certificate(s) from <infile> in base64 format\n"
        "   otherwise, certificates are read from standard input\n"
        "INPUT\n"
        "   --pem            input file is in PEM format\n"
        "   --der            input file is in DER format\n"
        "   --json           input file is in JSON format\n"
        "OUTPUT\n"
        "   no option        output certificate(s) as JSON\n"
        "   --prefix         output only the certificate prefix\n"
        "   --prefix-as-hex  output only the certificate prefix as hexadecimal\n"
        "   --log-malformed <outfile> write malformed certs to <outfile> in DER format\n"
        "   --filter <spec>  output only certificates matching <spec>:\n"
        "            weak\n"
        "   --key-group      identify duplicate keys with key_group number\n"
        "   --common-key <f> write certs with common keys into output file <f>\n"
        "   --trunc-test     parse every possible truncation of certificates\n"
        "OTHER\n"
        "   --trust <roots>  trust certificates in <roots>\n"
        "   --help           print this message\n";

    fprintf(stdout, help_message, progname);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    const char *infile = NULL;
    const char *filter = NULL;
    const char *logfile = NULL;
    const char *trust = NULL;
    const char *common_key = NULL;
    bool prefix = false;
    bool prefix_as_hex = false;
    bool input_is_pem = false;
    bool input_is_json = false;
    bool input_is_der = false;
    bool key_group = false;
    bool trunc_test = false;
    bool pem_output = false;
    bool sha1_output = false;
    bool verbose = false;    // this could be set by a command line option

    // parse arguments
    while (1) {
        int option_index = 0;
        enum arg_type {
             case_input,
             case_output,
             case_prefix,
             case_prefix_as_hex,
             case_pem_output,
             case_sha1_output,
             case_pem,
             case_json,
             case_der,
             case_filter,
             case_log_malformed,
             case_key_group,
             case_common_key,
             case_trunc_test,
             case_trust,
             case_help,
        };
        static struct option long_options[] = {
             {"input",          required_argument, NULL,  case_input         },
             {"pem",            no_argument,       NULL,  case_pem           },
             {"json",           no_argument,       NULL,  case_json          },
             {"der",            no_argument,       NULL,  case_der           },
             {"prefix",         no_argument,       NULL,  case_prefix        },
             {"prefix-as-hex",  no_argument,       NULL,  case_prefix_as_hex },
             {"pem-output",     no_argument,       NULL,  case_pem_output    },
             {"sha1-output",    no_argument,       NULL,  case_sha1_output   },
             {"filter",         required_argument, NULL,  case_filter        },
             {"log-malformed",  required_argument, NULL,  case_log_malformed },
             {"key-group",      no_argument,       NULL,  case_key_group     },
             {"common-key",     required_argument, NULL,  case_common_key    },
             {"trunc-test",     no_argument,       NULL,  case_trunc_test    },
             {"trust",          required_argument, NULL,  case_trust         },
             {"help",           no_argument,       NULL,  case_help          },
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
        case case_sha1_output:
            if (optarg) {
                fprintf(stderr, "error: option 'sha1-output' does not accept an argument\n");
                usage(argv[0]);
            }
            sha1_output = true;
            break;
        case case_pem_output:
            if (optarg) {
                fprintf(stderr, "error: option 'pem-output' does not accept an argument\n");
                usage(argv[0]);
            }
            pem_output = true;
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
        case case_der:
            if (optarg) {
                fprintf(stderr, "error: option 'der' does not accept an argument\n");
                usage(argv[0]);
            }
            input_is_der = true;
            break;
        case case_filter:
            if (!optarg) {
                fprintf(stderr, "error: option 'filter' requires an argument\n");
                usage(argv[0]);
            }
            if (strncmp("regex=", optarg, strlen("regex=")) == 0) {
                optarg += strlen("regex=");
                fprintf(stderr, "filter option '%s'\n", optarg);
            } else if (strcmp("weak", optarg) != 0) {
                fprintf(stderr, "error: unrecognized filter option '%s'\n", optarg);
                usage(argv[0]);
            }
            filter=optarg;
            break;
        case case_log_malformed:
            if (!optarg) {
                fprintf(stderr, "error: option 'log-malformed' needs an argument\n");
                usage(argv[0]);
            }
            logfile = optarg;
            break;
        case case_key_group:
            if (optarg) {
                fprintf(stderr, "error: option 'key-group' does not accept an argument\n");
                usage(argv[0]);
            }
            key_group = true;
            break;
        case case_common_key:
            if (!optarg) {
                fprintf(stderr, "error: option 'common-key' needs an argument\n");
                usage(argv[0]);
            }
            common_key = optarg;
            break;
        case case_trunc_test:
            if (optarg) {
                fprintf(stderr, "error: option 'trunc-test' does not accept an argument\n");
                usage(argv[0]);
            }
            trunc_test = true;
            break;
        case case_trust:
            if (!optarg) {
                fprintf(stderr, "error: option 'trust' needs an argument\n");
                usage(argv[0]);
            }
            trust = optarg;
            break;
        case case_help:
            if (optarg) {
                fprintf(stderr, "error: option 'help' does not accept an argument\n");
            }
            usage(argv[0]);
            break;
        case '?':
            usage(argv[0]);
            break;
        case case_output:
            break;
        default:
            ;
        }
    }
   if (optind < argc) {
        printf("error: unrecognized options string(s): ");
        while (optind < argc) {
            printf("%s ", argv[optind++]);
        }
        printf("\n");
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
    } else if (input_is_der) {
        reader = new der_file_reader(infile);
    } else {
        reader = new base64_file_reader(infile);
    }

    static struct dictionary *kg = NULL;
    static struct dictionary key_group_dict;
    if (key_group) {
        kg = &key_group_dict;
    }

    // common_keys
    std::unordered_map<std::basic_string<uint8_t>, std::basic_string<uint8_t>> keys_to_certs{};

    std::list<struct x509_cert> trusted_certs;
    uint8_t trusted_cert_buf[256 * 1024];
    uint8_t *cb = trusted_cert_buf;
    size_t cb_len = sizeof(trusted_cert_buf);
    if (trust) {
        struct file_reader *reader = new pem_file_reader(trust);
        reader->get_cert_list(trusted_certs, cb, cb_len);
        // for (auto &c : trusted_certs) {
        //    c.print_as_json(stdout);
        // }
    }

    unsigned int log_index = 0;
    uint8_t cert_buf[256 * 1024];
    ssize_t cert_len = 1;
    while ((cert_len = reader->get_cert(cert_buf, sizeof(cert_buf))) > 0) {

        // fprintf_raw_as_hex(stderr, cert_buf, cert_len);
        // fprintf(stderr, "\n");

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

        } else if (sha1_output) {

            fprint_sha1_hash(stdout, cert_buf, cert_len);

        } else {

            // parse certificate, then print as JSON
            char buffer[64*8192];       // note: hardcoded length for now
            struct buffer_stream buf(buffer, sizeof(buffer));
            struct x509_cert c;
            try {
                if (trunc_test) {

                    for (ssize_t trunc_len=0; trunc_len <= cert_len; trunc_len++) {
                        fprintf(stdout, "{ \"trunc_len\": %zd }\n", trunc_len);
                        buf = { buffer, sizeof(buffer) };
                        struct x509_cert cc;
                        cc.parse(cert_buf, trunc_len);
                        cc.print_as_json(buf, trusted_certs, kg);
                        buf.write_line(stdout);
                    }

                } else if (common_key) {

                    // detect distinct certificates that have identical keys
                    c.parse(cert_buf, cert_len);
                    if (c.is_valid()) {
                        std::basic_string<uint8_t> k;
                        c.get_subject_public_key(k);

                        auto key_and_cert = keys_to_certs.find(k);
                        if (key_and_cert != keys_to_certs.end()) {
                            if (verbose) {
                                fprintf(stdout, "found duplicate for key ");
                                datum tmp{k.c_str(), k.c_str() + k.length()};
                                tmp.fprint_hex(stdout);
                                fputc('\n', stdout);
                            }

                            // open/create a file to write certs with key k into
                            //
                            std::string key_as_hex = hex_encode(k.c_str(), k.length());
                            std::string filename{common_key};
                            filename += "-" + key_as_hex.substr(32, 48);
                            base64_file_writer b64writer{filename.c_str()};

                            // write certs to file
                            if (b64writer.is_empty()) {
                                // write first certificate with key k into file
                                if (b64writer.write_cert(key_and_cert->second.c_str(), key_and_cert->second.length()) < 0) {
                                    fprintf(stderr, "error: could not write original certificate to base64 output file\n");
                                }
                            }
                            if (b64writer.write_cert(cert_buf, cert_len) < 0) {
                                fprintf(stderr, "error: could not write certificate to base64 output file\n");
                            }

                        } else {
                            std::basic_string<uint8_t> tmp_cert{cert_buf, cert_len};
                            keys_to_certs.insert({k, tmp_cert});
                        }

                        // note: b64writer closes its file at the end of
                        // this scope, though the data in the file
                        // probably won't be written out to disk until
                        // immediately
                    }

                } else {

                    std::regex rgx;
                    if (filter && strcmp(filter, "weak") != 0) {
                        rgx = std::regex{filter};
                    }
                    char *search_start = (char *)cert_buf;
                    char *search_end = search_start + cert_len;
                    c.parse(cert_buf, cert_len);
                    if ((filter == NULL)
                        || (strcmp(filter, "weak") == 0 && (c.is_not_currently_valid()
                                                           || c.subject_key_is_weak()
                                                           || c.signature_is_weak()
                                                           || c.is_nonconformant()
                                                           || c.is_self_issued()
                                                            || !c.is_trusted(trusted_certs)))
                        || std::regex_search(search_start, search_end, rgx)) {

                        if (pem_output) {
                            bool success = write_pem(stdout, cert_buf, cert_len, "CERTIFICATE");
                            if (!success) {
                                throw std::runtime_error{"could not write PEM output"};
                            }
                        } else {
                            c.print_as_json(buf, trusted_certs, kg);
                            buf.write_line(stdout);
                        }
                    }

                }
            } catch (const char *s) {
                fprintf(stderr, "caught exception: %s\n", s);
                if (logfile) {
                    std::string filename(logfile);
                    filename.append(std::to_string(log_index++));
                    filename.append(".der");
                    der_file_writer der_file(filename.c_str());
                    if (der_file.write_cert(cert_buf, cert_len) < 0) {
                        fprintf(stderr, "error: could not write certificate %s to file\n", filename.c_str());
                    }
                    //c.print_as_json(buf);
                }
            }
        }
    }

    delete reader;

    exit(EXIT_SUCCESS);

}
