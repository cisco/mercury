// pem.hpp
//
// PEM file reading

#ifndef PEM_HPP
#define PEM_HPP

#include <list>
#include "libmerc/datum.h"

struct file_reader {
    virtual ssize_t get_cert(uint8_t *outbuf, size_t outbuf_len) = 0;
    virtual ~file_reader() = default;

    void write(writeable &w) {
        ssize_t length = get_cert(w.data, w.writeable_length());
        w.update(length);
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
        const char opening_line[] = "-----BEGIN";
        const char closing_line[] = "-----END";

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
                fprintf(stderr, "error: PEM certificiate %zd too long for buffer, or missing closing line\n", cert_number);
                return -1; // PEM certificate is too long for buffer, or missing closing line
            }
            memcpy(b_ptr, line, advance);
            b_ptr += advance;
        }
        ssize_t cert_len = base64::decode(outbuf, outbuf_len, base64_buffer, b_ptr - base64_buffer);
        if (nread <= 0 && !is_closed)
            fprintf(stderr, "error: PEM format incomplete for certificate %zd\n", cert_number);
        free(line); // TBD: we shouldn't need to call this after every read, but valgrind says we do :-(
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

#endif // PEM_HPP
