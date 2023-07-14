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

    enum pem_label {
        NONE                    = 0,
        CERTIFICATE             = 1,
        X509_CRL                = 2,
        CERTIFICATE_REQUEST     = 3,
        PKCS7                   = 4,
        CMS                     = 5,
        PRIVATE_KEY             = 6,
        ENCRYPTED_PRIVATE_KEY   = 7,
        ATTRIBUTE_CERTIFICATE   = 8,
        PUBLIC_KEY              = 9,
        RSA_PRIVATE_KEY         = 10,
        NUM_PEM_LABELS          = 11
    };
    static constexpr const char *pem_label_string[NUM_PEM_LABELS] = {
        "NONE",
        "CERTIFICATE",
        "X509 CRL",
        "CERTIFICATE REQUEST",
        "PKCS7",
        "CMS",
        "PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "ATTRIBUTE CERTIFICATE",
        "PUBLIC KEY",
        "RSA PRIVATE KEY"
    };

    FILE *stream;
    char *line;
    size_t cert_number;
    pem_label last_label = NONE;

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

    pem_label get_pem_label(const char *line, size_t length) {
        const char *opening = "-----BEGIN ";
        if (line == nullptr) {
            return NONE;
        }
        if (strncmp(line, opening, strlen(opening)) != 0) {
            return NONE;
        }

        // find start, end, and length of label string
        //
        const char *label = line + strlen(opening);
        const char *line_end = line + length;
        const char *label_end = label;
        while (label_end < line_end) {
            if (*label_end == '-') {
                break;
            }
            label_end++;
        }
        size_t label_length = label_end-label;

        for (size_t i=0; i<NUM_PEM_LABELS; i++) {
            if (strncmp(pem_label_string[i], label, label_length) == 0) {
                return (pem_label)i;
            }
        }
        return NONE;
    }

    pem_label get_label() const {
        return last_label;
    }

    ssize_t get_cert(uint8_t *outbuf, size_t outbuf_len) {
        size_t len = 0;
        ssize_t nread = 0;
        const char closing_line[] = "-----END";

        cert_number++;

        // check for opening
        nread = getline(&line, &len, stream);
        if (nread == -1) {
            free(line); // TBD: we shouldn't need to call this after every read, but valgrind says we do :-(
            return 0;  // empty line; assue we are done with certificates
        }
        last_label = get_pem_label(line, nread);
        if (last_label == NONE) {
            fprintf(stderr, "error: not in PEM format in textual element %zd\n", cert_number);
            free(line); // TBD: we shouldn't need to call this after every read, but valgrind says we do :-(
            return -1;  // error: not in PEM format
        }

        // marshall data
        char base64_buffer[16*8192];       // note: hardcoded length for now
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

    void write(writeable &w) {
        ssize_t length = get_cert(w.data, w.writeable_length());
        w.update(length);
        last_label = get_label();
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
