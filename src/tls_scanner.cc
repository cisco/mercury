//
// tls_scanner.cc
//
// tls_scanner scans an HTTPS server and obtains and reports its TLS
// certificate chain and HTTP response.  It can access domain-fronted
// HTTP servers, and test for domain fronting, when an inner_hostname
// is provided that is distinct from the (outer) hostname.  By
// default, it reports all of the "src=" links in the returned HTML;
// if the HTTP response status code indicates that the resource has
// moved (codes 301 and 302), then the entire response body is printed
// out.  The program is a simple wrapper around the tls_scanner class.

#include <string>
#include <unordered_map>
#include <set>
#include <regex>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "libmerc/asn1/x509.h"
#include "libmerc/http.h"
#include "libmerc/json_object.h"

class tls_scanner {
private:
    SSL_CTX *ctx = NULL;

    constexpr static const char *tlsv1_3_only = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256";

public:
    tls_scanner(const std::string &hostname, std::string &inner_hostname) {

        std::string &http_host_field = inner_hostname;
        if (inner_hostname == "") {
            http_host_field = hostname;
        }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_library_init();
        SSL_load_error_strings();
#endif
        // initialize openssl session context
        ctx = SSL_CTX_new(TLS_client_method());
        if (ctx == NULL) {
            throw "error: could not initialize TLS context\n";
        }
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            throw "error: could not initialize TLS verification\n";
        }

        std::string host_and_port = hostname + ":443";
        BIO *bio = BIO_new_connect(host_and_port.c_str());
        if (bio == nullptr) {
            throw "error: could not create BIO\n";
        }
        if (BIO_do_connect(bio) <= 0) {
            throw "error: could not connect\n";
        }

        BIO *tls_bio = BIO_new_ssl(ctx, 1);
        if (tls_bio == NULL) {
            throw "error: BIO_new_ssl() returned NULL\n";
        }

        BIO_push(tls_bio, bio);

        SSL *tls = NULL;
        BIO_get_ssl(tls_bio, &tls);
        if (tls == NULL) {
            throw "error: could not initialize TLS context\n";
        }

        constexpr bool tls_version_1_3_only = false;
        if (tls_version_1_3_only) {
            int status = SSL_set_min_proto_version(tls, TLS1_3_VERSION);
            if (status != 1) {
                fprintf(stderr, "warning: could not set protocol version to 1.3 (status=%d)\n", status);
                // throw "error: could not set protocol version to 1.2\n";
            }
        }

        // status = SSL_set_cipher_list(tls, tlsv1_3_only);
        // if (status != 1) {
        //     fprintf(stderr, "warning: SSL_CTX_set_cipher_list() returned %d\n", status);
        //     // throw "error: could not set TLSv1.3-only ciphersuites\n";
        // }

        SSL_set_tlsext_host_name(tls, hostname.c_str());
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        SSL_set1_host(tls, hostname.c_str());
#endif

        if (BIO_do_handshake(tls_bio) <= 0) {
            throw "error: TLS handshake failed\n";
        }

        int err = SSL_get_verify_result(tls);
        if (err != X509_V_OK) {
            const char *message = X509_verify_cert_error_string(err);
            fprintf(stderr, "note: certificate verification failed (%s, code %d)\n", message, err);
        }
        X509 *cert = SSL_get_peer_certificate(tls);
        if (cert == nullptr) {
            fprintf(stderr, "note: server did not present a certificate\n");
        }

        uint8_t *cert_buffer = NULL;
        int cert_len = i2d_X509(cert, &cert_buffer);
        if (cert_len > 0) {

            // parse and print certificate using libmerc/asn1/x509.h
            struct x509_cert cc;
            cc.parse(cert_buffer, cert_len);
            cc.print_as_json(stdout);

        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        if (X509_check_host(cert, hostname.data(), hostname.size(), 0, nullptr) != 1) {
            fprintf(stderr, "note: host verification failed\n");
        }
#else
        // X509_check_host() called automatically
#endif

        // send HTTP request
        std::string line = "GET / HTTP/1.1";
        std::string request = line + "\r\n";
        request += "Host: " + http_host_field + "\r\n";
        request += "User-Agent: Mozilla/5.0 (Linux; ; ) AppleWebKit/ (KHTML, like Gecko) Chrome/ Mobile Safari/\r\n"; // pretend we're Android
        request += "Connection: close\r\n";
        request += "\r\n";
        BIO_write(tls_bio, request.data(), request.size());
        BIO_flush(tls_bio);

        // get HTTP response
        int http_response_len = 0, read_len = 0;
        char http_buffer[1024*256] = {};
        char *current = http_buffer;
        do {
            read_len = BIO_read(tls_bio, current, sizeof(http_buffer) - http_response_len);
            current += read_len;
            http_response_len += read_len;
            //fprintf(stderr, "BIO_read %d bytes\n", read_len);
        } while (read_len > 0 || BIO_should_retry(tls_bio));

        // parse and process http_response message
        if(http_response_len > 0) {

            //fprintf(stdout, "%.*s", http_response_len, http_buffer);

            // parse http headers, and print as JSON
            const unsigned char *tmp = (const unsigned char *)http_buffer;
            struct datum http{tmp, tmp+http_response_len};
            if (true) {
                http_response response;
                response.parse(http);

                char output_buffer[1024*16];
                struct buffer_stream output_buffer_stream{output_buffer, sizeof(output_buffer)};
                struct json_object http_record{&output_buffer_stream};
                response.write_json(http_record);
                http_record.close();
                output_buffer_stream.write_line(stdout);

                if (true || response.status_code.compare("301", 3) == 0 || response.status_code.compare("302", 3) == 0 ) {
                    // print out redirect data
                    fprintf(stdout, "body: %.*s", (int)http.length(), http.data);
                }
            }
            // print out raw body
            //fprintf(stdout, "body: %.*s", (int)http.length(), http.data);

            // print out links
            std::set<std::string> src_links = {};
            std::string http_body = http.get_string();
            std::smatch matches;
            std::regex rgx("src.{2,8}(http(s)*:)*//[a-zA-Z0-9-]*(\\.[a-zA-Z0-9-]*)*");
            while (std::regex_search(http_body, matches, rgx)) {
                // fprintf(stdout, "%s\n", matches[0].str().c_str());
                src_links.insert(matches[0].str());
                http_body = matches.suffix().str();
            }
            for (const auto &x : src_links) {
                fprintf(stdout, "%s\n", x.c_str());
            }
        }
    }
};


int main(int argc, char *argv[]) {

    //fprintf(stdout, "openssl version number: %08x\n", (unsigned int)OPENSSL_VERSION_NUMBER);

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <hostname> [ <inner_hostname> ]\n", argv[0]);
        return EXIT_FAILURE;
    }
    std::string hostname = argv[1];
    std::string inner_hostname = "";
    if (argc == 3) {
        inner_hostname = argv[2];
    }

    try {
        tls_scanner scanner(hostname, inner_hostname);
    }
    catch (const char *s) {
        fprintf(stderr, "%s", s);
    }
    return 0;

}
