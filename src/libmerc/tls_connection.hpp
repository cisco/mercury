// tls_connection.hpp
//
// Copyright (c) 2023 Cisco Systems, Inc. License at
// https://github.com/cisco/mercury/blob/master/LICENSE

#ifndef TLS_CONNECTION_HPP
#define TLS_CONNECTION_HPP

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <vector>
#include <string>

#include "verbosity.hpp"
#include "http.h"

// hostname parses a host name
//
struct hostname : public datum {

    hostname() : datum{NULL, NULL} { }

    void parse(struct datum &d) {
        accept_hostname(d);
    }
    void accept_hostname(struct datum &d) {
        if (d.data == NULL || d.data >= d.data_end) {
            return;
        }
        data = d.data;
        const uint8_t *tmp_data = d.data;
        while (tmp_data < d.data_end) {
            if (!isalnum(*tmp_data) && *tmp_data != '.' && *tmp_data != '-') {
                break;
            }
            tmp_data++;
        }
        data_end = d.data = tmp_data;
    }
};

// uri_path parses an HTTP URI path
//
struct uri_path : public datum {

    uri_path() : datum{NULL, NULL} { }

    void parse(struct datum &d) {
        accept_path(d);
    }
    void accept_path(struct datum &d) {
        if (d.data == NULL || d.data >= d.data_end) {
            return;
        }
        data = d.data;
        const uint8_t *tmp_data = d.data;
        while (tmp_data < d.data_end) {
            // note: this function works with valid paths that are
            // exctacted from HTML links, which are terminated by a
            // quotation, but it is not appropriate for other use
            // cases
            if (*tmp_data == '\"') {
                break;
            }
            tmp_data++;
        }
        data_end = d.data = tmp_data;
    }
};

// uri parses an HTTP URI
//
struct uri {
    struct datum scheme;
    struct hostname host;
    struct uri_path path;

public:
    uri(struct datum &d) : scheme{}, host{}, path{} {
        parse(d);
    }
    void parse(struct datum &d) {
        // find start of host
        uint8_t slash_pair[2] = { '/', '/' };
        if (d.skip_up_to_delim(slash_pair, sizeof(slash_pair)) == false) {
            return;
        };

        host.parse(d);
        path.parse(d);
    }
};


// class tls_connection creates a TLS over TCP connection with a
// remote server, performing a DNS lookup of the hostname if needed.
// It is aimed at the use case of scanning servers.  The peer
// certificate (and other information) can be obtained through
// get_tls(), and send_http_request() can be used to complete an HTTP
// request/response exchange.
//
class tls_connection {
    std::string host;
    verbosity_level verbosity;
    int sockfd;
    int sock;
    SSL *ssl = nullptr;
    SSL_CTX *ctx = nullptr;

    bool valid = false;

public:

    tls_connection(const char *host_or_addr, verbosity_level verb, uint16_t port=443) :
        host{host_or_addr},
        verbosity{verb}
    {

        // fprintf(stdout, "openssl version number: %08x\n", (unsigned int)OPENSSL_VERSION_NUMBER);

        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (!sockfd) {
            if (verbosity >= verbosity_level::warnings) {
                fprintf(stderr, "warning: could not create socket\n");
            }
            return;
        }
        std::vector<sockaddr_in> sa = get_sockaddr_in(host.c_str(), verbosity, port);
        if (sa.empty()) {
            if (verbosity >= verbosity_level::warnings) {
                fprintf(stderr, "warning: could not get address for host '%s'\n", host.c_str());
            }
            return;
        }

        int retval = connect(sockfd, (struct sockaddr *)&sa[0], sizeof(sa[0]));
        if (retval) {
            if (verbosity >= verbosity_level::warnings) {
                fprintf(stderr, "warning: could not connect socket\n");
            }
            return;
        }

        if (fcntl(sockfd, F_SETFL, SOCK_NONBLOCK) == -1) {
            if (verbosity >= verbosity_level::warnings) {
                fprintf(stderr, "warning: could not set socket to non-blocking\n");
            }
            return;
        }

        if (tls_handshake() < 0) {
            return;
        }
        valid = true;
    }

    ~tls_connection() {
        if (ctx != nullptr) {
            SSL_CTX_free(ctx);
        }
        if (ssl != nullptr) {
            SSL_free(ssl);
        }
    }

    bool is_valid() const { return valid; }

    SSL *get_tls() { return ssl; }

    int read(char *buf, int *buffer_length) {
        if (!valid) {
            return -1;
        }
        int len = *buffer_length;
        char *data = buf;
        char *buf_end = buf + *buffer_length;
        int err;
        while (true) {
            // fprintf(stderr, "debug: attempting to read %zd bytes from tls connection\n", buf_end - buf);
            len=SSL_read(ssl, buf, buf_end - buf);
            if (len > 0) {
                buf += len; // advance buffer write location
            } else if (len <= 0) {
                err = SSL_get_error(ssl, len);
                if (err != SSL_ERROR_WANT_READ) {
                    // fprintf(stderr, "SSL_read() error: %s\n", err_string(err));
                    break;
                }
            }
        }
        *buffer_length = buf - data;
        return 1;
    }

    int write(const char *buf, size_t length) {
        if (!valid) {
            if (verbosity >= verbosity_level::warnings) {
                fprintf(stderr, "warning: attempted write() to an invalid connection\n");
            }
            return -1;
        }
        int len = SSL_write(ssl, buf, length);
        if (len < 0) {
            int err = SSL_get_error(ssl, len);
            switch (err) {
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
                return 0;
            default:
                if (verbosity >= verbosity_level::warnings) {
                    fprintf(stderr, "warning: SSL_write() error: %s\n", err_string(err));
                }
            return -1;
            }
        }
        return 1;
    }

    int tls_handshake() {

        // create TLS connection over socket
        //
        SSL_library_init();
        const SSL_METHOD *method = TLS_client_method();
        ctx = SSL_CTX_new(method);
        ssl = SSL_new(ctx);
        if (!ssl) {
            if (verbosity >= verbosity_level::warnings) {
                fprint_openssl_err(stderr, "warning: could not create \"SSL\"");
            }
            return -1;
        }

        // don't perform certificate validation, so that we can obtain
        // self-issued certificates
        //
        SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);

        if (SSL_set_fd(ssl, sockfd) != 1) {
            if (verbosity >= verbosity_level::warnings) {
                fprint_openssl_err(stderr, "warning: could not set SSL fd");
            }
            return -1;
        }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sockfd, &fds);
        while (true) {

            int err = SSL_connect(ssl);
            if (err == 1) {
                break;
            }

            int ssl_error = SSL_get_error(ssl, err);
            if (ssl_error == SSL_ERROR_WANT_READ) {
                int result = select(sockfd + 1, &fds, NULL, NULL, NULL);
                if (result == -1) {
                    if (verbosity >= verbosity_level::warnings) {
                        fprintf(stderr, "warning: select() reports error code %d\n", errno);
                    }
                    return -1;
                }
            } else if (ssl_error == SSL_ERROR_WANT_WRITE) {
                int result = select(sockfd + 1, NULL, &fds, NULL, NULL);
                if (result == -1) {
                    if (verbosity >= verbosity_level::warnings) {
                        fprintf(stderr, "warning: select() reports error code %d\n", errno);
                    }
                    return -1;
                }
            } else {
                if (verbosity >= verbosity_level::warnings) {
                    std::string tmp{"warning: could not create TLS connection to "};
                    tmp += host;
                    fprint_openssl_err(stderr, tmp.c_str());
                }
                return -1;
            }
        }

        // fprintf (stderr, "established TLS connection with %s\n", SSL_get_cipher(ssl));

        return 0;
    }

    std::set<std::string> send_http_request(std::string path,
                                            const std::string &hostname,
                                            const std::string &http_host_field,
                                            const std::string &user_agent,
                                            bool doh) {
        std::set<std::string> src_links;

        // send HTTP request
        //
        if (doh) {
            path += doh_path(http_host_field);
        }
        std::string line = "GET " + path + " HTTP/1.1";
        std::string request = line + "\r\n";
        request += "User-Agent: " + user_agent;
        request += "\r\nConnection: close\r\n";
        if (doh) {
            request += "Accept: application/dns-message\r\nHost: " + hostname + "\r\n";
        } else {
            request += "Host: " + http_host_field + "\r\n";
        }
        request += "\r\n";
        if (tls_connection::write(request.data(), request.size()) < 0) {
            if (verbosity >= verbosity_level::warnings) {
                fprintf(stderr, "warning: could not send http request\n");
            }
            return src_links; // return empty set
        }

        // parse HTTP request for JSON output
        //
        const uint8_t *http_req_buffer = (const uint8_t *)request.data();
        struct datum http_req_data{http_req_buffer, http_req_buffer + request.length()};
        http_request req{http_req_data};

        // report http request
        //
        char output_buffer[1024*16];
        struct buffer_stream output_buffer_stream{output_buffer, sizeof(output_buffer)};
        struct json_object http_record{&output_buffer_stream};
        req.write_json(http_record, true);
        http_record.close();
        output_buffer_stream.write_line(stdout);

        // get HTTP response
        //
        char http_buffer[1024*256] = {};
        int read_len = sizeof(http_buffer);
        tls_connection::read(http_buffer, &read_len);

        // parse and process http_response message
        if (read_len > 0) {

            bool parse_response = true;
            std::string redirect;  // stores HTTP redirect, if there is one

            // parse http headers, and print as JSON
            //
            const unsigned char *tmp = (const unsigned char *)http_buffer;
            struct datum http{tmp, tmp+read_len};
            if (parse_response) {
                http_response response{http};

                output_buffer_stream = {output_buffer, sizeof(output_buffer)}; // reset
                struct json_object response_record{&output_buffer_stream};
                response.write_json(response_record, true);
                response_record.close();
                output_buffer_stream.write_line(stdout);

                std::basic_string<uint8_t> loc = { 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n', ':', ' ' };
                struct datum location = response.get_header((const char *)loc.data());
                if (location.is_not_empty()) {
                    uri location_uri{location};

                    redirect = location_uri.host.get_string();
                }

                std::basic_string<uint8_t> ct = { 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 't', 'y', 'p', 'e', ':', ' ' };
                struct datum content_type = response.get_header((const char *)ct.data());
                if (content_type.is_not_empty()) {

                    uint8_t app_type_dns[] = { 'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', '/', 'd', 'n', 's', '-', 'm', 'e', 's', 's', 'a', 'g', 'e' };
                    struct datum app_type_dns_datum{app_type_dns, app_type_dns + sizeof(app_type_dns)};
                    if (content_type.case_insensitive_match(app_type_dns_datum)) {

                        // output response as JSON object
                        //
                        std::string dns_response = dns_get_json_string((const char *)http.data, http.length());
                        fprintf(stdout, "{\"dns\":%s}\n", dns_response.c_str());

                    }
                }

                bool print_response_body = false; // TODO: reconnect to tls_scanner
                if (print_response_body) { // || response.status_code.compare("301", 3) == 0 || response.status_code.compare("302", 3) == 0 ) {
                    // print out redirect data
                    fprintf(stdout, "body: %.*s\n", (int)http.length(), http.data);
                }

            }

            // find src= links in page (http body)
            //
            std::string http_body = http.get_string();
            std::smatch matches;
            //std::regex rgx("src.{2,8}(http(s)*:)*//[a-zA-Z0-9-]*(\\.[a-zA-Z0-9-]*)*");
            std::regex rgx("src=\"[^\"]*\"");
            while (std::regex_search(http_body, matches, rgx)) {
                src_links.insert(matches[0].str());
                http_body = matches.suffix().str();
            }

            if (!redirect.empty()) {
                //
                // construct a src link that represents the redirect
                //
                std::string link{"src=\"https://"};
                link += redirect;
                link += "\"";
                src_links.insert(link);
            }
        }
        return src_links;
    }

    static void fprint_openssl_err(FILE *f, const char *msg=nullptr) {
        if (msg != nullptr) {
            fprintf(f, "%s: ", msg);
        }
        int err = ERR_get_error();
        if (err != 0) {
            char *str = ERR_error_string(err, 0);
            if (str != nullptr) {
                fprintf(f, "%s", str);
            }
        }
        fputc('\n', f);
        return;
    }

    static const char *err_string(int err) {
        switch (err) {
        case SSL_ERROR_WANT_READ:        return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE:       return "SSL_ERROR_WANT_WRITE";
        case SSL_ERROR_ZERO_RETURN:      return "SSL_ERROR_ZERO_RETURN";
        case SSL_ERROR_SYSCALL:          return "SSL_ERROR_SYSCALL";
        case SSL_ERROR_SSL:              return "SSL_ERROR_SSL";
        case SSL_ERROR_WANT_CONNECT:     return "SSL_ERROR_WANT_CONNECT";
        case SSL_ERROR_WANT_ACCEPT:      return "SSL_ERROR_WANT_ACCEPT";
        case SSL_ERROR_WANT_X509_LOOKUP: return "SSL_ERROR_WANT_X509_LOOKUP";
        default:
            ;
        }
        return "UNKNOWN ERROR";
    }

    static std::vector<sockaddr_in> get_sockaddr_in(const char *hostname, verbosity_level verbosity, int port=0) {
        std::vector<sockaddr_in> addr_vec;
        int err;
        struct addrinfo hints{}, *addrs;
        char *service = nullptr;
        char port_str[16] = {};
        if (port != 0) {
            sprintf(port_str, "%d", port);
            service = port_str;
        }

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        err = getaddrinfo(hostname, service, &hints, &addrs);
        if (err != 0) {
            if (verbosity >= verbosity_level::warnings) {
                fprintf(stderr, "warning: %s: %s\n", hostname, gai_strerror(err));
            }
            return addr_vec; // return empty list
        }
        for (struct addrinfo *a = addrs; a != NULL; a = a->ai_next) {
            if (a->ai_family == AF_INET) {
                const sockaddr_in *tmp = (const sockaddr_in *)a->ai_addr;
                addr_vec.push_back(*tmp);
            }

        }
        freeaddrinfo(addrs);
        return addr_vec;
    }

    static inline std::string doh_path(const std::string &query_name) {

        // experimental support for DoH queries
        //
        // TODO: encapsulate DNS encoding within DNS classes for
        // the sake of maintainability
        //
        // TODO: add POST URI=/dns-query technique
        //
        // TODO: add other GET technique
        //
        // curl -i -H 'accept: application/dns-json' 'https://doh.facebook-dns.com/dns-query?name=cisco.com&type=A'
        // curl -i -H 'accept: application/dns-message' https://one.one.one.one/dns-query?dns=AAABAAABAAAAAAAABWNpc2NvA2NvbQAAAQAB

        std::string path;
        path += "dns-query?dns=";

        uint8_t dns_message[2048];
        dns_hdr *header = (dns_hdr *)&dns_message[0];
        header->id = 0x0000;           // DoH clients SHOULD use 0 in each request
        header->flags = hton<uint16_t>(0x0100);
        header->qdcount = hton<uint16_t>(1);
        header->ancount = hton<uint16_t>(0);
        header->nscount = hton<uint16_t>(0);
        header->arcount = hton<uint16_t>(0);

        uint8_t *rr_start = &dns_message[sizeof(dns_hdr)];

        uint8_t *s = (uint8_t *)query_name.c_str();
        while (true) {
            uint8_t *t = s;
            while (true) {
                if (*t == '.' || *t == 0) {
                    break;
                }
                t++;
            }
            if (t == s) {
                break;
            }
            *rr_start++ = (uint8_t) (t - s);
            memcpy(rr_start, s, (t-s));
            rr_start += (t - s);
            if (*t == 0) {
                break;
            }
            t++;
            s = t;
        }
        *rr_start++ = 0; // terminate name with zero-length label

        if (true) {
            *rr_start++ = 0x00; // qtype in network byte order (A)
            *rr_start++ = 0x01;
        } else {
            *rr_start++ = 0x00; // qtype in network byte order (AAAA)
            *rr_start++ = 0x1c;
        }
        *rr_start++ = 0x00; // qclass in network byte order (IN)
        *rr_start++ = 0x01;

        size_t dns_message_len = rr_start - &dns_message[0];

        std::string dns_query = dns_get_json_string((const char *)dns_message, dns_message_len);
        fprintf(stdout, "{\"dns\":%s}\n", dns_query.c_str());

        std::string dns_string = base64_encode(dns_message, dns_message_len, base64url_table);
        path += dns_string;

        return path;
    }

};

#endif // TLS_CONNECTION_HPP
