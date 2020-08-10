/*
 * json_file_io.c
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "json_file_io.h"
#include "json_object.h"
#include "extractor.h"
#include "packet.h"
#include "ept.h"
#include "utils.h"
#include "analysis.h"
#include "llq.h"
#include "buffer_stream.h"
#include "dns.h"

extern struct global_variables global_vars; /* defined in config.c */

#define json_file_needs_rotation(jf) (--((jf)->record_countdown) == 0)
#define SNI_HDR_LEN 9
#define FP_BUF_LEN 2048

enum status json_file_rotate(struct json_file *jf) {
    char outfile[MAX_FILENAME];

    if (jf->file) {
        // printf("rotating output file\n");

        if (fclose(jf->file) != 0) {
            perror("could not close json file");
        }
    }

    if (jf->max_records) {
        /*
         * create filename that includes sequence number and date/timestamp
         */
        char file_num[MAX_HEX];
        snprintf(file_num, MAX_HEX, "%x", jf->file_num++);
        enum status status = filename_append(outfile, jf->outfile_name, "-", file_num);
        if (status) {
            return status;
        }

        char time_str[128];
        struct timeval now;
        gettimeofday(&now, NULL);
        strftime(time_str, sizeof(time_str) - 1, "%Y%m%d%H%M%S", localtime(&now.tv_sec));
        status = filename_append(outfile, outfile, "-", time_str);
        if (status) {
            return status;
        }
    } else {
        strncpy(outfile, jf->outfile_name, sizeof(outfile));
    }

    jf->file = fopen(outfile, jf->mode);
    if (jf->file == NULL) {
        perror("error: could not open fingerprint output file");
        return status_err;
    }

    jf->record_countdown = jf->max_records;

    return status_ok;
}

enum status json_file_init(struct json_file *jf,
                           const char *outfile_name,
                           const char *mode,
                           uint64_t max_records) {

    if (copy_string_into_buffer(jf->outfile_name, sizeof(jf->outfile_name), outfile_name, MAX_FILENAME) != 0) {
        return status_err;
    }
    jf->mode = mode;
    jf->record_countdown = jf->max_records;
    jf->file_num = 0;
    jf->max_records = max_records; /* note: if 0, effectively no rotation */
    jf->file = NULL;               /* initialized in json_file_rotate()   */

    return json_file_rotate(jf);
}

void write_flow_key(struct buffer_stream &buf, const struct key &k) {
    if (k.ip_vers == 6) {
        const uint8_t *s = (const uint8_t *)&k.addr.ipv6.src;
        buf.strncpy("\"src_ip\":\"");
        buf.write_ipv6_addr(s);

        const uint8_t *d = (const uint8_t *)&k.addr.ipv6.dst;
        buf.strncpy("\",\"dst_ip\":\"");
        buf.write_ipv6_addr(d);

    } else {

        const uint8_t *s = (const uint8_t *)&k.addr.ipv4.src;
        buf.strncpy("\"src_ip\":\"");
        buf.write_ipv4_addr(s);

        const uint8_t *d = (const uint8_t *)&k.addr.ipv4.dst;
        buf.strncpy("\",\"dst_ip\":\"");
        buf.write_ipv4_addr(d);
    }

    buf.strncpy("\",\"protocol\":");
    buf.write_uint8(k.protocol);

    buf.strncpy(",\"src_port\":");
    buf.write_uint16(k.src_port);

    buf.strncpy(",\"dst_port\":");
    buf.write_uint16(k.dst_port);

}

void write_flow_key(struct json_object &o, const struct key &k) {
    if (k.ip_vers == 6) {
        const uint8_t *s = (const uint8_t *)&k.addr.ipv6.src;
        o.print_key_ipv6_addr("src_ip", s);

        const uint8_t *d = (const uint8_t *)&k.addr.ipv6.dst;
        o.print_key_ipv6_addr("dst_ip", d);

    } else {

        const uint8_t *s = (const uint8_t *)&k.addr.ipv4.src;
        o.print_key_ipv4_addr("src_ip", s);

        const uint8_t *d = (const uint8_t *)&k.addr.ipv4.dst;
        o.print_key_ipv4_addr("dst_ip", d);

    }

    o.print_key_uint8("protocol", k.protocol);
    o.print_key_uint16("src_port", k.src_port);
    o.print_key_uint16("dst_port", k.dst_port);

}

int append_packet_json(struct buffer_stream &buf,
                       uint8_t *packet,
                       size_t length,
                       struct timespec *ts) {
    extern unsigned int packet_filter_threshold;

    struct packet_filter pf;
    pf.tcp_init_msg_filter = NULL;

    /*
     * apply packet filter to packet; return if no fingerprints or metadata found
     */
    struct key k;
    size_t bytes_extracted = packet_filter_extract(&pf, &k, packet, length);
    if (bytes_extracted <= packet_filter_threshold && pf.x.packet_data.type == packet_data_type_none) {
        return 0;
    }

    struct json_object record{&buf};

    /*
     * output fingerprint (if any)
     */
    if (bytes_extracted > packet_filter_threshold) {
        uint8_t *extractor_buffer = pf.x.output_start;
        switch(pf.x.fingerprint_type) {
        case fingerprint_type_dhcp_client:
            {
                struct json_object fps{record, "fingerprints"};
                fps.print_key_ept("dhcp", extractor_buffer, bytes_extracted);
                fps.close();
            }
            break;
        case fingerprint_type_tls:
            {
                struct json_object fps{record, "fingerprints"};
                fps.print_key_ept("tls", extractor_buffer, bytes_extracted);
                fps.close();
            }
            break;
        case fingerprint_type_tcp:
            {
                struct json_object fps{record, "fingerprints"};
                fps.print_key_ept("tcp", extractor_buffer, bytes_extracted);
                fps.close();
            }
            break;
        case fingerprint_type_http:
            {
                struct json_object fps{record, "fingerprints"};
                fps.print_key_ept("http", extractor_buffer, bytes_extracted);
                fps.close();
                record.print_key_string("complete", (pf.x.proto_state.state == state_done) ? "yes" : "no");
            }
            break;
        case fingerprint_type_http_server:
            {
                struct json_object fps{record, "fingerprints"};
                fps.print_key_ept("http_server", extractor_buffer, bytes_extracted);
                fps.close();
                record.print_key_string("complete", (pf.x.proto_state.state == state_done) ? "yes" : "no");
            }
            break;
        case fingerprint_type_tls_server:
            {
                struct json_object fps{record, "fingerprints"};
                fps.print_key_ept("tls_server", extractor_buffer, bytes_extracted);
                fps.close();
            }
            break;
        case fingerprint_type_dtls:
            {
                struct json_object fps{record, "fingerprints"};
                fps.print_key_ept("dtls", extractor_buffer, bytes_extracted);
                fps.close();
            }
            break;
        case fingerprint_type_dtls_server:
            {
                struct json_object fps{record, "fingerprints"};
                fps.print_key_ept("dtls_server", extractor_buffer, bytes_extracted);
                fps.close();
            }
            break;
        case fingerprint_type_ssh:
            {
                struct json_object fps{record, "fingerprints"};
                fps.print_key_ept("ssh", extractor_buffer, bytes_extracted);
                fps.close();
            }
            break;
        case fingerprint_type_ssh_kex:
            {
                struct json_object fps{record, "fingerprints"};
                fps.print_key_ept("ssh_kex", extractor_buffer, bytes_extracted);
                fps.close();
            }
            break;
        default:
            ;    /* no fingerprint; do nothing */
        }
    }

    // construct a list of http header names to be printed out
    //
    uint8_t ua[] = { 'u', 's', 'e', 'r', '-', 'a', 'g', 'e', 'n', 't', ':', ' ' };
    struct parser user_agent{ua, ua+sizeof(ua)};
    std::pair<struct parser, std::string> user_agent_name{user_agent, "user_agent"};

    uint8_t h[] = { 'h', 'o', 's', 't', ':', ' ' };
    struct parser host{h, h+sizeof(h)};
    std::pair<struct parser, std::string> host_name{host, "host"};

    uint8_t xff[] = { 'x', '-', 'f', 'o', 'r', 'w', 'a', 'r', 'd', 'e', 'd', '-', 'f', 'o', 'r', ':', ' ' };
    struct parser xff_parser{xff, xff+sizeof(xff)};
    std::pair<struct parser, std::string> x_forwarded_for{xff_parser, "x_forwarded_for"};

    uint8_t v[] = { 'v', 'i', 'a', ':', ' ' };
    struct parser v_parser{v, v+sizeof(v)};
    std::pair<struct parser, std::string> via{v_parser, "via"};

    std::list<std::pair<struct parser, std::string>> names_to_print{user_agent_name, host_name, x_forwarded_for, via};

    /*
     * output packet_data (if any)
     */
    if (pf.x.packet_data.type == packet_data_type_http_user_agent) {
        struct json_object http{record, "http"};
        struct json_object http_request{http, "request"};
        if (global_vars.metadata_output) {
            struct http_request request;
            request.parse(pf.x.transport_data);
            http_request.print_key_json_string("method", request.method.data, request.method.length());
            http_request.print_key_json_string("uri", request.uri.data, request.uri.length());
            http_request.print_key_json_string("protocol", request.protocol.data, request.protocol.length());
            // http.print_key_json_string("headers", request.headers.data, request.headers.length());
            // request.headers.print_host(http, "host");

            // run the list of http headers to be printed out against
            // all headers, and print the values corresponding to each
            // of the matching names
            //
            request.headers.print_matching_names(http_request, names_to_print);

        } else {
            http_request.print_key_json_string("user_agent", pf.x.packet_data.value, pf.x.packet_data.length);
        }
        http_request.close();
        http.close();
    }
    if (pf.x.packet_data.type == packet_data_type_http_no_user_agent) {
        if (global_vars.metadata_output) {
            struct json_object http{record, "http"};
            struct json_object http_request{http, "request"};
            struct http_request request;
            request.parse(pf.x.transport_data);
            http_request.print_key_json_string("method", request.method.data, request.method.length());
            http_request.print_key_json_string("uri", request.uri.data, request.uri.length());
            http_request.print_key_json_string("protocol", request.protocol.data, request.protocol.length());
            // http.print_key_json_string("headers", request.headers.data, request.headers.length());
            // request.headers.print_host(http, "host");

            // run the list of http headers to be printed out against
            // all headers, and print the values corresponding to each
            // of the matching names
            //
            request.headers.print_matching_names(http_request, names_to_print);
            http_request.close();
            http.close();
        }
    }
    if (pf.x.packet_data.type == packet_data_type_tls_sni) {
        if (pf.x.packet_data.length >= SNI_HDR_LEN) {
            struct json_object tls{record, "tls"};
            struct json_object tls_client{tls, "client"};
            if (global_vars.metadata_output) {
                struct tls_client_hello hello;
                hello.parse(pf.x.transport_data);
                tls_client.print_key_hex("version", hello.protocol_version);
                tls_client.print_key_hex("random", hello.random);
                tls_client.print_key_hex("session_id", hello.session_id);
                tls_client.print_key_hex("cipher_suites", hello.ciphersuite_vector);
                tls_client.print_key_hex("compression_methods", hello.compression_methods);
                //tls.print_key_hex("extensions", hello.extensions);
                //hello.extensions.print(tls, "extensions");
                hello.extensions.print_server_name(tls_client, "server_name");
                hello.extensions.print_session_ticket(tls_client, "session_ticket");
                hello.fingerprint(tls_client, "fingerprint");
            } else {
                tls_client.print_key_json_string("server_name", pf.x.packet_data.value + SNI_HDR_LEN, pf.x.packet_data.length - SNI_HDR_LEN);
            }
            tls_client.close();
            tls.close();
        }
    }
    if (pf.x.packet_data.type == packet_data_type_tls_no_sni) {
        if (global_vars.metadata_output) {
            struct json_object tls{record, "tls"};
            struct json_object tls_client{tls, "client"};
            struct tls_client_hello hello;
            hello.parse(pf.x.transport_data);
            tls_client.print_key_hex("version", hello.protocol_version);
            tls_client.print_key_hex("random", hello.random);
            tls_client.print_key_hex("session_id", hello.session_id);
            tls_client.print_key_hex("cipher_suites", hello.ciphersuite_vector);
            tls_client.print_key_hex("compression_methods", hello.compression_methods);
            //tls.print_key_hex("extensions", hello.extensions);
            //hello.extensions.print(tls, "extensions");
            hello.extensions.print_server_name(tls_client, "server_name");
            hello.extensions.print_session_ticket(tls_client, "session_ticket");
            tls_client.close();
            tls.close();
        }
    }
    if (pf.x.packet_data.type == packet_data_type_tls_cert) {
        struct json_object tls{record, "tls"};
        struct json_object tls_server{tls, "server"};
        if (global_vars.metadata_output) {
            struct tls_server_hello hello;
            hello.parse(pf.x.transport_data);
            if (hello.random.is_not_empty()) {
                tls_server.print_key_hex("random", hello.random);
            }
        }
        struct json_array server_certs{tls_server, "certs"};
        if (!global_vars.certs_json_output) {
            write_extract_certificates(server_certs, pf.x.packet_data.value, pf.x.packet_data.length);
        } else {
            write_extract_cert_full(server_certs, pf.x.packet_data.value, pf.x.packet_data.length);
        }
        server_certs.close();
        tls_server.close();
        tls.close();
    }
    if (pf.x.packet_data.type == packet_data_type_dtls_sni) {
        if (pf.x.packet_data.length >= SNI_HDR_LEN) {
            struct json_object dtls{record, "dtls"};
            dtls.print_key_json_string("server_name", pf.x.packet_data.value  + SNI_HDR_LEN, pf.x.packet_data.length - SNI_HDR_LEN);
            dtls.close();
        }
    }
    if (pf.x.packet_data.type == packet_data_type_dns_server) {
        struct json_object dns{record, "dns"};
        write_dns_server_data(pf.x.packet_data.value, pf.x.packet_data.length, dns, !global_vars.dns_json_output);
        dns.close();
    }
    if (pf.x.packet_data.type == packet_data_type_wireguard && pf.x.packet_data.length == sizeof(uint32_t)) {
        struct json_object wg{record, "wireguard"};
        uint32_t tmp = ntohl(*(const uint32_t *)pf.x.packet_data.value);
        struct parser si{(uint8_t *)&tmp, (uint8_t *)&tmp + sizeof(uint32_t)};
        wg.print_key_hex("sender_index", si);
        wg.close();
    }

    /*
     * output flow key, analysis (if it's configured), and the timestamp
     */
    if (global_vars.do_analysis) {
        struct flow_key key = flow_key_init();
        flow_key_set_from_packet(&key, packet, length);
        write_analysis_from_extractor_and_flow_key(buf, &pf.x, &key);
    }

    write_flow_key(record, k);

    record.print_key_timestamp("event_start", ts);
    // struct timestamp_writer t{ts}; record.print_key_value("event_start", t);

    //    buf.snprintf(dstr, doff, dlen, trunc, ",\"flowhash\":\"%016lx\"", flowhash(key, ts->tv_sec));

    buf.strncpy("}\n");

    return buf.length();
}


void json_file_write(struct json_file *jf,
                     uint8_t *packet,
                     size_t length,
                     unsigned int sec,
                     unsigned int nsec) {

    struct timespec ts;
    char obuf[LLQ_MSG_SIZE];

    ts.tv_sec = sec;
    ts.tv_nsec = nsec;

    obuf[0] = '\0';
    struct buffer_stream buf(obuf, LLQ_MSG_SIZE);
    append_packet_json(buf, packet, length, &ts);
    int r = buf.length();

    if ((buf.trunc == 0) && (r > 0)) {
        fwrite(obuf, r, 1, jf->file);

        if (json_file_needs_rotation(jf)) {
            json_file_rotate(jf);
        }
    }
}


void json_queue_write(struct ll_queue *llq,
                      uint8_t *packet,
                      size_t length,
                      unsigned int sec,
                      unsigned int nsec) {

    if (llq->msgs[llq->widx].used == 0) {

        //char obuf[LLQ_MSG_SIZE];
        // int olen = LLQ_MSG_SIZE;
        // int ooff = 0;
        // int trunc = 0;

        llq->msgs[llq->widx].ts.tv_sec = sec;
        llq->msgs[llq->widx].ts.tv_nsec = nsec;


        //obuf[sizeof(struct timespec)] = '\0';
        llq->msgs[llq->widx].buf[0] = '\0';

        struct buffer_stream buf(llq->msgs[llq->widx].buf, LLQ_MSG_SIZE);
        append_packet_json(buf, packet, length, &(llq->msgs[llq->widx].ts));
        int r = buf.length();
        if ((buf.trunc == 0) && (r > 0)) {

            llq->msgs[llq->widx].len = r;

            //fprintf(stderr, "DEBUG: sent a message!\n");
            __sync_synchronize(); /* A full memory barrier prevents the following flag set from happening too soon */
            llq->msgs[llq->widx].used = 1;

            /* fprintf(stderr, "DEBUG QUEUE %d packet time: %ld.%09ld\n", */
            /*         llq->qnum, */
            /*         llq->msgs[llq->widx].ts.tv_sec, */
            /*         llq->msgs[llq->widx].ts.tv_nsec); */

            //llq->next_write();
            llq->widx = (llq->widx + 1) % LLQ_DEPTH;
        }
    }
    else {
        //fprintf(stderr, "DEBUG: queue bucket used!\n");

        // TODO: this is where we'd update an output drop counter
        // but currently this spot in the code doesn't have access to
        // any thread stats pointer or similar and I don't want
        // to update a global variable in this location.
    }

}
