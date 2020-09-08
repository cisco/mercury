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
#include "proto_identify.h"
#include "tls.h"
#include "http.h"
#include "wireguard.h"
#include "ssh.h"
#include "dhcp.h"
#include "tcpip.h"

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
    if (bytes_extracted <= packet_filter_threshold && pf.x.msg_type == msg_type_unknown) {
        return 0;
    }
    // The following hack is needed in order to pass 'make test'; it
    // will be eliminated when the json_object record is only created
    // if/when the the packet parsing that follows the assignment of
    // msg_type is successfull.  That is, the plan is to allow the
    // parsing functions for each protocol to decide whether or not
    // anything should be printed out for a particular packet.
    //
    if (bytes_extracted <= packet_filter_threshold && pf.x.msg_type == msg_type_tls_client_hello) {
        return 0;
    }

    struct json_object record{&buf};

    /*
     * output fingerprint (if any)
     */
    if (bytes_extracted > packet_filter_threshold) {
        uint8_t *extractor_buffer = pf.x.output_start;
        struct json_object fps{record, "fingerprints"};
        switch(pf.x.fingerprint_type) {
        case fingerprint_type_dhcp_client:
            fps.print_key_ept("dhcp", extractor_buffer, bytes_extracted);
            break;
        case fingerprint_type_tls:
            fps.print_key_ept("tls", extractor_buffer, bytes_extracted);
            break;
        case fingerprint_type_tcp:
            fps.print_key_ept("tcp", extractor_buffer, bytes_extracted);
            {
                struct tcp_packet tcp_pkt;
                tcp_pkt.parse(pf.x.tcp);
                //tcp_pkt.write_json(fps);
            }
            break;
        case fingerprint_type_http:
            fps.print_key_ept("http", extractor_buffer, bytes_extracted);
            break;
        case fingerprint_type_http_server:
            fps.print_key_ept("http_server", extractor_buffer, bytes_extracted);
            break;
        case fingerprint_type_tls_server:
            fps.print_key_ept("tls_server", extractor_buffer, bytes_extracted);
            break;
        case fingerprint_type_dtls:
            fps.print_key_ept("dtls", extractor_buffer, bytes_extracted);
            break;
        case fingerprint_type_dtls_server:
            fps.print_key_ept("dtls_server", extractor_buffer, bytes_extracted);
            break;
        case fingerprint_type_ssh:
            fps.print_key_ept("ssh", extractor_buffer, bytes_extracted);
            break;
        case fingerprint_type_ssh_kex:
            fps.print_key_ept("ssh_kex", extractor_buffer, bytes_extracted);
            break;
        default:
            ;    /* no fingerprint; do nothing */
        }
        fps.close();

        switch(pf.x.fingerprint_type) {
        case fingerprint_type_http:
        case fingerprint_type_http_server:
            record.print_key_string("complete", (pf.x.proto_state.state == state_done) ? "yes" : "no");
        default:
            ;
        }
    }

    /*
     * output metadata
     */
    switch(pf.x.msg_type) {
    case msg_type_http_request:
        http_request::write_json(pf.x.transport_data, record, global_vars.metadata_output);
        break;
    case msg_type_tls_client_hello:
        {
            struct tls_record rec;
            rec.parse(pf.x.transport_data);
            struct tls_handshake handshake;
            handshake.parse(rec.fragment);
            struct tls_client_hello hello;
            hello.parse(handshake.body);
            hello.write_json(record, global_vars.metadata_output);
            /*
             * output analysis (if it's configured)
             */
            if (global_vars.do_analysis) {
                struct flow_key key = flow_key_init();
                flow_key_set_from_packet(&key, packet, length);
                write_analysis_from_extractor_and_flow_key(buf, &pf.x, &key);
            }
        }
        break;
    case msg_type_tls_server_hello:
    case msg_type_tls_certificate:
        {
            struct tls_record rec;
            struct tls_handshake handshake;
            struct tls_server_hello hello;
            struct tls_server_certificate certificate;

            // parse server_hello and/or certificate
            //
            rec.parse(pf.x.transport_data);
            handshake.parse(rec.fragment);
            if (handshake.msg_type == handshake_type::server_hello) {
                hello.parse(handshake.body);
                if (rec.fragment.is_not_empty()) {
                    struct tls_handshake h;
                    h.parse(rec.fragment);
                    certificate.parse(h.body);
                }

            } else if (handshake.msg_type == handshake_type::certificate) {
                certificate.parse(handshake.body);
            }
            struct tls_record rec2;
            rec2.parse(pf.x.transport_data);
            struct tls_handshake handshake2;
            handshake2.parse(rec2.fragment);
            if (handshake2.msg_type == handshake_type::certificate) {
                certificate.parse(handshake2.body);
            }

            // output certificate (always) and server_hello (if configured to)
            //
            if ((global_vars.metadata_output && hello.protocol_version.is_not_empty())
                || certificate.certificate_list.is_not_empty()) {
                struct json_object tls{record, "tls"};
                struct json_object tls_server{tls, "server"};
                if (global_vars.metadata_output) { // && hello.protocol_version.is_not_empty()) {
                    hello.write_json(tls_server);
                }
                if (certificate.certificate_list.is_not_empty()) {
                    struct json_array server_certs{tls_server, "certs"};
                    certificate.write_json(server_certs, global_vars.certs_json_output);
                    server_certs.close();
                }
                tls_server.close();
                tls.close();
            }
        }
        break;
    case msg_type_http_response:
        if (global_vars.metadata_output) {
            http_response::write_json(pf.x.transport_data, record);
        }
        break;
    case msg_type_wireguard:
        {
            wireguard_handshake_init wg;
            wg.parse(pf.x.transport_data);
            wg.write_json(record);
        }
        break;
    case msg_type_dns:
        {
            struct json_object dns{record, "dns"};
            write_dns_server_data(pf.x.transport_data.data,
                                  pf.x.transport_data.length(),
                                  dns,
                                  !global_vars.dns_json_output);
            dns.close();
        }
        break;
    case msg_type_dtls_client_hello:
        {
            struct dtls_record dtls_rec;
            dtls_rec.parse(pf.x.transport_data);
            struct dtls_handshake handshake;
            handshake.parse(dtls_rec.fragment);
            if (handshake.msg_type == handshake_type::client_hello) {
                struct tls_client_hello hello;
                hello.parse(handshake.body);
                hello.write_json(record, global_vars.metadata_output);
            }
        }
        break;
    case msg_type_ssh:
        {
            record.print_key_json_string("ssh_init_data", pf.x.transport_data.data, pf.x.transport_data.length());
            struct ssh_init_packet init_packet;
            init_packet.parse(pf.x.transport_data);
            init_packet.write_json(record, global_vars.metadata_output);
#if 0
            if (pf.x.transport_data.is_not_empty()) {
                record.print_key_json_string("ssh_residual_data", pf.x.transport_data.data, pf.x.transport_data.length());
                struct ssh_binary_packet pkt;
                pkt.parse(pf.x.transport_data);
                struct ssh_kex_init kex_init;
                kex_init.parse(pkt.payload);
                kex_init.write_json(record, global_vars.metadata_output);
            }
#endif
        }
        break;
    case msg_type_ssh_kex:
        {
            // record.print_key_json_string("ssh_kex_data", pf.x.transport_data.data, pf.x.transport_data.length());
            struct ssh_binary_packet pkt;
            pkt.parse(pf.x.transport_data);
            struct ssh_kex_init kex_init;
            kex_init.parse(pkt.payload);
            kex_init.write_json(record, global_vars.metadata_output);
        }
        break;
    case msg_type_dhcp:
        {
            struct dhcp_discover dhcp_disco;
            dhcp_disco.parse(pf.x.transport_data);
            dhcp_disco.write_json(record);
        }
    case msg_type_dtls_server_hello:
    case msg_type_dtls_certificate:
        // cases that fall through here are not yet supported
    case msg_type_unknown:
        // no output
        break;
    }

    /*
     * output flow key and timestamp
     */
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
