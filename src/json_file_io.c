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
#include "eth.h"
#include "udp.h"

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

void tcp_data_write_json(struct buffer_stream &buf,
                         struct datum &pkt,
                         struct key &k,
                         struct tcp_packet &tcp_pkt,
                         struct timespec *ts,
                         struct tcp_reassembler &reassembler) {
        enum tcp_msg_type msg_type = get_message_type(pkt.data, pkt.length());
        switch(msg_type) {
        case tcp_msg_type_http_request:
            {
                struct http_request request;
                request.parse(pkt);
                if (request.is_not_empty()) {
                    struct json_object record{&buf};
                    struct json_object fps{record, "fingerprints"};
                    fps.print_key_value("http", request);
                    fps.close();
                    record.print_key_string("complete", request.headers.complete ? "yes" : "no");
                    request.write_json(record, global_vars.metadata_output);
                    write_flow_key(record, k);
                    record.print_key_timestamp("event_start", ts);
                    record.close();
                }
            }
            break;
        case tcp_msg_type_tls_client_hello:
            {
                struct tls_record rec;
                rec.parse(pkt);
                struct tls_handshake handshake;
                handshake.parse(rec.fragment);
                if (handshake.additional_bytes_needed) {
                    reassembler.copy_packet(k, tcp_pkt.header, tcp_pkt.data_length, handshake.additional_bytes_needed);
                    return;
                }
                struct tls_client_hello hello;
                hello.parse(handshake.body);
                if (hello.is_not_empty()) {
                    struct json_object record{&buf};
                    struct json_object fps{record, "fingerprints"};
                    fps.print_key_value("tls", hello);
                    fps.close();
                    hello.write_json(record, global_vars.metadata_output);
                    /*
                     * output analysis (if it's configured)
                     */
                    if (global_vars.do_analysis) {
                        write_analysis_from_extractor_and_flow_key(buf, hello, k);
                    }
                    write_flow_key(record, k);
                    record.print_key_timestamp("event_start", ts);
                    record.close();
                }
            }
            break;
        case tcp_msg_type_tls_server_hello:
        case tcp_msg_type_tls_certificate:
            {
                struct tls_record rec;
                struct tls_handshake handshake;
                struct tls_server_hello hello;
                struct tls_server_certificate certificate;

                // parse server_hello and/or certificate
                //
                rec.parse(pkt);
                handshake.parse(rec.fragment);
                if (handshake.msg_type == handshake_type::server_hello) {
                    hello.parse(handshake.body);
                    if (rec.is_not_empty()) {
                        struct tls_handshake h;
                        h.parse(rec.fragment);
                        certificate.parse(h.body);
                    }

                } else if (handshake.msg_type == handshake_type::certificate) {
                    certificate.parse(handshake.body);
                }
                struct tls_record rec2;
                rec2.parse(pkt);
                struct tls_handshake handshake2;
                handshake2.parse(rec2.fragment);
                if (handshake2.msg_type == handshake_type::certificate) {
                    certificate.parse(handshake2.body);
                }

                if (certificate.additional_bytes_needed) {
                    reassembler.copy_packet(k, tcp_pkt.header, tcp_pkt.data_length, certificate.additional_bytes_needed);
                    return;
                }

                bool have_hello = hello.is_not_empty();
                bool have_certificate = certificate.is_not_empty();
                if (have_hello || have_certificate) {
                    struct json_object record{&buf};

                    // output fingerprint
                    if (have_hello) {
                        struct json_object fps{record, "fingerprints"};
                        fps.print_key_value("tls_server", hello);
                        fps.close();
                    }

                    // output certificate (always) and server_hello (if configured to)
                    //
                    if ((global_vars.metadata_output && have_hello) || have_certificate) {
                        struct json_object tls{record, "tls"};
                        struct json_object tls_server{tls, "server"};
                        if (have_certificate) {
                            struct json_array server_certs{tls_server, "certs"};
                            certificate.write_json(server_certs, global_vars.certs_json_output);
                            server_certs.close();
                        }
                        if (global_vars.metadata_output && have_hello) {
                            hello.write_json(tls_server);
                        }
                        tls_server.close();
                        tls.close();
                    }
                    write_flow_key(record, k);
                    record.print_key_timestamp("event_start", ts);
                    record.close();
                }
            }
            break;
        case tcp_msg_type_http_response:
            {
                struct http_response response;
                response.parse(pkt);
                if (response.is_not_empty()) {
                    struct json_object record{&buf};
                    struct json_object fps{record, "fingerprints"};
                    fps.print_key_value("http_server", response);
                    fps.close();
                    record.print_key_string("complete", response.headers.complete ? "yes" : "no");
                    if (global_vars.metadata_output) {
                        response.write_json(record);
                    }
                    write_flow_key(record, k);
                    record.print_key_timestamp("event_start", ts);
                    record.close();
                }
            }
            break;
        case tcp_msg_type_ssh:
            {
                struct ssh_init_packet init_packet;
                init_packet.parse(pkt);
                struct json_object record{&buf};
                struct json_object fps{record, "fingerprints"};
                fps.print_key_value("ssh", init_packet);
                fps.close();
                init_packet.write_json(record, global_vars.metadata_output);
#ifdef SSHM
                if (pkt.is_not_empty()) {
                    pkt.accept('\n');
                    record.print_key_json_string("ssh_residual_data", pkt.data, pkt.length());
                    struct ssh_binary_packet bin_pkt;
                    bin_pkt.parse(pkt);
                    struct ssh_kex_init kex_init;
                    kex_init.parse(bin_pkt.payload);
                    kex_init.write_json(record, global_vars.metadata_output);
                }
#endif
                write_flow_key(record, k);
                record.print_key_timestamp("event_start", ts);
                record.close();
            }
            break;
        case tcp_msg_type_ssh_kex:
            {
                // record.print_key_json_string("ssh_kex_data", pkt.data, pkt.length());
                struct ssh_binary_packet ssh_pkt;
                ssh_pkt.parse(pkt);
                struct ssh_kex_init kex_init;
                kex_init.parse(ssh_pkt.payload);
                if (kex_init.additional_bytes_needed) {
                    reassembler.copy_packet(k, tcp_pkt.header, tcp_pkt.data_length, kex_init.additional_bytes_needed);
                }
                if (kex_init.is_not_empty()) {
                    struct json_object record{&buf};
                    struct json_object fps{record, "fingerprints"};
                    fps.print_key_value("ssh_kex", kex_init);
                    fps.close();
                    kex_init.write_json(record, global_vars.metadata_output);
                    write_flow_key(record, k);
                    record.print_key_timestamp("event_start", ts);
                    record.close();
                }
            }
            break;
        case tcp_msg_type_unknown:
            // no output
            break;
        }

}

int append_packet_json(struct buffer_stream &buf,
                       uint8_t *packet,
                       size_t length,
                       struct timespec *ts,
                       struct tcp_reassembler &reassembler) {
    struct key k;
    struct datum pkt{packet, packet+length};
    size_t transport_proto = 0;
    size_t ethertype = 0;
    parser_process_eth(&pkt, &ethertype);
    switch(ethertype) {
    case ETH_TYPE_IP:
        parser_process_ipv4(&pkt, &transport_proto, &k);
        break;
    case ETH_TYPE_IPV6:
        parser_process_ipv6(&pkt, &transport_proto, &k);
        break;
    default:
        ;
    }
    if (transport_proto == 6) {
        struct tcp_packet tcp_pkt;
        tcp_pkt.parse(pkt);
        tcp_pkt.set_key(k);
        if (tcp_pkt.is_SYN()) {
            struct json_object record{&buf};
            struct json_object fps{record, "fingerprints"};
            fps.print_key_value("tcp", tcp_pkt);
            fps.close();
            if (global_vars.metadata_output) {
                 tcp_pkt.write_json(fps);
            }
            write_flow_key(record, k);
            record.print_key_timestamp("event_start", ts);
            record.close();
        }

        const struct tcp_buffer *data_buf = reassembler.check_packet(k, tcp_pkt.header, pkt.length());
        if (data_buf) {
            // fprintf(stderr, "REASSEMBLED TCP PACKET\n");
            struct datum reassembled_tcp_data{data_buf->data, data_buf->data + data_buf->last_byte_needed};
            tcp_data_write_json(buf, reassembled_tcp_data, k, tcp_pkt, ts, reassembler);

        } else {
            tcp_data_write_json(buf, pkt, k, tcp_pkt, ts, reassembler);
        }

    } else if (transport_proto == 17) {
        struct udp_packet udp_pkt;
        udp_pkt.parse(pkt);
        udp_pkt.set_key(k);
        enum udp_msg_type msg_type = udp_get_message_type(pkt.data, pkt.length());
        switch(msg_type) {
        case udp_msg_type_wireguard:
            {
                wireguard_handshake_init wg;
                wg.parse(pkt);
                struct json_object record{&buf};
                wg.write_json(record);
                write_flow_key(record, k);
                record.print_key_timestamp("event_start", ts);
                record.close();
            }
            break;
        case udp_msg_type_dns:
            {
                struct json_object record{&buf};
                struct json_object dns{record, "dns"};
                write_dns_server_data(pkt.data,
                                      pkt.length(),
                                      dns,
                                      !global_vars.dns_json_output);
                dns.close();
                write_flow_key(record, k);
                record.print_key_timestamp("event_start", ts);
                record.close();
            }
            break;
        case udp_msg_type_dtls_client_hello:
            {
                struct dtls_record dtls_rec;
                dtls_rec.parse(pkt);
                struct dtls_handshake handshake;
                handshake.parse(dtls_rec.fragment);
                if (handshake.msg_type == handshake_type::client_hello) {
                    struct tls_client_hello hello;
                    hello.parse(handshake.body);
                    if (hello.is_not_empty()) {
                        struct json_object record{&buf};
                        struct json_object fps{record, "fingerprints"};
                        fps.print_key_value("dtls", hello);
                        fps.close();
                        hello.write_json(record, global_vars.metadata_output);
                        write_flow_key(record, k);
                        record.print_key_timestamp("event_start", ts);
                        record.close();
                    }
                }
            }
            break;
        case udp_msg_type_dhcp:
            {
                struct dhcp_discover dhcp_disco;
                dhcp_disco.parse(pkt);
                if (dhcp_disco.is_not_empty()) {
                    struct json_object record{&buf};
                    struct json_object fps{record, "fingerprints"};
                    fps.print_key_value("dhcp", dhcp_disco);
                    fps.close();
                    if (global_vars.metadata_output) {
                        dhcp_disco.write_json(record);
                        write_flow_key(record, k);
                        record.print_key_timestamp("event_start", ts);
                    }
                    record.close();
                }
            }
            break;
        case udp_msg_type_dtls_server_hello:
        case udp_msg_type_dtls_certificate:
            // cases that fall through here are not yet supported
        case udp_msg_type_unknown:
            // no output
            break;
        }
    }

    //    buf.snprintf(dstr, doff, dlen, trunc, ",\"flowhash\":\"%016lx\"", flowhash(key, ts->tv_sec));

    if (buf.length() != 0) {
        buf.strncpy("\n");
        return buf.length();
    }
    return 0;
}

void json_queue_write(struct ll_queue *llq,
                      uint8_t *packet,
                      size_t length,
                      unsigned int sec,
                      unsigned int nsec,
                      struct tcp_reassembler &reassembler) {

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
        append_packet_json(buf, packet, length, &(llq->msgs[llq->widx].ts), reassembler);
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
