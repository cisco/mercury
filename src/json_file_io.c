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
#include "extractor.h"
#include "packet.h"
#include "ept.h"
#include "utils.h"
#include "analysis.h"
#include "llq.h"

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

void fprintf_timestamp(FILE *f, unsigned int sec, unsigned int usec) {

    fprintf(f, ",\"event_start\":%u.%06u", sec, usec); // not sure why usec has fewer than 6 digits, but appears to work
}


int append_timestamp(char *dstr, int *doff, int dlen, int *trunc,
                     struct timespec *ts) {

    int r;

    r = append_snprintf(dstr, doff, dlen, trunc, ",\"event_start\":%u.%06u", ts->tv_sec, ts->tv_nsec / 1000);

    return r;
}


int append_packet_json(char *dstr, int *doff, int dlen, int *trunc,
                       uint8_t *packet,
                       size_t length,
                       struct timespec *ts) {

    extern unsigned int packet_filter_threshold;

    struct packet_filter pf;
    pf.tcp_init_msg_filter = NULL;

    /*
     * apply packet filter to packet; return if no fingerprints or metadata found
     */
    size_t bytes_extracted = packet_filter_extract(&pf, packet, length);
    if (bytes_extracted <= packet_filter_threshold && pf.x.packet_data.type == packet_data_type_none) {
        return 0;
    }

    int r = 0;

    r += append_putc(dstr, doff, dlen, trunc,
                     '{');

    /*
     * output fingerprint (if any)
     */
    if (bytes_extracted > packet_filter_threshold) {
        uint8_t *extractor_buffer = pf.x.output_start;
        switch(pf.x.fingerprint_type) {
        case fingerprint_type_dhcp_client:
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\"fingerprints\":{\"dhcp\":\"");
            r += append_binary_ept_as_paren_ept(dstr, doff, dlen, trunc,
                                                extractor_buffer, bytes_extracted);
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\"},");
            break;
        case fingerprint_type_tls:
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\"fingerprints\":{\"tls\":\"");
            r += append_binary_ept_as_paren_ept(dstr, doff, dlen, trunc,
                                                extractor_buffer, bytes_extracted);
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\"},");
            break;
        case fingerprint_type_tcp:
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\"fingerprints\":{\"tcp\":\"");
            r += append_binary_ept_as_paren_ept(dstr, doff, dlen, trunc,
                                                extractor_buffer, bytes_extracted);
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\"},");
            break;
        case fingerprint_type_http:
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\"fingerprints\":{\"http\":\"");
            r += append_binary_ept_as_paren_ept(dstr, doff, dlen, trunc,
                                                extractor_buffer, bytes_extracted);
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\"},");
            r += append_snprintf(dstr, doff, dlen, trunc,
                                 "\"complete\":\"%s\",", (pf.x.proto_state.state == state_done) ? "yes" : "no");
            break;
        case fingerprint_type_http_server:
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\"fingerprints\":{\"http_server\":\"");
            r += append_binary_ept_as_paren_ept(dstr, doff, dlen, trunc,
                                                extractor_buffer, bytes_extracted);
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\"},");
            r += append_snprintf(dstr, doff, dlen, trunc,
                                 "\"complete\":\"%s\",", (pf.x.proto_state.state == state_done) ? "yes" : "no");
            break;
        case fingerprint_type_tls_server:
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\"fingerprints\":{\"tls_server\":\"");
            r += append_binary_ept_as_paren_ept(dstr, doff, dlen, trunc,
                                                extractor_buffer, bytes_extracted);
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\"},");
            break;
        case fingerprint_type_dtls:
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\"fingerprints\":{\"dtls\":\"");
            r += append_binary_ept_as_paren_ept(dstr, doff, dlen, trunc,
                                                extractor_buffer, bytes_extracted);
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\"},");
            break;
        case fingerprint_type_dtls_server:
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\"fingerprints\":{\"dtls_server\":\"");
            r += append_binary_ept_as_paren_ept(dstr, doff, dlen, trunc,
                                                extractor_buffer, bytes_extracted);
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\"},");
            break;
        default:
            ;    /* no fingerprint; do nothing */
        }
    }

    /*
     * output packet_data (if any)
     */
    if (pf.x.packet_data.type == packet_data_type_http_user_agent) {
        r += append_strncpy(dstr, doff, dlen, trunc,
                            "\"http\":{");
        r += append_json_string(dstr, doff, dlen, trunc,
                                "user_agent",
                                pf.x.packet_data.value,
                                pf.x.packet_data.length);
        r += append_strncpy(dstr, doff, dlen, trunc,
                            "},");
    }
    if (pf.x.packet_data.type == packet_data_type_tls_sni) {
        if (pf.x.packet_data.length >= SNI_HDR_LEN) {
            r += append_strncpy(dstr, doff, dlen, trunc,
                            "\"tls\":{");
            r += append_json_string(dstr, doff, dlen, trunc,
                                    "server_name",
                                    pf.x.packet_data.value  + SNI_HDR_LEN,
                                    pf.x.packet_data.length - SNI_HDR_LEN);
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "},");
        }
    }
    if (pf.x.packet_data.type == packet_data_type_tls_cert) {
        /* print the certificates in base64 format */
        r += append_strncpy(dstr, doff, dlen, trunc,
                            "\"tls\":{\"server_certs\":[");
        r += append_extract_certificates(dstr, doff, dlen, trunc,
                                         pf.x.packet_data.value, pf.x.packet_data.length);
        r += append_strncpy(dstr, doff, dlen, trunc,
                            "]},");
    }
    if (pf.x.packet_data.type == packet_data_type_dtls_sni) {
        if (pf.x.packet_data.length >= SNI_HDR_LEN) {
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "\"dtls\":{");
            r += append_json_string(dstr, doff, dlen, trunc,
                                    "server_name",
                                    pf.x.packet_data.value  + SNI_HDR_LEN,
                                    pf.x.packet_data.length - SNI_HDR_LEN);
            r += append_strncpy(dstr, doff, dlen, trunc,
                                "},");
        }
    }

    /*
     * output flow key, analysis (if it's configured), and the timestamp
     */
    struct flow_key key = flow_key_init();
    flow_key_set_from_packet(&key, packet, length);

    r += append_analysis_from_extractor_and_flow_key(dstr, doff, dlen, trunc,
                                                 &pf.x, &key);

    r += append_packet_flow_key(dstr, doff, dlen, trunc,
                                packet, length);

    r += append_timestamp(dstr, doff, dlen, trunc,
                          ts);

    //    r += append_snprintf(dstr, doff, dlen, trunc, ",\"flowhash\":\"%016lx\"", flowhash(key, ts->tv_sec));

    r += append_strncpy(dstr, doff, dlen, trunc,
                                "}\n");

    return r;
}


void json_file_write(struct json_file *jf,
                     uint8_t *packet,
                     size_t length,
                     unsigned int sec,
                     unsigned int nsec) {

    struct timespec ts;
    char obuf[LLQ_MSG_SIZE];
    int olen = LLQ_MSG_SIZE;
    int ooff = 0;
    int trunc = 0;

    ts.tv_sec = sec;
    ts.tv_nsec = nsec;

    obuf[0] = '\0';
    int r = append_packet_json(&(obuf[0]), &ooff, olen, &trunc,
                              packet, length, &ts);

    if ((trunc == 0) && (r > 0)) {
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
        int olen = LLQ_MSG_SIZE;
        int ooff = 0;
        int trunc = 0;

        llq->msgs[llq->widx].ts.tv_sec = sec;
        llq->msgs[llq->widx].ts.tv_nsec = nsec;


        //obuf[sizeof(struct timespec)] = '\0';
        llq->msgs[llq->widx].buf[0] = '\0';

        int r = append_packet_json(llq->msgs[llq->widx].buf, &ooff, olen, &trunc,
                                   packet, length, &(llq->msgs[llq->widx].ts));

        if ((trunc == 0) && (r > 0)) {

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
