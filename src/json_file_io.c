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

#define json_file_needs_rotation(jf) (--((jf)->record_countdown) == 0)

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

#define SNI_HDR_LEN 9

#define FP_BUF_LEN 2048

void json_file_write(struct json_file *jf,
                     uint8_t *packet,
                     size_t length,
                     unsigned int sec,
                     unsigned int usec) {
    extern unsigned int packet_filter_threshold;
    struct parser p;
    struct extractor x;
    uint8_t extractor_buffer[FP_BUF_LEN]= { 0 };
    size_t bytes_extracted;
    FILE *file = jf->file;

    extractor_init(&x, extractor_buffer, FP_BUF_LEN);
    parser_init(&p, packet, length);
    bytes_extracted = parser_extractor_process_packet(&p, &x);
    if (bytes_extracted > packet_filter_threshold) {
        switch(x.fingerprint_type) {
        case fingerprint_type_tls:
            fprintf(file, "{\"fingerprints\":{");
            fprintf(file, "\"tls\":\"");
            fprintf_binary_ept_as_paren_ept(file, extractor_buffer, bytes_extracted);
            fprintf(file, "\"}");
            if (x.packet_data.type == packet_data_type_tls_sni) {
                if (x.packet_data.length >= SNI_HDR_LEN) {
                    fprintf(file, ",\"tls\":{");
                    fprintf_json_string(file,
                                        "server_name",
                                        x.packet_data.value  + SNI_HDR_LEN,
                                        x.packet_data.length - SNI_HDR_LEN);
                    fprintf(file, "}");
                }
            }
            fprintf(file, ",");

            //uint8_t *tls_fp;
            //size_t tls_fp_len;
            //uint8_t *sni;
            //size_t sni_len;
            // struct inference_engine *inferencer;
            // struct inference_results results;
            // get_tls_fp_and_sni_from_buffer(exctactor_buffer, bytes_extracted, &tls_fp, &tls_fp_len, &sni, &sni_len);
            // inference_engine_get_results(inferencer, &key, tls_fp, tls_fp_len, sni, sni_len, &results);

            break;
        case fingerprint_type_tcp:
            fprintf(file, "{\"fingerprints\":{");
            fprintf(file, "\"tcp\":\"");
            fprintf_binary_ept_as_paren_ept(file, extractor_buffer, bytes_extracted);
            fprintf(file, "\"},");
            break;
        case fingerprint_type_http:
            fprintf(file, "{\"fingerprints\":{");
            fprintf(file, "\"http\":\"");
            fprintf_binary_ept_as_paren_ept(file, extractor_buffer, bytes_extracted);
            fprintf(file, "\"},");
            fprintf(file, "\"complete\":\"%s\",", (x.proto_state.state == state_done) ? "yes" : "no");

            if (x.packet_data.type == packet_data_type_http_user_agent) {
                fprintf(file, "\"http\":{");
                fprintf_json_hex_string(file,
                                        "user_agent",
                                        x.packet_data.value,
                                        x.packet_data.length);
                fprintf(file, "},");
            }

            break;
        case fingerprint_type_http_server:
            fprintf(file, "{\"fingerprints\":{");
            fprintf(file, "\"http_server\":\"");
            fprintf_binary_ept_as_paren_ept(file, extractor_buffer, bytes_extracted);
            fprintf(file, "\"},");
            fprintf(file, "\"complete\":\"%s\",", (x.proto_state.state == state_done) ? "yes" : "no");
            break;
        case fingerprint_type_tls_server:
            fprintf(file, "{\"fingerprints\":{");
            fprintf(file, "\"tls_server\":\"");
            fprintf_binary_ept_as_paren_ept(file, extractor_buffer, bytes_extracted);
            fprintf(file, "\"},");
            break;
        default:
            /* print nothing */
            return;
            //fprintf(file, "\"unknown\":\"");
            //fprintf_binary_ept_as_paren_ept(file, extractor_buffer, bytes_extracted);
            //fprintf(file, "\"},");
        }

        struct flow_key key = flow_key_init();
        flow_key_set_from_packet(&key, packet, length);
        fprintf_analysis_from_extractor_and_flow_key(file, &x, &key);

        packet_fprintf_flow_key(file, packet, length);
        fprintf_timestamp(file, sec, usec);
        fprintf(file, "}\n");

        if (json_file_needs_rotation(jf)) {
            json_file_rotate(jf);
        }
    }

}
