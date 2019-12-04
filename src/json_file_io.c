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

/* macro for fputc */
#define FPUTC(C, F)                                       \
        if (fputc((int)C, F) == EOF) {                    \
            perror("Error while printing base64 char\n"); \
            return;                                       \
        }

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};

static size_t mod_table[] = {0, 2, 1};
static void fprintf_json_base64_string(FILE *file,
                    const unsigned char *data,
                    size_t input_length) {

    size_t i = 0;
    while ( i < input_length) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        FPUTC(encoding_table[(triple >> 3 * 6) & 0x3F], file);
        FPUTC(encoding_table[(triple >> 2 * 6) & 0x3F], file);
        FPUTC(encoding_table[(triple >> 1 * 6) & 0x3F], file);
        FPUTC(encoding_table[(triple >> 0 * 6) & 0x3F], file);
    }

    for (i = 0; i < mod_table[input_length % 3]; i++) {
        FPUTC('=', file);
    }
}

void json_file_write(struct json_file *jf,
		     uint8_t *packet,
		     size_t length,
		     unsigned int sec,
		     unsigned int usec) {
    extern unsigned int packet_filter_threshold;
    FILE *file = jf->file;
    struct packet_filter pf;
    pf.tcp_init_msg_filter = NULL;
 
    size_t bytes_extracted = packet_filter_extract(&pf, packet, length);
    if (bytes_extracted > packet_filter_threshold) {
        uint8_t *extractor_buffer = pf.x.output_start;
	switch(pf.x.fingerprint_type) {
	case fingerprint_type_tls:
	    fprintf(file, "{\"fingerprints\":{");
	    fprintf(file, "\"tls\":\"");
	    fprintf_binary_ept_as_paren_ept(file, extractor_buffer, bytes_extracted);
	    fprintf(file, "\"}");
	    if (pf.x.packet_data.type == packet_data_type_tls_sni) {
		if (pf.x.packet_data.length >= SNI_HDR_LEN) {
		    fprintf(file, ",\"tls\":{");
		    fprintf_json_string(file,
					"server_name",
					pf.x.packet_data.value  + SNI_HDR_LEN,
					pf.x.packet_data.length - SNI_HDR_LEN);
		    fprintf(file, "}");
		}
	    }
	    fprintf(file, ",");

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
	    fprintf(file, "\"complete\":\"%s\",", (pf.x.proto_state.state == state_done) ? "yes" : "no");

	    if (pf.x.packet_data.type == packet_data_type_http_user_agent) {
		fprintf(file, "\"http\":{");
		fprintf_json_hex_string(file,
					"user_agent",
					pf.x.packet_data.value,
					pf.x.packet_data.length);
		fprintf(file, "},");
	    }
	    
	    break;
	case fingerprint_type_http_server:
	    fprintf(file, "{\"fingerprints\":{");
	    fprintf(file, "\"http_server\":\"");
	    fprintf_binary_ept_as_paren_ept(file, extractor_buffer, bytes_extracted);
	    fprintf(file, "\"},");
	    fprintf(file, "\"complete\":\"%s\",", (pf.x.proto_state.state == state_done) ? "yes" : "no");
	    break;
	case fingerprint_type_tls_server:
	    fprintf(file, "{\"fingerprints\":{");
	    fprintf(file, "\"tls_server\":\"");
	    fprintf_binary_ept_as_paren_ept(file, extractor_buffer, bytes_extracted);
	    fprintf(file, "\"},");
	    break;
	case fingerprint_type_tls_cert:
        /* print the certificate in base64 format */
        fprintf(file, "{\"tls\":{");
        fprintf(file, "\"server_certs\":[\"");
        fprintf_json_base64_string(file,
                                    pf.x.packet_data.value,
                                    pf.x.packet_data.length);
        /* check if we have another certificate */
        if (pf.x.cert_data.type == packet_data_type_tls_cert) {
            fprintf(file, "\",\""); /* preceding comma to separate array elements */
            fprintf_json_base64_string(file,
                                        pf.x.cert_data.value,
                                        pf.x.cert_data.length);
        }
	    fprintf(file, "\"]},");
	    break;
	case fingerprint_type_tls_server_and_cert:
        /* print the fingerprint */
	    fprintf(file, "{\"fingerprints\":{");
	    fprintf(file, "\"tls_server\":\"");
	    fprintf_binary_ept_as_paren_ept(file, extractor_buffer, bytes_extracted);
	    fprintf(file, "\"},");

        /* print the certificate in base64 format */
	    fprintf(file, "\"tls\":{");
        fprintf(file, "\"server_certs\":[\"");
        fprintf_json_base64_string(file,
                                    pf.x.packet_data.value,
                                    pf.x.packet_data.length);
        /* check if we have another certificate */
        if (pf.x.cert_data.type == packet_data_type_tls_cert) {
            fprintf(file, "\",\""); /* preceding comma to separate array elements */
            fprintf_json_base64_string(file,
                                        pf.x.cert_data.value,
                                        pf.x.cert_data.length);
        }
	    fprintf(file, "\"]},");
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
	fprintf_analysis_from_extractor_and_flow_key(file, &pf.x, &key);

	packet_fprintf_flow_key(file, packet, length);
	fprintf_timestamp(file, sec, usec);
	fprintf(file, "}\n");

	if (json_file_needs_rotation(jf)) {
	    json_file_rotate(jf);
	}
    }

}
