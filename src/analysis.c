/*
 * analysis.c
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */


#include <arpa/inet.h>
#include "analysis.h"
#include "ept.h"

/* 
 * analysis_cfg is a global variable that configures the analysis
 */
enum analysis_cfg analysis_cfg = analysis_off;

#ifdef HAVE_PYTHON3

#include "python_interface.h"

int analysis_init() {
    extern enum analysis_cfg analysis_cfg;
    analysis_cfg = analysis_on;
    return init_python();
}

int analysis_finalize() {
    extern enum analysis_cfg analysis_cfg;
    analysis_cfg = analysis_off;
    return finalize_python();
}

#define SNI_HEADER_LEN 9

#define MAX_DST_ADDR_LEN 40
void flow_key_sprintf_dst_addr(const struct flow_key *key,
			       char *dst_addr_str) {
 
    if (key->type == ipv4) {
	uint8_t *d = (uint8_t *)&key->value.v4.dst_addr;
	snprintf(dst_addr_str,
		 MAX_DST_ADDR_LEN,
		 "%u.%u.%u.%u",
		 d[0], d[1], d[2], d[3]);		
    } else if (key->type == ipv6) {
	uint8_t *d = (uint8_t *)&key->value.v6.dst_addr;
	snprintf(dst_addr_str,
		 MAX_DST_ADDR_LEN,
		 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		 d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
    }
}

#define MAX_FP_STR_LEN 4096
#define MAX_SNI_LEN     257
void fprintf_analysis_from_extractor_and_flow_key(FILE *file,
						  const struct extractor *x,
						  const struct flow_key *key) {
    //struct results_obj *r_p;
    char *r_p;
    extern enum analysis_cfg analysis_cfg;

    if (analysis_cfg == analysis_off) {
	return; /* do not perform any analysis */
    }
    
    if (x->fingerprint_type == fingerprint_type_tls) {
	char dst_addr_string[MAX_DST_ADDR_LEN];
	unsigned char fp_string[MAX_FP_STR_LEN];
	char tmp_sni[MAX_SNI_LEN];
	uint16_t dest_port = 0;
	
	uint8_t *extractor_buffer = x->output_start;
	size_t bytes_extracted = extractor_get_output_length(x);
	sprintf_binary_ept_as_paren_ept(extractor_buffer, bytes_extracted, fp_string, MAX_FP_STR_LEN); /* should check return result */
	flow_key_sprintf_dst_addr(key, dst_addr_string);
	if (x->packet_data.type == packet_data_type_tls_sni) {
	    size_t sni_len = x->packet_data.length - SNI_HEADER_LEN;
	    sni_len = sni_len > MAX_SNI_LEN-1 ? MAX_SNI_LEN-1 : sni_len;
	    memcpy(tmp_sni, x->packet_data.value + SNI_HEADER_LEN, sni_len);
	    tmp_sni[sni_len] = 0; /* null termination */
	}
	
	fprintf(file, "\"analysis\":");
	py_process_detection(&r_p, (char *)fp_string, tmp_sni, dst_addr_string, dest_port);
	fprintf(file, "%s", r_p);
	fprintf(file, ",");
    }

}

#else /* HAVE_PYTHON3 is not defined */

int analysis_init() {
    fprintf(stderr, "error: analysis requested, but analysis engine not present\n"); 
    return -1; 
}

int analysis_finalize() {
    /* nothing to do */
    return -1;
}

void fprintf_analysis_from_extractor_and_flow_key(FILE *file,
						  const struct extractor *x,
						  const struct flow_key *key) {
    (void)file; /* unused */
    (void)x;    /* unused */
    (void)key;  /* unused */
}


#endif /* HAVE_PYTHON3 */
