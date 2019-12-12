/*
 * utils.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */


#include "pcap_file_io.h"

void packet_handler_null(uint8_t *ignore,
			 const struct pcap_pkthdr *pcap_pkthdr,
			 const uint8_t *packet);

void packet_handler_printf(uint8_t *ignore,
			   const struct pcap_pkthdr *pcap_pkthdr,
			   const uint8_t *packet);


enum status hex_to_raw(const void *output,
		       size_t output_buf_len,
		       const char *null_terminated_hex_string);

void fprintf_json_hex_string(FILE *file,
                            const unsigned char *data,
                            size_t len);

void fprintf_raw_as_hex(FILE *f, const uint8_t *data, unsigned int len);

void fprintf_json_hex_string(FILE *f, const char *key, const uint8_t *data, unsigned int len);

void fprintf_json_string(FILE *f, const char *key, const uint8_t *data, unsigned int len);

enum status drop_root_privileges(const char *username, const char *directory);

int copy_string_into_buffer(char *dst, size_t dst_len, const char *src, size_t max_src_len);

void fprintf_json_base64_string(FILE *file, const unsigned char *data, size_t input_length);

void printf_raw_as_hex(const uint8_t *data, unsigned int len);
