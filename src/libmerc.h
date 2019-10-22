/*
 * @file libmerc.h
 * 
 * @brief interface to mercury packet metadata capture and analysis library
 */

#ifndef LIBMERC_H
#define LIBMERC_H


/** 
 * @brief extracts a TLS client fingerprint from a packet
 *
 * Extracts a TLS clientHello fingerprint from the TCP data field
 * (which starts at @em data and contains @em data_len bytes) and
 * writes it into the output buffer (which starts at @em outbuf and
 * contains @em outbuf_len bytes) in bracket notation (human readable)
 * form, if there is enough room for it.
 * 
 * @param [in] data the start of the TCP data field
 * @param [in] data_len the number of bytes in the TCP data field
 * @param [out] outbuf the output buffer
 * @param [in] outbuf_len the number of bytes in the output buffer
 *
 */
size_t extract_fp_from_tls_client_hello(uint8_t *data,
					size_t data_len,
					uint8_t *outbuf,
					size_t outbuf_len);


enum status proto_ident_config(const char *config_string);

enum status static_data_config(const char *config_string);


#endif /* LIBMERC_H */
