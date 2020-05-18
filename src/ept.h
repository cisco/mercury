/*
 * @file ept.h - encoded parse tree for protocol fingerprinting
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef EPT_H
#define EPT_H

#include <stdio.h> 
#include <stdint.h>
#include "mercury.h"
#include "buffer_stream.h"

/**
 * Encoded Parse Tree (EPT) 
 * 
 * An Encoded Parse Tree (EPT) is a general and flexible way to
 * represent a fingerprint.  It faithfully represents the
 * implementation-static data extracted from packets, using a tree of
 * byte strings that can be serialized in readable or binary form.
 * 
 * Selective packet parsing produces a parse tree whose leaves contain
 * the selected fields of the packet.  Each leaf (external node) of
 * the parse tree contains a byte string, and each internal node holds
 * an ordered list of nodes.  The tree is serialized with a preorder
 * traversal, so that the selected fields appear in the same order in
 * the serialized data as they do on the wire.  For a particular
 * fingerprint format, the position of the node in the tree determines
 * its semantics; for instance, the first leaf may be the version
 * field, and so on.  
 * 
 * Each protocol has its own fingerprint format, which specifies the
 * fields that are extracted from the packets and how they are
 * normalized.  Because protocols evolve over time, fingerprint
 * formats need to be able to evolve as well.  We define formats for
 * TLS, TCP, SSH, and DHCP.
 * 
 * The human-readable representation of an EPT uses bracket
 * expressions.  Each leaf is a hexadecimal string surrounded by
 * parentheses, such as "(474554)", and each internal node is
 * represented by a pair of balanced parenthesis that surround the
 * nodes that it holds, such as "((0000)(000b00020100))".  Bracket
 * expressions are commonly used in natural language processing, and
 * they can be easily parsed in a single pass.  The binary
 * representation of an EPT uses a simple type-length-value encoding
 * that is defined below.
 *
 * EPT is both flexible and reversible, meeting the following requirements:
 *  
 *   - It can easily accommodate changes in the fingerprint format, and
 *     can readily be applied to new protocols,
 * 
 *   - It can represent any selected fields from the fingerprint,
 *
 *   - It can support approximate fingerprint matching, so that slightly
 *     different fingerprints from slightly different applications can
 *     be matched,
 *
 *   - It avoids computationally expensive operations, such as
 *     cryptographic hashing, to facilitate use at high data rates,
 *
 *   - It provides both binary and human-readable forms.
 */


/**
 * set QUOTED_ASCII to 1 for readable output like "(\"GET\")"; set it
 * to 0 for hex output like "(474554)"
 */
#define QUOTED_ASCII 0

#define PARENT_NODE_INDICATOR 0x8000
#define LENGTH_MASK           0x7fff

/* utility functions */

void encode_uint16(uint8_t *p, uint16_t x);

uint16_t decode_uint16(const void *x);

/* output functions */

enum status fprintf_binary_ept_as_paren_ept(FILE *f,
					    const unsigned char *data,
					    unsigned int len);

void fprintf_binary_ept_as_tls_json(FILE *f,
				    const unsigned char *data,
				    unsigned int len);

void write_binary_ept_as_paren_ept(struct buffer_stream &buf, const unsigned char *data, unsigned int length);

size_t sprintf_binary_ept_as_paren_ept(uint8_t *data,
				       size_t length,
				       unsigned char *outbuf,
				       size_t outbuf_len);

size_t binary_ept_from_paren_ept(uint8_t *outbuf,
				 const uint8_t *outbuf_end,
				 const uint8_t *paren_ept,
				 const uint8_t *paren_ept_end);

enum status binary_ept_print_as_tls(uint8_t *data,
				    size_t length);


#endif /* EPT_H */
