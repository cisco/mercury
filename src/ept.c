/*
 * ept.c - encoded parse tree for protocol fingerprinting
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <ctype.h>    /* for isprint()  */
#include "ept.h"
#include "utils.h"

/* utility functions */

void encode_uint16(uint8_t *p, uint16_t x) {
    p[0] = x >> 8;
    p[1] = 0xff & x;
}

uint16_t decode_uint16 (const void *x) {
    uint16_t y;
    const unsigned char *z = (const unsigned char *)x;

    y = z[0];
    y = y << 8;
    y += z[1];
    return y;
}

unsigned int string_is_printable(const unsigned char *x,
                                 size_t len) {
    const unsigned char *end = x + len;

    while (x < end) {
        if (!isprint(*x)) {
            return 0;
        }
        x++;
    }
    return 1;
}

/* output functions */


#define ELEMENT_HDR_LEN 2

enum ept_node_type {
    ept_node_type_none     = 0,
    ept_node_type_list = 1,
    ept_node_type_string = 2,
    ept_node_type_empty_list = 3
};

struct element {
    enum ept_node_type type;
    const uint8_t *data;
    ssize_t length;
};

#define MAX_DEPTH 4

struct element_iterator {
    struct element element;
    ssize_t length[MAX_DEPTH];
    unsigned int depth;
};

void element_iterator_print(struct element_iterator *ei) {
    printf("\nelement type:    %d\t", ei->element.type);
    //printf("element data:    %p\t", ei->element.data);
    printf("element length:  %zd\t", ei->element.length);
    printf("iterator depth:  %u\t", ei->depth);
    printf("iterator length: %zd,%zd,%zd,%zd\n", ei->length[0], ei->length[1], ei->length[2], ei->length[3]);
}

enum status element_init(struct element *e,
                         const unsigned char *data,
                         unsigned int max_length) {

    if (max_length < sizeof(uint16_t)) {
        return status_err;
    }
    uint16_t tmp = decode_uint16(data);
    uint16_t length = (tmp & LENGTH_MASK);
    if (length + sizeof(uint16_t) > max_length) {
        fprintf(stderr, "element_init length: %04d\tmax_length: %04u\n", length, max_length);
        return status_err;
    }
    if (tmp & PARENT_NODE_INDICATOR) {
        if (length > 0) {
            e->type = ept_node_type_list;
        } else {
            e->type = ept_node_type_empty_list;
        }
    } else {
        e->type = ept_node_type_string;
    }
    e->data = data + sizeof(uint16_t);
    e->length = length;

    return status_ok;
}


enum iterator_status {
    iterator_status_done = 0,
    iterator_status_not_done = 1
};

enum iterator_status element_iterator_init(struct element_iterator *ei,
                                           const unsigned char *data,
                                           size_t data_length) {

    ei->depth = 0;
    ei->length[0] = data_length;
    for (int i=1; i < MAX_DEPTH; i++) {
        ei->length[i] = 0;
    }
    if (element_init(&ei->element, data, data_length) == status_ok) {
        return iterator_status_not_done;
    }
    return iterator_status_done; /* indicate error */
}

enum iterator_status element_iterator_advance(struct element_iterator *iterator) {
    struct element *element = &iterator->element;

    // element_iterator_print(iterator);

    if (element->type == ept_node_type_string || element->type == ept_node_type_empty_list) {

        if (element->length > iterator->length[iterator->depth]) {
            /*
             * error: not enough data in buffer
             */
            return iterator_status_done;
        }
        /*
         * advance to location of next element
         */
        iterator->length[iterator->depth] -= (element->length) + ELEMENT_HDR_LEN;

        if (iterator->length[iterator->depth] <= 0) {
            if (iterator->depth == 0) {
                return iterator_status_done;
            } else {
                /*
                 * if we are out of data at this level, then pop up one level
                 */
                iterator->depth--;
            }
        }
        const uint8_t *next_data = element->data + element->length;
        ssize_t next_length = iterator->length[iterator->depth];
        if (element_init(element, next_data, next_length) == status_ok) {
            return iterator_status_not_done;
        } else {
            return iterator_status_done;
        }

    } else if (element->type == ept_node_type_list) {

        /*
         * advance to next element one level down
         */
        iterator->length[iterator->depth] -= (element->length + ELEMENT_HDR_LEN);
        iterator->depth++;
        iterator->length[iterator->depth] = element->length;
        if (element_init(element, element->data, element->length) == status_ok) {
            return iterator_status_not_done;
        } else {
            printf("ERROR 3\n");
            return iterator_status_done;
        }
    }
    return iterator_status_done; /* should not get here */
}

void fprintf_string_as_ascii_or_hex(FILE *f, const unsigned char *data, size_t len) {
    if (string_is_printable(data, len)) {
        putc('\'', f);
        for (size_t i=0; i<len; i++) {
            putc(*data++, f);
        }
        putc('\'', f);
    } else {
        fprintf_raw_as_hex(f, data, len);
    }
}

void fprintf_string_as_ascii(FILE *f, const unsigned char *data, size_t len) {
    putc('\'', f);
    for (size_t i=0; i<len; i++) {
        if (isprint(*data)) {
            if (*data == '\"' || *data == '"') {
                putc('\\', f);
            } else if (*data == '\b') {
                putc('\\', f);
                putc('b', f);
            } else if (*data == '\f') {
                putc('\\', f);
                putc('f', f);
            } else if (*data == '\n') {
                putc('\\', f);
                putc('n', f);
            } else if (*data == '\r') {
                putc('\\', f);
                putc('r', f);
            } else if (*data == '\t') {
                putc('\\', f);
                putc('t', f);
            }
            putc(*data, f);
        } else {
            putc('.', f);  /* suppress nonprintable characters */
        }
        ++data;
    }
    putc('\'', f);
}

void element_fprintf(FILE *f, const struct element *e) {
    fprintf(f, "(");
    fprintf_raw_as_hex(f, e->data, e->length);
    fprintf(f, ")");
}

void element_printf(const struct element *e) {
    element_fprintf(stdout, e);
}

enum status print_buffer_as_element(uint8_t *data,
                                    size_t length) {
    struct element_iterator ei;
    if (element_iterator_init(&ei, data, length) == iterator_status_done) {
        return status_err;
    }

    unsigned int last_depth = ei.depth;
    do {

        // element_iterator_print(&ei);

        if (ei.element.type == ept_node_type_string) {
            if (ei.depth > last_depth) {
                printf("(");
            }
            if (ei.depth < last_depth) {
                printf(")");
            }
            element_printf(&ei.element);
        }
        last_depth = ei.depth;

    } while (element_iterator_advance(&ei) != iterator_status_done);

    // element_iterator_print(&ei);

    return status_ok;
}

struct char_pair {
    unsigned char hi;
    unsigned char lo;
};

unsigned char *raw_to_hex(unsigned char *outbuf,
                          unsigned char *outbuf_end,
                          const unsigned char *raw,
                          size_t raw_len) {
    struct char_pair hex[256] = {
        { '0', '0' }, { '0', '1' }, { '0', '2' }, { '0', '3' },
        { '0', '4' }, { '0', '5' }, { '0', '6' }, { '0', '7' },
        { '0', '8' }, { '0', '9' }, { '0', 'a' }, { '0', 'b' },
        { '0', 'c' }, { '0', 'd' }, { '0', 'e' }, { '0', 'f' },
        { '1', '0' }, { '1', '1' }, { '1', '2' }, { '1', '3' },
        { '1', '4' }, { '1', '5' }, { '1', '6' }, { '1', '7' },
        { '1', '8' }, { '1', '9' }, { '1', 'a' }, { '1', 'b' },
        { '1', 'c' }, { '1', 'd' }, { '1', 'e' }, { '1', 'f' },
        { '2', '0' }, { '2', '1' }, { '2', '2' }, { '2', '3' },
        { '2', '4' }, { '2', '5' }, { '2', '6' }, { '2', '7' },
        { '2', '8' }, { '2', '9' }, { '2', 'a' }, { '2', 'b' },
        { '2', 'c' }, { '2', 'd' }, { '2', 'e' }, { '2', 'f' },
        { '3', '0' }, { '3', '1' }, { '3', '2' }, { '3', '3' },
        { '3', '4' }, { '3', '5' }, { '3', '6' }, { '3', '7' },
        { '3', '8' }, { '3', '9' }, { '3', 'a' }, { '3', 'b' },
        { '3', 'c' }, { '3', 'd' }, { '3', 'e' }, { '3', 'f' },
        { '4', '0' }, { '4', '1' }, { '4', '2' }, { '4', '3' },
        { '4', '4' }, { '4', '5' }, { '4', '6' }, { '4', '7' },
        { '4', '8' }, { '4', '9' }, { '4', 'a' }, { '4', 'b' },
        { '4', 'c' }, { '4', 'd' }, { '4', 'e' }, { '4', 'f' },
        { '5', '0' }, { '5', '1' }, { '5', '2' }, { '5', '3' },
        { '5', '4' }, { '5', '5' }, { '5', '6' }, { '5', '7' },
        { '5', '8' }, { '5', '9' }, { '5', 'a' }, { '5', 'b' },
        { '5', 'c' }, { '5', 'd' }, { '5', 'e' }, { '5', 'f' },
        { '6', '0' }, { '6', '1' }, { '6', '2' }, { '6', '3' },
        { '6', '4' }, { '6', '5' }, { '6', '6' }, { '6', '7' },
        { '6', '8' }, { '6', '9' }, { '6', 'a' }, { '6', 'b' },
        { '6', 'c' }, { '6', 'd' }, { '6', 'e' }, { '6', 'f' },
        { '7', '0' }, { '7', '1' }, { '7', '2' }, { '7', '3' },
        { '7', '4' }, { '7', '5' }, { '7', '6' }, { '7', '7' },
        { '7', '8' }, { '7', '9' }, { '7', 'a' }, { '7', 'b' },
        { '7', 'c' }, { '7', 'd' }, { '7', 'e' }, { '7', 'f' },
        { '8', '0' }, { '8', '1' }, { '8', '2' }, { '8', '3' },
        { '8', '4' }, { '8', '5' }, { '8', '6' }, { '8', '7' },
        { '8', '8' }, { '8', '9' }, { '8', 'a' }, { '8', 'b' },
        { '8', 'c' }, { '8', 'd' }, { '8', 'e' }, { '8', 'f' },
        { '9', '0' }, { '9', '1' }, { '9', '2' }, { '9', '3' },
        { '9', '4' }, { '9', '5' }, { '9', '6' }, { '9', '7' },
        { '9', '8' }, { '9', '9' }, { '9', 'a' }, { '9', 'b' },
        { '9', 'c' }, { '9', 'd' }, { '9', 'e' }, { '9', 'f' },
        { 'a', '0' }, { 'a', '1' }, { 'a', '2' }, { 'a', '3' },
        { 'a', '4' }, { 'a', '5' }, { 'a', '6' }, { 'a', '7' },
        { 'a', '8' }, { 'a', '9' }, { 'a', 'a' }, { 'a', 'b' },
        { 'a', 'c' }, { 'a', 'd' }, { 'a', 'e' }, { 'a', 'f' },
        { 'b', '0' }, { 'b', '1' }, { 'b', '2' }, { 'b', '3' },
        { 'b', '4' }, { 'b', '5' }, { 'b', '6' }, { 'b', '7' },
        { 'b', '8' }, { 'b', '9' }, { 'b', 'a' }, { 'b', 'b' },
        { 'b', 'c' }, { 'b', 'd' }, { 'b', 'e' }, { 'b', 'f' },
        { 'c', '0' }, { 'c', '1' }, { 'c', '2' }, { 'c', '3' },
        { 'c', '4' }, { 'c', '5' }, { 'c', '6' }, { 'c', '7' },
        { 'c', '8' }, { 'c', '9' }, { 'c', 'a' }, { 'c', 'b' },
        { 'c', 'c' }, { 'c', 'd' }, { 'c', 'e' }, { 'c', 'f' },
        { 'd', '0' }, { 'd', '1' }, { 'd', '2' }, { 'd', '3' },
        { 'd', '4' }, { 'd', '5' }, { 'd', '6' }, { 'd', '7' },
        { 'd', '8' }, { 'd', '9' }, { 'd', 'a' }, { 'd', 'b' },
        { 'd', 'c' }, { 'd', 'd' }, { 'd', 'e' }, { 'd', 'f' },
        { 'e', '0' }, { 'e', '1' }, { 'e', '2' }, { 'e', '3' },
        { 'e', '4' }, { 'e', '5' }, { 'e', '6' }, { 'e', '7' },
        { 'e', '8' }, { 'e', '9' }, { 'e', 'a' }, { 'e', 'b' },
        { 'e', 'c' }, { 'e', 'd' }, { 'e', 'e' }, { 'e', 'f' },
        { 'f', '0' }, { 'f', '1' }, { 'f', '2' }, { 'f', '3' },
        { 'f', '4' }, { 'f', '5' }, { 'f', '6' }, { 'f', '7' },
        { 'f', '8' }, { 'f', '9' }, { 'f', 'a' }, { 'f', 'b' },
        { 'f', 'c' }, { 'f', 'd' }, { 'f', 'e' }, { 'f', 'f' }
    };

    unsigned int i;

    for (i=0; i < raw_len; i++) {
        if (outbuf + 2 >= outbuf_end) {
            return outbuf_end;
        }

        struct char_pair c = hex[*raw++];
        *outbuf++ = c.hi;
        *outbuf++ = c.lo;
    }
    return outbuf;
}

unsigned char *element_sprintf(const struct element *e,
                               unsigned char *outbuf,
                               unsigned char *outbuf_end) {
    if (outbuf >= outbuf_end) {
        return outbuf_end;
    }
    *outbuf++ = '(';
    outbuf = raw_to_hex(outbuf, outbuf_end, e->data, e->length);
    if (outbuf >= outbuf_end) {
        return outbuf_end;
    }
    *outbuf++ = ')';
    return outbuf;
}

size_t sprintf_binary_ept_as_paren_ept(uint8_t *data,
                                       size_t length,
                                       unsigned char *outbuf,
                                       size_t outbuf_len) {

    unsigned char *outbuf_end = outbuf + outbuf_len;
    if (outbuf >= outbuf_end) {
        return 0;  /* error: at end of output buffer */
    }

    struct element_iterator ei;
    if (element_iterator_init(&ei, data, length) == iterator_status_done) {
        return status_err;
    }

    const unsigned char *outbuf_inital = outbuf;

    unsigned int last_depth = ei.depth;
    do {

        if (ei.element.type == ept_node_type_string) {
            if (ei.depth > last_depth) {
                *outbuf++ = '(';
            }
            if (ei.depth < last_depth) {
                *outbuf++ = ')';
            }
            outbuf = element_sprintf(&ei.element, outbuf, outbuf_end);
        }
        last_depth = ei.depth;
        if (outbuf >= outbuf_end) {
            return 0;  /* error: at end of output buffer */
        }

    } while (element_iterator_advance(&ei) != iterator_status_done);

    if (ei.depth < last_depth) {
        *outbuf++ = ')';
    }

    *outbuf = 0; /* null-terminate string */

    return outbuf - outbuf_inital;
}

enum status fprintf_binary_ept_as_paren_ept(FILE *f,
                                            const unsigned char *data,
                                            unsigned int length) {

    //    fprintf(stderr, "%s with length %04u\n", __func__, length);

    struct element_iterator ei;
    if (element_iterator_init(&ei, data, length) == iterator_status_done) {
        return status_err;
    }

    unsigned int last_depth = ei.depth;
    do {

        if (ei.element.type == ept_node_type_empty_list) {
            fprintf(f, "()");
        }
        if (ei.element.type == ept_node_type_string) {
            if (ei.depth > last_depth) {
                fprintf(f, "(");
            }
            if (ei.depth < last_depth) {
                fprintf(f, ")");
            }
            element_fprintf(f, &ei.element);
        }
        last_depth = ei.depth;

    } while (element_iterator_advance(&ei) != iterator_status_done);

    if (ei.depth < last_depth) {
        fprintf(f, ")");
    }

    return status_ok;
}

void write_element(struct buffer_stream &buf, const struct element *e) {
    buf.write_char('(');
    buf.raw_as_hex(e->data, e->length);
    buf.write_char(')');
}

void write_binary_ept_as_paren_ept(buffer_stream &buf, const unsigned char *data, unsigned int length) {

    struct element_iterator ei;

    if (element_iterator_init(&ei, data, length) == iterator_status_done) {
        return;
    }

    unsigned int last_depth = ei.depth;
    do {

        if (ei.element.type == ept_node_type_empty_list) {
            buf.strncpy("()");
        }
        if (ei.element.type == ept_node_type_string) {
            if (ei.depth > last_depth) {
                buf.write_char('(');
            }
            if (ei.depth < last_depth) {
                buf.write_char(')');
            }
            write_element(buf, &ei.element);
        }
        last_depth = ei.depth;

    } while ((element_iterator_advance(&ei) != iterator_status_done) && (buf.trunc == 0));

    if (ei.depth < last_depth) {
        buf.write_char(')');
    }

}

enum status binary_ept_print_as_tls(uint8_t *data,
                                    size_t length) {
    struct element_iterator ei;

    printf("\n");
    enum iterator_status iterator_status = element_iterator_init(&ei, data, length);
    if (iterator_status == iterator_status_done) {
        return status_err;
    }
    if (ei.element.type == ept_node_type_string) {
        printf("version:      ");
        element_printf(&ei.element);
        printf("\n");
    }
    iterator_status = element_iterator_advance(&ei);
    if (iterator_status != iterator_status_not_done) {
        return status_err;
    }
    if (ei.element.type == ept_node_type_string) {
        printf("ciphersuites: ");
        element_printf(&ei.element);
        printf("\n");
    }
    iterator_status = element_iterator_advance(&ei);
    if (iterator_status != iterator_status_not_done) {
        return status_err;
    }
    if (ei.element.type == ept_node_type_list) {
        printf("extensions:   (");
        iterator_status = element_iterator_advance(&ei);
        unsigned int last_depth = ei.depth;
        do {
            if (ei.element.type == ept_node_type_string) {
                element_printf(&ei.element);
            }
            iterator_status = element_iterator_advance(&ei);
        } while (iterator_status == iterator_status_not_done && ei.depth == last_depth);
    }
    printf(")\n");
    if (iterator_status == iterator_status_not_done) {
        printf("sni:          ");
        element_printf(&ei.element);
        printf("\n");
    }

    return status_ok;

}

struct paren_ept {
    enum ept_node_type type;  /* string, list, or unknown */
    size_t bytes;             /* number of bytes in expr  */
    uint8_t *header;          /* location to write header */
};

#define paren_ept_init_data { ept_node_type_none, 0, NULL }

void paren_ept_init(struct paren_ept *e, uint8_t *hdr) {
    e->type = ept_node_type_none;
    e->bytes = 0;
    e->header = hdr;
}

uint8_t hex_to_raw_uint8(const uint8_t *hexstr) {
    uint8_t raw;

    raw = ((hexstr[0] & '@') ? hexstr[0] + 9 : hexstr[0]) << 4;
    raw |= ((hexstr[1] & '@') ? hexstr[1] + 9 : hexstr[1]) & 0xF;

    return raw;
}

#define MAX_LEVELS 4

size_t binary_ept_from_paren_ept(uint8_t *outbuf,
                                 const uint8_t *outbuf_end,
                                 const uint8_t *inbuf,
                                 const uint8_t *inbuf_end) {
    uint8_t *outbuf_orig = outbuf;
    struct paren_ept expr[MAX_LEVELS] = { paren_ept_init_data, };
    uint8_t hexdata[3] = { 0, 0, 0 };
    size_t hexdata_index = 0;
    uint16_t hdr;

    size_t bytes_written = 0;
    int level = -1;
    while (inbuf < inbuf_end) {

        switch (*inbuf) {
        case '(':
            if (level > -1) {
                expr[level].type = ept_node_type_list;
            }
            if (level > MAX_LEVELS) {
                return 0;
            }
            level++;
            paren_ept_init(&expr[level], outbuf);
            outbuf += 2;
            hexdata_index = 0;
            break;
        case ')':
            switch(expr[level].type) {
            case ept_node_type_none:
            case ept_node_type_string:
                if (hexdata_index) {
                    return 0; /* error: incomplete hex pair */
                }
                // printf("got %c\n", *inbuf);
                hdr = bytes_written;
                encode_uint16(expr[level].header, hdr);
                if (level > 0) {
                    expr[level-1].bytes += bytes_written + 2;
                    // printf("adding to length: %zu (%zx)\n", bytes_written + 2, bytes_written + 2);
                }
                bytes_written = 0;
                break;
            case ept_node_type_list:
                hdr = expr[level].bytes | PARENT_NODE_INDICATOR;
                encode_uint16(expr[level].header, hdr);
                // printf("level: %u\tencoding: %x\n", level, hdr);
                break;
            case ept_node_type_empty_list: /* just to suppress compiler warnings */
                break;
            }
            level--;
            if (level < -1) {
                return 0;
            }
            break;
        default:
            if (!isxdigit(*inbuf)) {
                return 0;  /* error */
            }
            switch (expr[level].type) {
            case ept_node_type_none:
            case ept_node_type_string:
                if (hexdata_index) {
                    hexdata[1] = *inbuf;
                    //printf("hex: %s\t%zu\n", hexdata, hexdata_index);
                    *outbuf++ = hex_to_raw_uint8(hexdata);
                    bytes_written++;
                    hexdata_index = 0;
                } else {
                    hexdata[0] = *inbuf;
                    hexdata_index = 1;
                }
                break;
            case ept_node_type_list:
            case ept_node_type_empty_list: /* just to suppress compiler warnings */
                return 0; /* error */
            }
        }

        if (outbuf >= outbuf_end) {
            return 0; /* error: at end of output buffer */
        }

        //	printf("%c\n", *inbuf);
        inbuf++;
    }

    //    printf("level: %d\n", level);

    return outbuf - outbuf_orig;
}
