/*
 * utils.c
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <time.h>
#include "mercury.h"
#include "pcap_file_io.h"
#include "utils.h"


/* append_snprintf
 * takes the base address of a string, the offset in the string, total length, and a truncation flag
 * and stores the desired snprintf() content at that offset.
 *
 * return: the amount stored (or needed to be stored in case of truncation)
 */
int append_snprintf(char *dstr, int *doff, int dlen, int *trunc,
                    const char *fmt, ...) {

    /* Check to make sure the offset isn't already longer than the length */
    if (*doff >= dlen) {
        *trunc = 1;
        return 0;
    }

    va_list args;
    va_start(args, fmt);
    int r = vsnprintf(&(dstr[*doff]), dlen - *doff, fmt, args);
    va_end(args);

    /* Check for truncation */
    if (r >= dlen - *doff) {
        fprintf(stderr, "Truncation occurred in substr_snprintf(...). Space available: %u; needed: %d\n",
                dlen - *doff, r);

        *doff = dlen;
        *trunc = 1;
    } else {
        *doff = *doff + r;
        *trunc = 0;
    }

    return r;
}


int append_strncpy(char *dstr, int *doff, int dlen, int *trunc,
                   const char *sstr) {

    /* Check to make sure the offset isn't already longer than the length */
    if (*doff >= dlen) {
        *trunc = 1;
        return 0;
    }

    int gn = 0; /* got a null */
    int i = 0;
    while (*doff + i < dlen - 1) {
        if (sstr[i] != '\0') {
            dstr[*doff + i] = sstr[i];
            i++;
        } else {
            dstr[*doff + i] = sstr[i];
            gn = 1;
            break;
        }
    }

    /* Always put a null even when truncating */
    if (gn != 1) {
        dstr[*doff + i] = '\0';
        *trunc = 1;
    }

    /* adjust the offset */
    *doff = *doff + i;

    return i; /* i doesn't count the null, just like in snprintf */
}


int append_putc(char *dstr, int *doff, int dlen, int *trunc,
                char schr) {

    /* Check to make sure the offset isn't already longer than the length */
    if (*doff >= dlen) {
        *trunc = 1;
        return 0;
    }

    if (*doff < dlen - 1) {
        dstr[*doff] = schr;
        *doff = *doff + 1;
        dstr[*doff] = '\0';

        return 1;
    } else {
        *trunc = 1;
        /* Always put a null even when truncating */
        dstr[*doff] = '\0';

        return 0;
    }
}

int append_memcpy(char *dstr, int *doff, int dlen, int *trunc, const void *s, ssize_t length) {
    const uint8_t *src = (const uint8_t *)s;

    /* Check to make sure the offset isn't already longer than the length */
    if (*doff >= dlen) {
        *trunc = 1;
        return 0;
    }

    if (*doff < dlen - length) {   // TBD: over/under flow?
        memcpy(dstr + *doff, src, length);
        *doff = *doff + length;
        return length;
    } else {
        *trunc = 1;
        return 0;
    }
}

int append_raw_as_hex(char *dstr, int *doff, int dlen, int *trunc,
                      const uint8_t *data, unsigned int len) {
    *trunc = 0;
    int r = 0;
    for (unsigned int i = 0; (i < len) && (*trunc == 0); i++) {
        r += append_snprintf(dstr, doff, dlen, trunc,
                             "%02x", data[i]);
    }

    return r;
}


void fprintf_raw_as_hex(FILE *f, const uint8_t *data, unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

    while (x < end) {
        fprintf(f, "%02x", *x++);
    }
}


int append_json_hex_string(char *dstr, int *doff, int dlen, int *trunc,
                           const char *key, const uint8_t *data, unsigned int len) {
    *trunc = 0;
    int r = 0;

    r += append_snprintf(dstr, doff, dlen, trunc,
                         "\"%s\":\"0x", key);
    for (unsigned int i = 0; (i < len) && (*trunc == 0); i++) {
        r += append_snprintf(dstr, doff, dlen, trunc,
                             "%02x", data[i]);
    }
    r += append_putc(dstr, doff, dlen, trunc, '"');

    return r;
}


void fprintf_json_hex_string(FILE *f, const char *key, const uint8_t *data, unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

    fprintf(f, "\"%s\":\"0x", key);
    while (x < end) {
        fprintf(f, "%02x", *x++);
    }
    fprintf(f, "\"");
}


int append_json_string_escaped(char *dstr, int *doff, int dlen, int *trunc,
                               const char *key, const uint8_t *data, unsigned int len) {
    *trunc = 0;
    int r = 0;

    r += append_snprintf(dstr, doff, dlen, trunc,
                         "\"%s\":\"", key);

    for (unsigned int i = 0; (i < len) && (*trunc == 0); i++) {
        if (data[i] < 0x20) {                   /* escape control characters   */
            r += append_snprintf(dstr, doff, dlen, trunc,
                                 "\\u%04x", data[i]);
        } else if (data[i] > 0x7f) {            /* escape non-ASCII characters */
            r += append_snprintf(dstr, doff, dlen, trunc,
                                 "\\u%04x", data[i]);
        } else {
            if (data[i] == '"' || data[i] == '\\') { /* escape special characters   */
                r += append_putc(dstr, doff, dlen, trunc,
                                 '\\');
            }
            r += append_putc(dstr, doff, dlen, trunc,
                             data[i]);
        }
    }

    r += append_putc(dstr, doff, dlen, trunc,
                     '"');

    return r;
}


void fprintf_json_string_escaped(FILE *f, const char *key, const uint8_t *data, unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

    fprintf(f, "\"%s\":\"", key);
    while (x < end) {
        if (*x < 0x20) {                   /* escape control characters   */
            fprintf(f, "\\u%04x", *x);
        } else if (*x > 0x7f) {            /* escape non-ASCII characters */
            fprintf(f, "\\u%04x", *x);
        } else {
            if (*x == '"' || *x == '\\') { /* escape special characters   */
                fprintf(f, "\\");
            }
            fprintf(f, "%c", *x);
        }
        x++;
    }
    fprintf(f, "\"");
}


unsigned int string_is_nonascii(const uint8_t *data, size_t len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

    uint8_t sum = 0;
    while (x < end) {
        sum |= *x;
        x++;
    }
    return sum & 0x80; /* return 0 if no high bits are set */
}


inline bool string_starts_with_0x(const uint8_t *data, size_t len) {
    if (len > 2 && data[0] == '0' && data[1] == 'x') {
        return true;
    }
    return false;
}


int append_json_string(char *dstr, int *doff, int dlen, int *trunc,
                       const char *key, const uint8_t *data, unsigned int len) {

    int r;
    if (string_is_nonascii(data, len) || string_starts_with_0x(data, len)) {
        r = append_json_hex_string(dstr, doff, dlen, trunc,
                                   key, data, len);
    } else {
        r = append_json_string_escaped(dstr, doff, dlen, trunc,
                                       key, data, len);
    }

    return r;
}


void fprintf_json_string(FILE *f, const char *key, const uint8_t *data, unsigned int len) {

    if (string_is_nonascii(data, len) || string_starts_with_0x(data, len)) {
        fprintf_json_hex_string(f, key, data, len);
    } else {
        fprintf_json_string_escaped(f, key, data, len);
    }
}


size_t hex_to_raw(const void *output,
                  size_t output_buf_len,
                  const char *null_terminated_hex_string) {
    const char *hex = null_terminated_hex_string;
    const unsigned char *out = (uint8_t *)output;
    size_t count = 0;

    while (output_buf_len-- > 0) {
        if (hex[0] == 0) {
            break;
        }
        if (hex[1] == 0) {
            return 0;   /* error, report no data copied */
        }
        sscanf(hex, "%2hhx", (unsigned char *)&out[count++]);
        hex += 2;
    }

    return count;
}


void packet_handler_printf(uint8_t *ignore,
                           const struct pcap_pkthdr *pcap_pkthdr,
                           const uint8_t *packet) {

    (void)ignore;

    printf("--------------------------------\npacket\ntimestamp: %u.%u\nlength: %u\n",
           (unsigned int)pcap_pkthdr->ts.tv_sec,
           (unsigned int)pcap_pkthdr->ts.tv_usec,
           pcap_pkthdr->caplen);
    fprintf_raw_as_hex(stdout, packet, pcap_pkthdr->caplen);
    printf("\n");

}


void packet_handler_null(uint8_t *ignore,
                         const struct pcap_pkthdr *pcap_pkthdr,
                         const uint8_t *packet) {

    (void)ignore;
    (void)pcap_pkthdr;
    (void)packet;

}


/*
 * drop_root_privileges() returns 0 on success and -1 on failure
 */
enum status drop_root_privileges(const char *username, const char *directory) {
    gid_t gid;
    uid_t uid;
    const char *new_username;
    struct passwd *userdata = NULL;

    /*
     * if asked to run as user=root, don't drop root privileges
     */
    if (username && strcmp("root", username) == 0) {
        return status_ok;
    }

    if (username == NULL) {

        /*
         * if we are not root, we have nothing to do
         */
        if (getuid() != 0) {
            return status_ok;
        }

        /*
         * set new user's UID, GID, and username from environment variables
         */
        uid = getuid();
        if (uid == 0) {
            const char *sudo_uid = getenv("SUDO_UID");
            if (sudo_uid == NULL) {
                fprintf(stderr, "error: environment variable `SUDO_UID` not found; cannot set user to '%s'\n", username);
                return status_err;
            }
            errno = 0;
            uid = (uid_t) strtoll(sudo_uid, NULL, 10);
            if (errno) {
                perror("error converting SUDO_UID to int");
                return status_err;
            }
        }

        gid = getgid();
        if (gid == 0) {
            const char *sudo_gid = getenv("SUDO_GID");
            if (sudo_gid == NULL) {
                fprintf(stderr, "error: environment variable `SUDO_GID` not found; cannot set user to '%s'\n", username);
                return status_err;
            }
            errno = 0;
            gid = (gid_t) strtoll(sudo_gid, NULL, 10);
            if (errno) {
                perror("error converting SUDO_GID to int");
                return status_err;
            }
        }

        new_username = getenv("SUDO_USER");
        if (new_username == NULL) {
            fprintf(stderr, "error: environment variable `SUDO_USER` not found; cannot set user to '%s'\n", username);
            return status_err;
        }

    } else {

        userdata = getpwnam(username);
        if (userdata) {
            new_username = userdata->pw_name;
            gid = userdata->pw_gid;
            uid = userdata->pw_uid;
        } else {
            fprintf(stderr, "error: could not find user '%.32s'\n", username);
            return status_err;
        }
    }


    /*
     * set gid, uid and groups
     */
    if (initgroups(new_username, gid)) {
        perror("error setting groups");
        return status_err;
    }
    if (setgid(gid)) {
        perror("error setting GID");
        return status_err;
    }
    if (setuid(uid)) {
        perror("error setting UID");
        return status_err;
    }

    /*
     * check to make sure that we achieved our goals
     */
    if (setuid(0) == 0 || seteuid(0) == 0) {
        printf("failed to drop root privileges\n");
        return status_err;
    }

    /*
     * change working directory to a non-root one, if asked
     */
    if (directory) {
        if (chdir(directory) != 0) {
            perror("error changing current working directory");
            return status_err;
        }
    }

    return status_ok;
}

/*
 * copy_string_into_buffer(dst, dst_len, src, src_len)
 *
 * dst         - destination buffer
 * dst_len     - bytes in destination buffer
 * src         - (null terminated) source string
 * max_src_len - maximum length of source string
 *
 * return value:
 *       0 success
 *      -1 if string is not null-terminated
 *      -1 if string does not fit into buffer
 */

int copy_string_into_buffer(char *dst, size_t dst_len, const char *src, size_t max_src_len) {

    size_t src_len = strnlen(src, max_src_len);
    if (src_len == max_src_len) {
        return -1; /* error: no null termination in source */
    }
    if (src_len + 1 > dst_len) {
        return -1; /* error: source string (plus null) too large for destination */
    }
    strcpy(dst, src);
    return 0;
}

/* macro for fputc */
#define FPUTC(C, F)                                     \
    if (fputc((int)C, F) == EOF) {                      \
        perror("Error while printing base64 char\n");   \
        return;                                         \
    }

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};


int append_json_base64_string(char *dstr, int *doff, int dlen, int *trunc,
                              const unsigned char *data,
                              size_t input_length) {

    *trunc = 0;
    int r = 0;
    size_t i = 0;
    size_t rem = input_length % 3; /* so it can be 0, 1 or 2 */
    size_t len = input_length - rem; /* always a multiple of 3 */
    uint32_t oct_a, oct_b, oct_c, trip;

    r += append_putc(dstr, doff, dlen, trunc,
                '"');
    while ((i < len) && (*trunc == 0)) {

        oct_a = data[i++];
        oct_b = data[i++];
        oct_c = data[i++];

        trip = (oct_a << 0x10) + (oct_b << 0x08) + oct_c;

        r += append_putc(dstr, doff, dlen, trunc,
                         encoding_table[(trip >> (3 * 6)) & 0x3F]);
        r += append_putc(dstr, doff, dlen, trunc,
                         encoding_table[(trip >> (2 * 6)) & 0x3F]);
        r += append_putc(dstr, doff, dlen, trunc,
                         encoding_table[(trip >> (1 * 6)) & 0x3F]);
        r += append_putc(dstr, doff, dlen, trunc,
                         encoding_table[(trip >> (0 * 6)) & 0x3F]);
    }

    if (rem > 0) {
        oct_a = data[i++];
        oct_b = (i < input_length)? data[i++] : 0;
        oct_c = (i < input_length)? data[i++] : 0;

        trip = (oct_a << 0x10) + (oct_b << 0x08) + oct_c;

        /**
         * if remainder is zero, we are done.
         * if remainder is 1, we need to get one more byte from data.
         * if remainder is 2, we need to get two more bytes from data.
         * Afterwards, we need to pad the encoded_data with '=' appropriately.
         */
        if (rem == 1) {
            /* This one byte spans 2 bytes in encoded_data */
            /* Pad the last 2 bytes */
            r += append_putc(dstr, doff, dlen, trunc,
                             encoding_table[(trip >> (3 * 6)) & 0x3F]);
            r += append_putc(dstr, doff, dlen, trunc,
                             encoding_table[(trip >> (2 * 6)) & 0x3F]);
            r += append_strncpy(dstr, doff, dlen, trunc,
                                (char *)"==");
        } else if (rem == 2) {
            /* These two bytes span 3 bytes in encoded_data */
            /* Pad the remaining last byte */
            r += append_putc(dstr, doff, dlen, trunc,
                             encoding_table[(trip >> (3 * 6)) & 0x3F]);
            r += append_putc(dstr, doff, dlen, trunc,
                             encoding_table[(trip >> (2 * 6)) & 0x3F]);
            r += append_putc(dstr, doff, dlen, trunc,
                             encoding_table[(trip >> (1 * 6)) & 0x3F]);
            r += append_putc(dstr, doff, dlen, trunc,
                             '=');
        }
    }
    r += append_putc(dstr, doff, dlen, trunc,
                     '"');

    return r;
}

/*
 * fprintf_json_base64_string(file, data, input_length)
 *
 * file         - file pointer to the output file
 * data         - pointer to start of data
 * input_length - number of bytes of data
 *
 * return value:
 *       void
 */
void fprintf_json_base64_string(FILE *file,
                                const unsigned char *data,
                                size_t input_length) {

    size_t i = 0;
    size_t rem = input_length % 3; /* so it can be 0, 1 or 2 */
    size_t len = input_length - rem; /* always a multiple of 3 */
    uint32_t oct_a, oct_b, oct_c, trip;

    FPUTC('\"', file);
    while (i < len) {

        oct_a = data[i++];
        oct_b = data[i++];
        oct_c = data[i++];

        trip = (oct_a << 0x10) + (oct_b << 0x08) + oct_c;

        FPUTC(encoding_table[(trip >> (3 * 6)) & 0x3F], file);
        FPUTC(encoding_table[(trip >> (2 * 6)) & 0x3F], file);
        FPUTC(encoding_table[(trip >> (1 * 6)) & 0x3F], file);
        FPUTC(encoding_table[(trip >> (0 * 6)) & 0x3F], file);
    }

    if (rem > 0) {
        oct_a = data[i++];
        oct_b = (i < input_length)? data[i++] : 0;
        oct_c = (i < input_length)? data[i++] : 0;

        trip = (oct_a << 0x10) + (oct_b << 0x08) + oct_c;

        /**
         * if remainder is zero, we are done.
         * if remainder is 1, we need to get one more byte from data.
         * if remainder is 2, we need to get two more bytes from data.
         * Afterwards, we need to pad the encoded_data with '=' appropriately.
         */
        if (rem == 1) {
            /* This one byte spans 2 bytes in encoded_data */
            /* Pad the last 2 bytes */
            FPUTC(encoding_table[(trip >> (3 * 6)) & 0x3F], file);
            FPUTC(encoding_table[(trip >> (2 * 6)) & 0x3F], file);
            fprintf(file, "==");
        } else if (rem == 2) {
            /* These two bytes span 3 bytes in encoded_data */
            /* Pad the remaining last byte */
            FPUTC(encoding_table[(trip >> (3 * 6)) & 0x3F], file);
            FPUTC(encoding_table[(trip >> (2 * 6)) & 0x3F], file);
            FPUTC(encoding_table[(trip >> (1 * 6)) & 0x3F], file);
            fprintf(file, "=");
        }
    }
    FPUTC('\"', file);
}


int append_json_hex_string(char *dstr, int *doff, int dlen, int *trunc,
                           const uint8_t *data, unsigned int len) {
    *trunc = 0;
    int r = 0;

    r += append_putc(dstr, doff, dlen, trunc,
                     '"');
    for (unsigned int i = 0; (i < len) && (*trunc == 0); i++) {
        r += append_snprintf(dstr, doff, dlen, trunc,
                             "%02x", data[i]);
    }
    r += append_putc(dstr, doff, dlen, trunc, '"');

    return r;
}


void fprintf_json_hex_string(FILE *file,
                             const unsigned char *data,
                             size_t len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;
    fprintf(file, "\"");
    while(x < end) {
        fprintf(file, "%02x", *x++);
    }
    fprintf(file, "\"");
}
/*
 * printf_raw_as_hex(data, len)
 *
 * data   - pointer to start of data
 * len    - number of bytes of data
 *
 * return value:
 *       void
 */

void printf_raw_as_hex(const uint8_t *data, unsigned int len) {
    const unsigned char *x = data;
    printf("\n  Len = %u\n", len);
    if (len > 128) {
        len = 128;
    }
    const unsigned char *end = data + len;
    int i;

    for (x = data; x < end; ) {
        for (i=0; i < 16 && x < end; i++) {
            printf(" %02x", *x++);
        }
        printf("\n");
    }
}

#define MAX_READABLE_SUFFIX 9
char *readable_number_suffix[MAX_READABLE_SUFFIX] = {
    (char *)"",
    (char *)"K",
    (char *)"M",
    (char *)"G",
    (char *)"T",
    (char *)"P",
    (char *)"E",
    (char *)"Z",
    (char *)"Y"
};

void get_readable_number_int(unsigned int power,
                             unsigned int input,
                             unsigned int *num_output,
                             char **str_output) {
    unsigned int index = 0;

    while ((input > power) && ((index + 1) < MAX_READABLE_SUFFIX)) {
	index++;
	input = input / power;
    }
    *num_output = input;
    *str_output = readable_number_suffix[index];

}

void get_readable_number_float(double power,
                               double input,
                               double *num_output,
                               char **str_output) {
    unsigned int index = 0;

    while ((input > power) && ((index + 1) < MAX_READABLE_SUFFIX)) {
	index++;
	input = input / power;
    }
    *num_output = input;
    *str_output = readable_number_suffix[index];

}

enum status filename_append(char dst[MAX_FILENAME],
                            const char *src,
                            const char *delim,
                            const char *tail) {

    if (tail) {

        /*
         * filename = directory || '/' || thread_num
         */
        if (strnlen(src, MAX_FILENAME) + strlen(tail) + 1 > MAX_FILENAME) {
            return status_err; /* filename too long */
        }
        strncpy(dst, src, MAX_FILENAME);
        strcat(dst, delim);
        strcat(dst, tail);

    } else {

        if (strnlen(src, MAX_FILENAME) >= MAX_FILENAME) {
            return status_err; /* filename too long */
        }
        strncpy(dst, src, MAX_FILENAME);

    }
    return status_ok;
}

void timer_start(struct timer *t) {
    if (clock_gettime(CLOCK_REALTIME, &t->before) != 0) {
        // failed to get clock time, set the uninitialized struct to zero
        bzero(&t->before, sizeof(struct timespec));
        perror("error: could not get clock time before fwrite file header\n");
    }
}

#define BILLION 1000000000L

uint64_t timer_stop(struct timer *t) {
    uint64_t nano_sec = 0;
    if (clock_gettime(CLOCK_REALTIME, &t->after) != 0) {
        perror("error: could not get clock time after fwrite file header\n");
    } else {
        // It is assumed that if this call is successful, the previous call is also successful.
        // We got clock time after writting, now compute the time difference in nano seconds
        nano_sec += (BILLION * (t->after.tv_sec - t->before.tv_sec)) + (t->after.tv_nsec - t->before.tv_nsec);
    }
    return nano_sec;
}
