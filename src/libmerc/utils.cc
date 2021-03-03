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
#include "libmerc.h"
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

void fprintf_raw_as_hex(FILE *f, const uint8_t *data, unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

    while (x < end) {
        fprintf(f, "%02x", *x++);
    }
}

// void fprintf_json_string_escaped(FILE *f, const char *key, const uint8_t *data, unsigned int len) {
//     const unsigned char *x = data;
//     const unsigned char *end = data + len;

//     fprintf(f, "\"%s\":\"", key);
//     while (x < end) {
//         if (*x < 0x20) {                   /* escape control characters   */
//             fprintf(f, "\\u%04x", *x);
//         } else if (*x > 0x7f) {            /* escape non-ASCII characters */
//             fprintf(f, "\\u%04x", *x);
//         } else {
//             if (*x == '"' || *x == '\\') { /* escape special characters   */
//                 fprintf(f, "\\");
//             }
//             fprintf(f, "%c", *x);
//         }
//         x++;
//     }
//     fprintf(f, "\"");
// }

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
                fprintf(stderr, "error: environment variable `SUDO_UID` not found; could not drop root privileges\n");
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
                fprintf(stderr, "error: environment variable `SUDO_GID` not found; could not drop root privileges\n");
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
            fprintf(stderr, "error: environment variable `SUDO_USER` not found; could not drop root privileges\n");
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

enum status filename_append(char dst[FILENAME_MAX],
                            const char *src,
                            const char *delim,
                            const char *tail) {

    if (tail) {

        /*
         * filename = directory || '/' || thread_num
         */
        if (strnlen(src, FILENAME_MAX) + strlen(tail) + 1 > FILENAME_MAX) {
            return status_err; /* filename too long */
        }
        strncpy(dst, src, FILENAME_MAX);
        strcat(dst, delim);
        strcat(dst, tail);

    } else {

        if (strnlen(src, FILENAME_MAX) >= FILENAME_MAX) {
            return status_err; /* filename too long */
        }
        strncpy(dst, src, FILENAME_MAX);

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
