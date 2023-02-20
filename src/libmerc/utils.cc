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
#include <stdlib.h>
#include <time.h>
#include "libmerc.h"
#include "utils.h"

#ifndef _WIN32
#include <pwd.h>
#include <grp.h>
#endif

/* utility functions */

void fprintf_raw_as_hex(FILE *f, const uint8_t *data, unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

    while (x < end) {
        fprintf(f, "%02x", *x++);
    }
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

#ifndef _WIN32
  
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
                printf_err(log_err, "environment variable `SUDO_UID` not found; could not drop root privileges\n");
                return status_err;
            }
            errno = 0;
            uid = (uid_t) strtoll(sudo_uid, NULL, 10);
            if (errno) {
                printf_err(log_err, "could not convert SUDO_UID to int (%s)\n", strerror(errno));
                return status_err;
            }
        }

        gid = getgid();
        if (gid == 0) {
            const char *sudo_gid = getenv("SUDO_GID");
            if (sudo_gid == NULL) {
                printf_err(log_err, "environment variable `SUDO_GID` not found; could not drop root privileges\n");
                return status_err;
            }
            errno = 0;
            gid = (gid_t) strtoll(sudo_gid, NULL, 10);
            if (errno) {
                printf_err(log_err, "could not convert SUDO_GID to int (%s)\n", strerror(errno));
                return status_err;
            }
        }

        new_username = getenv("SUDO_USER");
        if (new_username == NULL) {
            printf_err(log_err, "environment variable `SUDO_USER` not found; could not drop root privileges\n");
            return status_err;
        }

    } else {

        userdata = getpwnam(username);
        if (userdata) {
            new_username = userdata->pw_name;
            gid = userdata->pw_gid;
            uid = userdata->pw_uid;
        } else {
            printf_err(log_err, "could not find user '%.32s'\n", username);
            return status_err;
        }
    }

    /*
     * set gid, uid and groups
     */
    if (initgroups(new_username, gid)) {
        printf_err(log_err, "could not set groups (%s)\n", strerror(errno));
        return status_err;
    }
    if (setgid(gid)) {
        printf_err(log_err, "could not set GID (%s)\n", strerror(errno));
        return status_err;
    }
    if (setuid(uid)) {
        printf_err(log_err, "could not set UID (%s)\n", strerror(errno));
        return status_err;
    }

    /*
     * check to make sure that we achieved our goals
     */
    if (setuid(0) == 0 || seteuid(0) == 0) {
        printf_err(log_err, "failed to drop root privileges\n");
        return status_err;
    }

    /*
     * change working directory to a non-root one, if asked
     */
    if (directory) {
        if (chdir(directory) != 0) {
            printf_err(log_err, "could not change current working directory (%s)\n", strerror(errno));
            return status_err;
        }
    }

    return status_ok;

#else   // _WIN32 not defined

    printf_err(log_err, "could not drop root privileges; operation not supported on WIN32\n");
    return status_err;

#endif


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

void get_readable_number_float(double power,
                               double input,
                               double *num_output,
                               char **str_output) {
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
        if (src != dst)
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
        //
        // failed to get clock time, set the uninitialized struct to zero
        //
        memset(&t->before, 0, sizeof(t->before));
        printf_err(log_err, "could not get clock time (%s)\n", strerror(errno));
    }
}

#define BILLION 1000000000L

uint64_t timer_stop(struct timer *t) {
    uint64_t nano_sec = 0;
    if (clock_gettime(CLOCK_REALTIME, &t->after) != 0) {
        printf_err(log_err, "could not get clock time (%s)\n", strerror(errno));
    } else {
        // It is assumed that if this call is successful, the previous call is also successful.
        // We got clock time after writting, now compute the time difference in nano seconds
        nano_sec += (BILLION * (t->after.tv_sec - t->before.tv_sec)) + (t->after.tv_nsec - t->before.tv_nsec);
    }
    return nano_sec;
}

#define MAX_ADDR_STR_LEN 48
void sprintf_ipv6_addr(char *addr_str, const uint8_t *ipv6_addr) {
    int trunc = 0;
    int offset = 0;
    int len;
    len = append_ipv6_addr(addr_str, &offset, MAX_ADDR_STR_LEN, &trunc, ipv6_addr);
    addr_str[len] = '\0';
}

