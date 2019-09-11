/*
 * utils.c
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include "mercury.h"
#include "pcap_file_io.h"


void fprintf_raw_as_hex(FILE *f, const uint8_t *data, unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

    while (x < end) {
        fprintf(f, "%02x", *x++);
    }
}

void fprintf_json_hex_string(FILE *f, const char *key, const uint8_t *data, unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

    fprintf(f, "\"%s\":\"", key);
    while (x < end) {
        fprintf(f, "%02x", *x++);
    }
    fprintf(f, "\"");
}

void fprintf_json_string(FILE *f, const char *key, const uint8_t *data, unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

    fprintf(f, "\"%s\":\"", key);
    while (x < end) {
	if (*x == '"' || *x == '\\') { // || *x == '/') {
	    fprintf(f, "\\");
	}
        fprintf(f, "%c", *x++);
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
		printf("environment variable `SUDO_UID` not found\n");
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
		printf("environment variable SUDO_GID not found\n");
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
            printf("environment variable `SUDO_USER` not found\n");
	    return status_err;
	}

    } else {

	userdata = getpwnam(username);
	if (userdata) {
	    new_username = userdata->pw_name;
	    gid = userdata->pw_gid;
	    uid = userdata->pw_uid;
        } else {
            printf("%s: could not find user '%.32s'", strerror(errno), username);
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
