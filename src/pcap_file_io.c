/*
 * pcap_file_io.c
 *
 * functions for reading and writing packets using the (old) libpcap
 * file format
 * 
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at 
 * https://github.com/cisco/mercury/blob/master/LICENSE 
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE            /* get fadvise() and fallocate() */
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#include "mercury.h"
#include "pcap_file_io.h"
#include "pkt_processing.h"
#include "signal_handling.h"
#include "libmerc/utils.h"
#include "llq.h"


enum linktype {
    LINKTYPE_NULL =       0,  // BSD loopback encapsulation
    LINKTYPE_ETHERNET =   1,  // Ethernet
    LINKTYPE_RAW      = 101   // Raw IP; begins with IPv4 or IPv6 header
};

/*
 * constants used in file format
 */
static uint32_t magic = 0xa1b2c3d4;
static uint32_t cagim = 0xd4c3b2a1;

/*
 * global pcap header (one per file, at beginning)
 */
struct pcap_file_hdr {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
}  __attribute__((packed));

/*
 * packet header (one per packet, right before it)
 */
struct pcap_packet_hdr {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} __attribute__((packed));

#define ONE_KB (1024)
#define ONE_MB (1024 * ONE_KB)
#ifndef FBUFSIZE
   #define STREAM_BUFFER_SIZE (ONE_MB)
#else
   #define STREAM_BUFFER_SIZE FBUFSIZE
#endif
#define PRE_ALLOCATE_DISK_SPACE  (100 * ONE_MB)

static inline void set_file_io_buffer(struct pcap_file *f, const char *fname) {
    f->buffer = (unsigned char *) malloc(STREAM_BUFFER_SIZE);
    if (f->buffer != NULL) {
        if (setvbuf(f->file_ptr, (char *)f->buffer, _IOFBF, STREAM_BUFFER_SIZE) != 0) {
            printf("%s: error setting i/o buffer for file %s\n", strerror(errno), fname);
            free(f->buffer);
            f->buffer = NULL;
        } else {
            f->buf_len = STREAM_BUFFER_SIZE;
        }
    } else {
        printf("warning: could not malloc i/o buffer for %s\n", fname);
    }
}

enum status write_pcap_file_header(FILE *f) {
    struct pcap_file_hdr file_header;
    file_header.magic_number = magic;
    file_header.version_major = 2;
    file_header.version_minor = 4;
    file_header.thiszone = 0;     /* no GMT correction for now */
    file_header.sigfigs = 0;      /* we don't claim sigfigs for now */
    file_header.snaplen = 65535;
    file_header.network = LINKTYPE_ETHERNET;

    size_t items_written = fwrite(&file_header, sizeof(file_header), 1, f);
    if (items_written == 0) {
        perror("error writing pcap file header");
        return status_err;
    }
    return status_ok;
}

enum status pcap_file_open(struct pcap_file *f,
                           const char *fname,
                           enum io_direction dir,
                           int flags) {
    struct pcap_file_hdr file_header;
    ssize_t items_read;

    switch(dir) {
    case io_direction_reader:
        f->flags = O_RDONLY;
        break;
    case io_direction_writer:
        f->flags = O_WRONLY;
        break;
    default:
        printf("error: unsupported flag, other flags=0x%x\n", flags);
        return status_err; /* unsupported flags */
    }

    if (f->flags == O_WRONLY) {
        /* create and open new file for writing */
        f->file_ptr = fopen(fname, "w");
        if (f->file_ptr == NULL) {
            printf("%s: error opening pcap file %s\n", strerror(errno), fname);
            return status_err; /* could not open file */
        }
        f->fd = fileno(f->file_ptr); // save file descriptor
        if (f->fd < 0) {
            printf("%s: error getting file descriptor for pcap file %s\n", strerror(errno), fname);
            return status_err; /* system call failed */
        }

        // set file i/o buffer
        set_file_io_buffer(f, fname);

        // set the file advisory for the write file
#ifdef POSIX_FADV_SEQUENTIAL
        if (posix_fadvise(f->fd, 0, 0, POSIX_FADV_SEQUENTIAL) != 0) {
            printf("%s: Could not set file advisory for pcap file %s\n", strerror(errno), fname);
        }

        f->allocated_size = 0; // initialize
        if (fallocate(f->fd, FALLOC_FL_KEEP_SIZE, 0, PRE_ALLOCATE_DISK_SPACE) != 0) {
            printf("warning: %s: Could not pre-allocate %d MB disk space for pcap file %s\n", 
                   strerror(errno), PRE_ALLOCATE_DISK_SPACE, fname);
        } else {
            f->allocated_size = PRE_ALLOCATE_DISK_SPACE;  // initial allocation
        }
#endif

        enum status status = write_pcap_file_header(f->file_ptr);
        if (status) {
            perror("error writing pcap file header");
            fclose(f->file_ptr);
            f->file_ptr = NULL;
            if (f->buffer != NULL) {
                free(f->buffer);
                f->buffer = NULL;
            }
            return status_err;
        }

        // initialize packets and bytes written
        f->bytes_written = sizeof(file_header);
        f->packets_written = 0;

    } else { /* O_RDONLY */

        if (strncmp(fname, "-", sizeof("-")) == 0) {
            /* read PCAP file from standard input */
            f->file_ptr = stdin;

        } else {

            /*  open existing file for reading */
            f->file_ptr = fopen(fname, "r");
            if (f->file_ptr == NULL) {
                printf("%s: error opening read file %s\n", strerror(errno), fname);
                return status_err; /* could not open file */
            }
        }

        f->fd = fileno(f->file_ptr);  // save file descriptor
        if (f->fd < 0) {
            printf("%s: error getting file descriptor for read file %s\n", strerror(errno), fname);
            return status_err; /* system call failed */
        }

        // set the file advisory for the read file, if it is not stdin
#ifdef POSIX_FADV_SEQUENTIAL
        if (f->file_ptr != stdin && posix_fadvise(f->fd, 0, 0, POSIX_FADV_SEQUENTIAL) != 0) {
            printf("%s: Could not set file advisory for read file %s\n", strerror(errno), fname);
        }
#endif

        // set file i/o buffer
        set_file_io_buffer(f, fname);
        f->bytes_written = 0L;  // will never write any bytes to this file opened for reading

        // printf("info: file %s opened\n", fname);

        items_read = fread(&file_header, sizeof(file_header), 1, f->file_ptr);
        if (items_read == 0) {
            if (errno) {
                perror("error: could not read PCAP file header");
            } else {
                fprintf(stderr, "error: could not read PCAP file header\n");
            }
            return status_err; /* could not read packet header from file */
        }
        if (file_header.magic_number == magic) {
            f->byteswap = 0;
            // printf("file is in pcap format\nno byteswap needed\n");
        } else if (file_header.magic_number == cagim) {
            f->byteswap = 1;
            // printf("file is in pcap format\nbyteswap is needed\n");
        } else {
            fprintf(stderr, "error: file %s not in pcap format (file header: %08x)\n",
                    fname, file_header.magic_number);
            if (file_header.magic_number == 0x0a0d0d0a) {
                fprintf(stderr, "error: pcap-ng format found; this format is currently unsupported\n");
            }
            exit(255);
        }
        if (f->byteswap) {
            file_header.version_major = htons(file_header.version_major);
            file_header.version_minor = htons(file_header.version_minor);
            file_header.thiszone = htonl(file_header.thiszone);
            file_header.sigfigs = htonl(file_header.sigfigs);
            file_header.snaplen = htonl(file_header.snaplen);
            file_header.network = htons(file_header.network);
        }
    }

    return status_ok;
}

inline bool pcap_packet_hdr_may_be_a_file_header(const struct pcap_packet_hdr *hdr) {
    return hdr->incl_len == 0 && (hdr->ts_sec == magic || hdr->ts_sec == cagim);
}

enum status pcap_file_reinit_file_hdr(struct pcap_file *f,
                                      const struct pcap_file_hdr *file_header) {

    if (f->flags != O_RDONLY) {
        fprintf(stderr, "error: attempt to reinitialize a writeable file (flags=0x%x)\n", f->flags);
        return status_err;
    }

	if (file_header->magic_number == magic) {
	    f->byteswap = 0;
	} else if (file_header->magic_number == cagim) {
	    f->byteswap = 1;
	} else {
	    if (file_header->magic_number == 0x0a0d0d0a) {
            fprintf(stderr, "error: pcap-ng format found; this format is currently unsupported\n");
            exit(255); // hard stop; we have data we can't process
	    } else {
            fprintf(stderr, "warning: file not in pcap format in %s (file header: %08x)\n",
                    __func__, file_header->magic_number);
        }
	}

    return status_ok;
}

enum status pcap_file_reinit(struct pcap_file *f,
                             struct pcap_pkthdr *pkthdr /* input and output */
                             ) {

    struct pcap_file_hdr file_hdr;
    memcpy(&file_hdr, pkthdr, sizeof(pcap_packet_hdr));
    uint8_t *tmp = (uint8_t *)&file_hdr;
    tmp += sizeof(pcap_packet_hdr);
    ssize_t items_read = fread(tmp, 1, sizeof(pcap_file_hdr) - sizeof(pcap_packet_hdr), f->file_ptr);
    if (items_read != sizeof(pcap_file_hdr) - sizeof(pcap_packet_hdr)) {
        fprintf(stderr, "error: could not read remainder of file header (only got %zu bytes, needed %zu)\n", items_read, sizeof(pcap_file_hdr) - sizeof(pcap_packet_hdr));
        return status_err;  /* could not read remainder of file header         */
    }
    if (pcap_file_reinit_file_hdr(f, &file_hdr) != status_ok) {
        fprintf(stderr, "error: could not reinitialze; not a valid file header\n");
        return status_err;  /* could not reinitialize; not a vaild file header */
    }

    /* read first packet header, and write its values as output */
    struct pcap_packet_hdr packet_hdr;
    items_read = fread(&packet_hdr, sizeof(packet_hdr), 1, f->file_ptr);
    if (items_read == 0) {
        return status_err_no_more_data; /* could not read packet header from file */
    }
    if (f->byteswap) {
        pkthdr->ts.tv_sec = ntohl(packet_hdr.ts_sec);
        pkthdr->ts.tv_usec = ntohl(packet_hdr.ts_usec);
        pkthdr->caplen = ntohl(packet_hdr.incl_len);
    } else {
        pkthdr->ts.tv_sec = packet_hdr.ts_sec;
        pkthdr->ts.tv_usec = packet_hdr.ts_usec;
        pkthdr->caplen = packet_hdr.incl_len;
    }
    return status_ok;
}

enum status pcap_file_write_packet_direct(struct pcap_file *f,
                      const void *packet,
                      size_t length,
                      unsigned int sec,
                      unsigned int usec) {
    size_t items_written;
    struct pcap_packet_hdr packet_hdr;

    if (packet && !length) {
	printf("warning: attempt to write an empty packet\n");
	return status_ok;
    }

    /* note: we never perform byteswap when writing */
    packet_hdr.ts_sec = sec;
    packet_hdr.ts_usec = usec;
    packet_hdr.incl_len = length;
    packet_hdr.orig_len = length;

    // write the packet header
    items_written = fwrite(&packet_hdr, sizeof(struct pcap_packet_hdr), 1, f->file_ptr);
    if (items_written == 0) {
        perror("error: could not write packet header to output file\n");
        return status_err;
    }

    // write the packet
    items_written = fwrite(packet, length, 1, f->file_ptr);
    if (items_written == 0) {
        perror("error: could not write packet data to output file\n");
        return status_err;
    }

    f->bytes_written += length + sizeof(struct pcap_packet_hdr);
    f->packets_written++;

#ifdef FALLOC_FL_KEEP_SIZE
    if ((f->allocated_size > 0) && (f->allocated_size - f->bytes_written) <= ONE_MB) {
        // need to allocate more
        if (fallocate(f->fd, FALLOC_FL_KEEP_SIZE, f->bytes_written, PRE_ALLOCATE_DISK_SPACE) != 0) {
            perror("warning: could not increase write file allocation by 100 MB");
        } else {
            f->allocated_size = f->bytes_written + PRE_ALLOCATE_DISK_SPACE;  // increase allocation
        }
    }
#endif

    return status_ok;
}


enum status advance(FILE *f, size_t length) {
    if (f == stdin) {
        for (size_t i=0; i < length; i++) {
            uint8_t tmp = getc(f);
            (void)tmp;
        }
    } else {
        if (fseek(f, length, SEEK_CUR) != 0) {
            perror("error: could not advance file pointer\n");
            return status_err;
        }
    }
    return status_ok;
}

#define BUFLEN  65536

enum status pcap_file_read_packet(struct pcap_file *f,
                                  struct pcap_pkthdr *pkthdr, /* output */
                                  void *packet_data           /* output */
                                  ) {
    ssize_t items_read;
    struct pcap_packet_hdr packet_hdr;

    if (f->file_ptr == NULL) {
        printf("File not open\n");
        return status_err;
    }

    items_read = fread(&packet_hdr, sizeof(packet_hdr), 1, f->file_ptr);
    if (items_read == 0) {
        return status_err_no_more_data; /* could not read packet header from file */
    }

    if (f->byteswap) {
        pkthdr->ts.tv_sec = ntohl(packet_hdr.ts_sec);
        pkthdr->ts.tv_usec = ntohl(packet_hdr.ts_usec);
        pkthdr->caplen = ntohl(packet_hdr.incl_len);
    } else {
        pkthdr->ts.tv_sec = packet_hdr.ts_sec;
        pkthdr->ts.tv_usec = packet_hdr.ts_usec;
        pkthdr->caplen = packet_hdr.incl_len;
    }

    if (f->file_ptr == stdin && pcap_packet_hdr_may_be_a_file_header(&packet_hdr)) {

        /*
         * we are reading from standard input, and the packet header
         * seems to be the header of a new file, so we will attempt to
         * reinitialize the pcap_file using that file header
         */
        if (pcap_file_reinit(f, pkthdr) != status_ok) {
            return status_err;
        }
    }
    if (pkthdr->caplen <= BUFLEN) {
        items_read = fread(packet_data, pkthdr->caplen, 1, f->file_ptr);
        if (items_read == 0) {
            fprintf(stderr, "error: could not read packet with caplen %u\n", pkthdr->caplen);
            return status_err;          /* could not read packet from file */
        }
    } else {
        fprintf(stderr, "warning: buffer size %u cannot store packet of length %u\n", BUFLEN, pkthdr->caplen);
        /*
         * The packet length is much bigger than BUFLEN.
         * Read BUFLEN bytes to process the packet and skip the remaining bytes.
         */
        if (fread(packet_data, BUFLEN, 1, f->file_ptr) == 0) {
            fprintf(stderr, "error: could not read %d bytes of the packet from file\n", (int)BUFLEN);
            return status_err;          /* could not read packet from file */
        }

        // advance the file pointer to skip the large packet
        advance(f->file_ptr, pkthdr->caplen - BUFLEN);

        // adjust the packet len and caplen
        pkthdr->len = pkthdr->caplen;
        pkthdr->caplen = BUFLEN;
        return status_ok;
    }

    return status_ok;
}


void packet_info_init_from_pkthdr(struct packet_info *pi,
				  struct pcap_pkthdr *pkthdr) {
    pi->len = pkthdr->caplen;
    pi->caplen = pkthdr->caplen;
    pi->ts.tv_sec = pkthdr->ts.tv_sec;
    pi->ts.tv_nsec = pkthdr->ts.tv_usec * 1000;
}

enum status pcap_file_dispatch_pkt_processor(struct pcap_file *f,
                                             struct pkt_proc *pkt_processor,
                                             int loop_count) {
    enum status status = status_ok;
    struct pcap_pkthdr pkthdr;
    uint8_t packet_data[BUFLEN];
    unsigned long total_length = sizeof(struct pcap_file_hdr); // file header is already written
    unsigned long num_packets = 0;
    struct packet_info pi;

    for (int i=0; i < loop_count && sig_close_flag == 0; i++) {
        do {
            status = pcap_file_read_packet(f, &pkthdr, packet_data);
            if (status == status_ok) {
                packet_info_init_from_pkthdr(&pi, &pkthdr);
                // process the packet that was read
                pkt_processor->apply(&pi, packet_data);
                num_packets++;
                total_length += pkthdr.caplen + sizeof(struct pcap_packet_hdr);
            }
        } while (status == status_ok && sig_close_flag == 0);

        if (i < loop_count - 1) {
            // Rewind the file to the first packet after skipping file header.
            if (fseek(f->file_ptr, sizeof(struct pcap_file_hdr), SEEK_SET) != 0) {
                perror("error: could not rewind file pointer\n");
                status = status_err;
            }
        }
    }

    pkt_processor->finalize();  // clear out buffers

    pkt_processor->bytes_written = total_length;
    pkt_processor->packets_written = num_packets;

    if (status == status_err_no_more_data) {
        return status_ok;
    }
    return status;
}

enum status pcap_file_close(struct pcap_file *f) {
    if (f->file_ptr != stdin && fclose(f->file_ptr) != 0) {
        perror("could not close input pcap file");
        return status_err;
    }
    if (f->buffer) {
        free(f->buffer);
    }
    return status_ok;
}



/*
 * start of serialized output code - first cut
 */

void pcap_queue_write(struct ll_queue *llq,
                      uint8_t *packet,
                      size_t length,
                      unsigned int sec,
                      unsigned int nsec,
                      bool blocking) {

    if (blocking) {
        while (llq->msgs[llq->widx].used != 0) {
            usleep(50); // sleep for fifty microseconds
        }
    }

    if (llq->msgs[llq->widx].used == 0) {

        //char obuf[LLQ_MSG_SIZE];
        int olen = LLQ_MSG_SIZE;
        int ooff = 0;
        int trunc = 0;

        llq->msgs[llq->widx].ts.tv_sec = sec;
        llq->msgs[llq->widx].ts.tv_nsec = nsec;

        //obuf[sizeof(struct timespec)] = '\0';
        llq->msgs[llq->widx].buf[0] = '\0';

        if (packet && !length) {
            fprintf(stderr, "warning: attempt to write an empty packet\n");
        }

        /* note: we never perform byteswap when writing */
        struct pcap_packet_hdr packet_hdr;
        packet_hdr.ts_sec = sec;
        packet_hdr.ts_usec = nsec;
        packet_hdr.incl_len = length;
        packet_hdr.orig_len = length;

        // write the packet header
        int r = append_memcpy(llq->msgs[llq->widx].buf, &ooff, olen, &trunc, &packet_hdr, sizeof(packet_hdr));

        // write the packet
        r += append_memcpy(llq->msgs[llq->widx].buf, &ooff, olen, &trunc, packet, length);

        // f->bytes_written += length + sizeof(struct pcap_packet_hdr);
        // f->packets_written++;

        if ((trunc == 0) && (r > 0)) {

            llq->msgs[llq->widx].len = r;

            //fprintf(stderr, "DEBUG: sent a message!\n");
            __sync_synchronize(); /* A full memory barrier prevents the following flag set from happening too soon */
            llq->msgs[llq->widx].used = 1;

            //llq->next_write();
            llq->widx = (llq->widx + 1) % LLQ_DEPTH;
        }
    }
    else {
        //fprintf(stderr, "DEBUG: queue bucket used!\n");

        // TODO: this is where we'd update an output drop counter
        // but currently this spot in the code doesn't have access to
        // any thread stats pointer or similar and I don't want
        // to update a global variable in this location.
    }

}

