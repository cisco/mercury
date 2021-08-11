// intercept.cc
//
// plaintext intercept shared object library
//
// compile as g++ intercept.cc -o intercept.so -fPIC -shared -lssl -lnss -D_GNU_SOURCE -fpermissive
// then export LD_PRELOAD="/home/mcgrew/mercury-transition/src/intercept.so"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>


#define COLOR_ON  "\033[32m"
#define COLOR_OFF "\033[39m"

#define GREEN(S) COLOR_ON S COLOR_OFF

void print_cmd(int pid) {
    char filename[FILENAME_MAX];
    int retval = snprintf(filename, sizeof(filename), "/proc/%d/cmdline", pid);
    if (retval >= sizeof(filename)) {
        fprintf(stderr, GREEN("warning: filename \"%s\" was truncated\n"), filename);
    }
    fprintf(stderr, GREEN("%s="), filename);
    // read network socket information from /proc filesystem
    //
    FILE *cmd_file = fopen(filename, "r");
    char *line = nullptr;
    size_t n = 0;
    ssize_t nread;
    char cmd[256];
    if (cmd_file) {
        nread = fread(cmd, 1, sizeof(cmd), cmd_file);
        fprintf(stderr, GREEN("%s\n"), cmd);
        fclose(cmd_file);
    }
}

void print_flow_key(const SSL *context) {

    // read network socket info from fd
    //
    int fd = SSL_get_fd(context);
    struct sockaddr_in address;
    bzero(&address, sizeof(address));
    socklen_t address_len = sizeof(address);
    getsockname(fd, (struct sockaddr *) &address, &address_len);
    char addr[17];
    inet_ntop(AF_INET, &address.sin_addr, addr, sizeof(addr));
    uint16_t port = ntohs(address.sin_port);
    fprintf(stderr, GREEN("%s:%u"), addr, port);
    getpeername(fd, (struct sockaddr *) &address, &address_len);
    inet_ntop(AF_INET, &address.sin_addr, addr, sizeof(addr));
    port = ntohs(address.sin_port);
    fprintf(stderr, GREEN(" -> %s:%u\n"), addr, port);
}

void write_data_to_file(int pid, const void *buffer, ssize_t bytes, bool filter=false) {

    if (filter && bytes < 3 || memcmp(buffer, "GET", 3) != 0) {
        return;
    }
    char filename[FILENAME_MAX];
    int retval = snprintf(filename, sizeof(filename), "plaintext-%d", pid);
    if (retval >= sizeof(filename)) {
        fprintf(stderr, GREEN("warning: filename \"%s\" was truncated\n"), filename);
    }
    FILE *plaintext_file = fopen(filename, "a+");
    if (plaintext_file) {
        fwrite(buffer, 1, bytes, plaintext_file);
        fclose(plaintext_file);
        fprintf(stderr, GREEN("wrote data to file %s\n"), filename);
    } else {
        fprintf(stderr, GREEN("error: could not write data to file %s\n"), filename);
    }
}

int SSL_write(SSL *context, const void *buffer, int bytes) {
    int (*original_SSL_write)(SSL *context, const void *buffer, int bytes);
    original_SSL_write = dlsym(RTLD_NEXT, "SSL_write");

    fprintf(stderr, GREEN("intercepted %s\n") , __func__);
    int pid = getpid();
    print_cmd(pid);
    print_flow_key(context);
    write_data_to_file(pid, buffer, bytes);

    return original_SSL_write(context, buffer, bytes);
}

int SSL_read(SSL *context, const void *buffer, int bytes) {
    int (*original_SSL_read)(SSL *context, const void *buffer, int bytes);
    original_SSL_read = dlsym(RTLD_NEXT, "SSL_read");

    fprintf(stderr, GREEN("intercepted %s\n"), __func__);
    int pid = getpid();
    print_cmd(pid);
    print_flow_key(context);
    write_data_to_file(pid, buffer, bytes);

    return original_SSL_read(context, buffer, bytes);
}

#include "nspr/prio.h"

PRInt32 PR_Write(PRFileDesc *fd, const void *buf, PRInt32 amount) {

    PRInt32 (*original_PR_Write)(PRFileDesc *fd, const void *buf, PRInt32 amount);
    original_PR_Write = dlsym(RTLD_NEXT, "PR_Write");
    if (original_PR_Write == nullptr) {
        fprintf(stderr, "note: could not load symbol PR_Write()\n");
        return 0;
    }

    fprintf(stderr, GREEN("note: intercepted %s\n"), __func__);
    int pid = getpid();
    print_cmd(pid);
    // TBD: how to print flow key???
    write_data_to_file(pid, buf, amount, true);

    return original_PR_Write(fd, buf, amount);
}

//
// ATTIC
//

#if 0
#include <openssl/bio.h>
int BIO_write(BIO *b, const void *data, int dlen) {
    fprintf(stderr, "intercept invoked\n");
    return BIO_write(BIO *b, const void *data, int dlen);
}
#endif

#if 0
    // read network socket information from /proc filesystem
    //
    FILE *tcp_file = fopen(filename, "r");
    char *line = nullptr;
    size_t n = 0;
    ssize_t nread;
    while ((nread = getline(&line, &n, tcp_file)) != -1) {
        // printf("Retrieved line of length %zu:\n", nread);
        fwrite(line, nread, 1, stderr);
        uint32_t src_addr = 0, dst_addr = 0;
        unsigned int src_port = 0, dst_port = 0;
        unsigned int ignore = 0;
        sscanf(line, "%u: %08x:%04x %08x:%04x", &ignore, &src_addr, &src_port, &dst_addr, &dst_port);
        if (dst_addr && dst_port) {
            fprintf(stderr, "pid: %u\t", pid);
            unsigned char *src_a = (unsigned char *)&src_addr;
            unsigned char *dst_a = (unsigned char *)&dst_addr;
            fprintf(stderr, "[%u.%u.%u.%u]:%u", src_a[0], src_a[1], src_a[2], src_a[3], src_port);
            fprintf(stderr, " -> ");
            fprintf(stderr, "[%u.%u.%u.%u]:%u\n", dst_a[0], dst_a[1], dst_a[2], dst_a[3], dst_port);
        }
    }
    fclose(tcp_file);
#endif
