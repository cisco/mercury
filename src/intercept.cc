// intercept.cc
//
// plaintext intercept shared object library
//
// compile as g++ intercept.cc -o intercept.so -fPIC -shared -lssl -lnspr4 -lgnutls -D_GNU_SOURCE -fpermissive -I/usr/include/nspr/
// then export LD_PRELOAD="/home/mcgrew/mercury-transition/src/intercept.so"

// Notes
//
// To intercept a function, the signature of the replacement function
// must exactly match that of the original.  Adding 'const' to a
// pointer will confuse a C++ compiler with an extraneous function
// overload, for example.
//
// Function interception seems to interfere with interrupt handling,
// based on experience.  Hitting Ctl^C during the run of an
// intercepted program sometimes causes problems to be reported by the
// application.  This issue deserves further investiation.
//
//

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

// Macros to colorize output
//
#define COLOR_ON  "\033[32m"
#define COLOR_OFF "\033[39m"

#define GREEN(S) COLOR_ON S COLOR_OFF

// read environment variables that configure intercept.so, and apply
// configuration as needed
//
const char *MAX_PT_LEN = getenv("INTERCEPT_MAX_PT_LEN");

ssize_t max_pt_len = MAX_PT_LEN ? atol(MAX_PT_LEN) : 0;

// Support functions for obtaining additional context from the
// application or OS, and writing data output
//
void print_cmd(int pid) {
    char filename[FILENAME_MAX];
    int retval = snprintf(filename, sizeof(filename), "/proc/%d/cmdline", pid);
    if (retval >= sizeof(filename)) {
        fprintf(stderr, GREEN("warning: filename \"%s\" was truncated\n"), filename);
    }
    fprintf(stderr, GREEN("%s="), filename);

    // read command associated with process from /proc filesystem
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

bool print_flow_key(int fd) {

    // read network socket info from fd
    //
    struct sockaddr_in address;
    bzero(&address, sizeof(address));
    socklen_t address_len = sizeof(address);
    int retval = getsockname(fd, (struct sockaddr *) &address, &address_len);
    if (retval == 0) {
        if (address.sin_family == AF_INET) {
            char addr[17];
            inet_ntop(AF_INET, &address.sin_addr, addr, sizeof(addr));
            uint16_t port = ntohs(address.sin_port);
            fprintf(stderr, GREEN("%s:%u"), addr, port);
            getpeername(fd, (struct sockaddr *) &address, &address_len);
            inet_ntop(AF_INET, &address.sin_addr, addr, sizeof(addr));
            port = ntohs(address.sin_port);
            fprintf(stderr, GREEN(" -> %s:%u\n"), addr, port);
        } else if (address.sin_family == AF_INET6) {
            // TBD: handle IPv6 case here
            fprintf(stderr, GREEN("warning: IPv6 addresses not yet handled\n"));
        }
        return true;
    }
    fprintf(stderr, GREEN("fd %d is not a socket (%s)\n"), fd, strerror(errno));
    return false;  // not a network socket
}

void write_data_to_file(int pid, const void *buffer, ssize_t bytes, bool filter=false) {

    // if max_pt_len set, then restrict output length to (at most) that value
    //
    if (max_pt_len) {
        if (bytes > max_pt_len) {
            bytes = max_pt_len;
        }
    }

    // If we want to filter the data that is written to disk, this is
    // a good place to do so.  This obsolete code is left here just to
    // facilitate experimentation with filtering.
    //
    // if (filter && bytes < 3 || memcmp(buffer, "GET", 3) != 0) {
    //     return;
    // }

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


// init/fini functions
//

void __attribute__ ((constructor)) intercept_init(void) {
    fprintf(stderr, GREEN("%s\n"), __func__);
}

void __attribute__ ((destructor)) intercept_fini(void) {
    fprintf(stderr, GREEN("%s\n"), __func__);
}


// intercepts
//

int SSL_write(SSL *context, const void *buffer, int bytes) {
    decltype(SSL_write) *original_SSL_write = (decltype(original_SSL_write)) dlsym(RTLD_NEXT, "SSL_write");

    fprintf(stderr, GREEN("intercepted %s\n") , __func__);
    int pid = getpid();
    print_cmd(pid);
    print_flow_key(SSL_get_fd(context));
    write_data_to_file(pid, buffer, bytes);

    return original_SSL_write(context, buffer, bytes);
}

int SSL_read(SSL *context, void *buffer, int bytes) {
    decltype(SSL_read) *original_SSL_read = (decltype(original_SSL_read)) dlsym(RTLD_NEXT, "SSL_read");

    fprintf(stderr, GREEN("intercepted %s\n"), __func__);
    int pid = getpid();
    print_cmd(pid);
    print_flow_key(SSL_get_fd(context));
    write_data_to_file(pid, buffer, bytes);

    return original_SSL_read(context, buffer, bytes);
}

#include "nspr/prio.h"
#include "nspr/private/pprio.h"

PRInt32 PR_Write(PRFileDesc *fd, const void *buf, PRInt32 amount) {
    decltype(PR_Write) *original_PR_Write = (decltype(original_PR_Write)) dlsym(RTLD_NEXT, "PR_Write");
    if (original_PR_Write == nullptr) {
        fprintf(stderr, "note: could not load symbol PR_Write()\n");
        return 0;
    }

    fprintf(stderr, GREEN("note: intercepted %s\n"), __func__);
    int pid = getpid();
    int native_fd = PR_FileDesc2NativeHandle(fd);
    if (print_flow_key(native_fd) == true) {
        print_cmd(pid);
        write_data_to_file(pid, buf, amount);
    }

    return original_PR_Write(fd, buf, amount);
}


// GNUTLS support
//

#include <gnutls/gnutls.h>

ssize_t gnutls_record_send(gnutls_session_t session,
                           const void * data,
                           size_t data_size) {

    fprintf(stderr, GREEN("note: intercepted %s\n"), __func__);
    decltype(gnutls_record_send) *original_gnutls_record_send = (decltype(original_gnutls_record_send)) dlsym(RTLD_NEXT, "gnutls_record_send");
    if (original_gnutls_record_send == nullptr) {
        fprintf(stderr, "note: could not load symbol gnutls_record_send()\n");
        exit(EXIT_FAILURE);
        return 0;
    }

    int pid = getpid();
    print_cmd(pid);
    fprintf(stderr, GREEN("fd?: %d\n"), gnutls_transport_get_int(session));
    int r = 0, s = 0;
    gnutls_transport_get_int2(session, &r, &s);
    fprintf(stderr, GREEN("fd2: %d\t%d\n"), r, s);
    print_flow_key(r);
    write_data_to_file(pid, data, data_size);

    return original_gnutls_record_send(session, data, data_size);
}

