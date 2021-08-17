// intercept.cc
//
// plaintext intercept shared object library
//
// compile as
//
//     make intercept.so
//
// then
//
//     export LD_PRELOAD="/usr/local/lib/intercept.so"
//
// in the shell where you want to perform TLS interception, replacing
// the path with one appropriate for your system.  This will cause TLS
// interception for all processes invoked in an environment with this
// variable set.  Data is written to the directory
// /usr/local/var/intercept, and to stderr.  You can use the variables
// INTERCEPT_VERBOSE and INTERCEPT_MAX_PT_LEN to set the verbosity (to
// 0 or 1) and maximum plaintext length that is captured for each
// intercepted read/write call (to a positive integer).

// Implementation Notes
//
// This shared object library implements function interception on
// Linux, which is sometimes called 'the LD_PRELOAD trick'.  The trick
// is to create a shared object library that contains a function with
// the exact same signature as the one that you want to intercept, and
// then cause the library to be loaded into the dynamic linker search
// path before the library containing that function.  A common use
// case for function interception is to avoid changing the behavior of
// the intercepted function, but to create side effects such as
// writing log entries based on the arguments passed to the
// intercepted function.  To make that easy, this library uses dlsym()
// to look up the original function, then invokes that function and
// passes its return value to the caller of the intercepted function.
// This implementation is hidden behind C macros, which hide much of
// the 'boilerplate' complexity of interception.
//
// To intercept a function int foo(char *bar) in the library
// libfoobar.so, it is necessary to add a function with the exact same
// signature in the intercept library, and add -lfoobar in the list of
// libraries to which the intercept library is linked.
//
// Linux uses the ELF standard for executable and library formats, and
// thus each process that links with a shared object gets its own copy
// of the global and static variables in the intercept library.  The
// library uses static variables to memoize the results of function
// calls like getpid(), to avoid performance degradation of needless
// repeated invocations of those functions.
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
// A good reference on Linux shared object libraries is
// https://tldp.org/HOWTO/Program-Library-HOWTO/shared-libraries.html

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

// check to see if stderr is a TTY; this enables us to suppress
// colorized output if needed
//
int tty = isatty(fileno(stderr));

// Macros to colorize output
//
#define RED_ON    "\033[31m"
#define GREEN_ON  "\033[32m"
#define YELLOW_ON "\033[33m"
#define COLOR_OFF "\033[39m"

#define GREEN(S)  tty ? (GREEN_ON  S COLOR_OFF) : S
#define YELLOW(S) tty ? (YELLOW_ON S COLOR_OFF) : S
#define RED(S)    tty ? (RED_ON    S COLOR_OFF) : S

// read environment variables that configure intercept.so, and apply
// configuration as needed
//
const char *MAX_PT_LEN = getenv("INTERCEPT_MAX_PT_LEN");

ssize_t max_pt_len = MAX_PT_LEN ? atol(MAX_PT_LEN) : 0;

const char *INTERCEPT_DIR = "/usr/local/var/intercept/";

const char *VERBOSE = getenv("INTERCEPT_VERBOSE");

long int verbose = VERBOSE ? atol(VERBOSE) : 0;

// Support functions for obtaining additional context from the
// application or OS, and writing data output
//
void print_cmd(int pid) {
    char filename[FILENAME_MAX];
    int retval = snprintf(filename, sizeof(filename), "/proc/%d/cmdline", pid);
    if (retval < 0) {
        fprintf(stderr, RED("error: could not write filename for PID=%d\n"), pid);
    }
    if (retval >= (int)sizeof(filename)) {
        fprintf(stderr, YELLOW("warning: filename \"%s\" was truncated\n"), filename);
    }

    static int have_cmd = 0;
    if (have_cmd == 0) {
        fprintf(stderr, GREEN("%s="), filename);

        // read command associated with process from /proc filesystem
        //
        FILE *cmd_file = fopen(filename, "r");
        char cmd[256];
        if (cmd_file) {
            fread(cmd, 1, sizeof(cmd), cmd_file);  // TBD: should verify that cmd is nonzero
            fprintf(stderr, GREEN("%s\n"), cmd);
            have_cmd = 1;
            fclose(cmd_file);
        }
     }
}

#include <sys/stat.h>

bool fd_is_socket(int fd) {
    struct stat statbuf;
    if (fstat(fd, &statbuf) == 0) {
        return S_ISSOCK(statbuf.st_mode);
    }
    return false;
}

void print_flow_key(int fd) {

    if (!fd_is_socket(fd)) {
        return;
    }

    // TBD: should have an array of flow_keys/booleans, one for each
    // file descriptor, so that we correctly handle processes with
    // multiple sockets
    //
    static bool have_flow_key = false;
    if (have_flow_key == true) {
        return;
    }

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
        have_flow_key = true;
        return;
    }
    fprintf(stderr, GREEN("fd %d is not a socket (%s)\n"), fd, strerror(errno));
}

void write_data_to_file(int pid, const void *buffer, ssize_t bytes, int fd=0) {

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
    strncpy(filename, INTERCEPT_DIR, sizeof(filename));
    size_t offset = strlen(filename);
    int retval;
    if (fd) {
        retval = snprintf(filename + offset, sizeof(filename) - offset, "plaintext-%d-%d", pid, fd);
    } else {
        retval = snprintf(filename + offset, sizeof(filename) - offset, "plaintext-%d", pid);
    }
    if (retval >= (int)(sizeof(filename) - offset)) {
        fprintf(stderr, GREEN("warning: filename \"%s\" was truncated\n"), filename);
    }
    FILE *plaintext_file = fopen(filename, "a+");
    if (plaintext_file) {
        fwrite(buffer, 1, bytes, plaintext_file);
        fclose(plaintext_file);
        if (verbose) { fprintf(stderr, GREEN("wrote data to file %s\n"), filename); }
    } else {
        fprintf(stderr, RED("error: could not write data to file %s\n"), filename);
    }
}

void fprintf_raw_as_hex(FILE *f, const uint8_t *data, unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

    while (x < end) {
        fprintf(f, "%02x", *x++);
    }
}

// libmerc
//

//#include "libmerc/libmerc.h"
#include "libmerc/tls.h"

// high level functions for processing network traffic
//

void process_outbound(const uint8_t *data, size_t length) {
    if (length > 2 && data[0] == 0x16 && data[1] == 0x03) {
        fprintf(stderr, GREEN("tls_handshake: "));
        //  fprintf_raw_as_hex(stderr, data, length);
        fputc('\n', stderr);

        struct datum tcp_data{data, data+length};

        struct tls_record rec;
        rec.parse(tcp_data);
        struct tls_handshake handshake;
        handshake.parse(rec.fragment);
        if (handshake.additional_bytes_needed) {
            fprintf(stderr, YELLOW("note: tls_handshake needs additional data\n"));
        }
        tls_client_hello hello;
        hello.parse(handshake.body);

        if (hello.is_not_empty()) {
            struct fingerprint fp;
            hello.compute_fingerprint(fp);

            char buffer[8*1024];
            struct buffer_stream buf(buffer, sizeof(buffer));
            struct json_object record{&buf};
            fp.write(record);
            hello.write_json(record, true);
            record.close();
            buf.write(stderr);
            fputc('\n', stderr);
        }

    }
}


// init/fini functions
//

void __attribute__ ((constructor)) intercept_init(void) {
    if (verbose) { fprintf(stderr, GREEN("%s\n"), __func__); }
}

void __attribute__ ((destructor)) intercept_fini(void) {
    if (verbose) { fprintf(stderr, GREEN("%s\n"), __func__); }
}


// the get_original() macro declares a function pointer, sets it to
// the original function being intercepted, and verifies that it is
// non-null
//
#define get_original(SSL_read)                                                                \
static decltype(SSL_read) *original_ ## SSL_read = nullptr;                                   \
if (original_ ## SSL_read == nullptr) {                                                       \
    original_ ## SSL_read = (decltype(original_ ## SSL_read)) dlsym(RTLD_NEXT, #SSL_read);    \
}                                                                                             \
if (original_ ## SSL_read == nullptr) {                                                       \
   fprintf(stderr, RED("error: could not load symbol ") #SSL_read "\n");                      \
   exit(EXIT_FAILURE);                                                                        \
}                                                                                             \
if (verbose) { fprintf(stderr, GREEN("intercepted %s\n") , __func__); }

// intercepts
//

int SSL_write(SSL *context, const void *buffer, int bytes) {
    get_original(SSL_write);

    int pid = getpid();
    print_cmd(pid);
    int fd = SSL_get_fd(context);
    print_flow_key(fd);
    write_data_to_file(pid, buffer, bytes, fd);

    return original_SSL_write(context, buffer, bytes);
}

int SSL_read(SSL *context, void *buffer, int bytes) {
    get_original(SSL_read);

    int pid = getpid();
    print_cmd(pid);
    int fd = SSL_get_fd(context);
    print_flow_key(fd);
    write_data_to_file(pid, buffer, bytes, fd);

    return original_SSL_read(context, buffer, bytes);
}

#include "nspr/prio.h"
#include "nspr/private/pprio.h"

PRInt32 PR_Write(PRFileDesc *fd, const void *buf, PRInt32 amount) {
    get_original(PR_Write);

    int pid = getpid();
    int native_fd = PR_FileDesc2NativeHandle(fd);
    if (fd_is_socket(native_fd)) {
        print_flow_key(native_fd);
        print_cmd(pid);
        write_data_to_file(pid, buf, amount, native_fd);
    }

    return original_PR_Write(fd, buf, amount);
}


// GNUTLS support
//

#include <gnutls/gnutls.h>

ssize_t gnutls_record_send(gnutls_session_t session,
                           const void * data,
                           size_t data_size) {

    get_original(gnutls_record_send);

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

// networking functions interception
//

#include <sys/types.h>
#include <sys/socket.h>

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    get_original(send);
    fprintf(stderr, GREEN("send()ing %zu bytes\n"), len);
    process_outbound((uint8_t *)buf, len);
    return original_send(sockfd, buf, len, flags);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    get_original(sendmsg);
    if (verbose) { fprintf(stderr, YELLOW("sendmsg() invoked\n")); }
    return original_sendmsg(sockfd, msg, flags);
}

#include <unistd.h>

ssize_t write(int fd, const void *buf, size_t count) {
    get_original(write);

    if (fd_is_socket(fd)) {
        process_outbound((uint8_t *)buf, count);
    }

    return original_write(fd, buf, count);
}
