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
#include <sys/file.h>
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
#define RED_ON     "\033[31m"
#define GREEN_ON   "\033[32m"
#define YELLOW_ON  "\033[33m"
#define BLUE_ON    "\033[34m"
#define MAGENTA_ON "\033[35m"
#define CYAN_ON    "\033[36m"
#define COLOR_OFF  "\033[39m"

#define RED(S)     tty ? (RED_ON     S COLOR_OFF) : S
#define GREEN(S)   tty ? (GREEN_ON   S COLOR_OFF) : S
#define YELLOW(S)  tty ? (YELLOW_ON  S COLOR_OFF) : S
#define BLUE(S)    tty ? (BLUE_ON    S COLOR_OFF) : S
#define MAGENTA(S) tty ? (MAGENTA_ON S COLOR_OFF) : S
#define CYAN(S)    tty ? (CYAN_ON    S COLOR_OFF) : S

// read environment variables that configure intercept.so, and apply
// configuration as needed
//
const char *MAX_PT_LEN = getenv("INTERCEPT_MAX_PT_LEN");

ssize_t max_pt_len = MAX_PT_LEN ? atol(MAX_PT_LEN) : 0;

#define DEFAULT_INTERCEPT_DIR "/usr/local/var/intercept/"

const char *ENV_INTERCEPT_DIR = getenv("INTERCEPT_DIR");

const char *INTERCEPT_DIR = ENV_INTERCEPT_DIR ? ENV_INTERCEPT_DIR : DEFAULT_INTERCEPT_DIR;

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

void get_cmd(int pid, char cmd[256], size_t cmd_len) {
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
        // read command associated with process from /proc filesystem
        //
        FILE *cmd_file = fopen(filename, "r");
        if (cmd_file) {
            fread(cmd, 1, cmd_len, cmd_file);  // TBD: should verify that cmd is nonzero
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

    // sanity check
    //
    if (bytes < 0 || bytes > 0x8000000) {
        fprintf(stderr, "note: unexpected length (%zd)\n", bytes);
    }

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
#include "libmerc/http.h"
#include "libmerc/json_object.h"
#include <ctype.h>

#include <unordered_set>
#include <string>

struct http_request_x : public http_request {

    bool method_is_valid() {

        //fprintf(stderr, "method: %.*s\n", (int)method.length(), method.data);

        std::string method_from_packet = method.get_string();
        std::unordered_set<std::string> standard_methods = {  // from https://www.iana.org/assignments/http-methods/http-methods.xhtml
            "ACL",
            "BASELINE-CONTROL",
            "BIND",
            "CHECKIN",
            "CHECKOUT",
            "CONNECT",
            "COPY",
            "DELETE",
            "GET",
            "HEAD",
            "LABEL",
            "LINK",
            "LOCK",
            "MERGE",
            "MKACTIVITY",
            "MKCALENDAR",
            "MKCOL",
            "MKREDIRECTREF",
            "MKWORKSPACE",
            "MOVE",
            "OPTIONS",
            "ORDERPATCH",
            "PATCH",
            "POST",
            "PRI",
            "PROPFIND",
            "PROPPATCH",
            "PUT",
            "REBIND",
            "REPORT",
            "SEARCH",
            "TRACE",
            "UNBIND",
            "UNCHECKOUT",
            "UNLINK",
            "UNLOCK",
            "UPDATE",
            "UPDATEREDIRECTREF",
            "VERSION-CONTROL"
        };
        return (standard_methods.find(method_from_packet) != standard_methods.end());
    }
};

// class intercept controls the behavior of this program; you can
// define totally new behavior by defining a class that inherits from
// this one
//

#include <syslog.h>

class intercept {
    int pid, ppid;
    FILE *outfile = nullptr;
    static constexpr size_t buffer_length = 8*1024;

public:

    intercept() : pid{getpid()}, ppid{getppid()} {
        if (verbose) { fprintf(stderr, GREEN("%s\n"), __func__); }

        outfile = fopen("intercept.json", "a+");
        // fprintf(stderr, BLUE("%s\n"), __func__);
        // openlog ("intercept", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
        // syslog(LOG_INFO, "pid: %d", pid);
        // print_cmd(pid);
        char cmd[256];
        char pcmd[256];
        get_cmd(pid, cmd, sizeof(cmd));
        get_cmd(ppid, pcmd, sizeof(pcmd));
        // fprintf(stderr, "ppid: %d\n", getppid());

        // write out process data:
        //
        //    pid: process ID
        //    cmd: command line
        //    ppid: parent process ID
        //    pcmd: parent command line
        //
        char buffer[buffer_length];
        struct buffer_stream buf(buffer, sizeof(buffer));
        struct json_object record{&buf};
        record.print_key_uint16("pid", pid);
        record.print_key_string("cmd", cmd);
        record.print_key_uint16("ppid", ppid);
        record.print_key_string("pcmd", pcmd);
        record.close();
        write_buffer_to_file(buf, outfile);

    }

    ~intercept() { closelog(); }

    void process_outbound(int fd, const uint8_t *data, ssize_t length);

    void process_outbound_plaintext(int fd, const uint8_t *data, ssize_t length) {
        // fprintf(stderr, BLUE("%s\n"), __func__);

        //print_flow_key(fd);
        // write_data_to_file(pid, data, length, fd);
        //  process_http_request(data, length);

        struct datum tcp_data{data, data+length};
        struct http_request_x http_req;
        http_req.parse(tcp_data);
        if (http_req.is_not_empty() && http_req.method_is_valid() && isupper(data[0])) {  // TODO: improve is_not_empty() with method check

            char buffer[buffer_length];
            struct buffer_stream buf(buffer, sizeof(buffer));
            struct json_object record{&buf};

            // write pid into record
            record.print_key_uint16("pid", pid);
            record.print_key_uint("fd", fd);

            http_req.write_json(record, true);

            // write time into record
            struct timespec ts;
            timespec_get(&ts, TIME_UTC);
            record.print_key_timestamp("event_start", &ts);

            record.close();
            write_buffer_to_file(buf, outfile);

        } else {
            if (verbose) { fprintf(stderr, RED("http_request unrecognized\n")); }
        }

    }

    void process_inbound_plaintext(int fd, const uint8_t *data, ssize_t length) {
        // fprintf(stderr, BLUE("%s\n"), __func__);
        //print_flow_key(fd);
        //write_data_to_file(pid, data, length, fd);
    }

    void process_dns_lookup(const char *dns_name, const char *service) {
        // fprintf(stderr, BLUE("%s: %s\t%s\n"), __func__, dns_name, service);

        char buffer[buffer_length];
        struct buffer_stream buf(buffer, sizeof(buffer));
        struct json_object record{&buf};

        // write pid into record
        record.print_key_uint16("pid", pid);

        // write dns info into record
        json_object dns_object{record, "dns"};
        dns_object.print_key_string("name", dns_name);
        //dns_object.print_key_string("service", service);
        dns_object.close();
        record.close();
        write_buffer_to_file(buf, outfile);

    }

    void write_buffer_to_file(struct buffer_stream &buf, FILE *outfile) {
        // if (tty) { fprintf(stderr, GREEN_ON); }
        int outfile_fd = fileno(outfile);
        if (flock(outfile_fd, LOCK_EX) != 0) {
            fprintf(stderr, "error: could not flock() file (%s)\n", strerror(errno));
        }
        buf.write_line(outfile);
        flock(outfile_fd, LOCK_UN);
        // if (tty) { fprintf(stderr, COLOR_OFF); }
    }

    void process_http_request(const uint8_t *data, ssize_t length);

    void process_tls_client_hello(int fd, const uint8_t *data, ssize_t length);

};


class intercept *intrcptr = new intercept;



// high level functions for processing network traffic
//

#if 0
void intercept::process_http_request(const uint8_t *data, ssize_t length) {
    struct datum tcp_data{data, data+length};
    struct http_request http_req;
    http_req.parse(tcp_data);
    if (http_req.is_not_empty() && isalnum(data[0])) {  // TODO: improve is_not_empty() with method check

        char buffer[buffer_length];
        struct buffer_stream buf(buffer, sizeof(buffer));
        struct json_object record{&buf};
        http_req.write_json(record, true);
        record.close();
        if (tty) { fprintf(stderr, GREEN_ON); }
        write_buffer_to_file(buf, outfile);
        if (tty) { fprintf(stderr, COLOR_OFF); }

    } else {
        if (verbose) { fprintf(stderr, RED("http_request unrecognized\n")); }
    }
}
#endif
void intercept::process_tls_client_hello(int fd, const uint8_t *data, ssize_t length) {

    if (length > 2 && data[0] == 0x16 && data[1] == 0x03) {
        if (verbose) { fprintf(stderr, GREEN("tls_handshake: ")); }
        //  fprintf_raw_as_hex(stderr, data, length); fputc('\n', stderr);

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

            char buffer[buffer_length];
            struct buffer_stream buf(buffer, sizeof(buffer));
            struct json_object record{&buf};

            // write pid into record
            record.print_key_uint16("pid", pid);
            record.print_key_uint("fd", fd);

            // write fingerprint into record
            fp.write(record);
            hello.write_json(record, true);
            record.close();
            write_buffer_to_file(buf, outfile);
        }
    }
}

void intercept::process_outbound(int fd, const uint8_t *data, ssize_t length) {
    process_tls_client_hello(fd, data, length);
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


// the get_original() macro declares a function pointer, sets it to
// the original function being intercepted, and verifies that it is
// non-null
//
#define invoke_original(func, ...)                                                        \
static decltype(func) *original_ ## func = nullptr;                                       \
if (original_ ## func == nullptr) {                                                       \
    original_ ## func = (decltype(original_ ## func)) dlsym(RTLD_NEXT, #func);            \
}                                                                                         \
if (original_ ## func == nullptr) {                                                       \
   fprintf(stderr, RED("error: could not load symbol ") #func "\n");                      \
   exit(EXIT_FAILURE);                                                                    \
}                                                                                         \
if (verbose) { fprintf(stderr, GREEN("intercepted %s\n") , __func__); }                   \
return original_ ## func (__VA_ARGS__)


// intercepts
//

// openssl and libcrypt functions
//

// #define INTERCEPT_EVP_CIPHER
#ifdef INTERCEPT_EVP_CIPHER

// Warning: EVP_Cipher interception is verbose
//
// TBD: determine enc/dec from CTX
//

#include <openssl/evp.h>

int EVP_Cipher(EVP_CIPHER_CTX *c,
               unsigned char *out,
               const unsigned char *in,
               unsigned int inl) {

    get_original(EVP_Cipher);

    fprintf(stderr, GREEN("intercepted %s (encrypting %u bytes)\n"), __func__, inl);

    const unsigned char *d = in;
    const unsigned char *d_end = in + inl;
    while (d < d_end) {
        if (isprint(*d)) {
            fputc(*d, stderr);
        } else {
            fputc('.', stderr);
        }
        d++;
    }

    return original_EVP_Cipher(c, out, in, inl);
}

#endif // INTERCEPT_EVP_CIPHER

int SSL_write(SSL *context, const void *buffer, int bytes) {

    intrcptr->process_outbound_plaintext(SSL_get_fd(context), (uint8_t *)buffer, bytes);
    invoke_original(SSL_write, context, buffer, bytes);
}

int SSL_read(SSL *context, void *buffer, int bytes) {

    intrcptr->process_inbound_plaintext(SSL_get_fd(context), (uint8_t *)buffer, bytes);
    invoke_original(SSL_read, context, buffer, bytes);
}

#include "nspr/prio.h"
#include "nspr/private/pprio.h"

PRInt32 PR_Write(PRFileDesc *fd, const void *buf, PRInt32 amount) {

    int native_fd = PR_FileDesc2NativeHandle(fd);
    if (fd_is_socket(native_fd)) {
        intrcptr->process_outbound_plaintext(native_fd, (uint8_t *)buf, amount);
    }
    invoke_original(PR_Write, fd, buf, amount);
}


// GNUTLS support
//

#include <gnutls/gnutls.h>

ssize_t gnutls_record_send(gnutls_session_t session,
                           const void *data,
                           size_t data_size) {

    get_original(gnutls_record_send);

    //int pid = getpid();
    //print_cmd(pid);
    //    fprintf(stderr, GREEN("%s: %.*s\n"), __func__, (int)data_size, (char *)data);
    // fprintf(stderr, GREEN("fd?: %d\n"), gnutls_transport_get_int(session));
    int r = 0, s = 0;
    gnutls_transport_get_int2(session, &r, &s);
    // fprintf(stderr, GREEN("fd2: %d\t%d\n"), r, s);
    // gnutls_transport_ptr_t tp;
    // tp = gnutls_transport_get_ptr(session);
    // fprintf(stderr, GREEN("tp: %p\n"), tp);

    int fd = (r < 32 && r > 0) ? r : 0;
    intrcptr->process_outbound_plaintext(fd, (uint8_t *)data, (ssize_t) data_size);

    //print_flow_key(r);
    //write_data_to_file(pid, data, data_size);

    return original_gnutls_record_send(session, data, data_size);
}

// the following gnutls functions are not yet supported; if
// intercepted, thier names will show up in the output, but no other
// actions will be performed
//
ssize_t gnutls_record_send2 (gnutls_session_t session, const void * data, size_t data_size, size_t pad, unsigned flags) {
    fprintf(stderr, RED("%s\n"), __func__);
    invoke_original(gnutls_record_send2, session, data, data_size, pad, flags);
}

ssize_t gnutls_record_send_early_data (gnutls_session_t session, const void * data, size_t data_size) {
    fprintf(stderr, RED("%s\n"), __func__);
    invoke_original(gnutls_record_send_early_data, session, data, data_size);
}

ssize_t gnutls_record_send_range (gnutls_session_t session, const void * data, size_t data_size, const gnutls_range_st * range) {
    fprintf(stderr, RED("%s\n"), __func__);
    invoke_original(gnutls_record_send_range, session, data, data_size, range);
}

void gnutls_transport_set_push_function(gnutls_session_t session,  gnutls_push_func push_func) {
    fprintf(stderr, RED("%s\n"), __func__);
    invoke_original(gnutls_transport_set_push_function, session, push_func);
}

// networking functions interception
//

#include <sys/types.h>
#include <sys/socket.h>

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    intrcptr->process_outbound(sockfd, (uint8_t *)buf, len);
    invoke_original(send, sockfd, buf, len, flags);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    if (verbose) { fprintf(stderr, YELLOW("sendmsg() invoked\n")); }  // note: no processing happening yet
    invoke_original(sendmsg, sockfd, msg, flags);
}

#include <unistd.h>

ssize_t write(int fd, const void *buf, size_t count) {

    if (fd_is_socket(fd)) {
        intrcptr->process_outbound(fd, (uint8_t *)buf, count);
    }
    invoke_original(write, fd, buf, count);
}

// dns interception
//

#include <netdb.h>

struct hostent *gethostbyname(const char *name) {

    fprintf(stderr, BLUE("gethostbyname: %s\n"), name);

    invoke_original(gethostbyname, name);
}

int getaddrinfo(const char *node,
                const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res) {

    //    fprintf(stderr, BLUE("%s: %s\t%s\n"), __func__, node, service);
    intrcptr->process_dns_lookup(node, service);

    invoke_original(getaddrinfo, node, service, hints, res);
}

int getnameinfo(const struct sockaddr *addr,
                socklen_t addrlen,
                char *host,
                socklen_t hostlen,
                char *serv,
                socklen_t servlen,
                int flags) {

    intrcptr->process_dns_lookup(host, serv);

    invoke_original(getnameinfo, addr, addrlen, host, hostlen, serv, servlen, flags);
}

// resolv.h
//
// #include <resolv/resolv.h>
//
// struct hostent *_gethtbyaddr (const char *addr, size_t __len, int __af);
