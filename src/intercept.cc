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
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <dirent.h>
#include <syslog.h>
#include <semaphore.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>


// Macros to colorize output
//
#define RED_ON     "\033[31m"
#define GREEN_ON   "\033[32m"
#define YELLOW_ON  "\033[33m"
#define BLUE_ON    "\033[34m"
#define MAGENTA_ON "\033[35m"
#define CYAN_ON    "\033[36m"
#define COLOR_OFF  "\033[39m"

#define sRED(S)     (RED_ON     S COLOR_OFF)
#define sGREEN(S)   (GREEN_ON   S COLOR_OFF)
#define sYELLOW(S)  (YELLOW_ON  S COLOR_OFF)
#define sBLUE(S)    (BLUE_ON    S COLOR_OFF)
#define sMAGENTA(S) (MAGENTA_ON S COLOR_OFF)
#define sCYAN(S)    (CYAN_ON    S COLOR_OFF)

#define RED(colorize, S)     colorize ? (sRED(S))     : S
#define GREEN(colorize, S)   colorize ? (sGREEN(S))   : S
#define YELLOW(colorize, S)  colorize ? (sYELLOW(S))  : S
#define BLUE(colorize, S)    colorize ? (sBLUE(S))    : S
#define MAGENTA(colorize, S) colorize ? (sMAGENTA(S)) : S
#define CYAN(colorize, S)    colorize ? (sCYAN(S))    : S

// tty is 1 if stderr is a TTY, and 0 otherwise; it enables us to
// suppress colorized output if needed
//
int tty = 0;

// read environment variables that configure intercept.so, and apply
// configuration as needed
//
const char *MAX_PT_LEN = getenv("intercept_max_pt_len");

ssize_t max_pt_len = MAX_PT_LEN ? atol(MAX_PT_LEN) : 0;

const char *VERBOSE = getenv("intercept_verbose");

long int verbose = VERBOSE ? atol(VERBOSE) : 0;

// Support functions for obtaining additional context from the
// application or OS, and writing data output
//
void print_cmd(int pid) {
    char filename[FILENAME_MAX];
    int retval = snprintf(filename, sizeof(filename), "/proc/%d/cmdline", pid);
    if (retval < 0) {
        fprintf(stderr, RED(tty,  "error: could not write filename for PID=%d\n"), pid);
    }
    if (retval >= (int)sizeof(filename)) {
        fprintf(stderr, YELLOW(tty, "warning: filename \"%s\" was truncated\n"), filename);
    }

    static int have_cmd = 0;
    if (have_cmd == 0) {
        fprintf(stderr, GREEN(tty, "%s="), filename);

        // read command associated with process from /proc filesystem
        //
        FILE *cmd_file = fopen(filename, "r");
        char cmd[256];
        if (cmd_file) {
            fread(cmd, 1, sizeof(cmd), cmd_file);  // TBD: should verify that cmd is nonzero
            fprintf(stderr, GREEN(tty, "%s\n"), cmd);
            have_cmd = 1;
            fclose(cmd_file);
        }
     }
}

size_t get_cmd(int pid, char *cmd, size_t cmd_len) {
    char filename[FILENAME_MAX];
    int retval = snprintf(filename, sizeof(filename), "/proc/%d/cmdline", pid);
    if (retval < 0) {
        fprintf(stderr, RED(tty, "error: could not write filename for PID=%d\n"), pid);
    }
    if (retval >= (int)sizeof(filename)) {
        fprintf(stderr, YELLOW(tty, "warning: filename \"%s\" was truncated\n"), filename);
    }

    // read command associated with process from /proc filesystem
    //
    FILE *cmd_file = fopen(filename, "r");
    size_t bytes_read;
    if (cmd_file) {
        // read command line from /proc filesystem, reserving last byte for null terminator
        //
        bytes_read = fread(cmd, 1, cmd_len-1, cmd_file);
        fclose(cmd_file);
        if (bytes_read > cmd_len) {  // this should never happen
            fprintf(stderr, YELLOW(tty, "warning: intercepter command line truncated\n"));
            cmd[0] = '\0';
        }

        // cmd will be formatted as one or more consecutive
        // null-terminated strings; we need to convert it into a
        // single null-terminated string with spaces between the
        // printable words
        //
        cmd[cmd_len-1] = '\0'; // null terminate buffer, to defend against truncation
        size_t last_null=0;
        for (size_t i=0; i < bytes_read; i++) {
            if (cmd[i] == '\0') {
                cmd[i] = ' ';
                last_null = i;
            }
        }
        cmd[last_null] = '\0';  // avoid trailing space
    }
    return bytes_read - 1;
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
            fprintf(stderr, GREEN(tty, "%s:%u"), addr, port);
            getpeername(fd, (struct sockaddr *) &address, &address_len);
            inet_ntop(AF_INET, &address.sin_addr, addr, sizeof(addr));
            port = ntohs(address.sin_port);
            fprintf(stderr, GREEN(tty, " -> %s:%u\n"), addr, port);
        } else if (address.sin_family == AF_INET6) {
            // TBD: handle IPv6 case here
            fprintf(stderr, GREEN(tty, "warning: IPv6 addresses not yet handled\n"));
        }
        have_flow_key = true;
        return;
    }
    fprintf(stderr, GREEN(tty, "fd %d is not a socket (%s)\n"), fd, strerror(errno));
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


// http parsing
//

// HPACK - HTTP2 Header [De]Compression
//

/* From RFC 7541

          | 1     | :authority                  |               |
          | 2     | :method                     | GET           |
          | 3     | :method                     | POST          |
          | 4     | :path                       | /             |
          | 5     | :path                       | /index.html   |
          | 6     | :scheme                     | http          |
          | 7     | :scheme                     | https         |
          | 8     | :status                     | 200           |
          | 9     | :status                     | 204           |
          | 10    | :status                     | 206           |
          | 11    | :status                     | 304           |
          | 12    | :status                     | 400           |
          | 13    | :status                     | 404           |
          | 14    | :status                     | 500           |
          | 15    | accept-charset              |               |
          | 16    | accept-encoding             | gzip, deflate |
          | 17    | accept-language             |               |
          | 18    | accept-ranges               |               |
          | 19    | accept                      |               |
          | 20    | access-control-allow-origin |               |
          | 21    | age                         |               |
          | 22    | allow                       |               |
          | 23    | authorization               |               |
          | 24    | cache-control               |               |
          | 25    | content-disposition         |               |
          | 26    | content-encoding            |               |
          | 27    | content-language            |               |
          | 28    | content-length              |               |
          | 29    | content-location            |               |
          | 30    | content-range               |               |
          | 31    | content-type                |               |
          | 32    | cookie                      |               |
          | 33    | date                        |               |
          | 34    | etag                        |               |
          | 35    | expect                      |               |
          | 36    | expires                     |               |
          | 37    | from                        |               |
          | 38    | host                        |               |
          | 39    | if-match                    |               |
          | 40    | if-modified-since           |               |
          | 41    | if-none-match               |               |
          | 42    | if-range                    |               |
          | 43    | if-unmodified-since         |               |
          | 44    | last-modified               |               |
          | 45    | link                        |               |
          | 46    | location                    |               |
          | 47    | max-forwards                |               |
          | 48    | proxy-authenticate          |               |
          | 49    | proxy-authorization         |               |
          | 50    | range                       |               |
          | 51    | referer                     |               |
          | 52    | refresh                     |               |
          | 53    | retry-after                 |               |
          | 54    | server                      |               |
          | 55    | set-cookie                  |               |
          | 56    | strict-transport-security   |               |
          | 57    | transfer-encoding           |               |
          | 58    | user-agent                  |               |
          | 59    | vary                        |               |
          | 60    | via                         |               |
          | 61    | www-authenticate            |               |
*/

class hpack_decoder {

public:
    datum input;

    hpack_decoder(datum &in) : input{in} {}

    void get_next(FILE *f) {
        fprintf(f, "\n%s:\t", __func__);

        uint8_t first;
        input.read_uint8(&first);

        fprintf(f, "first: %02x\t", first);

        if (first & 0x80) { // 1***: indexed header field
            // parse integer

            ssize_t value = decode(first, 7);
            fprintf(f, "indexed header field\tvalue: %zd\t", value);

        } else {  // literal header field

            if (first & 0x40) { // 01**: literal header field with incremental indexing
                //
                fprintf(f, "literal header field\t");
            }
            else if ((first & 0xf0) == 0) {  // 0000: literal header field without indexing
                //
                fprintf(f, "literal header field without indexing\t");

                ssize_t value = decode(first, 4);
                fprintf(f, "value: %zd\t", value);
                if (value > 0) {
                    // LOOK UP value IN TABLE
                } else {
                    // READ VALUE FROM INPUT
                }

            }
            else if ((first & 0xf0) == 1) {  // 0001: literal header field never indexed
                //
                fprintf(f, "literal header field never indexed\t");
           }
        }

        fprintf(f, "\n");
    }

    ssize_t decode(uint8_t first_byte, unsigned int N) {
        uint8_t mask;
        if (N==7) { mask = 0x7f; }
        if (N==6) { mask = 0x3f; }
        if (N==5) { mask = 0x1f; }
        if (N==4) { mask = 0x0f; }
        if (N==3) { mask = 0x07; }
        if (N==2) { mask = 0x03; }
        if (N==1) { mask = 0x01; }

        if ((first_byte & mask) < mask) {
            return first_byte & mask;   // value occupies single byte
        }

        // recover value from remaining bytes
        //
        int multiplier = 128;
        ssize_t tmp = 0;
        uint8_t next_byte;
        do {
            input.read_uint8(&next_byte);
            tmp += (next_byte & 0x7f) * multiplier;
            multiplier *= 128;
        } while(next_byte & 0x80 && input.is_not_empty());

        return tmp + mask;
    }
};

// Headers Frame (following RFC7540)
//
//    +---------------+
//    |Pad Length? (8)|
//    +-+-------------+-----------------------------------------------+
//    |E|                 Stream Dependency? (31)                     |
//    +-+-------------+-----------------------------------------------+
//    |  Weight? (8)  |
//    +-+-------------+-----------------------------------------------+
//    |                   Header Block Fragment (*)                 ...
//    +---------------------------------------------------------------+
//    |                           Padding (*)                       ...
//    +---------------------------------------------------------------+

class http2_headers {
    uint8_t pad_length;
    uint32_t e_stream_dependency;
    uint8_t weight;
    datum header_block_fragment;

public:
    http2_headers() : pad_length{0}, e_stream_dependency{0}, weight{0}, header_block_fragment{NULL, NULL} { }

    void parse(datum &d, bool padded=false, bool priority=false) {
        if (padded) {
            d.read_uint8(&pad_length);
        }
        if (priority) {
            d.read_uint32(&e_stream_dependency);
            d.read_uint8(&weight);
        }
        header_block_fragment = d;
    }

    void write_json(json_object &o) {
        json_object json_frame(o, "headers");
        json_frame.print_key_uint("pad_length", pad_length);
        // json_frame.print_key_uint("e", e_stream_dependency);  // TODO: need bit accessor function
        json_frame.print_key_uint("stream_dependency", e_stream_dependency);
        json_frame.print_key_hex("header_block_fragment", header_block_fragment);
        hpack_decoder headers{header_block_fragment};

        while(headers.input.is_not_empty()) {
            datum tmp = headers.input;
            headers.get_next(stderr);
            if (headers.input == tmp) {
                // we are not advancing, so abandon this loop
                fprintf(stderr, "break\n");
                break;
            }
        }
        json_frame.close();
    }
};


//  Frame Format (following RFC 7540)
//
//    +-----------------------------------------------+
//    |                 Length (24)                   |
//    +---------------+---------------+---------------+
//    |   Type (8)    |   Flags (8)   |
//    +-+-------------+---------------+-------------------------------+
//    |R|                 Stream Identifier (31)                      |
//    +=+=============================================================+
//    |                   Frame Payload (0...)                      ...
//    +---------------------------------------------------------------+
//

class http2_frame {
    uint64_t length;
    uint8_t type;
    uint8_t flags;
    uint32_t stream_id;
    datum payload;

public:

    enum type : uint8_t {
        DATA          = 0x0,
        HEADERS       = 0x1,
        PRIORITY      = 0x2,
        RST_STREAM    = 0x3,
        SETTINGS      = 0x4,
        PUSH_PROMISE  = 0x5,
        PING          = 0x6,
        GOAWAY        = 0x7,
        WINDOW_UPDATE = 0x8,
        CONTINUATION  = 0x9
    };

    http2_frame() : length{0}, type{0}, flags{0}, stream_id{0}, payload{NULL, NULL} {}

    void parse(struct datum &d) {
        d.read_uint(&length, 3);
        d.read_uint8(&type);
        d.read_uint8(&flags);
        d.read_uint32(&stream_id);
        payload = d;
    }

    const char *type_string(uint8_t t) {
        switch(t) {
        case DATA:           return "DATA";
        case HEADERS:        return "HEADERS";
        case PRIORITY:       return "PRIORITY";
        case RST_STREAM:     return "RST_STREAM";
        case SETTINGS:       return "SETTINGS";
        case PUSH_PROMISE:   return "PUSH_PROMISE";
        case PING:           return "PING";
        case GOAWAY:         return "GOAWAY";
        case WINDOW_UPDATE:  return "WINDOW_UPDATE";
        case CONTINUATION:   return "CONTINUATION";
        default:
            return "unknown";
        };
    }

    void write_json(struct json_object &o) {
        json_object json_frame(o, "frame");
        json_frame.print_key_uint("length", length);
        json_frame.print_key_string("type", type_string(type));
        json_frame.print_key_uint("flags", flags);
        json_frame.print_key_uint("stream_id", stream_id);
        json_frame.print_key_hex("payload", payload);

        if (type == HEADERS) {
            http2_headers h;
            h.parse(payload);
            h.write_json(o);
        }

        json_frame.close();
    }
};



struct http_request_x : public http_request {
    struct datum trailing_data;

    bool method_is_valid() {

        // method_is_valid() returns true if and only if the HTTP
        // method field in this request is one of the standard methods

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

    void parse(struct datum &p) {
        http_request::parse(p);
        trailing_data = p;
    }

    void write_json(struct json_object &o, bool output_metadata) {
        http_request::write_json(o, output_metadata);
        if (trailing_data.is_not_empty()) {
            o.print_key_hex("trailing_data", trailing_data);
        }
    }
};

// class output is responsible for data output - its interface
// abstracts away the details of where data goes and how it gets there
//

class output {
public:
    virtual void write_buffer(struct buffer_stream &buf) = 0;
    virtual ~output() {};

    enum type { unknown=0, file, log };

    static enum output::type get_type(const char *type_string) {
        if (type_string == nullptr) {
            return output::type::unknown;
        }
        std::string s{type_string};
        if (s.compare("file") == 0) {
            return output::type::file;
        }
        if (s.compare("log") == 0) {
            return output::type::log;
        }
        return output::type::unknown;
    }
};


class file_output : public output {
    FILE *outfile = nullptr;
    sem_t *outfile_sem = nullptr;
    static constexpr size_t buffer_length = 8*1024;

public:

    file_output() {

        //  use a named semaphore to ensure that writes to outfile are
        //  not overlapping
        //
        //  On a modern Linux system, this semaphore is located at
        //  /dev/shm/sem.intercept.  If there is a problem, you may
        //  need to delete that file
        //
        if ((outfile_sem = sem_open ("/intercept", O_CREAT, 0666, 1)) == SEM_FAILED) {
            perror ("intercept: sem_open()");
            exit(EXIT_FAILURE);
        }

        std::string outfile_name = "/usr/local/var/intercept/";  // default directory
        const char *ENV_INTERCEPT_DIR = getenv("intercept_dir");
        if (ENV_INTERCEPT_DIR) {
            if (strlen(ENV_INTERCEPT_DIR) > 0 && ENV_INTERCEPT_DIR[0] == '/') {
                outfile_name = ENV_INTERCEPT_DIR;
            } else {
                fprintf(stderr, "intercept: warning: %s is not an absolute directory path\n", ENV_INTERCEPT_DIR);
            }
        }

        // verify that we can access the output directory
        //
        if (access(outfile_name.c_str(), R_OK | W_OK) != 0) {
            fprintf(stderr,
                    RED(tty, "intercept: could not access directory %s (%s)\n"),
                    outfile_name.c_str(),
                    strerror(errno));
            exit(EXIT_FAILURE);
        }

        outfile_name += "/intercept.json";
        outfile = fopen(outfile_name.c_str(), "a+");
        if (outfile ==nullptr) {
            fprintf(stderr, RED(tty, "%s: could not open file %s (%s)\n"), __func__, outfile_name.c_str(), strerror(errno));
            exit(EXIT_FAILURE);
        }

    }

    ~file_output() {
        if (outfile) {
            fclose(outfile);
        }
        if (outfile_sem != SEM_FAILED) {
            sem_close(outfile_sem);
        }
        // closelog();
    }

    void write_buffer(struct buffer_stream &buf) {

        // POSIX semaphores for file locking
        //
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;
        if (sem_timedwait(outfile_sem, &ts) == -1) {   // use timedwait for resiliency
            perror ("intercept: sem_wait()");

            // failsafe: to recover from situations in which the
            // semaphore is not being released for whatever reason,
            // delete the semaphore and then create a new one
            //
            unlink("/dev/shm/sem.intercept");
            if ((outfile_sem = sem_open ("/intercept", O_CREAT, 0666, 1)) == SEM_FAILED) {
                perror ("intercept: sem_open()");
                exit(EXIT_FAILURE);
            }
        }
        // fprintf(stderr, GREEN(tty, "pid %d acquired semaphore\n"), pid);

        fseek(outfile, 0, SEEK_END); // move to end of file
        if (buf.write_line(outfile) < 0) {
            perror ("intercept: write()");
            exit(EXIT_FAILURE);
        }

        // fprintf(stderr, GREEN(tty, "pid %d releasing semaphore\n"), pid);
        if (sem_post(outfile_sem) == -1) {
            perror ("intercept: sem_post()");
            exit(EXIT_FAILURE);
        }
    }

};

struct syslog_output : public output {

    syslog_output() {
        openlog("intercept", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    }
    void write_buffer(struct buffer_stream &buf) {
        // buf.write_char('\n');
        buf.write_char('\0');
        syslog(LOG_INFO, "%s", buf.dstr);
    };

    ~syslog_output() {
        closelog();
    }
};



// class intercept controls the behavior of this library; you can
// define totally new behavior by defining a class that inherits from
// this one and overrides one or more member functions
//

class intercept {
    int pid, ppid;
    output *out;
    static constexpr size_t buffer_length = 8*1024;
    const char *INTERCEPT_DIR = nullptr;   // TODO: merge with ENV_INTERCEPT_DIR
    char cmd[256];
    size_t cmd_len = 0;
    char pcmd[256];
    size_t pcmd_len = 0;

public:

    // data_level is an enumeration that specifies the amount of data
    // to be reported in output
    //
    enum data_level { minimal_data = 0, full_data=1 };

    enum data_level output_level = full_data;

    intercept(output::type out_type) : pid{getpid()}, ppid{getppid()}, out{nullptr} {

        if (verbose) { fprintf(stderr, GREEN(tty, "%s\n"), __func__); }

        // create output object of appropriate type
        //
        switch(out_type) {
        case output::type::log:
            out = new syslog_output;
            break;
        case output::type::file:
        default:
            out = new file_output;   // default to file output
        }

        // fprintf(stderr, GREEN(tty, "intercepter build %s\t%s\n"), __DATE__, __TIME__);

        const char *intercept_output_level = getenv("intercept_output_level");
        if (intercept_output_level && strcmp(intercept_output_level, "full") == 0) {
            output_level = full_data;
        }
        if (intercept_output_level && strcmp(intercept_output_level, "minimal") == 0) {
            output_level = minimal_data;
        }

        // set cmd and pcmd
        //
        cmd_len = get_cmd(pid, cmd, sizeof(cmd));
        pcmd_len = get_cmd(ppid, pcmd, sizeof(pcmd));

        char buffer[buffer_length];
        struct buffer_stream buf(buffer, sizeof(buffer));
        struct json_object record{&buf};
        write_process_info(record, full_data);

        // write time into record
        struct timespec ts;
        timespec_get(&ts, TIME_UTC);
        record.print_key_timestamp("event_start", &ts);

        record.close();
        // write_buffer_to_file(buf, outfile);
        out->write_buffer(buf);

    }

    ~intercept() {
        delete out;
    }

    // write_process_info() writes information about the current
    // process to a json object with the following keys:
    //
    //    pid: process ID
    //    cmd: command line
    //    ppid: parent process ID
    //    pcmd: parent command line
    //
    void write_process_info(struct json_object &record, data_level level) {
        record.print_key_uint16("pid", pid);
        if (level) {
            record.print_key_json_string("cmd", (uint8_t *)cmd, cmd_len);
            record.print_key_uint16("ppid", ppid);
            record.print_key_json_string("pcmd", (uint8_t *)pcmd, pcmd_len);
        }
    }

    // write_flow_key() reads network socket info from the file
    // descriptor fd, then writes addresses and ports into json_object
    //
    void write_flow_key(struct json_object &record, int fd) {

        if (!fd_is_socket(fd)) {
            return;
        }

        // TODO: investigate performance, and determine if caching is
        // needed

        struct sockaddr_in address;
        bzero(&address, sizeof(address));
        socklen_t address_len = sizeof(address);
        int retval = getsockname(fd, (struct sockaddr *) &address, &address_len);
        if (retval == 0) {
            if (address.sin_family == AF_INET || address.sin_family == AF_INET6) {

                // report source address and source port
                //
                char addr[INET6_ADDRSTRLEN];
                inet_ntop(address.sin_family, &address.sin_addr, addr, sizeof(addr));
                uint16_t port = ntohs(address.sin_port);
                record.print_key_string("src_ip", addr);
                record.print_key_uint("src_port", port);

                // report destination address and destination port
                //
                getpeername(fd, (struct sockaddr *) &address, &address_len);
                inet_ntop(address.sin_family, &address.sin_addr, addr, sizeof(addr));
                port = ntohs(address.sin_port);
                record.print_key_string("dst_ip", addr);
                record.print_key_uint("dst_port", port);

            }
        }
    }

    void process_outbound(int fd, const uint8_t *data, ssize_t length);

    void process_outbound_plaintext(int fd, const uint8_t *data, ssize_t length) {

        static constexpr bool process_http2_frames = false;

        // fprintf(stderr, BLUE("%s\n"), __func__);

        //print_flow_key(fd);
        // write_data_to_file(pid, data, length, fd);
        //  process_http_request(data, length);

        struct datum tcp_data{data, data+length};
        struct http_request_x http_req{tcp_data};
        if (http_req.is_not_empty() && http_req.method_is_valid()) {

            char buffer[buffer_length];
            struct buffer_stream buf(buffer, sizeof(buffer));
            struct json_object record{&buf};

            // write pid into record
            write_process_info(record, output_level);
            record.print_key_uint("fd", fd);
            write_flow_key(record, fd);

            http_req.write_json(record, true);

            // write time into record
            struct timespec ts;
            timespec_get(&ts, TIME_UTC);
            record.print_key_timestamp("event_start", &ts);

            record.close();
            out->write_buffer(buf);

        } else if (process_http2_frames) {

            if (verbose) { fprintf(stderr, RED(tty, "http_request unrecognized\n")); }

            // write out plaintext data stream
            //
            struct datum tcp_data{data, data+length};
            if (tcp_data.is_not_empty()) {

                char buffer[buffer_length];
                struct buffer_stream buf(buffer, sizeof(buffer));
                struct json_object record{&buf};

                // write pid into record
                write_process_info(record, output_level);
                record.print_key_uint("fd", fd);
                write_flow_key(record, fd);

                record.print_key_hex("tcp_data", tcp_data);

                // parse as http2_frame
                //
                http2_frame frame;
                frame.parse(tcp_data);
                frame.write_json(record);

                // write time into record
                struct timespec ts;
                timespec_get(&ts, TIME_UTC);
                record.print_key_timestamp("event_start", &ts);

                record.close();
                out->write_buffer(buf);
            }

        }

    }

    void process_inbound(int fd, uint8_t *data, size_t length) {
        return; // TODO: fix this function

        fprintf(stderr, BLUE(tty, "%s got tcp_data\n"), __func__);
        fprintf_raw_as_hex(stderr, data, length); fputc('\n', stderr);

        if (length > 2 && data[0] == 0x16 && data[1] == 0x03) {
            if (verbose) { fprintf(stderr, GREEN(tty, "tls_handshake: ")); }
            //  fprintf_raw_as_hex(stderr, data, length); fputc('\n', stderr);

            struct datum tcp_data{data, data+length};

            struct tls_record rec{tcp_data};
            struct tls_handshake handshake;
            handshake.parse(rec.fragment);
            if (handshake.additional_bytes_needed) {
                fprintf(stderr, YELLOW(tty, "note: tls_handshake needs additional data\n"));
            }
            struct tls_server_hello hello;
            hello.parse(handshake.body);
            if (hello.is_not_empty()) {
                fprintf(stderr, BLUE(tty, "%s got tls_server_hello\n"), __func__);

                char buffer[buffer_length];
                struct buffer_stream buf(buffer, sizeof(buffer));
                struct json_object record{&buf};

                // write pid into record
                write_process_info(record, output_level);
                record.print_key_uint("fd", fd);
                write_flow_key(record, fd);

                hello.write_json(record);
                record.close();
                out->write_buffer(buf);

            }
        }

    }

    void process_inbound_plaintext(int fd, const uint8_t *data, ssize_t length) {
        // fprintf(stderr, BLUE("%s\n"), __func__);
        //print_flow_key(fd);
        //write_data_to_file(pid, data, length, fd);
    }

    void process_dns_lookup(const char *dns_name, const char *service) {
        // fprintf(stderr, BLUE("%s: %s\t%s\n"), __func__, dns_name, service);

        size_t dns_name_len = 0;
        if (dns_name) {
            dns_name_len = strlen(dns_name); // only run strlen() on valid pointers
        }

        char buffer[buffer_length];
        struct buffer_stream buf(buffer, sizeof(buffer));
        struct json_object record{&buf};

        write_process_info(record, output_level);
        // // write pid into record
        // record.print_key_uint16("pid", pid);
        // record.print_key_uint16("ppid", ppid);

        // write dns info into record
        json_object dns_object{record, "dns"};
        dns_object.print_key_json_string("name", (uint8_t *)dns_name, dns_name_len);
        //dns_object.print_key_json_string("service", service);
        dns_object.close();
        record.close();
        out->write_buffer(buf);

    }

    void write_data_to_file(const void *buffer, ssize_t bytes, int fd=0) {

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
            fprintf(stderr, GREEN(tty, "warning: filename \"%s\" was truncated\n"), filename);
        }
        FILE *plaintext_file = fopen(filename, "a+");
        if (plaintext_file) {
            fwrite(buffer, 1, bytes, plaintext_file);
            fclose(plaintext_file);
            if (verbose) { fprintf(stderr, GREEN(tty, "wrote data to file %s\n"), filename); }
        } else {
            fprintf(stderr, RED(tty, "error: could not write data to file %s\n"), filename);
        }
    }

    void process_http_request(int fd, const uint8_t *data, ssize_t length);

    void process_tls_client_hello(int fd, const uint8_t *data, ssize_t length);

};


// high level functions for processing network traffic
//

void intercept::process_http_request(int fd, const uint8_t *data, ssize_t length) {
    struct datum tcp_data{data, data+length};
    struct http_request http_req{tcp_data};
    if (http_req.is_not_empty()) {  // TODO: improve is_not_empty() with method check

        char buffer[buffer_length];
        struct buffer_stream buf(buffer, sizeof(buffer));
        struct json_object record{&buf};

        // write pid into record
        write_process_info(record, output_level);
        record.print_key_uint("fd", fd);
        write_flow_key(record, fd);

        // write fingerprint into record
        struct fingerprint fp;
        http_req.compute_fingerprint(fp);
        fp.write(record);
        http_req.write_json(record, true);

        record.close();

    } else {
        if (verbose) { fprintf(stderr, RED(tty, "http_request unrecognized\n")); }
    }
}

void intercept::process_tls_client_hello(int fd, const uint8_t *data, ssize_t length) {

    if (length > 2 && data[0] == 0x16 && data[1] == 0x03) {
        if (verbose) { fprintf(stderr, GREEN(tty, "tls_handshake: ")); }
        //  fprintf_raw_as_hex(stderr, data, length); fputc('\n', stderr);

        struct datum tcp_data{data, data+length};

        struct tls_record rec{tcp_data};
        struct tls_handshake handshake{rec.fragment};
        if (handshake.additional_bytes_needed) {
            fprintf(stderr, YELLOW(tty, "note: tls_handshake needs additional data\n"));
        }
        tls_client_hello hello{handshake.body};

        if (hello.is_not_empty()) {
            struct fingerprint fp;
            hello.compute_fingerprint(fp);

            char buffer[buffer_length];
            struct buffer_stream buf(buffer, sizeof(buffer));
            struct json_object record{&buf};

            // write pid into record
            write_process_info(record, output_level);
            record.print_key_uint("fd", fd);
            write_flow_key(record, fd);

            // write fingerprint into record
            fp.write(record);
            hello.write_json(record, true);
            record.close();
            out->write_buffer(buf);
        }
    }
}

void intercept::process_outbound(int fd, const uint8_t *data, ssize_t length) {
    process_tls_client_hello(fd, data, length);
    process_http_request(fd, data, length);
}


// global variable intrcptr
//
class intercept *intrcptr  = nullptr; // = new intercept;

// init/fini functions
//

void __attribute__ ((constructor)) intercept_init(void) {

    // check to see if stderr is a TTY, and suppress colorized output
    // if it is not
    //
    tty = isatty(fileno(stderr));

    if (verbose) { fprintf(stderr, GREEN(tty, "%s\n"), __func__); }

    // allocate global intercept object
    //
    intrcptr = new intercept(output::get_type(getenv("intercept_output_type")));

}

void __attribute__ ((destructor)) intercept_fini(void) {

    if (verbose) { fprintf(stderr, GREEN(tty, "%s\n"), __func__); }

    // free global intercept object
    //
    delete intrcptr;
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
    fprintf(stderr, RED(tty, "error: could not load symbol ") #SSL_read "\n");                \
    exit(EXIT_FAILURE);                                                                       \
}                                                                                             \
if (verbose) { fprintf(stderr, GREEN(tty, "intercepted %s\n") , __func__); }


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
   fprintf(stderr, RED(tty, "error: could not load symbol ") #func "\n");                      \
   exit(EXIT_FAILURE);                                                                    \
}                                                                                         \
if (verbose) { fprintf(stderr, GREEN(tty, "intercepted %s\n") , __func__); }              \
return original_ ## func (__VA_ARGS__)


// intercepts
//

// openssl and libcrypt functions
//

// #define INTERCEPT_EVP_CIPHER
#ifdef INTERCEPT_EVP_CIPHER

// Warning: EVP_Cipher interception is verbose
//
// TODO: determine enc/dec from CTX
//

#include <openssl/evp.h>

int EVP_Cipher(EVP_CIPHER_CTX *c,
               unsigned char *out,
               const unsigned char *in,
               unsigned int inl) {

    get_original(EVP_Cipher);

    fprintf(stderr, GREEN(tty, "intercepted %s (encrypting %u bytes)\n"), __func__, inl);

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
    //    fprintf(stderr, GREEN(tty, "%s: %.*s\n"), __func__, (int)data_size, (char *)data);
    // fprintf(stderr, GREEN(tty, "fd?: %d\n"), gnutls_transport_get_int(session));
    int r = 0, s = 0;
    gnutls_transport_get_int2(session, &r, &s);
    // fprintf(stderr, GREEN(tty, "fd2: %d\t%d\n"), r, s);
    // gnutls_transport_ptr_t tp;
    // tp = gnutls_transport_get_ptr(session);
    // fprintf(stderr, GREEN(tty, "tp: %p\n"), tp);

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
    fprintf(stderr, RED(tty, "%s\n"), __func__);
    invoke_original(gnutls_record_send2, session, data, data_size, pad, flags);
}

ssize_t gnutls_record_send_early_data (gnutls_session_t session, const void * data, size_t data_size) {
    fprintf(stderr, RED(tty, "%s\n"), __func__);
    invoke_original(gnutls_record_send_early_data, session, data, data_size);
}

ssize_t gnutls_record_send_range (gnutls_session_t session, const void * data, size_t data_size, const gnutls_range_st * range) {
    fprintf(stderr, RED(tty, "%s\n"), __func__);
    invoke_original(gnutls_record_send_range, session, data, data_size, range);
}

void gnutls_transport_set_push_function(gnutls_session_t session,  gnutls_push_func push_func) {
    fprintf(stderr, RED(tty, "%s\n"), __func__);
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
    if (verbose) { fprintf(stderr, YELLOW(tty, "sendmsg() invoked\n")); }  // note: no processing happening yet
    invoke_original(sendmsg, sockfd, msg, flags);
}


ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    fprintf(stderr, YELLOW(tty, "recv() invoked\n"));  // note: no processing happening yet
    invoke_original(recv, sockfd, buf, len, flags);
}

#include <unistd.h>

ssize_t write(int fd, const void *buf, size_t count) {

    if (fd_is_socket(fd)) {
        intrcptr->process_outbound(fd, (uint8_t *)buf, count);
    }
    invoke_original(write, fd, buf, count);
}


ssize_t read(int fd, void *buf, size_t count) {
    if (fd_is_socket(fd)) {
        intrcptr->process_inbound(fd, (uint8_t *)buf, count);
    }
    invoke_original(read, fd, buf, count);
}



// dns interception
//

#include <netdb.h>

struct hostent *gethostbyname(const char *name) {

    fprintf(stderr, BLUE(tty, "gethostbyname: %s\n"), name);

    invoke_original(gethostbyname, name);
}

int getaddrinfo(const char *node,
                const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res) {

    //    fprintf(stderr, BLUE(tty, "%s: %s\t%s\n"), __func__, node, service);
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
