// intercept_server.cc
//
// intercept_server is a a simple datagram server, for use with the
// intercept.so shared library; it serializes output from multiple
// processes, by reading strings from a datagram socket then writing
// them to a file

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#define SOCKET_PATH "/tmp/intercept.socket"

FILE *outfile;
int sock;

[[noreturn]] void handle_shutdown(int i) {
    const char *signame = "unknown";
    switch(i) {
    case SIGINT:
        signame = "SIGINT";
        break;
    case SIGHUP:
        signame = "SIGHUP";
        break;
    default:
        ;
    }
    fprintf(stderr, "caught signal %s, shutting down\n", signame);
    fflush(outfile);
    close(sock);
    unlink(SOCKET_PATH);
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {

    signal(SIGINT, handle_shutdown);
    signal(SIGHUP, handle_shutdown);

    // set output file from arguments
    //
    if (argc != 2) {
        fprintf(stderr, "usage: %s <outfile>\n", argv[0]);
        return EXIT_FAILURE;
    }
    FILE *outfile = fopen(argv[1], "w+");
    if (outfile == nullptr) {
        fprintf(stderr, "error: %s: could not open file %s for writing\n", strerror(errno), argv[1]);
        return EXIT_FAILURE;
    }

    // set name and address family
    //
    struct sockaddr_un name;
    name.sun_family = AF_UNIX;
    strcpy(name.sun_path, SOCKET_PATH);

    // if an old copy of the named socket is still around, remove it
    //
    if (unlink(SOCKET_PATH) < 0 && errno != ENOENT) {
        fprintf(stderr, "error: %s: could not unlink socket %s\n", strerror(errno), name.sun_path);
        return EXIT_FAILURE;
    }

    // create socket, then bind it to name
    //
    umask(0);
    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "error: %s: could not create socket %s\n", strerror(errno), name.sun_path);
        return EXIT_FAILURE;
    }
    if (bind(sock, (struct sockaddr *) &name, sizeof(struct sockaddr_un))) {
        fprintf(stderr, "error: %s: could not bind name %s to datagram socket\n", strerror(errno), name.sun_path);
        return EXIT_FAILURE;
    }

    // process messages
    //
    while (true) {
        char buf[20*1024];

        // read message from socket, then write to output
        //
        if (read(sock, buf, sizeof(buf)) < 0) {
            fprintf(stderr, "error: %s: could not read from socket %s\n", strerror(errno), name.sun_path);
        }
        fprintf(outfile, "%s\n", buf);
    }
    handle_shutdown(0);

    return 0;
}
