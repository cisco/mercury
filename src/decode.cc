// decode.cc
//
// decodes packet (and other) data

#include <string>
#include "libmerc/datum.h"
#include "libmerc/base64.h"
#include "libmerc/json_object.h"
#include "libmerc/dns.h"

int main(int, char *[]) {
    FILE *stream = stdin;
    char *line = NULL;
    size_t len = 0;

    bool hex_output = true;

    while (1) {
        ssize_t nread = getline(&line, &len, stream);
        if (nread == -1) {
            free(line);
            break;
        }
        uint8_t data_buf[8192];
        ssize_t data_len = base64::decode(data_buf, sizeof(data_buf), line, nread);
        if (data_len < 0) {
            fprintf(stderr, "error: could not base64 decode input line\n");
            exit(EXIT_FAILURE);
        }
        datum data{data_buf, data_buf+data_len};

        fprintf(stderr, "data_len: %zd\n", data_len);
        if (hex_output) {
            data.fprint_hex(stdout);
            fputc('\n', stdout);
        }

        // parse data as dns packet
        //
        dns_packet packet{data};
        if (packet.is_not_empty()) {
            char output_buffer[8192];
            struct buffer_stream buf{output_buffer, sizeof(output_buffer)};
            json_object o{&buf};
            packet.write_json(o);
            o.close();
            buf.write_line(stdout);
        } else {
            fprintf(stderr, "input was not dns\n");
        }

    }

    return 0;
}
