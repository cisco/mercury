// decode.cc
//
// decodes packet (and other) data

#include <string>
#include "libmerc/datum.h"
#include "libmerc/base64.h"
#include "libmerc/json_object.h"
#include "libmerc/dns.h"

size_t hex_to_raw(const void *output,
                  size_t output_buf_len,
                  const char *null_terminated_hex_string) {
    const char *hex = null_terminated_hex_string;
    const unsigned char *out = (uint8_t *)output;
    size_t count = 0;

    while (output_buf_len-- > 0) {
        if (hex[0] == 0 || hex[0] == '\n') {
            break;
        }
        if (hex[1] == 0) {
            return count;   /* error */
        }
        sscanf(hex, "%2hhx", (unsigned char *)&out[count++]);
        hex += 2;
    }
    return count;
}

int main(int, char *[]) {
    FILE *stream = stdin;
    char *line = NULL;
    size_t len = 0;

    bool hex_input = true;
    bool hex_output = false;

    while (1) {
        ssize_t nread = getline(&line, &len, stream);
        if (nread == -1) {
            free(line);
            break;
        }
        uint8_t data_buf[8192];
        ssize_t data_len;
        if (hex_input) {
            data_len = hex_to_raw(data_buf, sizeof(data_buf), line);
        } else {
            data_len = base64::decode(data_buf, sizeof(data_buf), line, nread);
        }
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
