
#include "libmerc/ldap.hpp"
#include "/home/mcgrew/dev/mercury-transition/src/libmerc/hex.hpp"

std::array<uint8_t, 190> binding_request_data = 0x3084000000b80201076184000000af0a010004000400878200a4a181a130819ea0030a0100a10b06092a864882f712010202a2818904818660818306092a864886f71201020202006f743072a003020105a10302010fa2663064a003020117a25d045b2754d8f79de369ce095485cbfb3527f5cd732f730822720b1d829c7a969c8122828a3a77d47f0b9cc0559f587cd18369e738c0ea57e738b3cd586aa4f8d7cc5d948f5b8e2bbf4cba31fd1acf504c77f6101b72a00dabb985c7fc4e_hex .array();

std::array<uint8_t, 14> br_simple_data = 0x300c020101600702010304008000_hex .array();

int main(int argc, char *argv[]) {

    datum d{br_simple_data};
    d.fprint_hex(stdout); fputc('\n', stdout);

    ldap::bind_request br{d};

    output_buffer<2048> buf;
    json_object o{&buf};
    br.write_json(o);
    o.close();
    buf.write_line(stdout);

    return 0;
}
