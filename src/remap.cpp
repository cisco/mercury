// remap.cpp
//
// merges pcap files and remaps private addresses
//

#include "pcap_file_io.h"
#include "libmerc/eth.h"
#include "libmerc/ip.h"
#include "libmerc/tcpip.h"
#include "libmerc/udp.h"
#include "pcap.h"

#include "libmerc/dns.h"
#include "libmerc/quic.h"
#include "libmerc/tls.h"
#include "libmerc/http.h"
#include "libmerc/file_set.hpp"
#include "options.h"

class address_remapper {

    struct file_data {
        std::string file_name;
        ipv4_address subnet;
        size_t packet_count{0};
        size_t tls_client_hello_count{0};
        size_t http_req_count{0};
        size_t quic_init_count{0};

        file_data(const std::string &s, ipv4_address sub) : file_name{s}, subnet{sub} { }

        void print_json(FILE *f) const {
            uint32_t a = subnet.get_value();
            fprintf(f,
                    "{\"file\":\"%s\","
                    "\"subnet\":\"%u.%u.%u.%u\","
                    "\"packet_count\":%zu,"
                    "\"tls_client_hello_count\":%zu,"
                    "\"http_req_count\":%zu,"
                    "\"quic_init_count\":%zu"
                    "}\n",
                    file_name.c_str(),
                    a >> 0  & 0xff,
                    a >> 8  & 0xff,
                    a >> 16 & 0xff,
                    a >> 24 & 0xff,
                    packet_count,
                    tls_client_hello_count,
                    http_req_count,
                    quic_init_count
                    );
        }

    };

    std::unordered_map<ipv4_address, ipv4_address> ipv4_map;
    std::vector<file_data> file_info;

    ipv4_address top_subnet{0x0000000a};      // 10.0.0.0 in host byte order
    ipv4_address top_addr{0x0000000a};        // 10.0.0.0 in host byte order
    ipv4_address top_server_addr{0x8000000a}; // 10.0.0.128 in host byte order

    pcap::file_writer w;
    const char *pcap_output_file_name;

    // ip_address_range clients;
    // ip_address_range servers;

    size_t tls_client_hello_count=0;
    size_t http_req_count=0;
    size_t quic_init_count=0;

    size_t ipv6_packet_count=0;

    quic_crypto_engine quic_crypto{}; // initialize engine for quic decryption

public:

    address_remapper(
                     // const ip_address_range &client_addrs,
                     // const ip_address_range &server_addrs,
                     const char *outfile_name) :
        w{outfile_name},
        pcap_output_file_name{outfile_name}
        // clients{client_addrs},
        // servers{server_addrs}
    {
        //pcap::ng::file_writer w{"test.pcapng"};
    }

    void set_input_file(const std::string &s) {

        top_addr = top_subnet;
        top_server_addr = hton(ntoh(top_subnet.get_value())+128);

        file_info.push_back({s, top_subnet});
        top_subnet.next_supernet(8);
        ipv4_map.clear();

        tls_client_hello_count=0;
        http_req_count=0;
        quic_init_count=0;

        ipv6_packet_count=0;
    }

    void dump_map(FILE *f) {
        for (const auto & x : file_info) {
            x.print_json(f);
        }
    }

    void readdress_packet(struct datum &pkt_data) {

        eth ethernet{pkt_data};
        uint16_t ethertype = ethernet.get_ethertype();
        switch(ethertype) {
        case ETH_TYPE_IP:
        case ETH_TYPE_IPV6:
            {
                key k;
                ip ip_pkt{pkt_data, k};
                if (ip_pkt.version() != 4) {
                    ++ipv6_packet_count;
                    return; // we can't process this packet
                }
                ip::protocol protocol = ip_pkt.transport_protocol();

                if (protocol == ip::protocol::tcp) {
                    struct tcp_packet tcp_pkt{pkt_data};
                    tcp_pkt.set_key(k);
                    {
                        datum tcp_data_copy{pkt_data};
                        tls_record rec{tcp_data_copy};
                        if (rec.type() == tls_content_type::handshake) {
                            struct tls_handshake handshake;
                            handshake.parse(rec.fragment);
                            if (handshake.type() == handshake_type::client_hello) {
                                tls_client_hello client_hello;
                                client_hello.parse(handshake.body);
                                if (client_hello.is_not_empty() == true) {
                                    ++tls_client_hello_count;
                                }
                            }
                        }
                    }
                    {
                        datum tcp_data_copy{pkt_data};
                        http_request http_req{tcp_data_copy};
                        if (http_req.is_not_empty()) {
                            ++http_req_count;
                        }
                    }

                } else if (protocol == ip::protocol::udp) {
                    class udp udp_pkt{pkt_data};
                    udp_pkt.set_key(k);
                    {
                        datum udp_data_copy = pkt_data;
                        quic_init quic{udp_data_copy, quic_crypto};
                        if (quic.is_not_empty() == true) {
                            ++quic_init_count;
                        }
                    }
                }

                bool src_is_service = k.src_port == 53;
                bool dst_is_service  = k.dst_port == 53;
                ipv4_address &src = src_is_service ? top_server_addr : top_addr;
                ipv4_address &dst = dst_is_service ? top_server_addr : top_addr;

                // auto [update_src, update_dst ] =
                ip_pkt.remap_private_addrs(ipv4_map, src, dst);
            }
            break;
        default:
            ;
        }
    }

    void process_directory(const char *dirname,
                           std::pair<time_t, time_t> before_and_after) {

        file_enumerator files{dirname, before_and_after};
        for (const auto& dir_entry : files.recursive_dir_it()) {
            std::optional<std::string> filename = files.get_matching_files(dir_entry);
            if (filename) {
                process_pcap(filename->c_str());
            }
        }
    }

    void process_pcap(const char *pcap_file_name) {
        size_t i=0;
        try {

            // ensure that the input file is not the same as the output file
            //
            if (std::filesystem::canonical(pcap_file_name) == std::filesystem::canonical(pcap_output_file_name)) {
                fprintf(stderr, "note: ignoring PCAP output file in input file set\n");
                return;    // skip further processing of this file
            }

            pcap::file_reader pcap(pcap_file_name);
            set_input_file(pcap_file_name);

            data_buffer<65536> buf;
            packet<65536> pkt;
            while (true) {

                datum pkt_data = pkt.get_next(pcap);
                if (!pkt_data.is_not_empty()) {
                    break;
                }

                buf << pkt_data;
                datum pkt_copy{buf.contents()};

                readdress_packet(pkt_copy);

                w.write(buf.contents());
                buf.reset();
                i++;
            }
        }
        catch (std::exception &e) {
            fprintf(stderr, "error processing pcap_file %s:\t", pcap_file_name);
            fprintf(stderr, "%s\n", e.what());
            exit(EXIT_FAILURE);
        }
        catch (...) {
            fprintf(stderr, "unknown error processing pcap_file %s\n", pcap_file_name);
            exit(EXIT_FAILURE);
        }

        file_info.back().packet_count = i;
        file_info.back().tls_client_hello_count = tls_client_hello_count;
        file_info.back().http_req_count = http_req_count;
        file_info.back().quic_init_count = quic_init_count;

        if (ipv6_packet_count) {
            fprintf(stderr, "warning: ignoring %zu ipv6 packets in %s\n", ipv6_packet_count, pcap_file_name);
        }

    }

};

using namespace mercury_option;

int main(int argc, char *argv[]) {

    option_processor opt({{ argument::required, "--directory",   "directory of input files" },
                          { argument::required, "--file",        "input file" },
                          { argument::required, "--modified-before", "ignore files not modified before %Y-%b-%d %H:%M:%S" },
                          { argument::required, "--modified-after",  "ignore files not modified after %Y-%b-%d %H:%M:%S" },
                          { argument::required, "--pcap-output", "PCAP output file name" },
                          { argument::required, "--json-output", "JSON output file name" },
                          { argument::none,     "--help",        "print usage summary" },
        });

    const char summary[] =
        "usage:\n"
        "   remap [OPTIONS]\n"
        "\n"
        "OPTIONS\n"
        ;
    if (!opt.process_argv(argc, argv)) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    if (opt.is_set("--help")) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_SUCCESS;
    }

    auto [ dir_is_set, dir ]                   = opt.get_value("--directory");
    auto [ file_is_set, file ]                 = opt.get_value("--file");
    auto [ mod_before_set, mod_before ]        = opt.get_value("--modified-before");
    auto [ mod_after_set, mod_after ]          = opt.get_value("--modified-after");
    auto [ pcap_outfile_is_set, pcap_outfile ] = opt.get_value("--pcap-output");
    auto [ json_outfile_is_set, json_outfile ] = opt.get_value("--json-output");

    if (!pcap_outfile_is_set) {
        fprintf(stderr, "error: no PCAP output file specified\n");
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    FILE *json_output_file = stdout;
    if (json_outfile_is_set) {
        json_output_file = fopen(json_outfile.c_str(), "w");
        if (json_output_file == nullptr) {
            perror("could not open JSON output file");
            return EXIT_FAILURE;
        }
    }

    // set the default { after, before } times to the start of the
    // epoch and the distant future, respectively
    //
    std::time_t a = 0;              // Wed Dec 31 19:00:00 1969
    std::time_t b = 0xfffffffff;    // Sun Aug 20 03:32:15 4147

    const char date_and_time_format[] = "%Y-%m-%d %H:%M:%S";
    if (mod_before_set) {
        std::istringstream before{mod_before};
        std::tm tm_before{};
        before >> std::get_time(&tm_before, date_and_time_format);
        if (!before) {
            fprintf(stderr,
                    "error: could not parse '%s' as %s\n",
                    mod_before.c_str(),
                    date_and_time_format
                    );
            opt.usage(stderr, argv[0], summary);
            return EXIT_FAILURE;
        }
        b = std::mktime(&tm_before);
    }

    if (mod_after_set) {
        std::istringstream after{mod_after};
        std::tm tm_after{};
        after >> std::get_time(&tm_after, "%Y-%m-%d %H:%M:%S");
        if (!after) {
            fprintf(stderr,
                    "error: could not parse '%s' as %s\n",
                    mod_after.c_str(),
                    date_and_time_format
                    );
            opt.usage(stderr, argv[0], summary);
            return EXIT_FAILURE;
        }
        a = std::mktime(&tm_after);
    }

    address_remapper remapper{
        // ip_address_range{ntoh<uint32_t>(0xc0a80000), 17},
        // ip_address_range{ntoh<uint32_t>(0xc0a88000), 17},
        pcap_outfile.c_str()
    };

    if (file_is_set) {
        remapper.process_pcap(file.c_str());
    }
    if (dir_is_set) {
        remapper.process_directory(dir.c_str(), {b, a});
    }

    remapper.dump_map(json_output_file);

    return 0;
}
